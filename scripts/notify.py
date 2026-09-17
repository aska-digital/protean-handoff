"""Protean Handoff - outbound notification policy: P0 allowlist, dedup, batching,
escalation (lock 3).

Nothing pings the phone unless it is P0 (I12). P1 waits for the morning report.

  P0 (the only classes that ping): lane_completion, gate_red, approval_pending,
      reconnect_failure, hold_blocked.
  everything else -> P1, including anything unrecognised (fail quiet, never ping).

Deduplication: `dedup_key = sha256(class | entity_id | state_fingerprint | time_bucket)`
with a 15-minute aligned bucket; identity-shaped classes (an approval_id, a hold_id,
an artifact sha256) dedup permanently instead. A suppressed duplicate increments a
counter and sends nothing (the counter is the `suppressed` rows in `notify.jsonl`).

Batching: P0 events inside one 60-second window merge into one message, max 10 rows,
one `next:`. Failure: three failed deliveries record `delivery unverified` and raise a
P0 escalation - a dropped P0 is never silent.

Delivery is delegated: this module renders the payload and returns a `send_spec` naming
the existing egress (`send_message` with an attested `platform:chat_id` target). It never
opens a transport, never sends, and never emits credentials.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import handoff_lib as lib
import render as render_mod

P0_CLASSES = {
    "lane_completion": "lane completion (stage done or a receipt artifact written)",
    "gate_red": "red gate verdict",
    "approval_pending": "new pending approval needing an operator decision",
    "reconnect_failure": "explicit reconnect failure (gateway unreachable or delivery failed)",
    "hold_blocked": "a hold blocked an attempted consequential action",
}

P1_CLASSES = {
    "progress": "progress",
    "heartbeat": "heartbeat",
    "gate_amber": "amber gate",
    "steer_queued": "queued steer",
    "lane_render": "per-lane render",
    "read": "read",
    "snapshot_refresh": "snapshot refresh",
    "skill_load": "skill load",
    "owner_notice": "unauthorized-sender notice (owner-side, once per sender per gateway process)",
    "morning_report": "morning report",
    "delivery_retry": "delivery retry",
    "informational": "informational",
    "approval_granted": "approval granted (recorded, never pings)",
}

# Delivered immediately but not a P0 ping: the lock's owner notice is one message per
# (platform, user_id) per gateway process, so it is deduped on the process id.
IMMEDIATE_NON_P0 = ("owner_notice",)

PERMANENT_CLASSES = {
    "approval_pending": "approval_id",
    "hold_blocked": "hold_id",
    "lane_completion": "artifact_sha256",
}

ACTIONS = ("sent", "batched", "suppressed", "held", "unverified")
DEVELOP_FALLBACK = "discord"


def notify_path(state_dir):
    return lib.state_path(state_dir, lib.NOTIFY)


def classify(event_class, deliver=False):
    """P0 allowlist. Unknown classes are P1: they never ping."""
    if event_class in P0_CLASSES:
        return {"class": event_class, "p0": True, "immediate": False,
                "reason": P0_CLASSES[event_class]}
    if event_class in IMMEDIATE_NON_P0:
        return {"class": event_class, "p0": False, "immediate": True,
                "reason": P1_CLASSES.get(event_class, "owner notice")}
    return {"class": event_class, "p0": False, "immediate": False,
            "reason": P1_CLASSES.get(event_class, "unclassified event: P1 by default (never pings)")}


def dedup_key(event_class, entity_id, state_fingerprint="", now=None, permanent=None):
    identity = str(entity_id or "")
    if permanent is None:
        permanent = event_class in PERMANENT_CLASSES
    if permanent:
        raw = "%s|%s|permanent" % (event_class, identity)
    else:
        raw = "%s|%s|%s|%s" % (event_class, identity, state_fingerprint or "",
                               lib.bucket_key(now=now))
    return lib.sha256_text(raw), bool(permanent)


def load_notify(state_dir, limit=lib.DEDUP_KEEP):
    rows, malformed = lib.read_jsonl(notify_path(state_dir), limit=limit)
    return rows, malformed


def resolve_targets(authz, platform=None):
    """Primary = operator home channel; failover = the other surface. One channel only."""
    homes = authz.get("home_channels") or {}
    primary_platform = platform
    if not primary_platform:
        for candidate in ("whatsapp", "discord"):
            entry = homes.get(candidate)
            chat_id = entry.get("chat_id") if isinstance(entry, dict) else entry
            if chat_id:
                primary_platform = candidate
                break
        else:
            return None, []
    entry = homes.get(primary_platform)
    chat_id = entry.get("chat_id") if isinstance(entry, dict) else entry
    if not chat_id:
        return None, []
    failover = []
    for candidate in ("whatsapp", "discord"):
        if candidate == primary_platform:
            continue
        other = homes.get(candidate)
        other_id = other.get("chat_id") if isinstance(other, dict) else other
        if other_id:
            failover.append({"platform": candidate, "chat_id": str(other_id)})
    return {"platform": primary_platform, "chat_id": str(chat_id)}, failover


def emit(state_dir, event_class, entity_id=None, state_fingerprint="", facts=None,
         subject=None, evidence=None, next_action=None, sigil=None, lane_id=None,
         now=None, authz=None, platform=None, permanent=None, artifact_sha256=None):
    """Classify, dedup, batch and render one notification. Never sends."""
    now = now or lib.utcnow()
    authz = authz if authz is not None else lib.load_authz(state_dir)
    verdict = classify(event_class)
    p0 = verdict["p0"]
    immediate = bool(verdict.get("immediate"))
    entity_id = str(entity_id or event_class)
    if event_class == "lane_completion" and artifact_sha256:
        state_fingerprint = artifact_sha256
    if immediate:
        state_fingerprint = str(os.getpid())
        permanent = True
    key, is_permanent = dedup_key(event_class, entity_id,
                                  state_fingerprint=state_fingerprint, now=now,
                                  permanent=permanent)

    rows, malformed = load_notify(state_dir)
    evidence = [str(e) for e in (evidence or []) if str(e)]
    ledger = notify_path(state_dir)
    if not evidence:
        evidence = [ledger]

    # dedup
    if is_permanent:
        for row in rows:
            if row.get("dedup_key") == key and row.get("action") in ("sent", "batched", "held"):
                lib.append_jsonl(ledger, {
                    "at": lib.iso(now), "class": event_class, "entity_id": entity_id,
                    "dedup_key": key, "permanent": True, "p0": p0, "action": "suppressed",
                    "note": "identity-shaped duplicate",
                })
                return lib.ok_result(p0=p0, suppressed=True, sent=False, dedup_key=key,
                                     permanent=True,
                                     summary="suppressed identity-shaped duplicate; nothing sent",
                                     evidence=[ledger],
                                     next="next: none - informational")
    else:
        bucket = lib.bucket_key(now=now)
        for row in rows:
            if row.get("dedup_key") == key and int(row.get("bucket") or -1) == bucket \
                    and row.get("action") in ("sent", "batched", "held"):
                lib.append_jsonl(ledger, {
                    "at": lib.iso(now), "class": event_class, "entity_id": entity_id,
                    "dedup_key": key, "permanent": False, "p0": p0, "action": "suppressed",
                    "bucket": bucket, "note": "duplicate inside the 15-minute window",
                })
                return lib.ok_result(p0=p0, suppressed=True, sent=False, dedup_key=key,
                                     permanent=False,
                                     summary="suppressed duplicate inside its window",
                                     evidence=[ledger],
                                     next="next: none - informational")

    # owner notice: delivered immediately (once per sender per gateway process), never batched
    if immediate:
        for row in rows:
            if row.get("dedup_key") == key and row.get("action") in ("sent", "batched"):
                lib.append_jsonl(ledger, {
                    "at": lib.iso(now), "class": event_class, "entity_id": entity_id,
                    "dedup_key": key, "permanent": True, "p0": False, "action": "suppressed",
                    "note": "owner notice already sent for this sender in this process",
                })
                return lib.ok_result(p0=False, suppressed=True, sent=False, immediate=True,
                                     dedup_key=key,
                                     summary="owner notice already sent once for this sender",
                                     evidence=[ledger],
                                     next="next: none - informational")
        payload = render_mod.build_envelope(sigil or "[err]", subject or "unauthorized sender",
                                            facts or ["identity not authorized"],
                                            evidence, next_action or "none - informational",
                                            now=now)
        target, failover = resolve_targets(authz, platform=platform)
        lib.append_jsonl(ledger, {
            "at": lib.iso(now), "class": event_class, "entity_id": entity_id,
            "dedup_key": key, "permanent": True, "p0": False, "action": "sent",
            "immediate": True, "payload_hash": lib.sha256_text(payload),
            "target": "%s:%s" % (target["platform"], target["chat_id"]) if target else None,
        })
        send_spec = None
        if target:
            send_spec = {"tool": "send_message",
                         "target": "%s:%s" % (target["platform"], target["chat_id"]),
                         "text": payload,
                         "note": "existing egress only; the agent owns the send call"}
        return lib.ok_result(p0=False, immediate=True, sent=bool(send_spec), suppressed=False,
                             dedup_key=key, message=payload, send_spec=send_spec,
                             evidence=[ledger],
                             next="next: none - informational")

    # P1 never pings: record it for the morning report only
    if not p0:
        lib.append_jsonl(ledger, {
            "at": lib.iso(now), "class": event_class, "entity_id": entity_id,
            "dedup_key": key, "permanent": is_permanent, "p0": False, "action": "held",
            "bucket": lib.bucket_key(now=now), "lane_id": lane_id,
            "note": "P1: waits for the morning report",
        })
        return lib.ok_result(p0=False, sent=False, suppressed=False, held=True, dedup_key=key,
                             summary=verdict["reason"] + " -> morning report only",
                             evidence=[ledger], next="next: morning-report")

    # batching: P0 rows inside one 60-second window merge into a single message
    window_start = now.timestamp() - lib.BATCH_WINDOW_SECONDS
    batch = []
    for row in rows:
        if not row.get("p0"):
            continue
        if row.get("action") not in ("sent", "batched", "held"):
            continue
        row_ts = lib.epoch(row.get("at"))
        if row_ts is not None and row_ts >= window_start:
            batch.append(row)
    batch.append({"at": lib.iso(now), "class": event_class, "entity_id": entity_id,
                  "dedup_key": key, "p0": True, "lane_id": lane_id,
                  "facts": [str(f) for f in (facts or [])][:3]})

    batched = len(batch) > 1
    overflow = max(0, len(batch) - lib.BATCH_MAX_ROWS)
    batch = batch[-lib.BATCH_MAX_ROWS:]

    classic = event_class == "reconnect_failure"
    chosen_sigil = sigil or ("[err]" if classic else "[P0]")
    if not subject:
        if batched:
            subject = "%d P0 events" % len(batch)
        else:
            subject = verdict["reason"].split(" (")[0].capitalize()
    merged_facts = []
    for row in batch:
        merged_facts.extend(row.get("facts") or [])
    if batched:
        merged_facts = ["%s: %s" % (row.get("class"), (row.get("facts") or [row.get("entity_id")])[0])
                        for row in batch]
    if overflow:
        merged_facts.append("%d more P0 row(s) waiting" % overflow)

    if event_class == "approval_pending" and entity_id.startswith("a-"):
        next_action = next_action or "approve %s" % entity_id
    if event_class == "hold_blocked":
        next_action = next_action or "release %s" % (entity_id if entity_id.startswith("h-") else "<hold_id>")
    next_action = next_action or "status all"

    payload = render_mod.build_envelope(chosen_sigil, subject, merged_facts, evidence,
                                        next_action, now=now)
    target, failover = resolve_targets(authz, platform=platform)
    lib.append_jsonl(ledger, {
        "at": lib.iso(now), "class": event_class, "entity_id": entity_id,
        "dedup_key": key, "permanent": is_permanent, "p0": True,
        "action": "batched" if batched else "sent",
        "bucket": lib.bucket_key(now=now), "lane_id": lane_id,
        "target": "%s:%s" % (target["platform"], target["chat_id"]) if target else None,
        "batch_size": len(batch), "payload_hash": lib.sha256_text(payload),
    })

    send_spec = None
    if target:
        send_spec = {"tool": "send_message", "target": "%s:%s" % (target["platform"], target["chat_id"]),
                     "text": payload, "failover_after_primary_failure": failover,
                     "note": "existing egress only; the agent owns the send call"}
    return lib.ok_result(
        p0=True, sent=bool(send_spec), batched=batched, suppressed=False, held=False,
        dedup_key=key, permanent=is_permanent, batch_size=len(batch), overflow=overflow,
        message=payload, send_spec=send_spec,
        primary=("%s:%s" % (target["platform"], target["chat_id"])) if target else None,
        failover_ready=bool(failover),
        evidence=[ledger] if not evidence else evidence,
        next="next: send via existing egress, then notify.py delivery --dedup-key %s --result delivered" % key,
    )


def record_delivery(state_dir, dedup_key, result, now=None, attempt=None, evidence=None):
    """Record a delivery outcome. Three failures -> unverified + P0 escalation."""
    now = now or lib.utcnow()
    lib.require(result in ("delivered", "failed"), "E_BAD_RESULT",
                "delivery result must be delivered or failed",
                "next: pass --result delivered|failed")
    rows, _ = load_notify(state_dir)
    failures = [r for r in rows if r.get("dedup_key") == dedup_key and r.get("action") == "delivery_failed"]
    attempt_no = attempt or (len(failures) + 1)
    ledger = notify_path(state_dir)
    lib.append_jsonl(ledger, {
        "at": lib.iso(now), "dedup_key": dedup_key, "action": "delivery_delivered"
        if result == "delivered" else "delivery_failed",
        "attempt": attempt_no, "p0": True,
        "note": "delivery verified" if result == "delivered" else "delivery failed",
    })
    if result == "delivered":
        return lib.ok_result(delivered=True, attempt=attempt_no, evidence=[ledger],
                             next="next: none - informational")

    if attempt_no < lib.NOTIFY_MAX_RETRIES:
        return lib.ok_result(delivered=False, attempt=attempt_no, unverified=False,
                             evidence=[ledger],
                             next="next: retry the send (attempt %d of %d)"
                                  % (attempt_no + 1, lib.NOTIFY_MAX_RETRIES))

    # bounded retries exhausted: unverified + raise as a P0 (a dropped P0 is never silent)
    lib.append_jsonl(ledger, {
        "at": lib.iso(now), "dedup_key": dedup_key, "action": "unverified",
        "attempt": attempt_no, "p0": True,
        "note": "delivery unverified after %d failures" % attempt_no,
        "connectivity_hint": "gateway",
    })
    escalation = emit(state_dir, "reconnect_failure", entity_id=dedup_key,
                      subject="delivery unverified",
                      facts=["delivery failed %d times for %s" % (attempt_no, dedup_key[:12]),
                             "treated as gateway-down until re-checked"],
                      evidence=[ledger] + [str(e) for e in (evidence or [])],
                      next_action="status all", now=now, permanent=True)
    return lib.ok_result(
        delivered=False, attempt=attempt_no, unverified=True, raised=True,
        escalation_message=escalation.get("message"), send_spec=escalation.get("send_spec"),
        evidence=[ledger],
        next="next: send the escalation, then reconnect.py-free recheck via status all",
    )


def list_notifications(state_dir, p0_only=False, limit=lib.DEDUP_KEEP):
    rows, malformed = load_notify(state_dir, limit=limit)
    if p0_only:
        rows = [r for r in rows if r.get("p0")]
    counts = {}
    for row in rows:
        counts[row.get("action")] = counts.get(row.get("action"), 0) + 1
    return rows, malformed, counts


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="notify.py",
        description="P0 notification allowlist, dedup, batching and escalation records.")
    parser.add_argument("--state-dir", help="handoff state directory")
    parser.add_argument("--authz-file")
    parser.add_argument("--now", help="override now (iso8601)")
    sub = parser.add_subparsers(dest="cmd")

    def add_event_args(p):
        p.add_argument("--class", dest="event_class", required=True)
        p.add_argument("--entity-id")
        p.add_argument("--fingerprint", dest="state_fingerprint", default="")
        p.add_argument("--artifact-sha256")
        p.add_argument("--lane")
        p.add_argument("--subject")
        p.add_argument("--fact", action="append", default=[])
        p.add_argument("--ev", action="append", default=[])
        p.add_argument("--next", dest="next_action")
        p.add_argument("--sigil", choices=list(lib.SIGILS))
        p.add_argument("--platform", help="force the primary surface (whatsapp|discord)")
        p.add_argument("--permanent", action="store_true")

    p_emit = sub.add_parser("emit", help="classify, dedup, batch and render one event")
    add_event_args(p_emit)

    p_filter = sub.add_parser("filter", help="report the P0/P1 decision for a class")
    p_filter.add_argument("--class", dest="event_class", required=True)

    p_delivery = sub.add_parser("delivery", help="record a delivery outcome")
    p_delivery.add_argument("--dedup-key", required=True)
    p_delivery.add_argument("--result", required=True, choices=["delivered", "failed"])
    p_delivery.add_argument("--attempt", type=int)
    p_delivery.add_argument("--ev", action="append", default=[])

    p_list = sub.add_parser("list", help="list notification records")
    p_list.add_argument("--p0", action="store_true")

    sub.add_parser("classes", help="print the P0 and P1 class maps")

    args = parser.parse_args(argv)
    try:
        state_dir = lib.resolve_state_dir(args.state_dir)
        lib.ensure_dir(state_dir)
        now = lib.parse_iso(args.now) or lib.utcnow()
        authz = lib.load_authz(state_dir, authz_file=args.authz_file)

        if args.cmd == "emit":
            return lib.emit(emit(state_dir, args.event_class, entity_id=args.entity_id,
                                 state_fingerprint=args.state_fingerprint,
                                 artifact_sha256=args.artifact_sha256, facts=args.fact,
                                 subject=args.subject, evidence=args.ev,
                                 next_action=args.next_action, sigil=args.sigil,
                                 lane_id=args.lane, now=now, authz=authz,
                                 platform=args.platform,
                                 permanent=True if args.permanent else None), 0)
        if args.cmd == "filter":
            verdict = classify(args.event_class)
            return lib.emit(lib.ok_result(class_name=args.event_class, p0=verdict["p0"],
                                          reason=verdict["reason"], evidence=[],
                                          next="next: none - informational"), 0)
        if args.cmd == "delivery":
            return lib.emit(record_delivery(state_dir, args.dedup_key, args.result,
                                            now=now, attempt=args.attempt, evidence=args.ev), 0)
        if args.cmd == "list":
            rows, malformed, counts = list_notifications(state_dir, p0_only=args.p0)
            return lib.emit(lib.ok_result(rows=rows, count=len(rows), malformed_rows=malformed,
                                          counts=counts, evidence=[notify_path(state_dir)],
                                          next="next: none - informational"), 0)
        if args.cmd == "classes":
            return lib.emit(lib.ok_result(p0=P0_CLASSES, p1=P1_CLASSES,
                                          immediate_non_p0=list(IMMEDIATE_NON_P0), evidence=[],
                                          next="next: none - informational"), 0)
        return lib.emit({"ok": False, "error": "E_USAGE", "message": "no subcommand given",
                         "evidence": [], "next": "next: emit|filter|delivery|list|classes"}, 2)
    except lib.HandoffError as exc:
        return lib.emit(exc.as_dict(), 1)


if __name__ == "__main__":
    sys.exit(main())
