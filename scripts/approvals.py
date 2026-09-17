"""Protean Handoff - consequential approval queue, ledger, fingerprints, holds (lock 4).

Single canonical home: `approvals.jsonl` (append-only, monotonic seq) plus the derived
`approvals.pending.json`; holds live in `holds.jsonl` plus the derived `holds.open.json`.

Model (lock 4 lifecycle: pending -> approved -> consumed, one way):

  request   a lane asks for authorization. Consequential kinds REQUIRE an explicit
            paired-DM identity to bind to; without it the request is refused
            (fail closed, E_NO_BINDING_TARGET).
  approve   the bound operator's decision. Identity must be the allowlisted paired-DM
            triple captured in `binding`; pending -> approved. If a fresh live target
            spec is supplied the fingerprint is compared NOW (mismatch -> E_BINDING_STALE,
            row voided, fresh request issued, nothing consumed).
  consume   the executing lane reports the read-back. `approved -> consumed` is the only
            transition that may create an execution record, and it is impossible without
            an observed fingerprint (E_NO_READBACK). Mismatch voids the row.
  deny      closes the row as denied; the reason is DATA and is never executed.
  expire    pending/approved rows past `expires_at` become `expired`, never pending.

Replay: single consumption, nonce uniqueness, and "a second approve of a consumed id
returns the original execution receipt with duplicate: true and executes nothing".

Identity/authz is re-evaluated here (not only in command.py) so this module fails closed
when called directly (brief security cases 1-4).
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import handoff_lib as lib

ITEM_RE = re.compile(r"^a-[0-9a-f]{8}$")
HOLD_RE = re.compile(r"^h-[0-9a-f]{8}$")
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")

FINGERPRINT_KINDS = ("merge", "delete", "transfer", "deploy", "external-write")
EXPLICIT_FINGERPRINT_KINDS = ("spend", "credential")


# --- fingerprints (lock 4) ---------------------------------------------------

def compute_fingerprint(kind, spec, explicit=None):
    """Return {fingerprint, fingerprint_input, target} for one consequential kind.

    lock 4 target fingerprints:
      merge                 -> repo + base + head_sha (exact, full sha)
      delete                -> sorted list of absolute paths + sha256 of each
      transfer              -> source + destination identity
      deploy/external-write -> destination + artifact sha256
      spend/credential      -> the lock names no fingerprint; an explicit fingerprint
                               string is required (fail closed without it).
    """
    lib.require(kind in lib.APPROVAL_KINDS, "E_UNKNOWN_KIND",
                "kind %r is not a consequential class" % (kind,),
                "next: use one of %s" % ", ".join(lib.APPROVAL_KINDS))
    spec = spec if isinstance(spec, dict) else {}

    if kind in EXPLICIT_FINGERPRINT_KINDS:
        lib.require(bool(explicit), "E_NO_FINGERPRINT",
                    "kind %s requires an explicit fingerprint string" % kind,
                    "next: pass --explicit-fingerprint <binding string>")
        input_obj = {"kind": kind, "explicit": str(explicit)}
        return {
            "fingerprint": lib.sha256_text(lib.canonical_json(input_obj)),
            "fingerprint_input": input_obj,
            "target": spec.get("target") or str(explicit),
        }

    if kind == "merge":
        repo, base, head = spec.get("repo"), spec.get("base"), spec.get("head_sha")
        lib.require(bool(repo) and bool(base) and bool(head), "E_INCOMPLETE_FINGERPRINT",
                    "merge fingerprint needs repo, base and head_sha",
                    "next: pass --spec '{\"repo\":..,\"base\":..,\"head_sha\":..}'")
        lib.require(bool(SHA_RE.match(str(head))), "E_BAD_FINGERPRINT",
                    "merge head_sha must be an exact (full) sha",
                    "next: resolve the head to its full 40-char sha")
        input_obj = {"kind": "merge", "repo": str(repo), "base": str(base), "head_sha": str(head).lower()}
        return {"fingerprint": lib.sha256_text(lib.canonical_json(input_obj)),
                "fingerprint_input": input_obj,
                "target": "%s %s<- %s" % (repo, base, str(head)[:12])}

    if kind == "delete":
        paths = spec.get("paths")
        if isinstance(paths, str):
            paths = [paths]
        lib.require(isinstance(paths, list) and paths, "E_INCOMPLETE_FINGERPRINT",
                    "delete fingerprint needs a non-empty absolute path list",
                    "next: pass --spec '{\"paths\":[\"/abs/path\",..]}'")
        entries = []
        for raw in paths:
            path = os.path.abspath(os.path.expanduser(str(raw)))
            lib.require(os.path.isabs(path), "E_BAD_FINGERPRINT",
                        "delete fingerprint paths must be absolute",
                        "next: use absolute paths only")
            digest = lib.sha256_file(path)
            entries.append([path, digest if digest else "missing"])
        entries.sort()
        input_obj = {"kind": "delete", "paths": entries}
        return {"fingerprint": lib.sha256_text(lib.canonical_json(input_obj)),
                "fingerprint_input": input_obj,
                "target": "%d path(s) %s" % (len(entries), entries[0][0])}

    if kind == "transfer":
        source, destination = spec.get("source"), spec.get("destination")
        lib.require(bool(source) and bool(destination), "E_INCOMPLETE_FINGERPRINT",
                    "transfer fingerprint needs source and destination identity",
                    "next: pass --spec '{\"source\":..,\"destination\":..}'")
        input_obj = {"kind": "transfer", "source": str(source), "destination": str(destination)}
        return {"fingerprint": lib.sha256_text(lib.canonical_json(input_obj)),
                "fingerprint_input": input_obj,
                "target": "%s -> %s" % (source, destination)}

    destination, artifact = spec.get("destination"), spec.get("artifact_sha256")
    lib.require(bool(destination) and bool(artifact), "E_INCOMPLETE_FINGERPRINT",
                "%s fingerprint needs destination and artifact_sha256" % kind,
                "next: pass --spec '{\"destination\":..,\"artifact_sha256\":..}'")
    lib.require(bool(SHA_RE.match(str(artifact))), "E_BAD_FINGERPRINT",
                "artifact_sha256 must be an exact sha256",
                "next: hash the artifact and retry")
    input_obj = {"kind": kind, "destination": str(destination),
                 "artifact_sha256": str(artifact).lower()}
    return {"fingerprint": lib.sha256_text(lib.canonical_json(input_obj)),
            "fingerprint_input": input_obj,
            "target": "%s (%s)" % (destination, str(artifact)[:12])}


def short_fingerprint(fingerprint):
    """Phone-visible short form (the full value stays in the ledger)."""
    return str(fingerprint or "")[:12]


# --- ledger ------------------------------------------------------------------

def approvals_path(state_dir):
    return lib.state_path(state_dir, lib.APPROVALS)


def holds_path(state_dir):
    return lib.state_path(state_dir, lib.HOLDS)


def load_ledger(state_dir):
    rows, malformed = lib.read_jsonl(approvals_path(state_dir))
    return rows, malformed


def fold(rows):
    """Fold ledger events into {approval_id: record}. Last event wins for status."""
    records = {}
    order = []
    for row in rows:
        approval = row.get("approval")
        if not isinstance(approval, dict):
            continue
        approval_id = approval.get("approval_id")
        if not approval_id:
            continue
        record = records.get(approval_id)
        if record is None:
            records[approval_id] = dict(approval)
            records[approval_id]["events"] = [row.get("event")]
            order.append(approval_id)
            continue
        merged = dict(record)
        merged.update(approval)
        merged["events"] = list(record.get("events") or []) + [row.get("event")]
        records[approval_id] = merged
    return records, order


def next_seq(state_dir):
    rows, _ = load_ledger(state_dir)
    highest = 0
    for row in rows:
        try:
            highest = max(highest, int(row.get("seq") or 0))
        except (TypeError, ValueError):
            continue
    return highest + 1


def _append(state_dir, event, approval, actor=None, reason=None, code=None, note=None, extra=None):
    row = {
        "event": event,
        "seq": next_seq(state_dir),
        "at": lib.iso(),
        "actor": actor,
        "approval_id": (approval or {}).get("approval_id"),
        "approval": approval,
        "reason": reason,
        "code": code,
        "note": note,
    }
    if extra:
        row.update(extra)
    lib.append_jsonl(approvals_path(state_dir), row)
    return row


def _append_hold(state_dir, event, hold, actor=None, reason=None):
    row = {
        "event": event,
        "seq": _hold_seq(state_dir),
        "at": lib.iso(),
        "actor": actor,
        "hold_id": (hold or {}).get("hold_id"),
        "hold": hold,
        "reason": reason,
    }
    lib.append_jsonl(holds_path(state_dir), row)
    return row


def _hold_seq(state_dir):
    rows, _ = lib.read_jsonl(holds_path(state_dir))
    highest = 0
    for row in rows:
        try:
            highest = max(highest, int(row.get("seq") or 0))
        except (TypeError, ValueError):
            continue
    return highest + 1


def effective_status(record, now=None):
    """Derived read of a row: a pending/approved row past expires_at is expired."""
    status = (record or {}).get("status")
    if status in ("pending", "approved"):
        expiry = lib.epoch((record or {}).get("expires_at"))
        if expiry is not None and expiry < (now or lib.utcnow()).timestamp():
            return "expired"
    return status


def refresh_derived(state_dir, now=None):
    """Rewrite approvals.pending.json and holds.open.json from the ledgers."""
    now = now or lib.utcnow()
    rows, malformed = load_ledger(state_dir)
    records, order = fold(rows)
    pending = []
    for approval_id in order:
        record = records[approval_id]
        status = effective_status(record, now=now)
        if status in ("pending", "approved"):
            pending.append({
                "approval_id": approval_id,
                "seq": record.get("seq"),
                "kind": record.get("kind"),
                "lane_id": record.get("lane_id"),
                "status": status,
                "expires_at": record.get("expires_at"),
                "fingerprint_short": short_fingerprint(record.get("target_fingerprint")),
                "next": "next: approve %s" % approval_id,
            })
    payload = {"generated_at": lib.iso(now), "ledger": approvals_path(state_dir),
               "malformed_rows": malformed, "open": pending}
    lib.atomic_write_json(lib.state_path(state_dir, lib.APPROVALS_PENDING), payload)

    hold_rows, hold_malformed = lib.read_jsonl(holds_path(state_dir))
    holds, hold_order = _fold_holds(hold_rows)
    open_holds = [holds[hold_id] for hold_id in hold_order
                  if holds[hold_id].get("status") == "open"]
    holds_payload = {"generated_at": lib.iso(now), "ledger": holds_path(state_dir),
                     "malformed_rows": hold_malformed, "open": open_holds}
    lib.atomic_write_json(lib.state_path(state_dir, lib.HOLDS_OPEN), holds_payload)
    return payload, holds_payload


# --- identity check (lock 5, re-evaluated here, fail closed) -----------------

def check_identity(identity, authz, env=None):
    """Consequential decisions need the allowlisted paired-DM triple."""
    decision = lib.authorize(identity, "approve", authz, env=env)
    if decision["decision"] != "allow" or decision.get("read_only"):
        raise lib.HandoffError("E_UNAUTHORIZED", lib.uniform_refusal("approval"),
                               "next: approve from the paired operator DM")
    return decision["authority"]


# --- request -----------------------------------------------------------------

def request(state_dir, kind, lane_id, requested_by, actor_user_id=None, platform=None,
            chat_id=None, message_id=None, ttl_seconds=None, spec=None, target=None,
            explicit_fingerprint=None, now=None):
    """Create a pending approval row bound to an exact target fingerprint."""
    now = now or lib.utcnow()
    lib.require(bool(lane_id), "E_NO_LANE", "an approval request needs a lane id",
                "next: pass --lane <p-project-role>")
    lib.require(bool(requested_by), "E_NO_REQUESTER", "an approval request needs a requester",
                "next: pass --requested-by <lane id or session id>")
    lib.require(bool(actor_user_id) and bool(platform) and bool(chat_id), "E_NO_BINDING_TARGET",
                "consequential approvals require an explicit paired-DM identity to bind to",
                "next: pass --actor-user-id/--platform/--chat-id from where the request is sent")

    binding_info = compute_fingerprint(kind, spec, explicit=explicit_fingerprint)
    records, _ = fold(load_ledger(state_dir)[0])

    approval_id = lib.new_id("a")
    while approval_id in records:
        approval_id = lib.new_id("a")
    nonce = lib.new_nonce()
    existing_nonces = {r.get("binding", {}).get("nonce") for r in records.values()}
    while nonce in existing_nonces:
        nonce = lib.new_nonce()

    ttl = int(ttl_seconds or lib.APPROVAL_DEFAULT_TTL_SECONDS)
    now_ts = now
    expires_ts = now_ts.timestamp() + ttl
    import datetime as _dt
    expires_at = lib.iso(_dt.datetime.fromtimestamp(expires_ts, tz=_dt.timezone.utc))

    record = {
        "approval_id": approval_id,
        "seq": next_seq(state_dir),
        "kind": kind,
        "lane_id": lane_id,
        "target": target or binding_info["target"],
        "target_fingerprint": binding_info["fingerprint"],
        "fingerprint_input": binding_info["fingerprint_input"],
        "requested_by": requested_by,
        "requested_at": lib.iso(now_ts),
        "expires_at": expires_at,
        "binding": {"actor_user_id": str(actor_user_id), "platform": str(platform),
                    "chat_id": str(chat_id), "message_id": message_id, "nonce": nonce},
        "status": "pending",
        "decided_at": None,
        "decided_by": None,
        "execution": {"executed_at": None, "receipt_path": None, "observed_fingerprint": None,
                      "observed_delivery": None, "failure_code": None},
    }
    _append(state_dir, "request", record)
    refresh_derived(state_dir, now=now)
    result = lib.ok_result(
        approval_id=approval_id, kind=kind, lane_id=lane_id, status="pending",
        target=record["target"], fingerprint_short=short_fingerprint(record["target_fingerprint"]),
        expires_at=expires_at, requested_by=requested_by,
        evidence=[approvals_path(state_dir), lib.state_path(state_dir, lib.APPROVALS_PENDING)],
        next="next: approve %s (from the paired operator DM)" % approval_id,
    )
    return result


# --- decisions ---------------------------------------------------------------

def _load_record(state_dir, approval_id):
    lib.require(bool(ITEM_RE.match(str(approval_id or ""))), "E_UNKNOWN_ITEM",
                lib.uniform_refusal(approval_id or "item"),
                "next: status <lane>")
    records, order = fold(load_ledger(state_dir)[0])
    record = records.get(approval_id)
    lib.require(record is not None, "E_UNKNOWN_ITEM", lib.uniform_refusal(approval_id),
                "next: status <lane>", evidence=[approvals_path(state_dir)])
    return record, records, order


def _consumed_receipt(record, state_dir, note="duplicate: already consumed"):
    execution = dict(record.get("execution") or {})
    return lib.ok_result(
        approval_id=record.get("approval_id"), status="consumed", duplicate=True,
        executed=False, execution=execution, note=note,
        evidence=[approvals_path(state_dir)] + ([execution.get("receipt_path")]
                                                if execution.get("receipt_path") else []),
        next="next: none - informational",
    )


def approve(state_dir, approval_id, identity, authz=None, env=None, observed_spec=None,
            explicit_fingerprint=None, consume=False, receipt_path=None,
            observed_delivery=None, now=None, reason=None):
    """Operator decision (lock 4). pending -> approved, and on request -> consumed."""
    now = now or lib.utcnow()
    authz = authz if authz is not None else lib.load_authz(state_dir)
    actor = None
    if identity:
        actor = {"platform": str(identity.get("platform") or ""),
                 "chat_id": str(identity.get("chat_id") or ""),
                 "user_id": str(identity.get("user_id") or "")}
    check_identity(identity or {}, authz, env=env)

    record, _, _ = _load_record(state_dir, approval_id)
    binding = record.get("binding") or {}
    if (actor["user_id"] != str(binding.get("actor_user_id") or "")
            or actor["chat_id"] != str(binding.get("chat_id") or "")
            or actor["platform"] != str(binding.get("platform") or "")):
        _append(state_dir, "refused", record, actor=actor, code="E_NOT_BOUND_ACTOR",
                reason="deciding identity is not the bound actor")
        raise lib.HandoffError("E_UNAUTHORIZED", lib.uniform_refusal(approval_id),
                               "next: approve from the DM this request was issued to",
                               evidence=[approvals_path(state_dir)])

    status = effective_status(record, now=now)
    if status == "consumed":
        return _consumed_receipt(record, state_dir)
    if status in ("denied", "voided", "expired"):
        _append(state_dir, "refused", record, actor=actor, code="E_UNIFORM_REFUSAL",
                reason="row is %s" % status)
        raise lib.HandoffError("E_%s_APPROVAL" % status.upper(), lib.uniform_refusal(approval_id),
                               "next: request a fresh approval", evidence=[approvals_path(state_dir)])
    if status == "approved":
        # already granted; a second approve before execution is an idempotent echo
        return lib.ok_result(approval_id=approval_id, status="approved", duplicate=True,
                             executed=False, approval=record,
                             evidence=[approvals_path(state_dir)],
                             next="next: none - lane %s must report the read-back"
                                  % record.get("lane_id"))

    holds = active_holds(state_dir, record.get("lane_id"), now=now)
    if holds:
        _append(state_dir, "refused", record, actor=actor, code="E_HOLD_ACTIVE",
                reason="hold %s covers this lane" % holds[0]["hold_id"])
        raise lib.HandoffError("E_HOLD_ACTIVE",
                               "approval blocked: hold %s is open" % holds[0]["hold_id"],
                               "next: release %s" % holds[0]["hold_id"],
                               evidence=[holds[0]["_path"], approvals_path(state_dir)])

    # fingerprint re-check when the caller supplied a fresh live target read-back
    if observed_spec is not None or explicit_fingerprint is not None:
        observed = compute_fingerprint(record.get("kind"), observed_spec or {},
                                       explicit=explicit_fingerprint)
        if observed["fingerprint"] != record.get("target_fingerprint"):
            voided = dict(record)
            voided["status"] = "voided"
            voided["decided_at"] = lib.iso(now)
            voided["decided_by"] = actor
            voided["execution"] = dict(record.get("execution") or {})
            voided["execution"]["failure_code"] = "E_BINDING_STALE"
            _append(state_dir, "voided", voided, actor=actor, code="E_BINDING_STALE",
                    reason="observed fingerprint %s != bound %s"
                           % (short_fingerprint(observed["fingerprint"]),
                              short_fingerprint(record.get("target_fingerprint"))))
            fresh = request(state_dir, record.get("kind"), record.get("lane_id"),
                            record.get("requested_by"),
                            actor_user_id=binding.get("actor_user_id"),
                            platform=binding.get("platform"), chat_id=binding.get("chat_id"),
                            spec=observed_spec, explicit_fingerprint=explicit_fingerprint,
                            target=record.get("target"), now=now)
            refresh_derived(state_dir, now=now)
            raise lib.HandoffError("E_BINDING_STALE",
                                   "target moved; approval refused and voided",
                                   "next: approve %s" % fresh["approval_id"],
                                   evidence=[approvals_path(state_dir)],
                                   fresh_approval_id=fresh["approval_id"])

    granted = dict(record)
    granted["status"] = "approved"
    granted["decided_at"] = lib.iso(now)
    granted["decided_by"] = actor
    _append(state_dir, "approved", granted, actor=actor, reason=reason)
    refresh_derived(state_dir, now=now)

    if not consume:
        return lib.ok_result(approval_id=approval_id, status="approved", duplicate=False,
                             executed=False, lane_id=record.get("lane_id"),
                             fingerprint_short=short_fingerprint(record.get("target_fingerprint")),
                             evidence=[approvals_path(state_dir)],
                             next="next: none - lane %s executes and reports the read-back"
                                  % record.get("lane_id"))

    executed = consume_approval(state_dir, approval_id, observed_spec=observed_spec,
                                explicit_fingerprint=explicit_fingerprint,
                                receipt_path=receipt_path, observed_delivery=observed_delivery,
                                actor=actor, now=now)
    return executed


def consume_approval(state_dir, approval_id, observed_spec=None, explicit_fingerprint=None,
                     receipt_path=None, observed_delivery=None, actor=None, now=None):
    """approved -> consumed with read-back evidence. No read-back, no consume."""
    now = now or lib.utcnow()
    record, _, _ = _load_record(state_dir, approval_id)
    status = effective_status(record, now=now)
    if status == "consumed":
        return _consumed_receipt(record, state_dir)
    if status != "approved":
        _append(state_dir, "refused", record, actor=actor, code="E_NOT_APPROVED",
                reason="consume attempted on a %s row" % status)
        raise lib.HandoffError("E_UNIFORM_REFUSAL" if status in ("denied", "voided", "expired")
                               else "E_NOT_APPROVED",
                               lib.uniform_refusal(approval_id),
                               "next: approve %s" % approval_id,
                               evidence=[approvals_path(state_dir)])
    if observed_spec is None and explicit_fingerprint is None:
        _append(state_dir, "refused", record, actor=actor, code="E_NO_READBACK",
                reason="consume attempted without a live target read-back")
        raise lib.HandoffError("E_NO_READBACK",
                               "refusing to consume without a target read-back",
                               "next: re-hash the live target and retry",
                               evidence=[approvals_path(state_dir)])

    observed = compute_fingerprint(record.get("kind"), observed_spec or {},
                                   explicit=explicit_fingerprint)
    if observed["fingerprint"] != record.get("target_fingerprint"):
        voided = dict(record)
        voided["status"] = "voided"
        voided["decided_at"] = lib.iso(now)
        voided["execution"] = dict(record.get("execution") or {})
        voided["execution"]["failure_code"] = "E_BINDING_STALE"
        _append(state_dir, "voided", voided, actor=actor, code="E_BINDING_STALE",
                reason="observed fingerprint mismatch at execution")
        refresh_derived(state_dir, now=now)
        raise lib.HandoffError("E_BINDING_STALE", "target moved; nothing executed",
                               "next: request a fresh approval",
                               evidence=[approvals_path(state_dir)])

    delivery = observed_delivery
    receipt_sha = lib.sha256_file(receipt_path) if receipt_path else None
    if delivery is None:
        delivery = "verified" if (receipt_path and receipt_sha) else "unverified"
    if delivery == "verified" and not (receipt_path and receipt_sha):
        delivery = "unverified"

    consumed = dict(record)
    consumed["status"] = "consumed"
    consumed["decided_at"] = record.get("decided_at") or lib.iso(now)
    consumed["execution"] = {
        "executed_at": lib.iso(now),
        "receipt_path": receipt_path,
        "observed_fingerprint": observed["fingerprint"],
        "observed_delivery": delivery,
        "failure_code": None,
    }
    _append(state_dir, "consumed", consumed, actor=actor,
            note="execution receipt recorded")
    refresh_derived(state_dir, now=now)
    evidence = [approvals_path(state_dir)]
    if receipt_path:
        evidence.append(receipt_path)
    return lib.ok_result(
        approval_id=approval_id, status="consumed", duplicate=False, executed=True,
        execution=consumed["execution"], fingerprint_short=short_fingerprint(observed["fingerprint"]),
        evidence=evidence,
        next="next: none - record the execution receipt path for the lane",
    )


def deny(state_dir, approval_id, identity, authz=None, env=None, reason=None, now=None):
    now = now or lib.utcnow()
    authz = authz if authz is not None else lib.load_authz(state_dir)
    actor = None
    if identity:
        actor = {"platform": str(identity.get("platform") or ""),
                 "chat_id": str(identity.get("chat_id") or ""),
                 "user_id": str(identity.get("user_id") or "")}
    check_identity(identity or {}, authz, env=env)
    record, _, _ = _load_record(state_dir, approval_id)
    binding = record.get("binding") or {}
    if (actor["user_id"] != str(binding.get("actor_user_id") or "")
            or actor["chat_id"] != str(binding.get("chat_id") or "")):
        _append(state_dir, "refused", record, actor=actor, code="E_NOT_BOUND_ACTOR",
                reason="deciding identity is not the bound actor")
        raise lib.HandoffError("E_UNAUTHORIZED", lib.uniform_refusal(approval_id),
                               "next: deny from the DM this request was issued to",
                               evidence=[approvals_path(state_dir)])

    status = effective_status(record, now=now)
    if status == "denied":
        return lib.ok_result(approval_id=approval_id, status="denied", duplicate=True,
                             evidence=[approvals_path(state_dir)],
                             next="next: none - informational")
    if status in ("consumed", "approved", "voided", "expired"):
        _append(state_dir, "refused", record, actor=actor, code="E_UNIFORM_REFUSAL",
                reason="deny attempted on a %s row" % status)
        raise lib.HandoffError("E_UNIFORM_REFUSAL", lib.uniform_refusal(approval_id),
                               "next: none - informational", evidence=[approvals_path(state_dir)])

    denied = dict(record)
    denied["status"] = "denied"
    denied["decided_at"] = lib.iso(now)
    denied["decided_by"] = actor
    # the reason is DATA: stored verbatim for the requesting lane, never interpreted
    denied["deny_reason"] = reason
    _append(state_dir, "denied", denied, actor=actor, reason=reason)
    refresh_derived(state_dir, now=now)
    return lib.ok_result(approval_id=approval_id, status="denied", duplicate=False,
                         lane_id=record.get("lane_id"), reason_is_data=True,
                         evidence=[approvals_path(state_dir)],
                         next="next: none - lane %s is told the reason as data" % record.get("lane_id"))


def expire(state_dir, now=None):
    now = now or lib.utcnow()
    rows, _ = load_ledger(state_dir)
    records, order = fold(rows)
    expired = []
    for approval_id in order:
        record = records[approval_id]
        if record.get("status") in ("pending", "approved") and effective_status(record, now=now) == "expired":
            updated = dict(record)
            updated["status"] = "expired"
            updated["execution"] = dict(record.get("execution") or {})
            updated["execution"]["failure_code"] = "E_EXPIRED_APPROVAL"
            _append(state_dir, "expired", updated, code="E_EXPIRED_APPROVAL",
                    reason="expires_at passed")
            expired.append(approval_id)
    refresh_derived(state_dir, now=now)
    return lib.ok_result(expired=expired, count=len(expired),
                         evidence=[approvals_path(state_dir)],
                         next="next: none - informational")


def list_approvals(state_dir, status=None, now=None):
    now = now or lib.utcnow()
    rows, malformed = load_ledger(state_dir)
    records, order = fold(rows)
    out = []
    for approval_id in order:
        record = records[approval_id]
        effective = effective_status(record, now=now)
        if status and effective != status:
            continue
        out.append({
            "approval_id": approval_id,
            "kind": record.get("kind"),
            "lane_id": record.get("lane_id"),
            "status": effective,
            "stored_status": record.get("status"),
            "target": record.get("target"),
            "fingerprint_short": short_fingerprint(record.get("target_fingerprint")),
            "expires_at": record.get("expires_at"),
            "executed_at": (record.get("execution") or {}).get("executed_at"),
        })
    return out, malformed


# --- holds -------------------------------------------------------------------

def _fold_holds(rows):
    holds = {}
    order = []
    for row in rows:
        hold = row.get("hold")
        if not isinstance(hold, dict):
            continue
        hold_id = hold.get("hold_id")
        if not hold_id:
            continue
        if hold_id in holds:
            merged = dict(holds[hold_id])
            merged.update(hold)
            merged["events"] = list(holds[hold_id].get("events") or []) + [row.get("event")]
            holds[hold_id] = merged
        else:
            holds[hold_id] = dict(hold)
            holds[hold_id]["events"] = [row.get("event")]
            order.append(hold_id)
    return holds, order


def hold(state_dir, scope="project", lane_id=None, reason=None, actor_user_id=None,
         platform=None, chat_id=None, now=None):
    """Open a hold row (bare hold = project-wide). Blocks consequential approvals."""
    now = now or lib.utcnow()
    scope = lane_id or scope or "project"
    lib.require(bool(actor_user_id) and bool(platform) and bool(chat_id), "E_NO_BINDING_TARGET",
                "a hold requires an explicit paired-DM identity",
                "next: send hold from the paired operator DM")
    if lane_id:
        snapshot = lib.read_json(lib.state_path(state_dir, lib.SNAPSHOT), default=None)
        lanes = [ln.get("lane_id") for ln in (snapshot or {}).get("lanes") or []]
        if lanes and lane_id not in lanes:
            raise lib.HandoffError("E_NO_LANE", "no lane %s in the snapshot" % lane_id,
                                   "next: status all",
                                   evidence=[lib.state_path(state_dir, lib.SNAPSHOT)])
    rows, _ = lib.read_jsonl(holds_path(state_dir))
    holds, order = _fold_holds(rows)
    for hold_id in order:
        existing = holds[hold_id]
        if existing.get("status") == "open" and existing.get("scope") == scope:
            return lib.ok_result(hold_id=hold_id, scope=scope, duplicate=True,
                                 status="open", evidence=[holds_path(state_dir)],
                                 next="next: release %s" % hold_id)

    hold_id = lib.new_id("h")
    while hold_id in holds:
        hold_id = lib.new_id("h")
    record = {
        "hold_id": hold_id,
        "scope": scope,
        "lane_id": lane_id,
        "reason": reason,
        "actor": {"platform": str(platform), "chat_id": str(chat_id),
                  "user_id": str(actor_user_id)},
        "opened_at": lib.iso(now),
        "status": "open",
        "released_at": None,
        "released_by": None,
    }
    _append_hold(state_dir, "open", record)
    refresh_derived(state_dir, now=now)
    return lib.ok_result(hold_id=hold_id, scope=scope, duplicate=False, status="open",
                         evidence=[holds_path(state_dir)],
                         next="next: release %s" % hold_id)


def release(state_dir, hold_id, identity=None, authz=None, env=None, now=None):
    now = now or lib.utcnow()
    lib.require(bool(HOLD_RE.match(str(hold_id or ""))), "E_UNKNOWN_HOLD",
                lib.uniform_refusal(hold_id or "hold"), "next: status all")
    authz = authz if authz is not None else lib.load_authz(state_dir)
    if identity:
        check_identity(identity, authz, env=env)
    rows, _ = lib.read_jsonl(holds_path(state_dir))
    holds, order = _fold_holds(rows)
    record = holds.get(hold_id)
    lib.require(record is not None, "E_UNKNOWN_HOLD", lib.uniform_refusal(hold_id),
                "next: status all", evidence=[holds_path(state_dir)])
    if record.get("status") == "released":
        return lib.ok_result(hold_id=hold_id, status="released", duplicate=True,
                             evidence=[holds_path(state_dir)], next="next: none - informational")
    released = dict(record)
    released["status"] = "released"
    released["released_at"] = lib.iso(now)
    released["released_by"] = identity
    _append_hold(state_dir, "released", released)
    refresh_derived(state_dir, now=now)
    return lib.ok_result(hold_id=hold_id, status="released", duplicate=False,
                         evidence=[holds_path(state_dir)], next="next: none - informational")


def active_holds(state_dir, lane_id=None, now=None):
    """Open holds covering a lane (project-wide or lane-scoped). Reconnect never releases."""
    rows, _ = lib.read_jsonl(holds_path(state_dir))
    holds, order = _fold_holds(rows)
    out = []
    for hold_id in order:
        record = holds[hold_id]
        if record.get("status") != "open":
            continue
        scope = record.get("scope")
        if scope == "project" or (lane_id and scope == lane_id):
            record = dict(record)
            record["_path"] = holds_path(state_dir)
            out.append(record)
    return out


# --- CLI ---------------------------------------------------------------------

def _emit_error(exc):
    return lib.emit(exc.as_dict(), 1)


def _identity(args):
    return {"platform": args.platform, "chat_id": args.chat_id, "user_id": args.user_id,
            "chat_kind": args.chat_kind}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="approvals.py",
        description="Consequential approval queue, ledger, fingerprint binding and holds.")
    parser.add_argument("--state-dir", help="handoff state directory")
    parser.add_argument("--authz-file", help="authz mirror path (default <state>/authz.json)")
    sub = parser.add_subparsers(dest="cmd")

    def add_identity(p):
        p.add_argument("--platform")
        p.add_argument("--chat-id")
        p.add_argument("--user-id")
        p.add_argument("--chat-kind", default="dm")

    p_req = sub.add_parser("request", help="create a pending approval bound to a fingerprint")
    p_req.add_argument("--kind", required=True, choices=list(lib.APPROVAL_KINDS))
    p_req.add_argument("--lane", required=True)
    p_req.add_argument("--requested-by", required=True)
    p_req.add_argument("--actor-user-id", required=True)
    p_req.add_argument("--platform", required=True)
    p_req.add_argument("--chat-id", required=True)
    p_req.add_argument("--message-id")
    p_req.add_argument("--target")
    p_req.add_argument("--spec", help="binding spec as JSON or @path")
    p_req.add_argument("--explicit-fingerprint")
    p_req.add_argument("--ttl", type=int)

    p_app = sub.add_parser("approve", help="operator decision (pending -> approved [-> consumed])")
    p_app.add_argument("--item", required=True)
    p_app.add_argument("--once", action="store_true", help="explicit single consumption")
    p_app.add_argument("--consume", action="store_true")
    p_app.add_argument("--observed-spec", help="live target spec as JSON or @path")
    p_app.add_argument("--explicit-fingerprint")
    p_app.add_argument("--receipt-path")
    p_app.add_argument("--observed-delivery", choices=["verified", "unverified"])
    add_identity(p_app)

    p_deny = sub.add_parser("deny", help="close the row as denied")
    p_deny.add_argument("--item", required=True)
    p_deny.add_argument("--reason")
    add_identity(p_deny)

    p_con = sub.add_parser("consume", help="approved -> consumed with read-back evidence")
    p_con.add_argument("--item", required=True)
    p_con.add_argument("--observed-spec")
    p_con.add_argument("--explicit-fingerprint")
    p_con.add_argument("--receipt-path")
    p_con.add_argument("--observed-delivery", choices=["verified", "unverified"])

    p_show = sub.add_parser("show", help="read one row")
    p_show.add_argument("--item", required=True)

    p_list = sub.add_parser("list", help="list rows")
    p_list.add_argument("--status", choices=list(lib.APPROVAL_STATUS))

    sub.add_parser("expire", help="sweep expired rows")

    p_hold = sub.add_parser("hold", help="open a hold row")
    p_hold.add_argument("--lane")
    p_hold.add_argument("--reason")
    add_identity(p_hold)

    p_rel = sub.add_parser("release", help="release a hold row")
    p_rel.add_argument("--hold-id", required=True)
    add_identity(p_rel)

    sub.add_parser("holds", help="list open holds")

    args = parser.parse_args(argv)

    def spec_value(raw):
        if raw is None:
            return None
        if raw.startswith("@"):
            return lib.read_json(raw[1:], default=None)
        try:
            import json as _json
            return _json.loads(raw)
        except ValueError:
            return {"target": raw}

    try:
        state_dir = lib.resolve_state_dir(args.state_dir)
        lib.ensure_dir(state_dir)
        authz = lib.load_authz(state_dir, authz_file=args.authz_file)

        if args.cmd == "request":
            return lib.emit(request(state_dir, args.kind, args.lane, args.requested_by,
                                    actor_user_id=args.actor_user_id, platform=args.platform,
                                    chat_id=args.chat_id, message_id=args.message_id,
                                    ttl_seconds=args.ttl, spec=spec_value(args.spec),
                                    target=args.target,
                                    explicit_fingerprint=args.explicit_fingerprint), 0)
        if args.cmd == "approve":
            return lib.emit(approve(state_dir, args.item, _identity(args), authz=authz,
                                    observed_spec=spec_value(args.observed_spec),
                                    explicit_fingerprint=args.explicit_fingerprint,
                                    consume=args.consume, receipt_path=args.receipt_path,
                                    observed_delivery=args.observed_delivery), 0)
        if args.cmd == "deny":
            return lib.emit(deny(state_dir, args.item, _identity(args), authz=authz,
                                 reason=args.reason), 0)
        if args.cmd == "consume":
            return lib.emit(consume_approval(state_dir, args.item,
                                             observed_spec=spec_value(args.observed_spec),
                                             explicit_fingerprint=args.explicit_fingerprint,
                                             receipt_path=args.receipt_path,
                                             observed_delivery=args.observed_delivery), 0)
        if args.cmd == "show":
            record, _, _ = _load_record(state_dir, args.item)
            return lib.emit(lib.ok_result(approval=record,
                                          status=effective_status(record),
                                          evidence=[approvals_path(state_dir)],
                                          next="next: none - informational"), 0)
        if args.cmd == "list":
            rows, malformed = list_approvals(state_dir, status=args.status)
            return lib.emit(lib.ok_result(items=rows, count=len(rows), malformed_rows=malformed,
                                          evidence=[approvals_path(state_dir)],
                                          next="next: none - informational"), 0)
        if args.cmd == "expire":
            return lib.emit(expire(state_dir), 0)
        if args.cmd == "hold":
            return lib.emit(hold(state_dir, lane_id=args.lane, reason=args.reason,
                                 actor_user_id=args.user_id, platform=args.platform,
                                 chat_id=args.chat_id), 0)
        if args.cmd == "release":
            return lib.emit(release(state_dir, args.hold_id, identity=_identity(args),
                                    authz=authz), 0)
        if args.cmd == "holds":
            open_holds = active_holds(state_dir)
            return lib.emit(lib.ok_result(holds=open_holds, count=len(open_holds),
                                          evidence=[holds_path(state_dir)],
                                          next="next: none - informational"), 0)
        return lib.emit({"ok": False, "error": "E_USAGE", "message": "no subcommand given",
                         "evidence": [], "next": "next: request|approve|deny|consume|hold|release|list|show|expire|holds"}, 2)
    except lib.HandoffError as exc:
        return _emit_error(exc)


if __name__ == "__main__":
    sys.exit(main())
