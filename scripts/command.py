"""Protean Handoff - deterministic phone command parser and router (lock 2, 5, 9).

The parser decides; the agent is transport. No model parsing is involved: a fixed
grammar over the first token, bounded input, stable error codes, and a one-row-per-
command append-only `cmd-log.jsonl` for idempotency.

Grammar (lock 2.1):
    command := verb [ws arg]*      verb := status|steer|approve|deny|hold|release|
                                           morning-report|help
    chat    := anything else                     (never guessed into a command)
    native  := anything starting with '/'        (passed through untouched, I11)

Rules honoured here: bare verbs only, case-insensitive, one command per message,
<= 400 chars, first token must be the verb, trailing tokens after a complete command
are ignored AND echoed back, an unknown verb is chat (never an error banner).

Fail closed: no identity, no authorization source, or no explicit paired-DM authority
for an execution verb produces a refusal or a silent drop - never an action.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import handoff_lib as lib
import approvals as approvals_mod
import notify as notify_mod
import render as render_mod

ITEM_RE = re.compile(r"^a-[0-9a-f]{8}$")
HOLD_RE = re.compile(r"^h-[0-9a-f]{8}$")
LANE_RE = re.compile(r"^p-[a-z0-9]+-[a-z0-9]+(-[0-9]+)?$")

HELP_ROWS = (
    "status [lane|all] - read-only lane state; changes nothing",
    "steer <lane> <note> - queue a note into the lane's live session",
    "approve <item> [once] - approve a pending item (paired DM only)",
    "deny <item> [reason] - deny a pending item; the reason is data",
    "hold [lane] [reason] - block consequential actions (bare = project)",
    "release <hold_id> - close a hold",
    "morning-report [now] - render the day's digest",
    "help - this list",
)

STEERABLE_HEALTH = ("live", "quiet", "laptop-asleep")
NOT_STEERABLE = ("stale", "unknown", "gateway-down")


def cmd_log_path(state_dir):
    return lib.state_path(state_dir, lib.CMD_LOG)


def parse(text):
    """Parse one message. Returns a dict; never raises, never guesses."""
    raw = text if isinstance(text, str) else ""
    stripped = raw.strip()
    if not stripped:
        return {"kind": "chat", "reason": "empty message", "raw": raw}
    if stripped.startswith("/"):
        return {"kind": "native", "passthrough": True, "reason": "leading slash stays native",
                "raw": raw}
    if len(stripped) > lib.MAX_COMMAND_CHARS:
        return {"kind": "chat", "reason": "over the 400-char command bound", "raw": raw}
    if "\n" in stripped or "\r" in stripped:
        return {"kind": "chat", "reason": "not a single message", "raw": raw}

    tokens = stripped.split()
    verb = tokens[0].lower()
    if verb not in lib.VERBS:
        return {"kind": "chat", "reason": "unknown verb is chat, never an error banner",
                "raw": raw}
    rest = tokens[1:]
    out = {"kind": "command", "verb": verb, "raw": raw, "args": {}, "trailing": []}
    upper_raw = stripped[len(tokens[0]):].strip()

    if verb == "status":
        target = rest[0] if rest else None
        out["args"] = {"lane": None if target in (None, "all") else target, "all": target == "all"}
        out["trailing"] = rest[1:]
    elif verb == "steer":
        if len(rest) < 2:
            return _usage("steer needs a lane and a note",
                          "next: steer <lane> <note>", raw)
        lane = rest[0]
        if not LANE_RE.match(lane):
            return _usage("steer target is not a lane id", "next: status all", raw)
        note = upper_raw.split(None, 1)[1] if len(upper_raw.split(None, 1)) > 1 else ""
        out["args"] = {"lane": lane, "note": note}
    elif verb == "approve":
        if not rest:
            return _usage("approve needs an item id", "next: status all", raw)
        if not ITEM_RE.match(rest[0]):
            return _usage("approve item is not an approval id", "next: approve <item>", raw)
        out["args"] = {"item": rest[0].lower(),
                       "once": any(t.lower() == "once" for t in rest[1:])}
        out["trailing"] = [t for t in rest[1:] if t.lower() != "once"]
    elif verb == "deny":
        if not rest:
            return _usage("deny needs an item id", "next: status all", raw)
        if not ITEM_RE.match(rest[0]):
            return _usage("deny item is not an approval id", "next: deny <item> [reason]", raw)
        reason = " ".join(rest[1:])
        out["args"] = {"item": rest[0].lower(), "reason": reason}
    elif verb == "hold":
        lane = None
        trailing = list(rest)
        if rest and LANE_RE.match(rest[0]):
            lane = rest[0]
            trailing = rest[1:]
        reason = " ".join(trailing)
        out["args"] = {"lane": lane, "reason": reason}
    elif verb == "release":
        if not rest:
            return _usage("release needs a hold id", "next: hold or status all", raw)
        if not HOLD_RE.match(rest[0]):
            return _usage("release target is not a hold id", "next: status all", raw)
        out["args"] = {"hold_id": rest[0].lower()}
        out["trailing"] = rest[1:]
    elif verb == "morning-report":
        out["args"] = {"now": any(t.lower() == "now" for t in rest)}
        out["trailing"] = [t for t in rest if t.lower() != "now"]
    elif verb == "help":
        out["args"] = {}
        out["trailing"] = rest
    return out


def _usage(message, next_action, raw):
    return {"kind": "command", "verb": raw.split()[0].lower() if raw.split() else "",
            "args": {}, "trailing": [], "raw": raw,
            "error": {"code": "E_USAGE", "message": message, "next": next_action}}


def command_id(identity, verb, args_text, now=None, window=None):
    raw = "%s|%s|%s|%s|%s|%s" % (identity.get("platform", ""), identity.get("chat_id", ""),
                                 identity.get("user_id", ""), verb, args_text,
                                 "" if window is None else window)
    return lib.sha256_text(raw)


def _lookup_duplicate(state_dir, cid, verb, window=None):
    rows, _ = lib.read_jsonl(cmd_log_path(state_dir))
    for row in reversed(rows):
        if row.get("command_id") != cid or row.get("verb") != verb:
            continue
        if window is not None and int(row.get("window") or -1) != int(window):
            continue
        return row
    return None


def log_command(state_dir, identity, verb, args_hash, cid, outcome, evidence,
                duplicate=False, error=None, lane_id=None, window=None, reply_text=None):
    rows, _ = lib.read_jsonl(cmd_log_path(state_dir))
    seq = 0
    for row in rows:
        try:
            seq = max(seq, int(row.get("seq") or 0))
        except (TypeError, ValueError):
            continue
    lib.append_jsonl(cmd_log_path(state_dir), {
        "seq": seq + 1,
        "at": lib.iso(),
        "platform": identity.get("platform", ""),
        "chat_id": identity.get("chat_id", ""),
        "user_id": identity.get("user_id", ""),
        "verb": verb,
        "args_hash": args_hash,
        "lane_id": lane_id,
        "command_id": cid,
        "window": window,
        "outcome": outcome,
        "duplicate": bool(duplicate),
        "error": error,
        # the rendered reply is replay-safe: it passed the envelope gate, so it holds
        # no secrets, no allowlist contents and no other user ids.
        "wire_reply_text": reply_text,
        "evidence": [str(e) for e in (evidence or [])],
    })


def _snapshot(state_dir):
    snapshot = lib.read_json(lib.state_path(state_dir, lib.SNAPSHOT), default=None)
    if isinstance(snapshot, dict):
        snapshot["_path"] = lib.state_path(state_dir, lib.SNAPSHOT)
    return snapshot


def _lane(snapshot, lane_id):
    lanes = [ln for ln in (snapshot or {}).get("lanes") or []]
    match = [ln for ln in lanes if ln.get("lane_id") == lane_id]
    if match:
        return match[0], lanes
    candidates = [ln.get("lane_id") for ln in lanes]
    if not candidates:
        raise lib.HandoffError("E_NO_LANE", "no lane %s on record" % lane_id,
                               "next: snapshot.py --build --state-dir <dir>")
    raise lib.HandoffError("E_AMBIGUOUS_LANE",
                           "no lane %s on record; the snapshot holds %d lane(s)"
                           % (lane_id, len(candidates)),
                           "next: status all", candidates=candidates)


def _lane_evidence(state_dir, lane):
    artifacts = (lane or {}).get("artifacts") or []
    if artifacts and artifacts[0].get("path"):
        return artifacts[0]["path"]
    return lib.state_path(state_dir, lib.SNAPSHOT)


def _run_inner(text, identity, state_dir, authz=None, env=None, now=None, observed_spec=None,
               explicit_fingerprint=None, receipt_path=None, chat_kind=None):
    now = now or lib.utcnow()
    identity = dict(identity or {})
    if chat_kind:
        identity["chat_kind"] = chat_kind
    identity.setdefault("chat_kind", "dm")
    authz = authz if authz is not None else lib.load_authz(state_dir)
    parsed = parse(text)

    if parsed["kind"] == "native":
        return lib.ok_result(kind="native", passthrough=True, verb=None,
                             command_id=None, wire_reply=None, executed=False,
                             evidence=[], next="next: none - native surface handles it")
    if parsed["kind"] == "chat":
        return lib.ok_result(kind="chat", passthrough=False, verb=None, command_id=None,
                             wire_reply=None, executed=False, reason=parsed.get("reason"),
                             evidence=[], next="next: none - not a handoff command")
    if parsed.get("error"):
        err = parsed["error"]
        cid = command_id(identity, parsed.get("verb", ""), str(parsed.get("args")))
        log_command(state_dir, identity, parsed.get("verb", ""), lib.sha256_text(text), cid,
                    "refused_usage", [cmd_log_path(state_dir)], error=err["code"])
        return lib.HandoffError(err["code"], err["message"], err["next"],
                                evidence=[cmd_log_path(state_dir)]).as_dict() | {"kind": "command"}

    verb = parsed["verb"]
    args = parsed["args"]
    decision = lib.authorize(identity, verb, authz, env=env)
    args_text = lib.canonical_json(args)
    cid = command_id(identity, verb, args_text)

    if decision["decision"] != "allow":
        silent = decision["decision"] == "silent_drop"
        outcome = "silent_drop" if silent else "refused"
        log_command(state_dir, identity, verb, lib.sha256_text(text), cid, outcome,
                    [cmd_log_path(state_dir)], error=decision["code"],
                    lane_id=args.get("lane"))
        reply = None if silent else _refusal_envelope(state_dir, args, verb)
        notice = None
        if decision.get("owner_notice"):
            notice = notify_mod.emit(state_dir, "owner_notice",
                                     entity_id="%s:%s" % (identity.get("platform"),
                                                          identity.get("user_id")),
                                     facts=["unauthorized sender id %s on %s"
                                            % (identity.get("user_id"), identity.get("platform")),
                                            "fix: allowlist or pairing grant"],
                                     evidence=[cmd_log_path(state_dir)],
                                     next_action="none - informational", now=now,
                                     authz=authz, platform=identity.get("platform"))
        return lib.ok_result(kind="command", verb=verb, accepted=False, executed=False,
                             silent=silent, command_id=cid, code=decision["code"],
                             wire_reply=reply, owner_notice_sent=bool(notice),
                             echoed_trailing=[] if silent else (parsed.get("trailing") or []),
                             evidence=[cmd_log_path(state_dir)],
                             next=("next: none - informational" if silent
                                   else "next: %s from the paired operator DM" % verb))

    if verb == "status":
        return _do_status(state_dir, identity, args, cid, parsed, now)
    if verb == "help":
        return _do_help(state_dir, identity, args, cid, parsed, now)
    if verb == "steer":
        return _do_steer(state_dir, identity, args, cid, parsed, now)
    if verb == "approve":
        return _do_approve(state_dir, identity, args, cid, parsed, now, authz, env,
                           observed_spec, explicit_fingerprint, receipt_path)
    if verb == "deny":
        return _do_deny(state_dir, identity, args, cid, parsed, now, authz, env)
    if verb == "hold":
        return _do_hold(state_dir, identity, args, cid, parsed, now, authz)
    if verb == "release":
        return _do_release(state_dir, identity, args, cid, parsed, now, authz, env)
    if verb == "morning-report":
        return _do_morning(state_dir, identity, args, cid, parsed, now)
    raise lib.HandoffError("E_UNIFORM_REFUSAL", lib.uniform_refusal(verb),
                           "next: help")


def run(text, identity, state_dir, authz=None, env=None, now=None, observed_spec=None,
        explicit_fingerprint=None, receipt_path=None, chat_kind=None, latency_seconds=None):
    """Parse, authorize, execute, and log one inbound message. Returns machine JSON.

    Protocol refusals come back as an error result (never an exception): the caller -
    the Orda session - renders `wire_reply` or stays silent, per the result.
    """
    try:
        return _run_inner(text, identity, state_dir, authz=authz, env=env, now=now,
                          observed_spec=observed_spec,
                          explicit_fingerprint=explicit_fingerprint,
                          receipt_path=receipt_path, chat_kind=chat_kind)
    except lib.HandoffError as exc:
        result = exc.as_dict()
        result["kind"] = "command"
        result["accepted"] = False
        result["executed"] = False
        result["silent"] = False
        result["wire_reply"] = None
        return result


def _refusal_envelope(state_dir, args, verb):
    try:
        return render_mod.build_envelope(
            "[err]", "command declined",
            [lib.uniform_refusal(verb), "no reason is disclosed for this connection"],
            [cmd_log_path(state_dir)], "help", now=None)
    except lib.HandoffError:
        return None


def _ok(state_dir, identity, verb, cid, parsed, outcome, evidence, reply, lane_id=None,
        window=None, **extra):
    log_command(state_dir, identity, verb, lib.sha256_text(parsed.get("raw", "")), cid,
                outcome, evidence, lane_id=lane_id, window=window, reply_text=reply)
    out = lib.ok_result(kind="command", verb=verb, command_id=cid, accepted=True,
                        executed=False, wire_reply=reply, evidence=evidence,
                        echoed_trailing=parsed.get("trailing") or [],
                        duplicate=False)
    out.update(extra)
    return out


def _do_status(state_dir, identity, args, cid, parsed, now):
    snapshot = _snapshot(state_dir)
    evidence = [lib.state_path(state_dir, lib.SNAPSHOT)]
    if not snapshot:
        raise lib.HandoffError("E_REPORT_UNAVAILABLE", "no snapshot to render",
                               "next: snapshot.py --build --state-dir %s" % state_dir,
                               evidence=evidence)
    lane_id = args.get("lane")
    reply = render_mod.status_message(snapshot, lane_id=lane_id, now=now)
    lanes = snapshot.get("lanes") or []
    stale = lib.seconds_since(snapshot.get("generated_at"), now=now)
    next_action = "status all"
    if lane_id:
        next_action = "none - informational"
    return _ok(state_dir, identity, "status", cid, parsed, "read_only", evidence, reply,
               lane_id=lane_id,
               read_only=True, snapshot_age_seconds=stale, lane_count=len(lanes),
               next="next: %s" % next_action)


def _do_help(state_dir, identity, args, cid, parsed, now):
    evidence = [lib.state_path(state_dir, lib.SNAPSHOT), cmd_log_path(state_dir)]
    reply = render_mod.build_envelope("[P1]", "handoff commands",
                                      ["%s. %s" % (i + 1, row) for i, row in enumerate(HELP_ROWS)],
                                      evidence, "none - informational", now=now)
    return _ok(state_dir, identity, "help", cid, parsed, "read_only", evidence, reply,
               read_only=True, verbs=list(lib.VERBS), next="next: none - informational")


def _do_steer(state_dir, identity, args, cid, parsed, now, ):
    lane_id = args["lane"]
    note = args.get("note") or ""
    window = lib.window_key(now=now, seconds=lib.STEER_WINDOW_SECONDS)
    cid = command_id(identity, "steer", lib.canonical_json({"lane": lane_id, "note": note}),
                     window=window)
    prior = _lookup_duplicate(state_dir, cid, "steer", window=window)
    snapshot = _snapshot(state_dir)
    evidence = [lib.state_path(state_dir, lib.SNAPSHOT)]
    if not snapshot:
        raise lib.HandoffError("E_REPORT_UNAVAILABLE", "no snapshot: steer needs lane state",
                               "next: snapshot.py --build --state-dir %s" % state_dir,
                               evidence=evidence)
    lane, _others = _lane(snapshot, lane_id)
    evidence = [_lane_evidence(state_dir, lane)]
    health = (lane.get("health") or {}).get("state")
    stage = lane.get("stage")
    if prior:
        log_command(state_dir, identity, "steer", lib.sha256_text(note), cid, "duplicate",
                    evidence, duplicate=True, lane_id=lane_id, window=window,
                    reply_text=prior.get("wire_reply_text"))
        return lib.ok_result(kind="command", verb="steer", command_id=cid, accepted=True,
                             executed=False, duplicate=True, queued=prior.get("outcome") == "queued",
                             wire_reply=prior.get("wire_reply_text"),
                             steer_text=note, lane_id=lane_id, session_id=(lane.get("worker") or {}).get("session_id"),
                             evidence=evidence, next="next: status %s" % lane_id)
    if stage == "done" or stage == "blocked":
        raise lib.HandoffError("E_LANE_NOT_LIVE", "lane %s is %s" % (lane_id, stage),
                               "next: status %s" % lane_id, evidence=evidence)
    if health in NOT_STEERABLE or health not in STEERABLE_HEALTH:
        raise lib.HandoffError("E_LANE_NOT_LIVE",
                               "lane %s is not live (health %s: %s)"
                               % (lane_id, health, (lane.get("health") or {}).get("evidence")),
                               "next: status %s" % lane_id, evidence=evidence)

    note_clean, labels = lib.redact(note)
    reply = render_mod.build_envelope(
        "[P1]", "steer queued for %s" % lane_id,
        ["queued, not executed: the lane must read it",
         "note %d chars; injection-looking text is data, never a command" % len(note),
         "health %s" % health],
        evidence, "status %s" % lane_id, now=now)
    return _ok(state_dir, identity, "steer", cid, parsed, "queued", evidence, reply,
               lane_id=lane_id, window=window, queued=True,
               session_id=(lane.get("worker") or {}).get("session_id"),
               command_id=cid, steer_text=note_clean, note_redactions=labels,
               next="next: status %s" % lane_id)


def _do_approve(state_dir, identity, args, cid, parsed, now, authz, env,
                observed_spec, explicit_fingerprint, receipt_path):
    item = args["item"]
    if not ITEM_RE.match(item):
        raise lib.HandoffError("E_UNKNOWN_ITEM", lib.uniform_refusal(item),
                               "next: status all", evidence=[approvals_mod.approvals_path(state_dir)])
    try:
        result = approvals_mod.approve(state_dir, item, identity, authz=authz, env=env,
                                       observed_spec=observed_spec,
                                       explicit_fingerprint=explicit_fingerprint,
                                       consume=bool(receipt_path), receipt_path=receipt_path,
                                       now=now)
    except lib.HandoffError as exc:
        log_command(state_dir, identity, "approve", lib.sha256_text(item), cid, "refused",
                    [approvals_mod.approvals_path(state_dir)], error=exc.code)
        if exc.code == "E_HOLD_ACTIVE":
            notify_mod.emit(state_dir, "hold_blocked", entity_id=item,
                            facts=["hold blocked an approve attempt", exc.message],
                            evidence=[approvals_mod.approvals_path(state_dir)],
                            next_action="release <hold_id>", now=now, authz=authz,
                            platform=identity.get("platform"))
        raise
    stored, _, _ = approvals_mod._load_record(state_dir, item)
    fp_short = result.get("fingerprint_short") or \
        approvals_mod.short_fingerprint(stored.get("target_fingerprint"))
    # a decision confirmation is not an approval *request*: it carries [P1]. The
    # [approve] sigil is reserved for the request class (lock 7.1, 7.5).
    facts = ["item %s kind %s" % (item, stored.get("kind")),
             "fingerprint %s" % fp_short,
             "status %s" % result.get("status"),
             "expires %s" % (stored.get("expires_at") or "n/a")]
    reply = render_mod.build_envelope("[P1]", "decision recorded %s" % item, facts,
                                      result.get("evidence") or [],
                                      (result.get("next") or "none - informational"),
                                      now=now)
    notify_mod.emit(state_dir, "approval_granted", entity_id=item,
                    facts=["approved", "fingerprint %s" % fp_short],
                    evidence=result.get("evidence") or [],
                    next_action="none - informational", now=now, authz=authz,
                    platform=identity.get("platform"))
    return _ok(state_dir, identity, "approve", cid, parsed, "approved",
               result.get("evidence") or [], reply, lane_id=result.get("lane_id"),
               approval_status=result.get("status"), fingerprint_short=fp_short,
               executed=bool(result.get("executed")),
               next=result.get("next") or "next: none - informational")


def _do_deny(state_dir, identity, args, cid, parsed, now, authz, env):
    item = args["item"]
    reason = args.get("reason") or ""
    result = approvals_mod.deny(state_dir, item, identity, authz=authz, env=env,
                                reason=reason, now=now)
    reply = render_mod.build_envelope("[P1]", "denied %s" % item,
                                      ["reason stored as data and relayed to the lane",
                                       "no consequential action runs"],
                                      result.get("evidence") or [], "none - informational",
                                      now=now)
    return _ok(state_dir, identity, "deny", cid, parsed, "denied",
               result.get("evidence") or [], reply, lane_id=result.get("lane_id"),
               reason_is_data=True, next="next: none - informational")


def _do_hold(state_dir, identity, args, cid, parsed, now, authz):
    lane_id = args.get("lane")
    reason = args.get("reason") or ""
    window = lib.window_key(now=now, seconds=lib.HOLD_WINDOW_SECONDS)
    cid = command_id(identity, "hold", lib.canonical_json({"scope": lane_id or "project",
                                                           "reason": reason}), window=window)
    result = approvals_mod.hold(state_dir, lane_id=lane_id, reason=reason,
                                actor_user_id=identity.get("user_id"),
                                platform=identity.get("platform"),
                                chat_id=identity.get("chat_id"), now=now)
    reply = render_mod.build_envelope(
        "[P1]", "hold %s" % ("project" if not lane_id else lane_id),
        ["consequential approvals are blocked until released",
         "hold id %s" % result["hold_id"]],
        result.get("evidence") or [], "release %s" % result["hold_id"], now=now)
    out = _ok(state_dir, identity, "hold", cid, parsed, "open", result.get("evidence") or [],
              reply, lane_id=lane_id, window=window, hold_id=result["hold_id"],
              duplicate=result.get("duplicate", False),
              next="next: release %s" % result["hold_id"])
    return out


def _do_release(state_dir, identity, args, cid, parsed, now, authz, env):
    result = approvals_mod.release(state_dir, args["hold_id"], identity=identity,
                                   authz=authz, env=env, now=now)
    reply = render_mod.build_envelope("[P1]", "released %s" % args["hold_id"],
                                      ["consequential actions unblock",
                                       "a reconnect never releases a hold by itself"],
                                      result.get("evidence") or [], "status all", now=now)
    return _ok(state_dir, identity, "release", cid, parsed, "released",
               result.get("evidence") or [], reply, hold_id=args["hold_id"],
               duplicate=result.get("duplicate", False), next="next: status all")


def _do_morning(state_dir, identity, args, cid, parsed, now):
    snapshot = _snapshot(state_dir)
    evidence = [lib.state_path(state_dir, lib.SNAPSHOT),
                lib.state_path(state_dir, lib.APPROVALS_PENDING),
                lib.state_path(state_dir, lib.HOLDS_OPEN)]
    if not snapshot:
        raise lib.HandoffError("E_REPORT_UNAVAILABLE", "no snapshot for the digest",
                               "next: snapshot.py --build --state-dir %s" % state_dir,
                               evidence=evidence)
    lanes = snapshot.get("lanes") or []
    stages = {}
    for lane in lanes:
        stages[lane.get("stage")] = stages.get(lane.get("stage"), 0) + 1
    pending, _malformed = approvals_mod.list_approvals(state_dir, status="pending", now=now)
    open_holds = approvals_mod.active_holds(state_dir, now=now)
    lateness = _report_lateness(state_dir, now)

    facts = ["%d lane(s): %s" % (len(lanes), ", ".join("%s=%s" % kv for kv in sorted(stages.items()))),
             "pending approvals: %s" % (", ".join(a["approval_id"] for a in pending) or "none"),
             "open holds: %s" % (", ".join(h["hold_id"] for h in open_holds) or "none")]
    blocked = [ln.get("lane_id") for ln in lanes if ln.get("stage") == "blocked"]
    if blocked:
        facts.append("blocked lanes: %s" % ", ".join(blocked))
    facts.append(lateness)
    reply = render_mod.build_envelope("[P1]", "morning report", facts, evidence,
                                      "status all", snapshot_ts=snapshot.get("generated_at"),
                                      now=now)
    return _ok(state_dir, identity, "morning-report", cid, parsed, "read_only", evidence, reply,
               read_only=True, pending_count=len(pending), hold_count=len(open_holds),
               lateness=lateness, override=bool(args.get("now")),
               next="next: approve <item>" if pending else "next: status all")


def _report_lateness(state_dir, now):
    schedule = "07:30"
    authz = lib.load_authz(state_dir)
    configured = authz.get("morning_report") or {}
    if isinstance(configured, dict) and configured.get("at"):
        schedule = str(configured["at"])
    try:
        hour, minute = [int(part) for part in schedule.split(":")[:2]]
    except (ValueError, IndexError):
        hour, minute = 7, 30
    local_now = now.astimezone()
    scheduled = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    delta = int((local_now - scheduled).total_seconds() // 60)
    if delta > 5:
        return "report late by %d min (scheduled %s)" % (delta, schedule)
    if delta < -5:
        return "report early by %d min (scheduled %s)" % (-delta, schedule)
    return "report on time (scheduled %s)" % schedule


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="command.py",
        description="Deterministic Protean Handoff phone command parser and router.")
    parser.add_argument("--state-dir", help="handoff state directory")
    parser.add_argument("--authz-file")
    parser.add_argument("--text", help="the message text")
    parser.add_argument("--text-file", help="read the message from a file")
    parser.add_argument("--platform")
    parser.add_argument("--chat-id")
    parser.add_argument("--user-id")
    parser.add_argument("--chat-kind", default="dm", choices=["dm", "group"])
    parser.add_argument("--now", help="override now (iso8601)")
    parser.add_argument("--observed-spec", help="live target spec for approve (JSON or @path)")
    parser.add_argument("--explicit-fingerprint")
    parser.add_argument("--receipt-path")
    parser.add_argument("--parse-only", action="store_true",
                        help="print the parse result without authorizing or acting")
    args = parser.parse_args(argv)

    try:
        if args.parse_only:
            return lib.emit({"ok": True, "parse": parse(args.text or "")}, 0)
        text = args.text
        if args.text_file:
            text = lib.read_text(args.text_file)
        lib.require(text is not None, "E_NO_TEXT", "no message text supplied",
                    "next: pass --text or --text-file")
        state_dir = lib.resolve_state_dir(args.state_dir)
        lib.ensure_dir(state_dir)
        identity = {"platform": args.platform, "chat_id": args.chat_id,
                    "user_id": args.user_id, "chat_kind": args.chat_kind}
        now = lib.parse_iso(args.now) or lib.utcnow()
        spec = None
        if args.observed_spec:
            spec = (lib.read_json(args.observed_spec[1:], default=None)
                    if args.observed_spec.startswith("@") else None)
        out = run(text, identity, state_dir, now=now, observed_spec=spec,
                  explicit_fingerprint=args.explicit_fingerprint,
                  receipt_path=args.receipt_path, chat_kind=args.chat_kind)
        code = 0 if (out.get("ok") and out.get("kind") == "command" and out.get("accepted")) else 1
        if out.get("kind") in ("chat", "native"):
            code = 0
        return lib.emit(out, code)
    except lib.HandoffError as exc:
        return lib.emit(exc.as_dict(), 1)


if __name__ == "__main__":
    sys.exit(main())
