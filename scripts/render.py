"""Protean Handoff — lane cards, envelope assembler, and the 7 validator gate.

Every phone-visible message is assembled here and re-validated before it can be
sent. A message that violates the envelope is never emitted: the assembler raises,
the validator exits non-zero (lock 7.9).

Envelope (lock 7), field order fixed:

    [sigil] <subject <= 72 chars>
    <fact lines, <= 8 total, <= 480 chars>
    ev: <abs-path-or-url>[ , <path>]
    next: <one explicit action>

Implementation readings (named, not silent):
  R1. `ev:` is the second-to-last line and `next:` the last - the lock fixes their
      order but not their adjacency; adjacency is required here so a validator can
      reject a message whose `next:` is buried mid-body.
  R2. `snapshot age: <n> min` is injected as a fact line whenever the render is
      derived from a snapshot older than 15 minutes (lock 1.D).
  R3. A message cap of 1000 chars is enforced on top of the lock's body budget
      (Hazen 4.1 phone-visible policy cap).
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import handoff_lib as lib

APPROVE_LABELS = ("item ", "kind ", "fp ", "expires ")
MAX_FIRST_LINE_CHARS = lib.MAX_SUBJECT_CHARS + 12   # sigil + space + subject


def _lines(text):
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n").split("\n")


def validate_message(text, snapshot_ts=None, now=None):
    """Return a list of violation dicts ([] means compliant). Never raises."""
    violations = []
    if text is None or not str(text).strip():
        return [{"code": "E_EMPTY_MESSAGE", "detail": "message is empty"}]
    text = str(text)
    lines = _lines(text)

    if len(text) > lib.MAX_MESSAGE_CHARS:
        violations.append({"code": "E_MESSAGE_TOO_LONG",
                           "detail": "%d chars > %d" % (len(text), lib.MAX_MESSAGE_CHARS)})

    first = lines[0] if lines else ""
    sigil = None
    for candidate in lib.SIGILS:
        if first.startswith(candidate + " ") or first == candidate:
            sigil = candidate
            break
    if sigil is None:
        violations.append({"code": "E_NO_SIGIL",
                           "detail": "line 1 must start with one of %s" % (", ".join(lib.SIGILS),)})
    elif first != sigil:
        subject = first[len(sigil) + 1:]
        if not subject.strip():
            violations.append({"code": "E_NO_SUBJECT", "detail": "subject is empty"})
        if len(subject) > lib.MAX_SUBJECT_CHARS:
            violations.append({"code": "E_SUBJECT_TOO_LONG",
                               "detail": "subject %d chars > %d" % (len(subject), lib.MAX_SUBJECT_CHARS)})
    if len(first) > MAX_FIRST_LINE_CHARS:
        violations.append({"code": "E_SUBJECT_TOO_LONG",
                           "detail": "line 1 is %d chars > %d" % (len(first), MAX_FIRST_LINE_CHARS)})

    if len(lines) < 3:
        violations.append({"code": "E_MISSING_SECTIONS",
                           "detail": "need a subject, an ev: line and a next: line"})

    # last line: next:
    last = lines[-1] if lines else ""
    if not last.startswith("next: "):
        violations.append({"code": "E_NO_NEXT", "detail": "last line must start with 'next: '"})
    else:
        payload = last[len("next: "):].strip()
        if not payload:
            violations.append({"code": "E_NO_NEXT", "detail": "next: payload is empty"})
        elif len(payload) > lib.MAX_NEXT_CHARS:
            violations.append({"code": "E_NEXT_TOO_LONG",
                               "detail": "next: payload %d chars > %d" % (len(payload), lib.MAX_NEXT_CHARS)})

    # ev: line - exactly one, second to last (R1)
    ev_lines = [ln for ln in lines if ln.startswith("ev:")]
    if not ev_lines:
        violations.append({"code": "E_NO_EVIDENCE", "detail": "no ev: line (an evidence-free message is a defect)"})
    else:
        if len(ev_lines) > 1:
            violations.append({"code": "E_MULTIPLE_EVIDENCE", "detail": "more than one ev: line"})
        if lines[-2] != ev_lines[0]:
            violations.append({"code": "E_EVIDENCE_POSITION",
                               "detail": "ev: must be the line immediately before next:"})
        pointers = [p.strip() for p in ev_lines[0][len("ev:"):].split(",") if p.strip()]
        if not pointers:
            violations.append({"code": "E_NO_EVIDENCE", "detail": "ev: carries no pointer"})
        if len(pointers) > lib.MAX_EV_POINTERS:
            violations.append({"code": "E_TOO_MANY_EVIDENCE",
                               "detail": "%d pointers > %d" % (len(pointers), lib.MAX_EV_POINTERS)})
        for pointer in pointers:
            if not (pointer.startswith("/") or pointer.startswith("http://") or pointer.startswith("https://")):
                violations.append({"code": "E_EVIDENCE_NOT_ABSOLUTE",
                                   "detail": "pointer is not an absolute path or URL: %s" % pointer})
            if any(ch.isspace() for ch in pointer):
                violations.append({"code": "E_EVIDENCE_IS_PROSE",
                                   "detail": "pointer contains whitespace (a pointer, never prose)"})

    # facts budget
    facts = lines[1:-2] if len(lines) >= 3 else []
    if len(facts) > lib.MAX_FACTS_LINES:
        violations.append({"code": "E_TOO_MANY_FACT_LINES",
                           "detail": "%d fact lines > %d" % (len(facts), lib.MAX_FACTS_LINES)})
    if len("\n".join(facts)) > lib.MAX_BODY_CHARS:
        violations.append({"code": "E_BODY_TOO_LONG",
                           "detail": "body %d chars > %d" % (len("\n".join(facts)), lib.MAX_BODY_CHARS)})

    # plain text only (7.2)
    if "```" in text or "`" in text:
        violations.append({"code": "E_MARKDOWN", "detail": "code fence or backtick present"})
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|") and stripped.count("|") >= 2:
            violations.append({"code": "E_MARKDOWN", "detail": "table row present"})
            break
    if "Traceback (most recent call last)" in text:
        violations.append({"code": "E_STACK_TRACE", "detail": "raw stack trace present"})

    # secrets (6)
    for label in lib.secret_labels(text):
        violations.append({"code": "E_SECRET_LIKE_VALUE",
                           "detail": "secret-like value present: %s" % label})

    # snapshot staleness marker (R2 / 1.D)
    if snapshot_ts:
        age = lib.seconds_since(snapshot_ts, now=now)
        if age is not None and age > lib.SNAPSHOT_STALE_SECONDS:
            if not any(ln.startswith("snapshot age: ") for ln in lines):
                violations.append({"code": "E_MISSING_SNAPSHOT_AGE",
                                   "detail": "snapshot older than 15 min without an age marker"})

    # approve-class extra fields (7.5)
    if sigil == "[approve]":
        for label in APPROVE_LABELS:
            if label not in text:
                violations.append({"code": "E_APPROVE_FIELD_MISSING",
                                   "detail": "approval request missing %r" % label.strip()})
        if not (last.startswith("next: approve ") or last.startswith("next: deny ")):
            violations.append({"code": "E_APPROVE_NEXT",
                               "detail": "approval request must end with the exact reply word"})
    return violations


def build_envelope(sigil, subject, facts, evidence, next_action,
                   snapshot_ts=None, now=None, extra_facts=None):
    """Assemble and validate a phone-visible message. Raises on any violation."""
    lib.require(sigil in lib.SIGILS, "E_BAD_SIGIL",
                "unknown class sigil %r" % (sigil,), "next: use one of %s" % ", ".join(lib.SIGILS))
    facts = [str(f).strip() for f in (facts or []) if str(f).strip()]
    evidence = [str(e).strip() for e in (evidence or []) if str(e).strip()]

    if snapshot_ts and extra_facts is None:
        extra_facts = []
    if snapshot_ts:
        age = lib.seconds_since(snapshot_ts, now=now)
        if age is not None and age > lib.SNAPSHOT_STALE_SECONDS:
            facts = list(facts) + ["snapshot age: %d min" % (age // 60)]

    if not evidence:
        raise lib.HandoffError("E_NO_EVIDENCE", "refusing to build an evidence-free message",
                               "next: attach an absolute receipt, approval or hold path")
    facts = facts[:lib.MAX_FACTS_LINES]

    text = "\n".join(
        ["%s %s" % (sigil, subject)]
        + facts
        + ["ev: %s" % ", ".join(evidence[:lib.MAX_EV_POINTERS])]
        + ["next: %s" % next_action]
    )
    violations = validate_message(text, snapshot_ts=snapshot_ts, now=now)
    if violations:
        raise lib.HandoffError("E_ENVELOPE_INVALID",
                               "assembled message failed the envelope gate",
                               "next: fix %s" % "; ".join(v["code"] for v in violations),
                               evidence=evidence, violations=violations)
    return text


# --- lane cards --------------------------------------------------------------

def health_line(lane, now=None):
    health = lane.get("health") or {}
    return "health %s (heartbeat %s, %s)" % (
        health.get("state"), _age_text(health.get("last_heartbeat_ts"), now),
        health.get("evidence") or "no evidence")


def _age_text(ts, now=None):
    age = lib.seconds_since(ts, now=now)
    if age is None:
        return "never"
    if age < 60:
        return "%ss ago" % age
    if age < 3600:
        return "%dm ago" % (age // 60)
    return "%dh ago" % (age // 3600)


def lane_card(lane, now=None):
    """Compact plain-text card facts for one lane (lock 7: <= 8 fact lines)."""
    now = now or lib.utcnow()
    worker = lane.get("worker") or {}
    gate = lane.get("gate") or {}
    health = lane.get("health") or {}
    connectivity = lane.get("connectivity") or {}
    artifacts = lane.get("artifacts") or []
    pending = lane.get("pending_approvals") or []
    holds = lane.get("merge_holds") or []

    card = [
        "lane %s stage %s role %s" % (lane.get("lane_id"), lane.get("stage"), lane.get("role")),
        "health %s - %s" % (health.get("state"), health.get("evidence") or "no evidence"),
        "worker pid %s alive=%s claim %s" % (worker.get("pid"), worker.get("process_alive"),
                                             worker.get("claim_status")),
        "gate %s %s" % (gate.get("state"), gate.get("name")),
        "pending: %s" % (", ".join(pending) if pending else "none"),
        "holds: %s" % (", ".join(holds) if holds else "none"),
        "gateway %s laptop %s" % (connectivity.get("gateway"), connectivity.get("laptop_state")),
    ]
    if artifacts:
        card.append("receipt %s" % artifacts[0].get("path"))
    return card[:lib.MAX_FACTS_LINES]


def status_message(snapshot, lane_id=None, now=None):
    """Render the status reply for one lane or the whole snapshot."""
    now = now or lib.utcnow()
    generated_at = (snapshot or {}).get("generated_at")
    lanes = (snapshot or {}).get("lanes") or []
    evidence = [_state_path_from_snapshot(snapshot)] if snapshot else []
    if not evidence:
        raise lib.HandoffError("E_REPORT_UNAVAILABLE", "no snapshot to render",
                               "next: run snapshot.py build --state-dir <dir>")

    if lane_id:
        cards = [ln for ln in lanes if ln.get("lane_id") == lane_id]
        if not cards:
            if lanes:
                raise lib.HandoffError(
                    "E_AMBIGUOUS_LANE",
                    "no lane %s on record; the snapshot holds %d lane(s)" % (lane_id, len(lanes)),
                    "next: status all", evidence=evidence,
                    candidates=[ln.get("lane_id") for ln in lanes])
            raise lib.HandoffError("E_NO_LANE", "the snapshot holds no lanes",
                                   "next: snapshot.py --build --state-dir <dir>",
                                   evidence=evidence)
        lane = cards[0]
        facts = lane_card(lane, now=now)
        facts.append("next action: %s" % ((lane.get("next_action") or {}).get("text") or "none"))
        subject = "%s %s" % (lane.get("lane_id"), lane.get("stage"))
        return build_envelope("[P1]", subject, facts[:lib.MAX_FACTS_LINES], evidence,
                              "status %s" % lane_id, snapshot_ts=generated_at, now=now)

    if not lanes:
        return build_envelope("[P1]", "no active lanes", ["snapshot has no lanes"],
                              evidence, "morning-report", snapshot_ts=generated_at, now=now)
    facts = ["%d lane(s)" % len(lanes)]
    for lane in lanes[:lib.MAX_FACTS_LINES - 1]:
        facts.append("%s stage %s health %s" % (lane.get("lane_id"), lane.get("stage"),
                                                (lane.get("health") or {}).get("state")))
    return build_envelope("[P1]", "lane status", facts, evidence, "status <lane>",
                          snapshot_ts=generated_at, now=now)


def _state_path_from_snapshot(snapshot):
    return snapshot.get("_path")


def snapshot_evidence_path(state_dir):
    return lib.state_path(state_dir, lib.SNAPSHOT)


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="render.py",
        description="Lane cards and envelope assembler/validator for the Protean Handoff skill.")
    parser.add_argument("--check", metavar="FILE",
                        help="validate a message file against the 7 envelope gate ('-' = stdin)")
    parser.add_argument("--spec", metavar="FILE",
                        help="JSON spec {sigil, subject, facts[], evidence[], next, snapshot_ts}")
    parser.add_argument("--status", action="store_true", help="render a status message from the snapshot")
    parser.add_argument("--lane-card", metavar="LANE_ID", help="print the compact card for one lane")
    parser.add_argument("--lane", metavar="LANE_ID", help="lane id for --status")
    parser.add_argument("--state-dir", help="handoff state directory (or %s)" % lib.STATE_DIR_ENV)
    parser.add_argument("--now", help="override 'now' (iso8601) for deterministic renders")
    parser.add_argument("--out", metavar="FILE", help="write the rendered message to this path")
    args = parser.parse_args(argv)

    try:
        now = lib.parse_iso(args.now) or lib.utcnow()

        if args.check:
            if args.check == "-":
                text = sys.stdin.read()
            else:
                text = lib.read_text(args.check)
                if text is None:
                    return lib.emit({"ok": False, "error": "E_NO_MESSAGE_FILE",
                                     "message": "cannot read %s" % args.check,
                                     "evidence": [], "next": "next: pass an existing message path"}, 1)
            violations = validate_message(text)
            return lib.emit({"ok": not violations, "violations": violations,
                             "lines": len(_lines(text)), "chars": len(text),
                             "evidence": [os.path.abspath(args.check)] if args.check != "-" else [],
                             "next": "next: none - informational" if not violations
                                     else "next: fix the envelope violations"},
                            0 if not violations else 1)

        if args.spec:
            spec = lib.read_json(args.spec)
            if not isinstance(spec, dict):
                raise lib.HandoffError("E_BAD_SPEC", "spec file is not a JSON object",
                                       "next: provide {sigil, subject, facts, evidence, next}")
            message = build_envelope(
                spec.get("sigil", "[P1]"), spec.get("subject", ""), spec.get("facts") or [],
                spec.get("evidence") or [], spec.get("next", "none - informational"),
                snapshot_ts=spec.get("snapshot_ts"), now=now)
            if args.out:
                lib.atomic_write_text(args.out, message + "\n", mode=0o600)
            return lib.emit({"ok": True, "message": message,
                             "evidence": [os.path.abspath(args.out)] if args.out else list(spec.get("evidence") or []),
                             "next": "next: send via existing egress (send_message platform:chat_id)"}, 0)

        state_dir = lib.resolve_state_dir(args.state_dir)
        snapshot = lib.read_json(lib.state_path(state_dir, lib.SNAPSHOT), default=None)

        if args.lane_card:
            if not isinstance(snapshot, dict):
                raise lib.HandoffError("E_REPORT_UNAVAILABLE", "no snapshot available",
                                       "next: run snapshot.py build --state-dir %s" % state_dir)
            lanes = [ln for ln in snapshot.get("lanes") or [] if ln.get("lane_id") == args.lane_card]
            if not lanes:
                raise lib.HandoffError("E_NO_LANE", "no lane %s in the snapshot" % args.lane_card,
                                       "next: status all",
                                       evidence=[snapshot_evidence_path(state_dir)])
            return lib.emit({"ok": True, "lane_card": lane_card(lanes[0], now=now),
                             "evidence": [snapshot_evidence_path(state_dir)],
                             "next": "next: status %s" % args.lane_card}, 0)

        if args.status:
            if not isinstance(snapshot, dict):
                raise lib.HandoffError("E_REPORT_UNAVAILABLE", "no snapshot available",
                                       "next: run snapshot.py build --state-dir %s" % state_dir)
            snapshot["_path"] = snapshot_evidence_path(state_dir)
            message = status_message(snapshot, lane_id=args.lane, now=now)
            violations = validate_message(message)
            if violations:
                raise lib.HandoffError("E_ENVELOPE_INVALID", "rendered status failed the envelope gate",
                                       "next: fix %s" % violations[0]["code"],
                                       evidence=[snapshot_evidence_path(state_dir)])
            if args.out:
                lib.atomic_write_text(args.out, message + "\n", mode=0o600)
            return lib.emit({"ok": True, "message": message,
                             "evidence": [os.path.abspath(args.out)] if args.out
                                         else [snapshot_evidence_path(state_dir)],
                             "next": "next: none - informational"}, 0)
    except lib.HandoffError as exc:
        return lib.emit(exc.as_dict(), 2)

    return lib.emit({"ok": False, "error": "E_USAGE", "message": "nothing to do",
                     "evidence": [], "next": "next: pass --check FILE, --spec FILE or --status"}, 2)


if __name__ == "__main__":
    sys.exit(main())
