"""Protean Handoff - verify.py: the invariant gate (lock 7.9, 10 acceptance).

Gates run in order and every violation is printed with evidence; the process exits
non-zero if anything fails.

  1. payload     - the skill payload exists and byte-compiles (fresh-clone safety)
  2. snapshot    - schema, (D) fields never trusted, persisted-vs-journal replay, hashes
  3. envelope    - every rendered message AND every logged wire reply passes the 7 gate
  4. approvals   - append-only monotone seq, one-way lifecycle, single consumption,
                   read-back executed only on a matching fingerprint
  5. holds       - open/release lifecycle, unique ids, no auto-release
  6. dedup       - notify.jsonl key integrity, identity-shaped keys never sent twice
  7. journal     - monotone seq, no malformed rows
  8. secrets     - no secret-like value anywhere in the state dir or the payload

Exit codes: 0 all gates pass, 1 violations, 2 usage/state error.
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
import snapshot as snapshot_mod

APPROVAL_EVENTS = ("request", "approved", "denied", "consumed", "expired", "voided", "refused")
HOLD_EVENTS = ("open", "released")
EVENT_STATUS = {"request": "pending", "approved": "approved", "denied": "denied",
                "consumed": "consumed", "expired": "expired", "voided": "voided"}
PAYLOAD_REQUIRED = ("SKILL.md", "references/protocol.md",
                    "scripts/handoff_lib.py", "scripts/snapshot.py", "scripts/render.py",
                    "scripts/command.py", "scripts/approvals.py", "scripts/notify.py",
                    "scripts/verify.py")
PAYLOAD_REPO = ("install.sh", "tests/test_handoff.py")
# a hardcoded home is an absolute /Users/<name>/.hermes path or a literal "~" + "/.hermes"
# inside code - prose that says no hardcoded home is not a violation. The second pattern
# is assembled at runtime so this file's own source cannot trip it.
HARDCODED_HOME_PATTERNS = (re.compile(r"/[A-Za-z0-9_.\-]+/" + r"\.hermes"),
                           re.compile(r"[\"']~" + r"/\.hermes"))
REDACTION_MARKER = re.compile(r"\[redacted:([a-z_+]+)\]")


def gate_payload(root):
    violations = []
    notes = []
    files = list(PAYLOAD_REQUIRED)
    if os.path.isfile(os.path.join(root, "install.sh")):
        files += list(PAYLOAD_REPO)
    else:
        notes.append("repo-only files not present (installed payload): %s"
                     % ", ".join(PAYLOAD_REPO))
    for relative in files:
        path = os.path.join(root, relative)
        if not os.path.isfile(path):
            violations.append({"code": "E_PAYLOAD_MISSING", "detail": "missing %s" % relative,
                               "evidence": path})
            continue
        if relative.endswith(".py"):
            source = lib.read_text(path)
            try:
                compile(source if source is not None else "", path, "exec")
            except (SyntaxError, ValueError) as exc:
                violations.append({"code": "E_PAYLOAD_COMPILE", "detail": str(exc),
                                   "evidence": path})
    for relative in files:
        if not relative.endswith(".py"):
            continue
        text = lib.read_text(os.path.join(root, relative)) or ""
        for pattern in HARDCODED_HOME_PATTERNS:
            match = pattern.search(text)
            if match:
                violations.append({"code": "E_HARDCODED_HOME",
                                   "detail": "%s hardcodes a hermes home path (%s)"
                                             % (relative, match.group(0)),
                                   "evidence": os.path.join(root, relative)})
                break
    skill = lib.read_text(os.path.join(root, "SKILL.md")) or ""
    if "references/protocol.md" not in skill:
        violations.append({"code": "E_SKILL_NO_POINTER",
                           "detail": "SKILL.md does not point at references/protocol.md",
                           "evidence": os.path.join(root, "SKILL.md")})
    install = lib.read_text(os.path.join(root, "install.sh")) or ""
    # the installer must not write into the core, a plugin dir, an adapter, a manifest
    # or an operator config file: only actual write behaviour is a violation, not the
    # operator next-step hints printed at the end of a successful run.
    for pattern in (r"cp[^\n]*(hermes-agent|plugins/platforms|command_manifest)",
                    r"(sed|echo|cat)[^\n]*config\.yaml",
                    r"(sed|echo|cat)[^\n]*\.env",
                    r"launchctl[^\n]*(load|bootstrap|submit|unload|kill)",
                    r"crontab[^\n]*-"):
        match = re.search(pattern, install)
        if match:
            violations.append({"code": "E_INSTALL_TOUCHES_CORE",
                               "detail": "install.sh writes outside the payload: %s" % match.group(0),
                               "evidence": os.path.join(root, "install.sh")})
    return violations, notes


def gate_snapshot(state_dir, ops_dir=None, gateway_state=None, soft=False):
    violations, report = snapshot_mod.verify_snapshot(state_dir, ops_dir=ops_dir,
                                                     gateway_state=gateway_state, soft=soft)
    return violations, report


def gate_envelopes(state_dir):
    violations = []
    checked = 0
    render_dir = lib.state_path(state_dir, lib.RENDER_DIR)
    if os.path.isdir(render_dir):
        for name in sorted(os.listdir(render_dir)):
            path = os.path.join(render_dir, name)
            if not os.path.isfile(path):
                continue
            text = lib.read_text(path) or ""
            checked += 1
            for violation in render_mod.validate_message(text):
                violation = dict(violation)
                violation["evidence"] = path
                violations.append(violation)
    rows, _ = lib.read_jsonl(lib.state_path(state_dir, lib.CMD_LOG))
    for row in rows:
        reply = row.get("wire_reply_text")
        if not reply:
            continue
        checked += 1
        for violation in render_mod.validate_message(reply):
            violation = dict(violation)
            violation["evidence"] = lib.state_path(state_dir, lib.CMD_LOG)
            violation["detail"] = "%s (command_id %s)" % (violation["detail"], row.get("command_id"))
            violations.append(violation)
    return violations, {"messages_checked": checked}


def gate_approvals(state_dir):
    violations = []
    rows, malformed = approvals_mod.load_ledger(state_dir)
    if malformed:
        violations.append({"code": "E_LEDGER_MALFORMED",
                           "detail": "%d malformed ledger row(s)" % malformed,
                           "evidence": approvals_mod.approvals_path(state_dir)})
    last_seq = 0
    seen_ids = {}
    nonces = {}
    for index, row in enumerate(rows):
        try:
            seq = int(row.get("seq") or 0)
        except (TypeError, ValueError):
            seq = 0
        if seq <= last_seq:
            violations.append({"code": "E_LEDGER_SEQ",
                               "detail": "seq %r is not monotonic at row %d" % (row.get("seq"), index),
                               "evidence": approvals_mod.approvals_path(state_dir)})
        last_seq = max(last_seq, seq)
        event = row.get("event")
        if event not in APPROVAL_EVENTS:
            violations.append({"code": "E_LEDGER_EVENT", "detail": "unknown event %r" % (event,)})
            continue
        approval = row.get("approval") or {}
        approval_id = approval.get("approval_id")
        if approval_id and not approvals_mod.ITEM_RE.match(str(approval_id)):
            violations.append({"code": "E_APPROVAL_ID", "detail": "bad approval_id %r" % (approval_id,)})
        if event == "refused":
            if approval.get("status") in ("approved", "consumed"):
                violations.append({"code": "E_REFUSAL_WITH_EXECUTION",
                                   "detail": "refused row %s carries status %s"
                                             % (approval_id, approval.get("status"))})
            continue
        if event == "request":
            if approval_id in seen_ids:
                violations.append({"code": "E_DUPLICATE_REQUEST",
                                   "detail": "approval %s requested twice" % approval_id})
            seen_ids[approval_id] = approval
            if approval.get("status") != "pending":
                violations.append({"code": "E_REQUEST_STATUS",
                                   "detail": "request row for %s is %r" % (approval_id, approval.get("status"))})
            fingerprint = str(approval.get("target_fingerprint") or "")
            if not re.match(r"^[0-9a-f]{64}$", fingerprint):
                violations.append({"code": "E_FINGERPRINT",
                                   "detail": "approval %s has a bad target_fingerprint" % approval_id})
            nonce = (approval.get("binding") or {}).get("nonce")
            if not nonce or len(str(nonce)) != lib.NONCE_CHARS:
                violations.append({"code": "E_NONCE",
                                   "detail": "approval %s nonce is not %d chars"
                                             % (approval_id, lib.NONCE_CHARS)})
            elif nonce in nonces:
                violations.append({"code": "E_NONCE_REUSE",
                                   "detail": "nonce reused by %s and %s" % (nonces[nonce], approval_id)})
            nonces[nonce] = approval_id
            binding = approval.get("binding") or {}
            for key in ("actor_user_id", "platform", "chat_id"):
                if not str(binding.get(key) or ""):
                    violations.append({"code": "E_BINDING_INCOMPLETE",
                                       "detail": "approval %s binding.%s is empty" % (approval_id, key)})
            requested, expires = lib.epoch(approval.get("requested_at")), lib.epoch(approval.get("expires_at"))
            if requested and expires and expires <= requested:
                violations.append({"code": "E_EXPIRY_ORDER",
                                   "detail": "approval %s expires before it was requested" % approval_id})
            continue

        expected = EVENT_STATUS.get(event)
        if expected and approval.get("status") != expected:
            violations.append({"code": "E_STATUS_EVENT_MISMATCH",
                               "detail": "%s event for %s carries status %r"
                                         % (event, approval_id, approval.get("status"))})
        events = seen_ids.setdefault(approval_id, None)
        if event == "consumed":
            history = [r for r in rows[:index]
                       if (r.get("approval") or {}).get("approval_id") == approval_id]
            if not any(r.get("event") == "approved" for r in history):
                violations.append({"code": "E_CONSUME_WITHOUT_APPROVE",
                                   "detail": "approval %s was consumed without an approved event"
                                             % approval_id})
            execution = approval.get("execution") or {}
            if not execution.get("observed_fingerprint"):
                violations.append({"code": "E_EXECUTION_NO_READBACK",
                                   "detail": "approval %s consumed without a read-back fingerprint"
                                             % approval_id})
            elif execution.get("observed_fingerprint") != approval.get("target_fingerprint"):
                violations.append({"code": "E_EXECUTION_FINGERPRINT",
                                   "detail": "approval %s executed against a different fingerprint"
                                             % approval_id})
            if execution.get("observed_delivery") not in ("verified", "unverified"):
                violations.append({"code": "E_EXECUTION_DELIVERY",
                                   "detail": "approval %s has no observed_delivery" % approval_id})
            if not execution.get("executed_at"):
                violations.append({"code": "E_EXECUTION_NO_TIME",
                                   "detail": "approval %s consumed without executed_at" % approval_id})
        if event == "voided":
            if (approval.get("execution") or {}).get("failure_code") != "E_BINDING_STALE":
                violations.append({"code": "E_VOID_REASON",
                                   "detail": "approval %s voided without E_BINDING_STALE" % approval_id})
        if event == "denied" and not approval.get("decided_by"):
            violations.append({"code": "E_DENY_NO_ACTOR",
                               "detail": "approval %s denied without a deciding identity" % approval_id})

    # single consumption, derived from the folded ledger
    records, order = approvals_mod.fold(rows)
    for approval_id, record in records.items():
        consumed = [e for e in record.get("events") or [] if e == "consumed"]
        if len(consumed) > 1:
            violations.append({"code": "E_DOUBLE_CONSUME",
                               "detail": "approval %s has %d consumed events" % (approval_id, len(consumed))})
    return violations, {"ledger_rows": len(rows), "approvals": len(order)}


def gate_holds(state_dir):
    violations = []
    rows, malformed = lib.read_jsonl(approvals_mod.holds_path(state_dir))
    if malformed:
        violations.append({"code": "E_HOLDS_MALFORMED",
                           "detail": "%d malformed hold row(s)" % malformed,
                           "evidence": approvals_mod.holds_path(state_dir)})
    holds, order = approvals_mod._fold_holds(rows)
    for index, row in enumerate(rows):
        event = row.get("event")
        if event not in HOLD_EVENTS:
            violations.append({"code": "E_HOLD_EVENT", "detail": "unknown hold event %r" % (event,)})
            continue
        hold = row.get("hold") or {}
        hold_id = hold.get("hold_id")
        if not approvals_mod.HOLD_RE.match(str(hold_id or "")):
            violations.append({"code": "E_HOLD_ID", "detail": "bad hold_id %r" % (hold_id,)})
        if event == "open":
            if not str(hold.get("scope") or ""):
                violations.append({"code": "E_HOLD_SCOPE",
                                   "detail": "hold %s has no scope" % hold_id})
            if hold.get("status") != "open":
                violations.append({"code": "E_HOLD_OPEN_STATUS",
                                   "detail": "open event for %s carries status %r" % (hold_id, hold.get("status"))})
        if event == "released":
            history = [r for r in rows[:index]
                       if (r.get("hold") or {}).get("hold_id") == hold_id]
            if not any(r.get("event") == "open" for r in history):
                violations.append({"code": "E_RELEASE_WITHOUT_OPEN",
                                   "detail": "hold %s released without an open event" % hold_id})
            if hold.get("status") != "released":
                violations.append({"code": "E_HOLD_RELEASE_STATUS",
                                   "detail": "released event for %s carries status %r"
                                             % (hold_id, hold.get("status"))})
            if not hold.get("released_at"):
                violations.append({"code": "E_HOLD_RELEASE_TIME",
                                   "detail": "hold %s released without a timestamp" % hold_id})
    return violations, {"holds": len(order), "hold_rows": len(rows)}


def gate_dedup(state_dir):
    violations = []
    rows, malformed = notify_mod.load_notify(state_dir)
    if malformed:
        violations.append({"code": "E_NOTIFY_MALFORMED",
                           "detail": "%d malformed notify row(s)" % malformed,
                           "evidence": notify_mod.notify_path(state_dir)})
    permanent_sends = {}
    for row in rows:
        key = row.get("dedup_key")
        if key and not re.match(r"^[0-9a-f]{64}$", str(key)):
            violations.append({"code": "E_DEDUP_KEY", "detail": "bad dedup_key %r" % (key,)})
        if not row.get("class") and not row.get("dedup_key"):
            violations.append({"code": "E_NOTIFY_CLASS", "detail": "notify row without a class"})
        if row.get("p0") and row.get("class") not in notify_mod.P0_CLASSES:
            violations.append({"code": "E_P0_CLASS",
                               "detail": "class %r pinged but is not a P0 class" % row.get("class")})
        action = row.get("action")
        if action is not None and action not in notify_mod.ACTIONS + ("delivery_delivered", "delivery_failed"):
            violations.append({"code": "E_NOTIFY_ACTION", "detail": "unknown action %r" % (action,)})
        if row.get("permanent") and action in ("sent", "batched"):
            permanent_sends[key] = permanent_sends.get(key, 0) + 1
    for key, count in sorted(permanent_sends.items()):
        if count > 1:
            violations.append({"code": "E_DEDUP_PERMANENT_RESEND",
                               "detail": "identity-shaped key sent %d times: %s" % (count, key[:12]),
                               "evidence": notify_mod.notify_path(state_dir)})
    counts = {}
    for row in rows:
        counts[row.get("action")] = counts.get(row.get("action"), 0) + 1
    return violations, {"notify_rows": len(rows), "counts": counts}


def gate_journal(state_dir):
    violations = []
    rows, malformed, path = snapshot_mod.read_journal(state_dir)
    if malformed:
        violations.append({"code": "E_JOURNAL_MALFORMED",
                           "detail": "%d malformed journal row(s)" % malformed, "evidence": path})
    last_seq = 0
    for index, row in enumerate(rows):
        try:
            seq = int(row.get("seq") or 0)
        except (TypeError, ValueError):
            seq = 0
        if seq <= last_seq:
            violations.append({"code": "E_JOURNAL_SEQ",
                               "detail": "journal seq %r not monotonic at row %d" % (row.get("seq"), index),
                               "evidence": path})
        last_seq = max(last_seq, seq)
        if not row.get("event") or not row.get("at"):
            violations.append({"code": "E_JOURNAL_ROW",
                               "detail": "journal row %d lacks event/at" % index, "evidence": path})
    return violations, {"journal_rows": len(rows)}


def gate_secrets(state_dir, root=None):
    violations = []
    scanned = 0
    targets = []
    for base in (state_dir, root):
        if not base or not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.getsize(path) > 4 * 1024 * 1024:
                    continue
                targets.append(path)
    for path in targets:
        text = lib.read_text(path)
        if text is None:
            continue
        if not os.path.isfile(path):
            continue
        if os.path.splitext(path)[1] in (".png", ".jpg", ".pdf", ".gz", ".zip"):
            continue
        scanned += 1
        for label in lib.secret_labels(text):
            violations.append({"code": "E_SECRET_LIKE_VALUE",
                               "detail": "secret-like value (%s) on disk" % label,
                               "evidence": path})
    return violations, {"files_scanned": scanned}


def run_gates(state_dir=None, root=None, ops_dir=None, gateway_state=None, soft=False):
    report = {"gates": {}}
    violations = []

    if root:
        found, _notes = gate_payload(root)
        report["gates"]["payload"] = {"ok": not found, "violations": found}
        violations.extend(found)
    if state_dir:
        found, detail = gate_snapshot(state_dir, ops_dir=ops_dir, gateway_state=gateway_state,
                                      soft=soft)
        report["gates"]["snapshot"] = {"ok": not found, "violations": found, "detail": detail}
        violations.extend(found)

        found, detail = gate_envelopes(state_dir)
        report["gates"]["envelope"] = {"ok": not found, "violations": found, "detail": detail}
        violations.extend(found)

        found, detail = gate_approvals(state_dir)
        report["gates"]["approvals"] = {"ok": not found, "violations": found, "detail": detail}
        violations.extend(found)

        found, detail = gate_holds(state_dir)
        report["gates"]["holds"] = {"ok": not found, "violations": found, "detail": detail}
        violations.extend(found)

        found, detail = gate_dedup(state_dir)
        report["gates"]["dedup"] = {"ok": not found, "violations": found, "detail": detail}
        violations.extend(found)

        found, detail = gate_journal(state_dir)
        report["gates"]["journal"] = {"ok": not found, "violations": found, "detail": detail}
        violations.extend(found)

    if state_dir or root:
        found, detail = gate_secrets(state_dir, root=root)
        report["gates"]["secrets"] = {"ok": not found, "violations": found, "detail": detail}
        violations.extend(found)

    report["ok"] = not violations
    report["violation_count"] = len(violations)
    report["violations"] = violations
    report["evidence"] = [p for p in [state_dir, root] if p]
    report["next"] = ("next: none - informational" if not violations
                      else "next: fix the violations above")
    return violations, report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description="Invariant gate: snapshot schema, envelopes, approvals, holds, dedup, journal, secrets.")
    parser.add_argument("--state-dir")
    parser.add_argument("--root", help="skill payload root (fresh-clone / post-install check)")
    parser.add_argument("--ops-dir")
    parser.add_argument("--gateway-state",
                        help="gateway state file for derived connectivity "
                             "(default: %s)" % "PROTEAN_HANDOFF_GATEWAY_STATE")
    parser.add_argument("--soft", action="store_true",
                        help="downgrade missing-artifact violations (laptop-asleep walk-away reads)")
    parser.add_argument("--payload-only", action="store_true")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root) if args.root else None
    if args.payload_only and root is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        gateway_state = args.gateway_state or os.environ.get("PROTEAN_HANDOFF_GATEWAY_STATE")
        state_dir = None
        if not args.payload_only:
            state_dir = lib.resolve_state_dir(args.state_dir, require=False)
        if state_dir is None and root is None:
            raise lib.HandoffError("E_NO_TARGET", "nothing to verify",
                                   "next: pass --state-dir <dir> and/or --root <payload root>")
        violations, report = run_gates(state_dir=state_dir, root=root, ops_dir=args.ops_dir,
                                       gateway_state=gateway_state, soft=args.soft)
        return lib.emit(report, 0 if not violations else 1)
    except lib.HandoffError as exc:
        return lib.emit(exc.as_dict(), 2)


if __name__ == "__main__":
    sys.exit(main())
