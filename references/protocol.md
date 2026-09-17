# Protean Handoff — protocol pointer

**Normative source (unchanged, governs):** `leo-protocol.md`, STATUS: LOCKED (stage 2, Leo).
The locked artifact defines the lane schema, the verbs, the invariants I1–I12, the message envelope,
the approval binding, the P0 notification classes, the lifecycle, the error cases and the build
boundary. Locate it in the deployment that installed this skill, e.g. under the orchestrator's
delegation cache (`…/cache/delegation/protean-handoff/leo-protocol.md`).

This file is an **index only**. Where it and the lock disagree, the lock wins. It invents nothing and
restates nothing that the lock already fixes; the implementation readings that were necessary are
named in `SKILL.md` §9 (live assignment, gateway-unknown cap, approve/consume split, `ev:`/`next:`
adjacency, `fingerprint_input`, notify never writing the snapshot, secret handling).

## Public contract index

**Invariants.** No new adapter · no Hermes-core change · skill/command/relay edge only · delivery
rides existing egress · disk is the truth · queued is not executed · read-back outranks self-report ·
consequential actions are never inferred · refusals are uniform and non-leaking · one fact, one home ·
bare verbs are Protean and `/` verbs stay native · nothing pings unless it is P0.

**Verbs** (bare, first token, case-insensitive, one per message, ≤ 400 chars):
`status | steer <lane> <note> | approve <item> [once] | deny <item> [reason] |
hold [lane] [reason] | release <hold_id> | morning-report [now] | help`.
`command_id = sha256(platform|chat_id|user_id|verb|args|window)`; `approve`/`deny` are
single-consumption on the `approval_id`, not windowed. Stable error codes: `E_NO_LANE`,
`E_AMBIGUOUS_LANE`, `E_LANE_NOT_LIVE`, `E_UNKNOWN_ITEM`, `E_EXPIRED_APPROVAL`, `E_ALREADY_CONSUMED`,
`E_BINDING_STALE`, `E_HOLD_ACTIVE`, `E_UNKNOWN_HOLD`, `E_REPORT_UNAVAILABLE`. Unknown verbs are chat;
`E_UNKNOWN_VERB` does not exist.

**Envelope.** `[sigil] subject(≤72)` / ≤8 fact lines, ≤480 chars / `ev:` 1–3 absolute pointers /
final `next:`. Sigils `[P0] [P1] [err] [approve]`. Plain text only. Approval requests carry item id,
kind, short fingerprint, expiry and the exact reply word. A message missing line 1, `ev:` or a final
`next:` is rejected by a gate that exits non-zero.

**Approvals.** `pending → approved → consumed` one way, side states `denied`, `expired`, `voided`.
Consequential classes: merge, delete, transfer, deploy, external-write, spend, credential. The target
fingerprint binds: merge → repo + base + full head sha; delete → sorted absolute paths + sha256 of
each; transfer → source + destination identity; deploy/external-write → destination + artifact
sha256. Executes only while the live fingerprint still matches; on mismatch the row is `voided` and a
fresh request is issued. A merge approval also dies when the head moves. `nonce` is 12 chars and
never reused; a consumed row is never re-consumed; an `approved` row past `expires_at` is `expired`.
An open hold returns `E_HOLD_ACTIVE` for every consequential `approve` on its lane.

**Auth.** Allowlist env ∪ pairing store; authority is the paired-DM triple `(platform, chat_id,
user_id)`; groups never execute and get read-only verbs only from an explicit
`handoff.groups.<platform>` grant; config/`.env` changes only (no code, no adapter). Unauthorized
senders are dropped silently with one owner notice naming only the sender id and the fix. Never in a
reply: tokens, secrets, other users' ids, allowlist contents, lane-existence disclosure.

**P0 classes.** Lane completion · red gate verdict · new pending approval · explicit reconnect
failure · hold blocking a consequential action. Everything else waits for the morning report.

**State.** `snapshot.json`, `journal.jsonl`, `approvals.jsonl`, `notify.jsonl`, `cmd-log.jsonl`,
`render/` (plus this implementation's `holds.jsonl` / derived `*.pending|open.json` and the read-only
`authz.json` operator mirror) under one state dir selected by explicit `--state-dir`.

**Build boundary.** This repo implements only the locked §10 file boundary: `SKILL.md`,
`scripts/{handoff_lib,snapshot,render,command,approvals,notify,verify}.py`,
`references/protocol.md`, `install.sh`, `tests/test_handoff.py`. `scripts/handoff_lib.py` is a
private shared-primitives module: it owns no state file and exposes no verb.

**Open / unverified** (do not assert): O1–O6 in the lock §11, and Hazen's U1–U7 (Discord numeric
cap, live approval/pairing round-trips, real sleep/down behaviour, partial-chunk duplicate
semantics, `timeout` position mapping).
