---
name: protean-handoff
description: Use when a phone must inspect, steer, or approve Protean lane work while away from the laptop. Snapshots lanes to disk, parses bare phone verbs deterministically, gates consequential approvals on a bound fingerprint, and renders P0-only messages for the existing Orda gateway egress.
version: 1.0.0
---

# Protean Handoff (phone orchestration at the skill edge)

Walk-away operation for a Protean run: the operator leaves the laptop, reads lane state on a
phone, steers a live lane, and approves consequential actions — without a new adapter, transport,
socket, daemon, Hermes-core edit, or gateway config edit.

Normative contract: `references/protocol.md`, which points at the locked architecture artifact
(`leo-protocol.md`, STATUS: LOCKED — schema, verbs, invariants, envelope, approval binding, P0
classes). This file adds procedure and command examples only; where an implementation reading of
the lock was needed it is named in §9 rather than left silent.

## 1. What rides on what

| Need | Existing machinery reused | This skill adds |
|---|---|---|
| Inbound phone command | Orda session turn on the WhatsApp/Discord route (`gateway.profile_routes`) | a deterministic parser (`scripts/command.py`) — the agent is transport, the parser decides |
| Outbound message | the `send_message` tool with an attested `platform:chat_id` target; cron `deliver:` to a home channel | rendering + the envelope gate (`scripts/render.py`) |
| Identity / authority | per-platform `*_ALLOWED_USERS`, the pairing store, the home channel | evaluation of the rules (fail closed) |
| Scheduled digest | an existing cron job | the digest body (`morning-report`) |
| State | disk under one state dir | journal, snapshot, approvals, holds, notify, cmd-log |

Never: a new adapter/connector/socket/daemon, an edit under `hermes-agent/**` (incl. `gateway/**`,
`plugins/platforms/**`, the slash-command manifest), a hand-edited `config.yaml`, or a new native
slash command. Bare verbs are Protean; `/`-prefixed input is passed to the native surface untouched.

## 2. Install

```
sh install.sh --dry-run                       # print the plan, change nothing
sh install.sh                                 # default: $HERMES_HOME/team-skills/orchestration/protean-handoff
sh install.sh --destination /path/to/team-skills/orchestration/protean-handoff
```

`install.sh` copies only the payload (SKILL.md, `scripts/*.py`, `references/*.md`) into a
`team-skills/` root, refuses unsafe destinations, prints the sha256 of every file it wrote, and
never touches gateway/core/config. The default root comes from `HERMES_HOME` (fallback
`$HOME/.hermes`).

Operator steps, run by a human (this skill documents them, it does not perform them):

1. Allowlist or pair the phone identity — `WHATSAPP_ALLOWED_USERS` / `DISCORD_ALLOWED_USERS`, or
   `hermes pairing approve <platform> <code>`.
2. Bind the home channel (`/sethome` in the operator DM, or the `home_channel` config value).
3. Write the authz mirror this skill reads (`<state>/authz.json`), holding only what the *operator*
   configured: `allowlists`, `home_channels`, optional `pairing_store`, optional `groups`
   (mirroring `handoff.groups.<platform>`), optional `morning_report.at`.
4. If phone approvals are promised, ensure approvals are enforced (`approvals.mode: smart|manual`)
   — with `off`, a phone `approve` does not gate a native tool path.
5. Schedule the digest with an explicit delivery target (never bare `origin`).

## 3. State (single canonical homes)

All state lives under one explicit `--state-dir` (never a hardcoded home; `PROTEAN_HANDOFF_STATE_DIR`
is the fallback). The installed skill's convention is `$HERMES_HOME/team-skills/ops/handoff`.

| file | role |
|---|---|
| `journal.jsonl` | append-only truth; the snapshot is replayable from it |
| `snapshot.json` | materialized lanes (atomically rewritten); derived fields recomputed, never trusted |
| `approvals.jsonl` | append-only approval ledger (monotonic `seq`) |
| `approvals.pending.json` | derived open rows |
| `holds.jsonl` / `holds.open.json` | append-only hold rows and the derived open set |
| `notify.jsonl` | notification records: dedup keys, batching, delivery outcomes (last 500 read) |
| `cmd-log.jsonl` | one row per command: actor triple, verb, args hash, `command_id`, outcome, evidence |
| `authz.json` | read-only operator mirror of allowlists / home channels / group grants |
| `render/` | rendered messages kept for verification; a render is never truth |

Writes are atomic (tmp + `os.replace` + fsync) with `0600` files inside a `0700` dir; ledgers are
append-only.

## 4. Daily procedure

```
# record a lane event, then materialize (every write appends a journal row first)
python3 scripts/snapshot.py --state-dir "$S" --event lane.dispatch --lane p-demo-mozi \
  --set '{"project":"demo","role":"mozi","stage":"build","worker":{"pid":1234,"session_id":"sess"}}'
python3 scripts/snapshot.py --state-dir "$S" --gateway-state "$GATEWAY_STATE" --build

python3 scripts/snapshot.py --state-dir "$S" --verify          # exit 0 = invariants hold
python3 scripts/render.py   --status --state-dir "$S"          # status reply
python3 scripts/render.py   --status --state-dir "$S" --lane p-demo-mozi
python3 scripts/render.py   --check message.txt                # exit 1 = envelope violation
python3 scripts/verify.py   --state-dir "$S" --root <skill>    # the full gate
```

Pass `--gateway-state <file>` (or export `PROTEAN_HANDOFF_GATEWAY_STATE`) on every build: without a
fresh gateway state file every lane's health caps at `unknown`, and execution verbs refuse.

Commands arrive as ordinary session text and are resolved through the parser:

```
python3 scripts/command.py --state-dir "$S" --platform whatsapp \
  --chat-id 275462072881175@lid --user-id 15550000001 --text "status p-demo-mozi"
python3 scripts/command.py --state-dir "$S" ... --text "steer p-demo-mozi tighten the tests"
python3 scripts/command.py --state-dir "$S" ... --text "approve a-23f6b5db"
python3 scripts/command.py --state-dir "$S" ... --text "deny a-23f6b5db too risky"
python3 scripts/command.py --state-dir "$S" ... --text "hold p-demo-mozi freeze merges"
python3 scripts/command.py --state-dir "$S" ... --text "release h-24ed2069"
python3 scripts/command.py --state-dir "$S" ... --text "morning-report"
python3 scripts/command.py --state-dir "$S" ... --text "help"
```

Every accepted action returns machine-readable JSON with `evidence` paths and an explicit `next`.
`wire_reply` is the message to send; a silent drop returns `wire_reply: null`.

Approvals (the lane asks, the operator decides, the lane reports the read-back):

```
python3 scripts/approvals.py --state-dir "$S" request --kind merge --lane p-demo-mozi \
  --requested-by p-demo-mozi --actor-user-id 15550000001 --platform whatsapp \
  --chat-id 275462072881175@lid --spec '{"repo":"<repo>","base":"main","head_sha":"<full sha>"}'
python3 scripts/approvals.py --state-dir "$S" approve --item a-23f6b5db --platform whatsapp \
  --chat-id 275462072881175@lid --user-id 15550000001
python3 scripts/approvals.py --state-dir "$S" consume --item a-23f6b5db \
  --observed-spec '{"repo":"<repo>","base":"main","head_sha":"<full sha>"}' \
  --receipt-path /abs/receipt.md
```

Notifications (P0 only pings; delivery uses the existing egress):

```
python3 scripts/notify.py --state-dir "$S" filter --class gate_red
python3 scripts/notify.py --state-dir "$S" emit --class lane_completion --entity-id p-demo-mozi \
  --artifact-sha256 <sha> --fact "lane done" --ev /abs/receipt.md
python3 scripts/notify.py --state-dir "$S" delivery --dedup-key <key> --result failed
```

The `send_spec` in the emit result is a *request*: Orda performs the send with the existing
`send_message` tool against the attested target. The skill never opens a transport.

## 5. Verb contract (lock §2)

| verb | syntax | effect | errors |
|---|---|---|---|
| `status` | `status` \| `status <lane>` \| `status all` | read-only render; changes nothing | `E_NO_LANE`, `E_AMBIGUOUS_LANE` |
| `steer` | `steer <lane> <text...>` | queues a note into the lane's live session; never an interrupt, never a new session | `E_NO_LANE`, `E_AMBIGUOUS_LANE`, `E_LANE_NOT_LIVE` |
| `approve` | `approve <item>` \| `approve <item> once` | consumes one pending approval; executes only on a matching fingerprint | `E_UNKNOWN_ITEM`, `E_EXPIRED_APPROVAL`, `E_ALREADY_CONSUMED`, `E_BINDING_STALE`, `E_HOLD_ACTIVE` |
| `deny` | `deny <item> [reason...]` | closes the row as denied; the reason is data for the lane | as above |
| `hold` | `hold` \| `hold <lane> [reason...]` | writes a hold row; blocks consequential actions (bare = project) | `E_NO_LANE`, `E_ALREADY_HELD` |
| `release` | `release <hold_id>` | closes a hold row | `E_UNKNOWN_HOLD` |
| `morning-report` | `morning-report` \| `morning-report now` | renders the day's digest; states its own lateness | `E_REPORT_UNAVAILABLE` |
| `help` | `help` | verb list with one example each | — |

Bare verb, first token, case-insensitive, one command per message, ≤ 400 chars. Unknown verbs are
chat — never an error banner. Trailing tokens after a complete command are ignored and echoed back
for confirmation. A repeat inside its window returns the original `command_id` with
`"duplicate": true` and injects nothing.

## 6. Message envelope (lock §7)

```
[<sigil>] <subject <= 72 chars>
<fact lines: <= 8 lines, <= 480 chars total, one fact per line>
ev: <absolute path or URL>[ , <path>]        (1-3 pointers, never prose)
next: <one explicit action>                  (always the last line)
```

Sigils: `[P0]`, `[P1]`, `[err]`, `[approve]`. Plain text only: no markdown, no tables, no stack
traces. Approval requests additionally carry item id, kind, short fingerprint, expiry and the exact
reply word. A message over 1000 chars, without `ev:`, without a final `next:`, or containing a
secret-like value is rejected (`render.py --check` exits non-zero) — a validator gate, not a
convention.

Example status reply:

```
[P1] p-demo-mozi build
lane p-demo-mozi stage build role mozi
health live - heartbeat 12s ago and pid 1234 alive
gate green unit
pending: none
holds: none
ev: /state/snapshot.json
next: status p-demo-mozi
```

## 7. P0 routing and quiet hours (lock §3)

Only these ping: lane completion, a red gate verdict, a new pending approval needing a decision, an
explicit reconnect failure, and a hold blocking an attempted consequential action. Everything else
(progress, heartbeats, amber gates, queued steers, duplicate repeats, renders, reads, snapshot
refreshes, skill loads) waits for the morning report — and an unrecognised class is P1 by default,
because nothing pings unless it is P0. A ping goes to exactly one channel (primary WhatsApp home
channel, Discord only as failover after the primary fails; never fan-out). Identical events dedup:
15-minute-bucketed for state-shaped events, permanent for identity-shaped ones (an `approval_id`, a
`hold_id`, an artifact `sha256`). P0 rows inside a 60-second window merge into one message, max 10
rows, one `next:`. After three failed deliveries the row is `delivery unverified` and escalates as a
P0 itself — a dropped P0 is never silent.

The one exception to "P0 only": the unauthorized-sender owner notice, sent once per
`(platform, user_id)` per gateway process.

## 8. Refusals and authority (lock §5)

Authority is the triple `(platform, chat_id, user_id)` of the operator's paired DM. An allowlisted
user in a group — or in any non-home chat — cannot execute anything: `approve`, `deny`, `hold`,
`release` and `steer` are refused, silently on the wire for a group. Read-only verbs (`status`,
`help`, `morning-report`) are granted in a group only by an explicit operator-written
`handoff.groups.<platform>` entry. An unauthorized sender is dropped silently (a reply would reveal
the bot), with one owner-side notice naming only the sender id and the fix, and the dropped text is
never echoed. An authorized user asking about an unknown or forbidden item gets the uniform refusal
`<item> declined: not an approved action for this connection` — no reason, no existence disclosure.
Missing identity, missing authz source, or a missing fingerprint binding fails closed.

## 9. Named implementation readings (no silent divergence)

* `live` assignment — the §1 ladder yields `quiet` / `laptop-asleep` / `stale` / `gateway-down` /
  `unknown`; `live` is assigned only when the heartbeat is ≤ 120 s old **and** the pid is alive
  **and** the gateway is not down. Nothing else yields `live`.
* Gateway evidence — no gateway state file, an unreadable one, or a status other than `running`
  yields `unknown`/`down`, never `up`; every lane's health then caps at `unknown`.
* Approve/consume split — §4's `pending → approved → consumed` is implemented as `approve` (the
  operator grant, which may also check a supplied live fingerprint) and `consume` (the executing
  lane's read-back, the only transition that may write an execution record, impossible without an
  observed fingerprint). A second decision on a consumed row returns the original execution receipt
  with `"duplicate": true` and executes nothing.
* Envelope adjacency — `ev:` must be the line immediately before the final `next:` (a validator
  needs a fixed position to reject a message whose `next:` is buried mid-body).
* `fingerprint_input` — the ledger stores the canonical binding input whose sha256 *is*
  `target_fingerprint`; the lock names the hash, not the field, and it is required to re-verify the
  binding at execution time. No other schema field is added.
* `notify.py` never writes `snapshot.json` — connectivity is derived at read time, so a delivery
  failure is recorded in `notify.jsonl` and escalated, and surfaces through the next derivation.
* Secret-like values are redacted before a snapshot is written; if one is found inside a message,
  the message is rejected rather than silently rewritten.

## 10. Recovery

1. Silence everywhere? Check the laptop is awake and plugged in, then `hermes gateway status` and the
   `gateway.log` tail. Lid-close sleep stops everything.
2. Duplicate delivery? Treat the delivery ledger's recovered-reply prefix as authoritative and do not
   re-approve; approvals are single-consumption anyway, so a replay executes nothing.
3. Snapshot older than 15 minutes renders with an explicit `snapshot age: <n> min` marker, and a
   consequential verb requires a fresh `status` first.
4. After a gap longer than 15 minutes: recompute every lane's health (rebuild the snapshot), treat
   artifacts newer than the last heartbeat as suspect, and void any approval whose fingerprint
   involves a suspect artifact; issue a fresh request instead of reopening a voided row.
5. Reconnect never releases a hold, never auto-approves a pending row, and never resurrects a
   crashed lane's pid.

## 11. Verification

```
python3 scripts/snapshot.py --state-dir "$S" --verify      # schema, (D) recomputation, replay hash
python3 scripts/render.py   --check message.txt            # envelope gate, exit 1 on violation
python3 scripts/verify.py   --state-dir "$S" --root <skill>  # all gates; non-zero on violations
python3 tests/test_handoff.py                              # behaviour + security acceptance tests
```

Gates: payload (files present, byte-compilable, no hardcoded home), snapshot (schema, derived fields
re-derived not trusted, journal replay, artifact hashes), envelope (every rendered message and every
logged wire reply), approvals (monotone seq, one-way lifecycle, single consumption, read-back
execution), holds (open/release lifecycle), dedup (key integrity, no permanent key sent twice),
journal (monotone seq), secrets (nothing secret-like anywhere in the state dir or payload).

## 12. Unverified / open

Inherited and unchanged: O1 `@session` link syntax; O2 Discord per-guild/thread deny behaviour; O3
WhatsApp group ingress is assumed DENY by policy; O4 cron catch-up after a long sleep; O5 which
path serves Discord for profile `orda`; O6 operator ids are deliberately not enumerated. Hazen's
UNVERIFIED limits (Discord numeric cap, live prompt/pairing round-trips, real sleep/down behaviour,
partial-chunk duplicates, `timeout` position mapping) are not asserted anywhere in this skill.
Operator ids in this document are the home-channel ids observed in config; no user id is invented.
