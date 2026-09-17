# Protean Handoff

Phone orchestration at the skill edge: walk away from the laptop and still
inspect, steer, and approve Protean lane work from a phone — over the
existing WhatsApp/Discord gateway, with no new adapter and no core change.

Normative contract: `references/protocol.md` (points at the locked
architecture). Procedure and daily use: `SKILL.md` (this README's companion
for the serving machine). Where this README and those files disagree, the
locked protocol wins.

Status note: the bare-verb phone commands below describe specified behavior
of this ingredient. The existing slash-command surface (leading `/`) is the
supported surface on any machine where this ingredient is not deployed and
audited. Do not rely on phone approvals or phone steering until the
ingredient is installed, configured, and independently verified on the
serving machine.

## What it does

- Lets the operator leave the laptop and read lane state on a phone, steer
  a live lane, and approve or deny consequential actions.
- Keeps one disk-backed snapshot per lane plus an append-only journal the
  snapshot can be replayed from, so state survives sleep and can be re-read
  without a live worker.
- Parses bare phone verbs deterministically (`status`, `steer`, `approve`,
  `deny`, `hold`, `release`, `morning-report`, `help`) through the handoff
  skill. The agent session is transport; the parser decides.
- Gates every consequential action behind an explicit phone approval bound
  to an exact target fingerprint, re-checked at execution time.
- Sends phone-visible messages in one strict envelope (class sigil, short
  facts, `ev:` evidence pointer, final `next:` action) and pings the phone
  only for P0 events. Everything else waits for the morning report.
- Records every command with an idempotency key so repeats inside the
  window return the original receipt marked duplicate instead of
  executing twice.

## What it does not do

- It adds no new app, adapter, transport, socket, or daemon. There is
  nothing new to install on the phone; the operator messages the same
  paired operator chat as before.
- It adds no new native slash command and edits no Hermes core, gateway,
  adapter, or slash-command manifest.
- It does not execute queued work on its own. An accepted `steer` is a
  queued receipt, never proof the model ran it. A sent notification is
  never proof the phone received it.
- It never approves anything by itself. Pending approvals stay pending
  across sleep and expire only by their own expiry time.
- It never guesses. Health states include `unknown`, `stale`, and
  `laptop-asleep` as first-class answers, and a snapshot older than
  15 minutes says its age on the card.
- It never handles credentials inside chat and never discloses lane
  existence, allowlist contents, other user ids, or secrets in any reply.

## Use-alone installation

Use-alone (operator on the phone, no install step):

- The ingredient lives at the skill/command edge on the serving machine,
  not on the phone. If it is deployed there, the operator just messages
  the paired operator DM.
- Confirm with the installer that the skill is deployed, the morning
  report is scheduled, and approvals are enforced before relying on
  phone approvals.

Install (the installer runs these on the serving machine):

```sh
sh install.sh --dry-run        # print the plan and file hashes; change nothing
sh install.sh                  # default destination under the Hermes home
sh install.sh --destination /absolute/path/to/team-skills/orchestration/protean-handoff
```

- `--destination` takes an absolute path and must live under the
  `team-skills/` tree. Unsafe destinations (the core tree, plugin or
  gateway dirs, the ops state dir, the filesystem root, the source repo
  itself) are refused. `--hermes-home` overrides the Hermes home used to
  derive the default destination; `--force` allows writing into a
  non-empty destination without a `SKILL.md`.
- The payload installer copies only the payload (`SKILL.md`,
  `scripts/*.py`, `references/*.md`), prints the sha256 of every file it
  wrote, and runs a post-install payload check.
- The payload installer does not install state and does not touch core,
  gateway, adapters, or operator config. The state directory is never
  created by the installer; point the scripts at one explicitly with
  `--state-dir` (convention: `$HERMES_HOME/team-skills/ops/handoff`).
  Never hand-edit `config.yaml`; use the `hermes config set` tooling.

## Setup

Operator checklist for a fresh install (each step runs on the serving
machine or in the paired chat; the ingredient only documents them):

1. Pair the bot numbers and confirm both surfaces show connected in the
   gateway status.
2. Bind the home chat (`/sethome` in the chosen DM), then confirm with
   `/whoami`. Proactive sends land in that chat.
3. Authorize the phone identity via the per-platform allowlist entries or
   the pairing-code flow. Values are operator-supplied and are never
   pasted into chat. Strangers get no reply at all.
4. Pin single-home routing: keep multiplex on for the default profile,
   define exactly one route entry per ingress, and read the gateway log
   tail. A route warning names a real drift to fix.
5. Schedule the morning brief with an explicit delivery target (confirm
   the exact cron flag spelling against the cron help at install time).
   A brief missed while the laptop slept arrives late and states its own
   lateness.
6. Enforce approvals BEFORE promising phone approvals. The observed live
   default approvals mode at audit time was `off`; with mode `off`, phone
   `approve` copy is dishonest. Set approvals to an enforcing mode
   (`smart` or `manual`) if phone approve/deny is promised.

## Commands

Rules first:

- Bare verbs (no leading slash) are Protean handoff commands, resolved by
  the handoff skill through the operator session. Leading-slash verbs
  (`/status`, `/steer`, `/approve`, ...) are native Hermes commands and
  are NOT handoff commands. The two namespaces never overlap.
- Exactly one command per message. The command must be the first token.
  Case does not matter. Messages are short (a few hundred characters).
- Unknown bare verbs are treated as ordinary chat, never as an error
  banner. `/`-prefixed input is passed to the native surface untouched.
- Every reply follows the envelope: first line class plus subject, short
  fact lines, an `ev:` evidence pointer, and a final `next:` line. A reply
  with no `ev:` or no final `next:` is a defect; re-ask with `status`.

| Verb | Syntax | Effect |
|---|---|---|
| `status` | `status`, `status <lane>`, `status all` | Read-only lane render. Starts nothing, changes nothing. |
| `steer` | `steer <lane> <text...>` | Queues a note into the live lane's session. No interrupt, no new session. Accepted means queued, never executed. |
| `approve` | `approve <item>`, `approve <item> once` | Consumes one pending approval. Single consumption; replays return the original receipt and execute nothing. Executes only if the target fingerprint still matches. |
| `deny` | `deny <item> [reason...]` | Closes the approval as denied; the reason is relayed to the requesting lane. |
| `hold` | `hold`, `hold <lane> [reason...]` | Blocks every consequential action on that lane until released. Bare `hold` means project-wide. |
| `release` | `release <hold_id>` | Closes a hold row; consequential actions unblock. |
| `morning-report` | `morning-report`, `morning-report now` | The day's digest: unresolved P0 first, then lane changes, with snapshot age stated. Late, never lost. |
| `help` | `help` | Verb list with one example each. |

Examples (placeholder ids; substitute the real lane, item, and hold ids
from a `status` card):

```text
status
status <lane>
steer <lane> hold the deploy until I confirm the changelog
approve <item> once
deny <item> too risky
hold <lane> waiting on design sign-off
release <hold_id>
morning-report
help
```

Error shapes:

- Unknown or ambiguous lane: an error card naming the candidate lanes
  plus `next: status all`.
- Lane not live: an error card plus `next: status <lane>`. Do not approve
  against it.
- Stale binding (target moved since approval was requested): the approval
  is voided and a fresh request is issued. Re-approve only the fresh item.
- Hold active: a refusal naming the hold id plus the release command.
- Snapshot older than 15 minutes: the card says its age; consequential
  verbs require a fresh `status` first.
- Possible duplicate redelivery after a restart: the message says it may
  be a duplicate. Confirm before acting; do not re-approve.

## Safety

- Consequential means gated, always: merge, delete, transfer, deploy,
  external write, spend, credential use or rotation. Reads, renders,
  listings, tests, and reversible local work on a non-protected branch
  never need approval.
- Approve consumes exactly one pending item. A second approve of the same
  item returns the original receipt marked duplicate and executes nothing.
- The approval executes only if the live target fingerprint still matches
  the requested fingerprint (exact head sha for merges; path hashes for
  deletes; destination plus artifact hash for deploys and external
  writes). On mismatch the item is voided and re-requested; approve only
  the fresh item.
- The deciding identity must be the paired-DM triple (platform, chat,
  user) the approval was requested from. A different user is refused.
  Display names and message text never authenticate.
- Holds beat approvals: while a lane holds an open hold, every
  consequential approve for that lane is refused until `release <hold_id>`.
- After execution the layer records a read-back (observed fingerprint,
  receipt path, verified or unverified delivery). Verified requires the
  read-back.
- Groups can never approve, deny, hold, or release, even for allowlisted
  members. Group execution attempts are silently dropped; the owner gets
  a minimal notice. Groups may receive read-only verbs only by an
  explicit operator grant.
- Unauthorized senders get a silent drop on the wire (a reply would leak
  that the bot exists) plus a minimal owner-side notice. Refusals are
  uniform and disclose nothing about lane existence or allowlist contents.
- Nothing pings the phone unless it is P0: lane completion, a red gate
  verdict, a new pending approval, an explicit reconnect failure, or a
  hold blocking an attempted consequential action. Everything else waits
  for the morning report.
- Approval precondition, repeated because it matters: none of the above
  gates anything while approvals mode is `off`. Enforce `smart` or
  `manual` first.

## Recovery

In this order:

1. Wake and power first. Is the laptop awake and plugged in? Lid-close
   sleep stops local workers and gateway activity. The keep-awake
   mechanism (`caffeinate` on macOS) cannot defeat lid-close sleep. Open
   the lid, plug in power, and wait for the machine to wake before
   anything else. Sleep is recoverable by waiting; a crash is not.
2. Gateway status and log tail. Check the gateway status, then read the
   last ~20 lines of the gateway log. A shutdown sequence with a persisted
   running state means the supervisor will revive it.
3. Route warnings. A route naming a profile the multiplexer does not
   serve is the health signal for route drift, not background noise. Fix
   drift at the owning profile config.
4. Session weirdness (cross-chat confusion, missing routing identity):
   run the session routing repair dry run first and apply second, with
   the gateway stopped during repair.
5. Re-pair LAST, never first. Only if the session dir shows a logged-out
   or broken bridge, and only after checking the session directory is
   writable and persistent. Re-pairing first destroys evidence for every
   step above.
6. After any gap over ~15 minutes: recompute health for every lane, mark
   changed artifacts suspect, take a fresh `status` before any approve,
   and void approvals touching suspect artifacts. Sleep vs crash after
   reconnect is re-derived, never assumed; `unknown` is an acceptable
   answer and guessing `live` is not.

Quick table: silence everywhere means wake/plug, then status plus log
tail. Bot ignores you means check allowlist/pairing, mention settings,
and the platform enabled flag (an explicit disable beats credentials).
A message that may be a duplicate after restart means confirm before
acting. Gateway down means lanes cap at `unknown` and a reconnect-failure
notice is itself a P0.

## Testing

The repo ships a stdlib-only acceptance suite that drives the public
script interfaces against temporary state directories. It touches no live
gateway state and no Hermes home:

```sh
python3 tests/test_handoff.py
python3 -m unittest discover -s tests
```

Targeted gates used during development:

```sh
sh install.sh --dry-run --hermes-home /tmp/example-hermes-home
python3 scripts/snapshot.py --state-dir <state> --verify
python3 scripts/render.py --check <message-file>
python3 scripts/verify.py --state-dir <state> --root <installed-skill-root>
```

A second `approve` of the same item must execute nothing; an envelope
with no `ev:` line must be rejected; a replayed journal must reproduce
the same snapshot hash.

## Files and further reading

- `SKILL.md` — procedure for the serving machine: install, state layout,
  daily commands, and the disclosed implementation readings.
- `references/protocol.md` — index of the normative protocol: invariants,
  verbs, envelope, approval binding, P0 classes, auth, state, and the
  open/unverified items.
- `scripts/` — the skill edge: snapshot, render, command parser,
  approvals and holds, notify, verify, plus a private shared-primitives
  module that owns no state file and exposes no verb.
- `install.sh` — the payload-only installer (`--destination`,
  `--hermes-home`, `--dry-run`, `--force`).
- `tests/test_handoff.py` — the acceptance suite.

## Limits

- No numeric Discord outbound cap is stated here; it is unverified. Keep
  phone-visible messages short (a few lines, one idea) and let the
  adapter chunk.
- No live round trip is promised in this file: approval prompts,
  pairing-code exchange, and sleep/down catch-up were not exercised
  against live bots for this README.
- Handoff-layer verbs are specified behavior, not a claim of a live
  verified deployment. Existing slash commands are the supported surface
  today; bare verbs become trustworthy on a given machine only after
  install, configuration, and independent audit there.
