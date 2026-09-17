#!/bin/sh
# Protean Handoff — fresh-install script.
#
# Copies ONLY the skill payload (SKILL.md, scripts/*.py, references/*.md) into a
# team-skills root. It never edits the Hermes core tree, the gateway tree, a platform
# adapter, a slash-command manifest, or any operator configuration file: it reads at
# most the HERMES_HOME environment variable to derive a default destination.
#
# Usage:
#   sh install.sh [--destination DIR] [--hermes-home DIR] [--dry-run] [--force]
#
# Exit codes: 0 installed (or a clean dry run), 1 refused/usage, 2 post-install check failed.

set -eu

SRC=$(cd "$(dirname "$0")" && pwd -P)
HERMES_ROOT=${HERMES_HOME:-$HOME/.hermes}
DEST=""
DRY_RUN=0
FORCE=0

usage() {
  cat <<'USAGE'
Protean Handoff installer

  --destination DIR   install root (absolute). Default:
                      $HERMES_HOME/team-skills/orchestration/protean-handoff
  --hermes-home DIR   hermes home used to derive the default destination
  --dry-run           print the plan and the file hashes; change nothing
  --force             allow writing into a non-empty destination without SKILL.md
  -h, --help          this text

The state directory is NOT created here. Point the scripts at one explicitly:

  python3 <dest>/scripts/snapshot.py --state-dir "$HERMES_HOME/team-skills/ops/handoff" --build
USAGE
}

refuse() {
  echo "install.sh: refused: $1" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --destination|--dest) [ $# -ge 2 ] || refuse "--destination needs a value"; DEST=$2; shift 2 ;;
    --hermes-home) [ $# -ge 2 ] || refuse "--hermes-home needs a value"; HERMES_ROOT=$2; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) refuse "unknown argument: $1" ;;
  esac
done

case "$HERMES_ROOT" in
  /*) ;;
  *) refuse "--hermes-home must be an absolute path (got: $HERMES_ROOT)" ;;
esac
[ -n "$DEST" ] || DEST="$HERMES_ROOT/team-skills/orchestration/protean-handoff"

case "$DEST" in
  /*) ;;
  *) refuse "--destination must be an absolute path (got: $DEST)" ;;
esac
case "$DEST" in
  *..*) refuse "destination must not contain '..'" ;;
esac
case "$DEST" in
  /) refuse "destination must not be the filesystem root" ;;
esac
case "$DEST" in
  "$HERMES_ROOT"/team-skills/*) ;;
  *) refuse "destination must live under $HERMES_ROOT/team-skills/" ;;
esac
case "$DEST" in
  *hermes-agent*|*/plugins/*|*/gateway/*|*team-skills/ops*) \
    refuse "destination must not point at the core tree, a plugin dir or the ops state dir" ;;
esac
[ "$DEST" = "$SRC" ] && refuse "destination is the source repository itself"
[ -L "$DEST" ] && refuse "destination is a symlink"
[ -e "$DEST" ] && [ ! -d "$DEST" ] && refuse "destination exists and is not a directory"

PAYLOAD_FILES="SKILL.md"
for f in "$SRC"/scripts/*.py; do [ -e "$f" ] && PAYLOAD_FILES="$PAYLOAD_FILES $f"; done
for f in "$SRC"/references/*.md; do [ -e "$f" ] && PAYLOAD_FILES="$PAYLOAD_FILES $f"; done

for f in $PAYLOAD_FILES; do
  [ -f "$f" ] || refuse "payload file missing: $f"
done

hash_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else echo "(no sha256 tool)"; fi
}

echo "protean-handoff installer"
echo "  source:      $SRC"
echo "  destination: $DEST"
echo "  hermes home: $HERMES_ROOT"
echo "  payload:     $(echo $PAYLOAD_FILES | wc -w | tr -d ' ') file(s)"

if [ -d "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null || true)" ] && [ ! -f "$DEST/SKILL.md" ]; then
  [ "$FORCE" -eq 1 ] || refuse "destination is non-empty and holds no SKILL.md (pass --force to overwrite)"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry run — no change made. Would write:"
  for f in $PAYLOAD_FILES; do
    rel=${f#"$SRC"/}
    echo "  $DEST/$rel  sha256=$(hash_of "$f")"
  done
  echo "state dir (not created): $HERMES_ROOT/team-skills/ops/handoff"
  exit 0
fi

mkdir -p "$DEST/scripts" "$DEST/references"
INSTALLED=0
for f in $PAYLOAD_FILES; do
  rel=${f#"$SRC"/}
  mkdir -p "$DEST/$(dirname "$rel")"
  cp "$f" "$DEST/$rel"
  chmod 644 "$DEST/$rel"
  echo "  wrote $DEST/$rel  sha256=$(hash_of "$DEST/$rel")"
  INSTALLED=$((INSTALLED + 1))
done

echo "installed $INSTALLED file(s); no core, gateway, adapter or operator file was read or written"

if command -v python3 >/dev/null 2>&1; then
  if python3 "$DEST/scripts/verify.py" --payload-only --root "$DEST" >/dev/null 2>&1; then
    echo "post-install payload check: ok"
  else
    echo "post-install payload check FAILED — inspect with:" >&2
    echo "  python3 $DEST/scripts/verify.py --payload-only --root $DEST" >&2
    exit 2
  fi
else
  echo "python3 not found: skipped the post-install payload check" >&2
fi

cat <<NEXT

next steps (operator actions, all outside this installer):
  1. allowlist or pair the phone identity (*_ALLOWED_USERS or 'hermes pairing approve')
  2. bind the operator home channel and confirm with /whoami
  3. write $HERMES_ROOT/team-skills/ops/handoff/authz.json (allowlists, home_channels, optional
     groups mirroring handoff.groups.<platform>, optional morning_report.at)
  4. if phone approvals are promised, ensure approvals.mode is smart or manual
  5. schedule the digest cron job with an explicit delivery target (never bare 'origin')
NEXT
exit 0
