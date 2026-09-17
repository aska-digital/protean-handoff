"""Protean Handoff — shared stdlib primitives (implementation support module).

This module is NOT a protocol component: it owns no state file and exposes no verb.
It carries the primitives the boundary scripts share:

  * atomic writes with restrictive modes, append-only jsonl helpers
  * iso8601 time helpers, window/bucket keys
  * secret-like value detection and redaction (credentials never leave in output)
  * derived-health primitives (process table, host boot id)
  * state-dir resolution (explicit --state-dir only; no hardcoded ~/.hermes)
  * identity/authz evaluation (locked protocol A1-A4) and the uniform refusal
  * machine-readable result envelopes (JSON with evidence paths + explicit next action)

Protocol authority: references/protocol.md -> the locked leo-protocol.md. Nothing
here may widen the lock; where an implementation reading of the lock is required it
is named in a comment and surfaced in SKILL.md.
"""

import datetime
import errno
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

SCHEMA_VERSION = 1

# --- locked-protocol budgets -------------------------------------------------
MAX_COMMAND_CHARS = 400          # 2.1: message <= 400 chars, single message
STEER_WINDOW_SECONDS = 600       # 2.2 steer idempotency window (10 min)
HOLD_WINDOW_SECONDS = 1800       # 2.2 hold idempotency window (30 min)
MAX_SUBJECT_CHARS = 72           # 7.1
MAX_FACTS_LINES = 8              # 7.2
MAX_BODY_CHARS = 480             # 7.2
MAX_EV_POINTERS = 3              # 7.3
MAX_NEXT_CHARS = 120             # 7.4 (implementation reading: one explicit action)
MAX_MESSAGE_CHARS = 1000         # Hazen 4.1 phone-visible policy cap
SNAPSHOT_STALE_SECONDS = 900     # 1.D: > 15 min -> explicit age marker
HEARTBEAT_QUIET_SECONDS = 900    # 1.D health ladder
HEARTBEAT_STALE_SECONDS = 3600   # 1.D health ladder
LIVE_HEARTBEAT_SECONDS = 120     # 1.D `live` assignment (see SKILL.md)
GATEWAY_FRESH_SECONDS = 900      # 1.D connectivity freshness
DEDUP_BUCKET_SECONDS = 900       # 3: 15-minute aligned window
BATCH_WINDOW_SECONDS = 60        # 3: P0 batching window
DEDUP_KEEP = 500                 # 3: notify.jsonl keeps the last 500 keys
NOTIFY_MAX_RETRIES = 3           # 3: three failures -> unverified + escalate
BATCH_MAX_ROWS = 10              # 3: max 10 rows per batched P0 message
APPROVAL_DEFAULT_TTL_SECONDS = 86400
NONCE_CHARS = 12                 # 4: nonce is 12 chars

SIGILS = ("[P0]", "[P1]", "[err]", "[approve]")
VERBS = ("status", "steer", "approve", "deny", "hold", "release", "morning-report", "help")
READONLY_VERBS = ("status", "help", "morning-report")   # A3: grantable in groups
EXECUTION_VERBS = ("steer", "approve", "deny", "hold", "release")

ROLES = ("orda", "proteus", "hazen", "leo", "frida", "mozi", "shaka")
STAGES = ("research", "analysis", "design", "build", "qa", "integration", "done", "blocked")
GATE_STATES = ("green", "amber", "red", "awaiting-review", "none")
HEALTH_STATES = ("live", "quiet", "stale", "laptop-asleep", "gateway-down", "unknown")
ARTIFACT_KINDS = ("spec", "receipt", "qa", "code", "report", "log", "evidence")
APPROVAL_KINDS = ("merge", "delete", "transfer", "deploy", "external-write", "spend", "credential")
APPROVAL_STATUS = ("pending", "approved", "denied", "consumed", "expired", "voided")

# state files owned by this skill inside the state dir (lock 10)
SNAPSHOT = "snapshot.json"
JOURNAL = "journal.jsonl"
APPROVALS = "approvals.jsonl"
APPROVALS_PENDING = "approvals.pending.json"
HOLDS = "holds.jsonl"
HOLDS_OPEN = "holds.open.json"
NOTIFY = "notify.jsonl"
CMD_LOG = "cmd-log.jsonl"
RENDER_DIR = "render"
AUTHZ = "authz.json"

UNIFORM_REFUSAL = "{item} declined: not an approved action for this connection"

# --- secret-like values (6: never in rendered messages, logs, or JSON output) --
SECRET_PATTERNS = (
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}")),
    ("slack_token", re.compile(r"\bxox[abpsr]-[A-Za-z0-9\-]{10,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer_header", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("secret_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|passwd|password|client[_-]?secret|bot[_-]?token)"
        r"\b\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{12,}")),
    ("phone_number", re.compile(r"(?<![\w.+])[+]\d{9,15}(?![\w])")),
    ("otp_code", re.compile(r"(?i)\b(otp|2fa|verification code)\b[^\n]{0,20}\b\d{6}\b")),
)


class HandoffError(Exception):
    """Fail-closed protocol error. message is safe to render (never leaks)."""

    def __init__(self, code, message, next_action="next: none - informational",
                 evidence=None, **extra):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.next_action = next_action
        self.evidence = list(evidence or [])
        self.extra = extra

    def as_dict(self):
        out = {
            "ok": False,
            "error": self.code,
            "message": self.message,
            "evidence": self.evidence,
            "next": self.next_action,
        }
        out.update(self.extra)
        return out


def require(cond, code, message, next_action="next: none - informational", evidence=None, **extra):
    if not cond:
        raise HandoffError(code, message, next_action, evidence, **extra)


# --- time --------------------------------------------------------------------

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(ts=None):
    ts = ts or utcnow()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=datetime.timezone.utc)
    return ts.astimezone(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value):
    """Tolerant iso8601 parse; returns None instead of raising."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def epoch(value):
    parsed = parse_iso(value) if isinstance(value, str) else value
    if parsed is None:
        return None
    return parsed.timestamp()


def seconds_since(value, now=None):
    ts = epoch(value)
    if ts is None:
        return None
    return int((now or utcnow()).timestamp() - ts)


def window_key(now=None, seconds=STEER_WINDOW_SECONDS):
    return int((now or utcnow()).timestamp() // seconds)


def bucket_key(now=None, seconds=DEDUP_BUCKET_SECONDS):
    return int((now or utcnow()).timestamp() // seconds)


# --- hashing -----------------------------------------------------------------

def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    if not path or not os.path.isfile(path):
        return None
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def state_hash(obj):
    return sha256_text(canonical_json(obj))


def new_id(prefix, seed=None):
    raw = seed if seed is not None else "%s|%s|%s" % (prefix, iso(), os.urandom(8).hex())
    return "%s-%s" % (prefix, sha256_text(str(raw))[:8])


def new_nonce():
    return os.urandom(8).hex()[:NONCE_CHARS]


# --- atomic + append-only file primitives ------------------------------------

def ensure_dir(path, mode=0o700):
    if path and not os.path.isdir(path):
        os.makedirs(path, mode=mode, exist_ok=True)
    if path:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_text(path, text, mode=0o600):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(directory)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".swp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_dir(directory)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def atomic_write_json(path, obj, mode=0o600):
    return atomic_write_text(path, json.dumps(obj, sort_keys=True, indent=2) + "\n", mode=mode)


def append_jsonl(path, obj, mode=0o600):
    """Append-only row. One compact JSON object per line, fsynced."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(directory)
    line = json.dumps(obj, sort_keys=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


def read_jsonl(path, limit=None):
    """Return (rows, malformed_count). Never raises on a missing/short file."""
    rows = []
    malformed = 0
    if not os.path.isfile(path):
        return rows, malformed
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except ValueError:
                    malformed += 1
                    continue
                if isinstance(parsed, dict):
                    rows.append(parsed)
                else:
                    malformed += 1
    except OSError:
        return rows, malformed
    if limit is not None and limit > 0:
        rows = rows[-limit:]
    return rows, malformed


def read_json(path, default=None):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


# --- secrets -----------------------------------------------------------------

def secret_scan(text):
    """Return a list of {label, start, end} for secret-like substrings."""
    if not text:
        return []
    hits = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            hits.append({"label": label, "start": match.start(), "end": match.end()})
    hits.sort(key=lambda h: h["start"])
    return hits


def secret_labels(text):
    return sorted({h["label"] for h in secret_scan(text)})


def redact(text):
    """Replace secret-like substrings; returns (clean_text, labels).

    Overlapping hits merge into one span that carries every label that matched, so a
    value tripping two patterns is still reported under both.
    """
    hits = secret_scan(text)
    if not hits:
        return text, []
    spans = []
    for hit in sorted(hits, key=lambda h: (h["start"], -h["end"])):
        if spans and hit["start"] <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], hit["end"])
            spans[-1][2].add(hit["label"])
        else:
            spans.append([hit["start"], hit["end"], {hit["label"]}])
    labels = sorted({h["label"] for h in hits})
    out = []
    cursor = 0
    for start, end, matched in spans:
        out.append(text[cursor:start])
        out.append("[redacted:%s]" % "+".join(sorted(matched)))
        cursor = end
    out.append(text[cursor:])
    return "".join(out), labels


def redact_deep(value):
    """Redact every string inside a nested JSON-able structure."""
    labels = []

    def walk(node):
        if isinstance(node, str):
            clean, found = redact(node)
            labels.extend(found)
            return clean
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, dict):
            return dict((key, walk(item)) for key, item in node.items())
        return node

    cleaned = walk(value)
    return cleaned, sorted(set(labels))


# --- derived health primitives (1.D) ----------------------------------------

_BOOT_ID_CACHE = {"value": None, "read": False}


def process_alive(pid):
    """True/False from the live process table on this host; None when not reportable."""
    if pid is None or pid == "":
        return None
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return None
    if pid_int <= 0:
        return None
    try:
        os.kill(pid_int, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        if exc.errno == errno.EPERM:
            return True
        return None


def host_boot_id():
    """Same-host boot identity: distinguishes reboot from crash. None when unknown."""
    if _BOOT_ID_CACHE["read"]:
        return _BOOT_ID_CACHE["value"]
    override = os.environ.get("PROTEAN_HANDOFF_BOOT_ID")
    if override:
        _BOOT_ID_CACHE["value"] = override
        _BOOT_ID_CACHE["read"] = True
        return override

    value = None
    linux_path = "/proc/sys/kernel/random/boot_id"
    if os.path.isfile(linux_path):
        text = read_text(linux_path)
        if text:
            value = text.strip()
    if value is None and sys.platform == "darwin":
        try:
            out = subprocess.run(["sysctl", "-n", "kern.boottime"], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=5)
            text = out.stdout.decode("utf-8", "replace").strip()
            match = re.search(r"sec\s*=\s*(\d+)", text)
            if match:
                value = "boot-%s" % match.group(1)
        except (OSError, subprocess.SubprocessError):
            value = None
    _BOOT_ID_CACHE["value"] = value
    _BOOT_ID_CACHE["read"] = True
    return value


def health_state(lane, now=None, gateway=None, clean_release=False, current_boot=None):
    """Health ladder of 1.D, with the single named `live` assignment.

    ladder: heartbeat <= 900 -> quiet; > 900 with pid alive -> quiet;
    > 3600 with pid absent, boot id unchanged, no clean release -> laptop-asleep;
    > 3600, pid absent, boot id changed -> stale; gateway unreachable -> unknown cap.
    `live` (implementation reading, see SKILL.md): heartbeat <= 120s and pid alive
    and gateway not down. Nothing else ever yields `live`.
    """
    now = now or utcnow()
    worker = lane.get("worker") or {}
    health = lane.get("health") or {}
    age = seconds_since(health.get("last_heartbeat_ts"), now)
    boot = worker.get("host_boot_id")
    if current_boot is None:
        current_boot = host_boot_id()
    alive = process_alive(worker.get("pid"))

    if gateway and gateway.get("gateway") == "down":
        return "gateway-down", "gateway unreachable at %s" % gateway.get("gateway_checked_at")
    if gateway and gateway.get("gateway") == "unknown":
        return "unknown", "gateway state unverified (no fresh gateway state evidence)"
    if age is None:
        return "unknown", "no heartbeat timestamp on record"
    if age <= LIVE_HEARTBEAT_SECONDS and alive:
        return "live", "heartbeat %ss ago and pid %s alive" % (age, worker.get("pid"))
    if age <= HEARTBEAT_QUIET_SECONDS:
        return "quiet", "heartbeat %ss ago (<= %ss)" % (age, HEARTBEAT_QUIET_SECONDS)
    if alive:
        return "quiet", "heartbeat %ss ago but pid %s is alive" % (age, worker.get("pid"))
    if age > HEARTBEAT_STALE_SECONDS:
        if boot and current_boot and boot != current_boot:
            return "stale", "heartbeat %ss ago, pid absent, boot id changed" % age
        if boot and current_boot and boot == current_boot and not clean_release:
            return "laptop-asleep", "heartbeat %ss ago, pid absent, boot id unchanged, no clean release" % age
        return "stale", "heartbeat %ss ago with pid absent (boot identity unverified)" % age
    return "quiet", "heartbeat %ss ago with pid absent below the stale threshold" % age


# --- state dir ---------------------------------------------------------------

STATE_DIR_ENV = "PROTEAN_HANDOFF_STATE_DIR"


def resolve_state_dir(explicit=None, require=True, create=False):
    """Explicit --state-dir, else PROTEAN_HANDOFF_STATE_DIR. Never a hardcoded home."""
    path = explicit or os.environ.get(STATE_DIR_ENV)
    if not path:
        if not require:
            return None
        raise HandoffError(
            "E_NO_STATE_DIR",
            "no handoff state directory configured",
            "next: rerun with --state-dir <ops/handoff path> (or set %s)" % STATE_DIR_ENV,
        )
    path = os.path.abspath(os.path.expanduser(path))
    if create:
        ensure_dir(path)
    return path


def state_path(state_dir, name):
    return os.path.join(state_dir, name)


# --- identity + authz (5: A1-A4) --------------------------------------------

def _split_ids(value):
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        parts = list(value)
    else:
        parts = re.split(r"[,\s]+", str(value))
    return [part.strip() for part in parts if part and part.strip()]


def env_allowlists(env=None):
    """Per-platform allowlist env vars (Hazen-verified key names)."""
    env = env if env is not None else os.environ
    out = {}
    global_ids = _split_ids(env.get("GATEWAY_ALLOWED_USERS"))
    for platform, key in (("whatsapp", "WHATSAPP_ALLOWED_USERS"),
                          ("discord", "DISCORD_ALLOWED_USERS")):
        ids = _split_ids(env.get(key))
        if global_ids:
            ids = list(ids) + list(global_ids)
        out[platform] = ids
    return out


def load_authz(state_dir=None, authz_file=None):
    """Load the authz mirror (allowlists / pairing-store union / home channels / group grants).

    The mirror is written by the installer from operator config (`.env` values and
    `handoff.groups.<platform>`); this skill never edits config. Env allowlists are
    always unioned in, so the mirror is optional.
    """
    path = None
    if authz_file:
        path = os.path.abspath(os.path.expanduser(authz_file))
    elif state_dir:
        path = state_path(state_dir, AUTHZ)
    data = read_json(path, default=None)
    if not isinstance(data, dict):
        data = {}
    allowlists = data.get("allowlists") if isinstance(data.get("allowlists"), dict) else {}
    pairing = data.get("pairing_store") if isinstance(data.get("pairing_store"), list) else []
    homes = data.get("home_channels") if isinstance(data.get("home_channels"), dict) else {}
    groups = data.get("groups") if isinstance(data.get("groups"), dict) else {}
    return {
        "path": path,
        "exists": bool(path and os.path.isfile(path)),
        "allowlists": allowlists,
        "pairing_store": pairing,
        "home_channels": homes,
        "groups": groups,
    }


def allowed_user_ids(platform, authz, env=None):
    ids = set(_split_ids(env_allowlists(env).get(platform)))
    ids.update(_split_ids((authz.get("allowlists") or {}).get(platform)))
    for row in authz.get("pairing_store") or []:
        if not isinstance(row, dict):
            continue
        if row.get("platform") and row.get("platform") != platform:
            continue
        ids.update(_split_ids(row.get("user_id") or row.get("ids")))
    return sorted(ids)


def home_channel(platform, authz):
    entry = (authz.get("home_channels") or {}).get(platform)
    if isinstance(entry, dict):
        return entry
    if isinstance(entry, str):
        return {"chat_id": entry}
    return {}


def group_grant(chat_id, platform, authz):
    """A3: read-only group grant is an explicit operator-written config value."""
    grants = authz.get("groups") or {}
    values = list(_split_ids(grants.get(platform)))
    return bool(chat_id) and chat_id in values


def authorize(identity, verb, authz, env=None):
    """Evaluate (platform, chat_id, user_id) against the locked auth rules.

    Returns a decision dict:
      decision: allow | refuse | silent_drop
      read_only: bool (group grants are read-only)
      code: internal code (never rendered to an unauthorized sender)
      reason: internal reason (logging only, never the wire)
      owner_notice: bool (A: one notice per (platform,user_id) per process)
      authority: the bound triple when allowed
    """
    identity = identity or {}
    platform = (identity.get("platform") or "").strip().lower()
    chat_id = str(identity.get("chat_id") or "").strip()
    user_id = str(identity.get("user_id") or "").strip()
    kind = (identity.get("chat_kind") or "").strip().lower() or "dm"

    if not platform or not chat_id or not user_id:
        return {"decision": "silent_drop", "read_only": False, "code": "E_UNAUTHORIZED",
                "reason": "incomplete identity triple", "owner_notice": False, "authority": None}

    allow = allowed_user_ids(platform, authz, env=env)
    if not allow and not (authz.get("home_channels") or {}):
        return {"decision": "silent_drop", "read_only": False, "code": "E_NO_AUTHZ_SOURCE",
                "reason": "no allowlist or pairing grant configured for %s" % platform,
                "owner_notice": False, "authority": None}

    if user_id not in allow:
        return {"decision": "silent_drop", "read_only": False, "code": "E_UNAUTHORIZED",
                "reason": "sender not in allowlist/pairing union", "owner_notice": True,
                "authority": None}

    home = home_channel(platform, authz)
    home_chat = str(home.get("chat_id") or "").strip()
    in_home = bool(home_chat) and chat_id == home_chat
    granted_group = group_grant(chat_id, platform, authz)
    # "group" means a declared group chat or one the operator granted read-only;
    # an ordinary non-home DM is neither - it gets the uniform refusal, not silence.
    in_group = kind == "group" or granted_group

    if verb not in READONLY_VERBS and verb not in EXECUTION_VERBS:
        decision = "silent_drop" if in_group else "refuse"
        return {"decision": decision, "read_only": False, "code": "E_VERB_NOT_GRANTED",
                "reason": "verb %r is outside the locked grantable set" % verb,
                "owner_notice": False, "authority": None}

    if verb in EXECUTION_VERBS and not in_home:
        # A3: groups never execute. A2: authority is the paired-DM triple, so any
        # non-home chat (group or other DM) cannot bind an execution verb.
        decision = "silent_drop" if in_group else "refuse"
        return {"decision": decision, "read_only": False, "code": "E_GROUP_EXECUTION_DENIED",
                "reason": "execution verb outside the paired-DM home channel",
                "owner_notice": in_group, "authority": None}

    if verb in READONLY_VERBS and not in_home:
        if granted_group:
            return {"decision": "allow", "read_only": True, "code": None,
                    "reason": "read-only group grant", "owner_notice": False,
                    "authority": {"platform": platform, "chat_id": chat_id, "user_id": user_id}}
        decision = "silent_drop" if in_group else "refuse"
        return {"decision": decision, "read_only": False, "code": "E_GROUP_NOT_GRANTED",
                "reason": "read-only group verb without handoff.groups grant",
                "owner_notice": in_group, "authority": None}

    return {"decision": "allow", "read_only": False, "code": None,
            "reason": "allowlisted paired-DM", "owner_notice": False,
            "authority": {"platform": platform, "chat_id": chat_id, "user_id": user_id}}


def uniform_refusal(item):
    return UNIFORM_REFUSAL.format(item=item)


# --- output ------------------------------------------------------------------

def emit(obj, exit_code=0, stream=None, pretty=True):
    stream = stream or sys.stdout
    payload = json.dumps(obj, sort_keys=True, indent=2 if pretty else None, default=str)
    stream.write(redact(payload)[0] + "\n")
    stream.flush()
    return exit_code


def ok_result(**fields):
    out = {"ok": True}
    out.update(fields)
    return out
