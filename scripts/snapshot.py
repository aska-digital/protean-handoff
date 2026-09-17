"""Protean Handoff - walk-away snapshot: build, refresh, verify (lock 1, 6/G1).

Disk is the truth (I5). The journal is the canonical record; `snapshot.json` is a
materialization that can be rebuilt from it, so losing the snapshot is not data loss.

  journal append -> derived recompute -> atomic snapshot rewrite (lock 8).

Every (D) field is recomputed here, never copied from a previous snapshot:
`worker.process_alive`, `health.staleness_seconds`, `health.state`, `health.evidence`
and the whole `connectivity` object. `--verify` re-derives and refuses to trust them:
if a stored (D) value disagrees with the recomputation, that is a violation.

Safety: a missing artifact path, an unreadable process table, a missing gateway state
file or a reboot all degrade to an explicit `unknown`/`missing`/`suspect` - never a
guess of `live`. Secret-like values are redacted before anything is written.
"""

import argparse
import datetime
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import handoff_lib as lib

DERIVED_PATHS = ("worker.process_alive", "health.staleness_seconds", "health.state",
                 "health.evidence", "connectivity")
# numeric derived fields are compared with a tolerance: a verify run seconds after a
# build legitimately re-derives a slightly larger staleness; the labels must still agree
STALENESS_TOLERANCE_SECONDS = 300

LANE_EVENTS = ("lane.dispatch", "lane.heartbeat", "lane.gate", "lane.artifact",
               "lane.stage", "lane.next", "lane.claim", "lane.done", "lane.continuity",
               "lane.approval", "lane.hold")

DEEP_FIELDS = ("worker", "continuity", "dispatch", "gate", "health", "connectivity",
               "next_action", "ops_refs")


def journal_path(state_dir):
    return lib.state_path(state_dir, lib.JOURNAL)


def snapshot_path(state_dir):
    return lib.state_path(state_dir, lib.SNAPSHOT)


def empty_lane(lane_id, project=None, role=None):
    inferred_role = role
    inferred_project = project
    if lane_id and lane_id.startswith("p-"):
        parts = lane_id.split("-")
        if len(parts) >= 3:
            inferred_project = inferred_project or parts[1]
            inferred_role = inferred_role or parts[2]
    return {
        "schema_version": lib.SCHEMA_VERSION,
        "lane_id": lane_id,
        "project": inferred_project or "",
        "role": inferred_role if inferred_role in lib.ROLES else "proteus",
        "stage": "build",
        "worker": {"pid": None, "ppid": None, "process_alive": None, "host_boot_id": None,
                   "claim_id": "", "claim_status": "none", "session_id": "", "launch_log": ""},
        "continuity": {"resume_session_id": None, "lineage_parent": None, "last_turn_ts": None},
        "dispatch": {"engine": "", "provider": "", "model": "", "run_id": "", "launched_at": None},
        "artifacts": [],
        "gate": {"state": "none", "name": "", "evidence": [], "last_verdict_ts": None},
        "pending_approvals": [],
        "merge_holds": [],
        "ops_refs": {"dispatch_ledger_row": None, "rotation_state_row": None},
        "health": {"last_heartbeat_ts": None, "staleness_seconds": None, "state": "unknown",
                   "evidence": "never derived"},
        "connectivity": {"gateway": "unknown", "gateway_checked_at": None,
                         "laptop_state": "unknown", "last_gateway_seen_ts": None},
        "next_action": {"text": "", "owner": ""},
        "updated_at": None,
        "writer_session_id": "",
    }


def _merge(lane, payload):
    for key, value in (payload or {}).items():
        if key in DEEP_FIELDS and isinstance(value, dict) and isinstance(lane.get(key), dict):
            merged = dict(lane[key])
            merged.update(value)
            lane[key] = merged
        elif key == "artifacts" and isinstance(value, list):
            existing = {a.get("path"): a for a in lane.get("artifacts") or []}
            for item in value:
                if isinstance(item, dict) and item.get("path"):
                    existing[item["path"]] = item
            lane["artifacts"] = list(existing.values())
        elif key in ("pending_approvals", "merge_holds") and isinstance(value, list):
            lane[key] = sorted(set((lane.get(key) or []) + [str(v) for v in value]))
        else:
            lane[key] = value
    return lane


def replay_lanes(journal_rows):
    """Fold journal rows into lane records. Rows without a lane are ignored."""
    lanes = {}
    order = []
    for row in journal_rows:
        event = row.get("event")
        if event in (None, "snapshot.materialized", "command", "notify"):
            continue
        lane_id = row.get("lane_id")
        if not lane_id:
            continue
        if lane_id not in lanes:
            lanes[lane_id] = empty_lane(lane_id)
            order.append(lane_id)
        payload = row.get("set") or row.get("lane")
        if isinstance(payload, dict):
            _merge(lanes[lane_id], payload)
        lanes[lane_id]["updated_at"] = row.get("at") or lanes[lane_id].get("updated_at")
        writer = row.get("writer_session_id")
        if writer:
            lanes[lane_id]["writer_session_id"] = writer
    return lanes, order


def read_journal(state_dir, journal=None):
    path = journal or journal_path(state_dir)
    rows, malformed = lib.read_jsonl(path)
    rows.sort(key=lambda r: int(r.get("seq") or 0))
    return rows, malformed, path


# --- soft readers (never a hard dependency, never a guess) --------------------

def _table_rows(text):
    """Lenient markdown-table parse: returns list of dict rows using the header map."""
    out = []
    header = None
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if all(re.match(r"^:?-{2,}:?$", c) for c in cells if c):
            continue
        if header is None:
            header = [c.lower() for c in cells]
            continue
        if len(cells) != len(header):
            continue
        out.append(dict(zip(header, cells)))
    return out


def read_ops_dir(ops_dir, project=None):
    """Best-effort ops ledger read for G1 replay. Missing/unparsable -> noted, not fatal."""
    result = {"ops_dir": os.path.abspath(ops_dir) if ops_dir else None, "notes": [],
              "claims": [], "dispatch_rows": [], "rotation_rows": []}
    if not ops_dir or not os.path.isdir(ops_dir):
        if ops_dir:
            result["notes"].append("ops dir not readable: %s" % ops_dir)
        return result

    inflight = lib.read_text(os.path.join(ops_dir, "INFLIGHT.md"))
    if inflight:
        for row in _table_rows(inflight):
            claim_id = row.get("claim") or row.get("claim_id") or row.get("id")
            if not claim_id:
                continue
            result["claims"].append({
                "claim_id": claim_id,
                "owner": row.get("owner") or row.get("agent") or "",
                "scope": row.get("scope") or row.get("paths") or "",
                "status": (row.get("status") or "").strip().lower() or "none",
                "project": (row.get("project") or "").strip(),
            })
    else:
        result["notes"].append("INFLIGHT.md not found under %s" % ops_dir)

    dispatch = lib.read_text(os.path.join(ops_dir, "DISPATCH-LEDGER.md"))
    if dispatch:
        result["dispatch_rows"] = _table_rows(dispatch)
    rotation = lib.read_text(os.path.join(ops_dir, "ROTATION-STATE.md"))
    if rotation:
        result["rotation_rows"] = _table_rows(rotation)
    return result


def gateway_status(gateway_state_path, now=None):
    """Derived connectivity (lock 1.D). Missing file -> unknown, never assumed up."""
    now = now or lib.utcnow()
    out = {"gateway": "unknown", "gateway_checked_at": lib.iso(now),
           "laptop_state": "unknown", "last_gateway_seen_ts": None}
    if not gateway_state_path:
        return out, "no gateway state file configured"
    if not os.path.isfile(gateway_state_path):
        return out, "gateway state file missing: %s" % gateway_state_path
    try:
        mtime = os.path.getmtime(gateway_state_path)
    except OSError:
        return out, "gateway state file unreadable"
    out["last_gateway_seen_ts"] = lib.iso(datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc))
    age = now.timestamp() - mtime
    data = lib.read_json(gateway_state_path, default=None)
    status = None
    if isinstance(data, dict):
        status = data.get("status") or data.get("gateway_state")
        if isinstance(data.get("gateway"), dict):
            status = data["gateway"].get("status") or status
    if age > lib.GATEWAY_FRESH_SECONDS:
        out["gateway"] = "down"
        return out, "gateway state is %ss old (> %ss): last seen %s" % (
            int(age), lib.GATEWAY_FRESH_SECONDS, out["last_gateway_seen_ts"])
    if status == "running":
        out["gateway"] = "up"
        out["laptop_state"] = "awake"
        return out, "gateway state fresh (%ss) and running" % int(age)
    if status:
        out["gateway"] = "down"
        return out, "gateway state fresh (%ss) and reports %r" % (int(age), status)
    out["gateway"] = "unknown"
    return out, "gateway state present but status unreadable"


# --- build -------------------------------------------------------------------

def _resolve_artifacts(lane, ops_dir=None):
    resolved = []
    for artifact in lane.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        item = dict(artifact)
        path = item.get("path") or ""
        item["path"] = os.path.abspath(os.path.expanduser(path)) if path else ""
        digest = lib.sha256_file(item["path"]) if item["path"] else None
        if item["path"] and os.path.isfile(item["path"]):
            try:
                stat = os.stat(item["path"])
                item["bytes"] = int(stat.st_size)
                item["mtime"] = lib.iso(datetime.datetime.fromtimestamp(stat.st_mtime,
                                                                      tz=datetime.timezone.utc))
            except OSError:
                item["status"] = "unreadable"
            if digest:
                item["sha256"] = digest
        else:
            item["status"] = "missing"
        item.setdefault("kind", "evidence")
        if item.get("kind") not in lib.ARTIFACT_KINDS:
            item["kind"] = "evidence"
        resolved.append(item)
    lane["artifacts"] = resolved
    return lane


def _attach_ops(lane, ops, project=None):
    lane_id = lane.get("lane_id") or ""
    for claim in ops.get("claims") or []:
        if claim["claim_id"] and claim["claim_id"] == (lane.get("worker") or {}).get("claim_id"):
            if not (lane.get("worker") or {}).get("claim_status") or lane["worker"]["claim_status"] == "none":
                lane["worker"]["claim_status"] = claim["status"] if claim["status"] in (
                    "active", "released", "crashed", "conflict") else "none"
    if ops.get("dispatch_rows") and not (lane.get("ops_refs") or {}).get("dispatch_ledger_row"):
        for row in ops["dispatch_rows"]:
            haystack = " ".join(str(v) for v in row.values()).lower()
            if lane_id and lane_id.lower() in haystack:
                lane.setdefault("ops_refs", {})
                lane["ops_refs"]["dispatch_ledger_row"] = "%s (dispatch row)" % lane_id
                break
    if ops.get("rotation_rows") and not (lane.get("ops_refs") or {}).get("rotation_state_row"):
        for row in ops["rotation_rows"]:
            haystack = " ".join(str(v) for v in row.values()).lower()
            if lane_id and lane_id.lower() in haystack:
                lane["ops_refs"]["rotation_state_row"] = "%s (rotation row)" % lane_id
                break
    if project and not lane.get("project"):
        lane["project"] = project
    return lane


def _parse_optional_json(raw):
    if raw is None:
        return None
    if raw.startswith("@"):
        return lib.read_json(raw[1:], default=None)
    try:
        import json as _json
        return _json.loads(raw)
    except ValueError:
        return None


REDACTION_MARKER = re.compile(r"\[redacted:([a-z_+]+)\]")


def collect_redaction_labels(journal_rows, built_lanes):
    """Labels this projection holds: explicit row labels plus every
    [redacted:<label>] marker carried inside the lane data itself."""
    labels = set()
    for row in journal_rows or []:
        for label in row.get("redactions") or []:
            labels.add(str(label))
    blob = lib.canonical_json(built_lanes)
    for marker in REDACTION_MARKER.finditer(blob):
        labels.update(part for part in marker.group(1).split("+") if part)
    return sorted(labels)


def build_lanes(state_dir, journal=None, ops_dir=None, gateway_state=None, laptop_state=None,
                now=None, project=None):
    now = now or lib.utcnow()
    rows, malformed, journal_file = read_journal(state_dir, journal=journal)
    lanes, order = replay_lanes(rows)
    ops = read_ops_dir(ops_dir, project=project)
    connectivity, connectivity_evidence = gateway_status(gateway_state, now=now)
    if laptop_state in ("awake", "sleeping", "unknown"):
        connectivity["laptop_state"] = laptop_state

    built = []
    for lane_id in order:
        redacted, _lane_labels = lib.redact_deep(lanes[lane_id])
        lane = dict(redacted) if isinstance(redacted, dict) else {}
        lane = dict(lane)
        lane.setdefault("schema_version", lib.SCHEMA_VERSION)
        lane["lane_id"] = lane_id
        _attach_ops(lane, ops, project=project)
        _resolve_artifacts(lane, ops_dir=ops_dir)
        worker = lane.get("worker") or {}
        alive = lib.process_alive(worker.get("pid"))
        worker["process_alive"] = alive
        if worker.get("pid") is not None and not worker.get("host_boot_id"):
            worker["host_boot_id"] = lib.host_boot_id()
        lane["worker"] = worker
        lane["connectivity"] = dict(connectivity)
        state, evidence = lib.health_state(lane, now=now, gateway=connectivity,
                                           current_boot=lib.host_boot_id())
        lane["health"] = dict(lane.get("health") or {})
        lane["health"]["staleness_seconds"] = lib.seconds_since(lane["health"].get("last_heartbeat_ts"), now)
        lane["health"]["state"] = state
        lane["health"]["evidence"] = evidence
        built.append(lane)

    snapshot = {
        "schema_version": lib.SCHEMA_VERSION,
        "generated_at": lib.iso(now),
        "journal": journal_file,
        "journal_seq": _highest_seq(rows),
        "journal_malformed_rows": malformed,
        "redactions": collect_redaction_labels(rows, built),
        "connectivity": connectivity,
        "connectivity_evidence": connectivity_evidence,
        "ops_notes": ops.get("notes") or [],
        "lanes": built,
    }
    snapshot["snapshot_hash"] = snapshot_hash(snapshot)
    return snapshot


def _highest_seq(rows):
    highest = 0
    for row in rows:
        try:
            highest = max(highest, int(row.get("seq") or 0))
        except (TypeError, ValueError):
            continue
    return highest


def persisted_projection(snapshot):
    """The (D)-free projection whose hash must survive a journal replay.

    Bookkeeping fields (generated_at, journal paths, redaction labels, the hash itself)
    are excluded: they are read/write metadata, not lane state. Artifact enrichment
    (bytes/mtime/sha256/status) is re-derived at read time and normalized away here;
    stored-vs-actual drift is still checked directly (E_ARTIFACT_DRIFT).
    """
    lanes = []
    for lane in snapshot.get("lanes") or []:
        lanes.append(_strip_derived(lane))
    return {"schema_version": snapshot.get("schema_version"), "lanes": lanes}


def snapshot_hash(snapshot):
    return lib.sha256_text(lib.canonical_json(persisted_projection(snapshot)))


def _strip_derived(lane):
    stripped = _deepcopy(lane)
    worker = stripped.get("worker") or {}
    worker.pop("process_alive", None)
    health = stripped.get("health") or {}
    for key in ("staleness_seconds", "state", "evidence"):
        health.pop(key, None)
    stripped.pop("connectivity", None)
    normalized = []
    for artifact in stripped.get("artifacts") or []:
        if isinstance(artifact, dict):
            normalized.append({"path": artifact.get("path"), "kind": artifact.get("kind")})
    stripped["artifacts"] = normalized
    return stripped


def _deepcopy(value):
    import copy
    return copy.deepcopy(value)


def write_snapshot(state_dir, snapshot, now=None):
    now = now or lib.utcnow()
    rows, _, _ = read_journal(state_dir)
    seq = _highest_seq(rows) + 1
    lib.append_jsonl(journal_path(state_dir), {
        "seq": seq, "at": lib.iso(now), "event": "snapshot.materialized",
        "snapshot_hash": snapshot.get("snapshot_hash"),
        "writer_session_id": os.environ.get("HERMES_SESSION_ID", ""),
    })
    # labels = every secret-like value found while projecting this snapshot (the
    # field is recomputed on every write, never inherited from an earlier render)
    clean, labels = lib.redact_deep(snapshot)
    clean["redactions"] = sorted(set(labels) | set(snapshot.get("redactions") or []))
    clean["journal_seq"] = seq
    lib.atomic_write_json(snapshot_path(state_dir), clean)
    return snapshot_path(state_dir), clean["redactions"]


# --- verify ------------------------------------------------------------------

def verify_snapshot(state_dir, journal=None, ops_dir=None, gateway_state=None,
                    laptop_state=None, soft=False, now=None):
    """Re-derive and refuse to trust (D) fields. Returns (violations, report)."""
    violations = []
    stored = lib.read_json(snapshot_path(state_dir), default=None)
    if not isinstance(stored, dict):
        return ([{"code": "E_NO_SNAPSHOT", "detail": "snapshot.json missing or unreadable",
                  "evidence": snapshot_path(state_dir)}],
                {"ok": False, "snapshot": snapshot_path(state_dir)})

    generated_at = lib.parse_iso(stored.get("generated_at")) or lib.utcnow()
    # the re-derivation is anchored to the snapshot's own recorded boot identity, so a
    # reboot between the snapshot and this verify run still reads as `stale` and a
    # sleep still reads as `laptop-asleep` - the ladder compares against the record.
    recorded_boot = None
    for lane in stored.get("lanes") or []:
        recorded_boot = (lane.get("worker") or {}).get("host_boot_id") or None
        if recorded_boot:
            break
    rebuilt = build_lanes(state_dir, journal=journal, ops_dir=ops_dir,
                          gateway_state=gateway_state, laptop_state=laptop_state,
                          now=generated_at)
    for lane in rebuilt.get("lanes") or []:
        worker = lane.get("worker") or {}
        if recorded_boot and not worker.get("host_boot_id"):
            worker["host_boot_id"] = recorded_boot
        state, evidence = lib.health_state(lane, now=generated_at,
                                           gateway=lane.get("connectivity"),
                                           current_boot=recorded_boot or lib.host_boot_id())
        lane["health"]["state"] = state
        lane["health"]["evidence"] = evidence

    # 1. schema
    if stored.get("schema_version") != lib.SCHEMA_VERSION:
        violations.append({"code": "E_SCHEMA_VERSION",
                           "detail": "schema_version %r != %r" % (stored.get("schema_version"),
                                                                  lib.SCHEMA_VERSION)})
    lanes = stored.get("lanes")
    if not isinstance(lanes, list):
        violations.append({"code": "E_SCHEMA_LANES", "detail": "lanes is not a list"})
        lanes = []
    for lane in lanes:
        violations.extend(_lane_schema_violations(lane))

    # 2. persisted fields must equal the journal replay (drift)
    stored_by_id = {ln.get("lane_id"): ln for ln in lanes}
    rebuilt_by_id = {ln.get("lane_id"): ln for ln in rebuilt.get("lanes") or []}
    for lane_id in sorted(set(stored_by_id) | set(rebuilt_by_id)):
        if lane_id not in stored_by_id:
            violations.append({"code": "E_REPLAY_LANE_MISSING",
                               "detail": "journal replay produced lane %s absent from the snapshot"
                                         % lane_id})
            continue
        if lane_id not in rebuilt_by_id:
            violations.append({"code": "E_REPLAY_LANE_EXTRA",
                               "detail": "snapshot holds lane %s with no journal support" % lane_id})
            continue
        violations.extend(_drift_violations(lane_id, stored_by_id[lane_id], rebuilt_by_id[lane_id]))

    # 3. derived fields must equal the recomputation (no trusting (D))
    for lane in lanes:
        violations.extend(_derived_violations(lane_id=lane.get("lane_id"), stored=lane,
                                              rebuilt=rebuilt_by_id.get(lane.get("lane_id"))))

    # 4. snapshot hash
    if stored.get("snapshot_hash") != snapshot_hash(stored):
        violations.append({"code": "E_SNAPSHOT_HASH",
                           "detail": "snapshot_hash does not match the persisted projection"})
    if rebuilt.get("snapshot_hash") != stored.get("snapshot_hash"):
        violations.append({"code": "E_REPLAY_HASH",
                           "detail": "journal replay produced hash %s, snapshot stores %s"
                                     % (lib.sha256_text(str(rebuilt.get("snapshot_hash")))[:12],
                                        lib.sha256_text(str(stored.get("snapshot_hash")))[:12])})

    # 5. artifacts on disk
    for lane in lanes:
        for artifact in lane.get("artifacts") or []:
            path = artifact.get("path")
            if not path:
                violations.append({"code": "E_ARTIFACT_NO_PATH",
                                   "detail": "lane %s has an artifact without a path"
                                             % lane.get("lane_id")})
                continue
            if not os.path.isfile(path):
                entry = {"code": "E_ARTIFACT_MISSING",
                         "detail": "artifact not on disk: %s" % path, "evidence": path,
                         "lane_id": lane.get("lane_id")}
                violations.append(entry)
                continue
            actual = lib.sha256_file(path)
            if artifact.get("sha256") and actual and artifact["sha256"] != actual:
                violations.append({"code": "E_ARTIFACT_DRIFT",
                                   "detail": "artifact hash changed since the snapshot: %s" % path,
                                   "evidence": path, "lane_id": lane.get("lane_id")})

    # 6. secrets
    raw = lib.read_text(snapshot_path(state_dir)) or ""
    for label in lib.secret_labels(raw):
        violations.append({"code": "E_SECRET_LIKE_VALUE",
                           "detail": "snapshot.json contains a secret-like value: %s" % label,
                           "evidence": snapshot_path(state_dir)})

    if soft:
        violations = [v for v in violations if v["code"] != "E_ARTIFACT_MISSING"]
    report = {
        "ok": not violations,
        "snapshot": snapshot_path(state_dir),
        "journal": journal or journal_path(state_dir),
        "lanes": len(lanes),
        "snapshot_hash": stored.get("snapshot_hash"),
        "replayed_hash": rebuilt.get("snapshot_hash"),
        "redactions": stored.get("redactions") or [],
        "violations": violations,
        "next": "next: none - informational" if not violations else "next: fix the violations above",
    }
    return violations, report


def _lane_schema_violations(lane):
    out = []
    lane_id = (lane or {}).get("lane_id")
    if not isinstance(lane, dict):
        return [{"code": "E_SCHEMA_LANE", "detail": "lane row is not an object"}]
    if not lane_id or not re.match(r"^p-[a-z0-9]+-[a-z0-9]+(-[0-9]+)?$", str(lane_id)):
        out.append({"code": "E_SCHEMA_LANE_ID", "detail": "bad lane_id %r" % (lane_id,)})
    if lane.get("role") not in lib.ROLES:
        out.append({"code": "E_SCHEMA_ROLE", "detail": "lane %s bad role %r" % (lane_id, lane.get("role"))})
    if lane.get("stage") not in lib.STAGES:
        out.append({"code": "E_SCHEMA_STAGE", "detail": "lane %s bad stage %r" % (lane_id, lane.get("stage"))})
    gate = lane.get("gate") or {}
    if gate.get("state") not in lib.GATE_STATES:
        out.append({"code": "E_SCHEMA_GATE", "detail": "lane %s bad gate state %r" % (lane_id, gate.get("state"))})
    health = lane.get("health") or {}
    if health.get("state") not in lib.HEALTH_STATES:
        out.append({"code": "E_SCHEMA_HEALTH", "detail": "lane %s bad health state %r" % (lane_id, health.get("state"))})
    worker = lane.get("worker") or {}
    if worker.get("claim_status") not in ("active", "released", "crashed", "conflict", "none"):
        out.append({"code": "E_SCHEMA_CLAIM", "detail": "lane %s bad claim_status %r" % (lane_id, worker.get("claim_status"))})
    if not (lane.get("artifacts") or []):
        out.append({"code": "E_SCHEMA_NO_ARTIFACT",
                    "detail": "lane %s has no artifact (the primary receipt path is required)" % lane_id})
    for key in ("updated_at", "writer_session_id"):
        if key not in lane:
            out.append({"code": "E_SCHEMA_FIELD", "detail": "lane %s missing %s" % (lane_id, key)})
    return out


def _drift_violations(lane_id, stored, rebuilt):
    out = []
    stored_p = _strip_derived(stored)
    rebuilt_p = _strip_derived(rebuilt)
    if lib.canonical_json(stored_p) != lib.canonical_json(rebuilt_p):
        keys = [k for k in set(list(stored_p) + list(rebuilt_p))
                if lib.canonical_json(stored_p.get(k)) != lib.canonical_json(rebuilt_p.get(k))]
        out.append({"code": "E_PERSISTED_DRIFT",
                    "detail": "lane %s persisted fields disagree with the journal replay: %s"
                              % (lane_id, ", ".join(sorted(keys)))})
    return out


def _derived_violations(lane_id, stored, rebuilt, now=None):
    out = []
    if not rebuilt:
        return out
    for path in DERIVED_PATHS:
        left = _get_path(stored, path)
        right = _get_path(rebuilt, path)
        if path == "health.staleness_seconds":
            # a re-derivation seconds later is not a violation: numeric derived fields
            # are compared with a tolerance and the health *state label* must still
            # agree (the evidence sentence embeds the age, so it follows the label).
            try:
                if left is not None and right is not None \
                        and abs(int(left) - int(right)) <= STALENESS_TOLERANCE_SECONDS \
                        and _get_path(stored, "health.state") == _get_path(rebuilt, "health.state"):
                    continue
            except (TypeError, ValueError):
                pass
        if path == "health.evidence" and \
                _get_path(stored, "health.state") == _get_path(rebuilt, "health.state"):
            continue  # the label agreed; the sentence differs only in embedded timing
        if lib.canonical_json(left) != lib.canonical_json(right):
            out.append({"code": "E_DERIVED_TRUSTED",
                        "detail": "lane %s stores %s=%r but the read-time derivation is %r"
                                  % (lane_id, path, _short(left), _short(right))})
    return out


def _get_path(obj, dotted):
    node = obj
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _short(value):
    text = lib.canonical_json(value)
    return text if len(text) <= 60 else text[:57] + "..."


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="snapshot.py",
        description="Build, refresh and verify the Protean Handoff walk-away snapshot.")
    parser.add_argument("--state-dir", help="handoff state directory")
    parser.add_argument("--journal", help="journal path (default <state>/journal.jsonl)")
    parser.add_argument("--ops-dir", help="ops ledger dir for G1 replay (INFLIGHT/DISPATCH/ROTATION)")
    parser.add_argument("--gateway-state", help="gateway state file for derived connectivity"
                                                " (or PROTEAN_HANDOFF_GATEWAY_STATE)")
    parser.add_argument("--laptop-state", choices=["awake", "sleeping", "unknown"])
    parser.add_argument("--project")
    parser.add_argument("--now", help="override now (iso8601)")
    parser.add_argument("--build", action="store_true", help="materialize snapshot.json from the journal")
    parser.add_argument("--verify", action="store_true", help="re-derive and check every invariant")
    parser.add_argument("--soft", action="store_true", help="downgrade missing-artifact violations")
    parser.add_argument("--print", dest="dump", action="store_true", help="print the snapshot JSON")
    parser.add_argument("--event", help="append a journal event for a lane")
    parser.add_argument("--lane", help="lane id for --event")
    parser.add_argument("--set", help="JSON object of fields for --event (or @path)")
    parser.add_argument("--no-write", action="store_true", help="derive only, never write")
    args = parser.parse_args(argv)

    try:
        state_dir = lib.resolve_state_dir(args.state_dir)
        lib.ensure_dir(state_dir)
        now = lib.parse_iso(args.now) or lib.utcnow()
        gateway_state = args.gateway_state or os.environ.get("PROTEAN_HANDOFF_GATEWAY_STATE")

        if args.event:
            lib.require(args.lane, "E_NO_LANE", "--event needs --lane",
                        "next: pass --lane <p-project-role>")
            lib.require(bool(re.match(r"^[a-z]+\.[a-z_]+$", args.event)), "E_BAD_EVENT",
                        "event names look like lane.heartbeat",
                        "next: use one of %s" % ", ".join(LANE_EVENTS))
            payload, labels = lib.redact_deep(_parse_optional_json(args.set) or {})
            rows, _, _ = read_journal(state_dir)
            seq = _highest_seq(rows) + 1
            lib.append_jsonl(journal_path(state_dir), {
                "seq": seq, "at": lib.iso(now), "event": args.event, "lane_id": args.lane,
                "set": payload, "redactions": labels,
                "writer_session_id": os.environ.get("HERMES_SESSION_ID", ""),
            })
            if args.build or not args.no_write:
                snapshot = build_lanes(state_dir, journal=args.journal, ops_dir=args.ops_dir,
                                       gateway_state=gateway_state,
                                       laptop_state=args.laptop_state, now=now,
                                       project=args.project)
                path, redactions = write_snapshot(state_dir, snapshot, now=now)
                return lib.emit(lib.ok_result(event=args.event, lane_id=args.lane, seq=seq,
                                              snapshot=path, snapshot_hash=snapshot["snapshot_hash"],
                                              redactions=redactions,
                                              evidence=[journal_path(state_dir), path],
                                              next="next: status %s" % args.lane), 0)
            return lib.emit(lib.ok_result(event=args.event, lane_id=args.lane, seq=seq,
                                          evidence=[journal_path(state_dir)],
                                          next="next: snapshot.py --build"), 0)

        if args.verify:
            violations, report = verify_snapshot(state_dir, journal=args.journal,
                                                 ops_dir=args.ops_dir,
                                                 gateway_state=gateway_state,
                                                 laptop_state=args.laptop_state,
                                                 soft=args.soft, now=now)
            if args.dump:
                print(lib.canonical_json(report))
            report["evidence"] = [snapshot_path(state_dir)]
            return lib.emit(report, 0 if not violations else 1)

        snapshot = build_lanes(state_dir, journal=args.journal, ops_dir=args.ops_dir,
                               gateway_state=gateway_state, laptop_state=args.laptop_state,
                               now=now, project=args.project)
        redactions = []
        path = snapshot_path(state_dir)
        if not args.no_write:
            path, redactions = write_snapshot(state_dir, snapshot, now=now)
        if args.dump:
            sys.stdout.write(lib.canonical_json(snapshot) + "\n")
        return lib.emit(lib.ok_result(
            snapshot=path, lanes=len(snapshot["lanes"]), snapshot_hash=snapshot["snapshot_hash"],
            connectivity=snapshot["connectivity"], redactions=redactions,
            derived_fields=list(DERIVED_PATHS),
            evidence=[path, journal_path(state_dir)],
            next="next: render.py --status --state-dir %s" % state_dir), 0)
    except lib.HandoffError as exc:
        return lib.emit(exc.as_dict(), 2)


if __name__ == "__main__":
    sys.exit(main())
