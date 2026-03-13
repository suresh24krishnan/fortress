# api/main.py
from __future__ import annotations

import os
import uuid
import threading
import datetime
import shlex
import sqlite3
import re
from typing import Any, Dict, Optional, List, Tuple

from fastapi import BackgroundTasks, FastAPI, HTTPException, Header, Query

from api.models import ProofStartRequest
from api.policy import load_policy
from api.lib.az_runner import run_az
from api.lib import ledger

app = FastAPI(title="FORTRESS Core API")

# Pathing for Persistence
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
L_PATH = os.path.join(BASE_DIR, "data", "ledger.db")

_JOBS: Dict[str, Dict[str, Any]] = {}
_BASELINES: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()

ADMIN_TOKEN = os.getenv("FORTRESS_ADMIN_TOKEN", "").strip()  # optional

_INT_RE = re.compile(r"^\s*-?\d+\s*$")


@app.on_event("startup")
def boot():
    """Initializes the database directory and schema."""
    os.makedirs(os.path.dirname(L_PATH), exist_ok=True)
    ledger.init_db(L_PATH)


# ---------------------------
# HELPERS (Persistence Layer)
# ---------------------------
def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sync_set_job(jid: str, data: Dict[str, Any]):
    with _LOCK:
        current = _JOBS.get(jid, {})
        current.update(data)
        current["updated_at_utc"] = _now_utc()
        _JOBS[jid] = current
    ledger.upsert_job(L_PATH, jid, current)


def _sync_set_baseline(bid: str, data: Dict[str, Any]):
    with _LOCK:
        current = _BASELINES.get(bid, {})
        current.update(data)
        current["updated_at_utc"] = _now_utc()
        _BASELINES[bid] = current
    ledger.upsert_baseline(L_PATH, bid, current)


def _admin_guard(x_admin_token: Optional[str]) -> None:
    if ADMIN_TOKEN and (x_admin_token or "").strip() != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")


def _extract_command_str(script: Any) -> str:
    if isinstance(script, list):
        return " ".join(str(x) for x in script)
    return str(script or "")


def _remediation_to_argv(rem_item: Any) -> Optional[List[str]]:
    if rem_item is None:
        return None
    if isinstance(rem_item, list):
        argv = [str(x).strip() for x in rem_item if str(x).strip()]
        return argv or None
    s = str(rem_item).strip()
    if not s:
        return None
    if not s.lower().startswith("az "):
        return None
    return [t for t in shlex.split(s, posix=False) if t.strip()]


def _evaluate(proof_key: str, cmd: str, rc: int, stdout: str, stderr: str) -> Tuple[str, Any, Any, bool]:
    """
    Returns: (evaluator, observed, expected, passed)

    We enforce proof semantics per proof type, so the attestation means something.
    """
    so = (stdout or "").strip()
    so_l = so.lower()
    se = (stderr or "").strip()

    if rc != 0:
        return "rc==0", {"stdout": so, "stderr": se}, None, False

    # --- Proof-specific semantics ---
    if proof_key == "keyvault_controls_posture":
        expected = "Disabled"
        passed = (so_l == "disabled")
        return "publicNetworkAccess == Disabled", so, expected, passed

    if proof_key == "keyvault_private_access":
        expected = "Deny"
        passed = (so_l == "deny")
        return "networkAcls.defaultAction == Deny", so, expected, passed

    if proof_key == "keyvault_private_endpoint_exists":
        # Policy uses: properties.privateEndpointConnections[0].id (avoid JMESPath length(...) due to az.cmd/CMD parsing)
        expected = "non-empty privateEndpointConnections[0].id"
        passed = bool(so) and so_l not in ("none", "null")
        return "stdout non-empty (privateEndpointConnections[0].id)", so, expected, passed


    if proof_key == "keyvault_rbac_enabled":
        expected = True
        if so_l in ("true", "false"):
            b = (so_l == "true")
            return "enableRbacAuthorization == true", b, expected, b
        return "boolean output", so, expected, False

    if proof_key == "keyvault_purge_protection_enabled":
        expected = True
        # Azure may return empty stdout for null when using -o tsv.
        if so_l in ("true", "false"):
            b = (so_l == "true")
            return "enablePurgeProtection == true", b, expected, b
        if so_l in ("", "none", "null"):
            # Treat missing / null as not enabled.
            return "enablePurgeProtection == true", False, expected, False
        return "enablePurgeProtection == true (unrecognized output)", so, expected, False


    if proof_key == "managed_identity_token_probe":
        return "rc==0 (identity context available)", "ok", "ok", True

    # --- Generic fallback (safe) ---
    if _INT_RE.match(so):
        return "rc==0 (int output)", int(so), None, True
    if so_l in ("true", "false"):
        return "rc==0 (bool output)", (so_l == "true"), None, True
    if so:
        return "rc==0 (stdout present)", so, None, True
    return "rc==0", "ok", None, True


def _legacy_evidence(stdout: str, stderr: str, rc: int) -> str:
    s = (stdout or "").strip()
    e = (stderr or "").strip()
    if s:
        return s
    if e:
        return e
    return f"rc={rc}"


def _ledger_delete_all() -> Dict[str, int]:
    ledger.init_db(L_PATH)
    con = sqlite3.connect(L_PATH)
    try:
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM jobs;")
        jobs_before = int(cur.fetchone()[0] or 0)
        cur.execute("SELECT COUNT(*) FROM baselines;")
        baselines_before = int(cur.fetchone()[0] or 0)

        cur.execute("DELETE FROM jobs;")
        cur.execute("DELETE FROM baselines;")
        con.commit()
        return {"jobs_deleted": jobs_before, "baselines_deleted": baselines_before}
    finally:
        con.close()


# ---------------------------
# CORE API ROUTES
# ---------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": _now_utc(), "ok": True}


@app.get("/policy")
async def get_policy():
    p = load_policy()
    return {"environments": p.environments, "proofs": p.proofs, "ok": True}


@app.get("/jobs")
async def list_jobs(limit: int = Query(50, ge=1, le=500)):
    ids = ledger.list_recent_job_ids(L_PATH, limit=int(limit))
    return {"job_ids": ids, "ok": True}


@app.get("/baselines")
async def list_baselines():
    ids = ledger.list_recent_baseline_ids(L_PATH, limit=20)
    return {"baseline_ids": ids, "ok": True}


@app.get("/jobs/{jid}")
async def get_job(jid: str):
    job = _JOBS.get(jid) or ledger.get_job(L_PATH, jid)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/baseline/{bid}")
async def get_baseline(bid: str):
    bl = _BASELINES.get(bid) or ledger.get_baseline(L_PATH, bid)
    if not bl:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return bl


@app.get("/controls")
async def controls(env: str = Query("dev")):
    """Small controls snapshot for the UI."""
    try:
        p = load_policy()
        if env not in p.environments:
            raise HTTPException(status_code=400, detail=f"Unknown env: {env}")

        e = p.environments[env]
        rg = getattr(e, "resource_group", None) or e.get("resource_group")
        kv = getattr(e, "keyvault_name", None) or e.get("keyvault_name")

        if not rg or not kv:
            return {"ok": False, "error": "Environment missing resource_group or keyvault_name", "keyvault": kv}

        pna = run_az(["az", "keyvault", "show", "-g", rg, "-n", kv, "--query", "properties.publicNetworkAccess", "-o", "tsv"], timeout_sec=30)
        rbac = run_az(["az", "keyvault", "show", "-g", rg, "-n", kv, "--query", "properties.enableRbacAuthorization", "-o", "tsv"], timeout_sec=30)

        out = {
            "ok": (pna.code == 0 and rbac.code == 0),
            "keyvault": kv,
            "public_network_access": (pna.stdout or pna.stderr or "").strip(),
            "rbac_enabled": (rbac.stdout or rbac.stderr or "").strip(),
        }
        if str(out["rbac_enabled"]).lower() in ("true", "false"):
            out["rbac_enabled"] = (str(out["rbac_enabled"]).lower() == "true")
        if not out["ok"]:
            out["error"] = (pna.stderr or rbac.stderr or "az query failed").strip()
        return out
    except HTTPException:
        raise
    except Exception as ex:
        return {"ok": False, "error": str(ex)}


@app.post("/admin/ledger/clear")
async def admin_clear_ledger(x_admin_token: Optional[str] = Header(default=None)):
    _admin_guard(x_admin_token)
    with _LOCK:
        _JOBS.clear()
        _BASELINES.clear()
    counts = _ledger_delete_all()
    return {"ok": True, **counts}


# ---------------------------
# EXECUTION ROUTES
# ---------------------------
@app.post("/proof/start")
async def start_proof(req: ProofStartRequest, bt: BackgroundTasks):
    jid = f"proof-{uuid.uuid4().hex[:8]}"
    msg = {
        "job_id": jid,
        "status": "Created",
        "env": req.env,
        "proof": req.proof,
        "step": "Queued",
        "created_at_utc": _now_utc(),
        "timeout_sec": int(req.timeout_sec or 0) or 120,
    }
    _sync_set_job(jid, msg)
    bt.add_task(_run_task, jid, req.env, req.proof, int(req.timeout_sec or 0) or 0)
    return {"job_id": jid, "status": "Created", "ok": True}


@app.post("/baselines/start")
async def start_baseline(bt: BackgroundTasks, env: str = Query("dev")):
    bid = f"bl-{uuid.uuid4().hex[:8]}"
    initial_data = {
        "baseline_id": bid,
        "env": env,
        "status": "Running",
        "created_at_utc": _now_utc(),
        "results": {},
    }
    _sync_set_baseline(bid, initial_data)
    bt.add_task(_run_baseline_task, bid, env)
    return {"baseline_id": bid, "status": "Running", "ok": True}


# ---------------------------
# BACKGROUND ENGINES
# ---------------------------
async def _run_task(jid: str, env_k: str, prf_k: str, timeout_override: int = 0):
    """Single Proof Execution with meaningful attestation semantics."""
    try:
        p = load_policy()
        if prf_k not in p.proofs:
            raise ValueError(f"Unknown proof: {prf_k}")

        proof_def = p.proofs[prf_k]
        tmax = int(getattr(proof_def, "timeout_sec_max", 120) or 120)
        timeout_sec = min(max(30, timeout_override or tmax), tmax)

        _sync_set_job(jid, {"status": "Running", "step": "Audit: Running", "started_at_utc": _now_utc(), "timeout_sec": timeout_sec})

        res = run_az(proof_def.script, timeout_sec=timeout_sec)
        cmd_str = _extract_command_str(proof_def.script)
        stdout = (res.stdout or "").strip()
        stderr = (res.stderr or "").strip()

        evaluator, observed, expected, passed = _evaluate(prf_k, cmd_str, int(res.code), stdout, stderr)
        att_status = "Execution Error" if int(res.code) != 0 else ("Passed" if passed else "Failed")

        evidence_block = {
            "proof": prf_k,
            "env": env_k,
            "command": cmd_str,
            "return_code": int(res.code),
            "observed": observed,
            "expected": expected,
            "stdout": stdout or None,
            "stderr": stderr or None,
            "evaluator": evaluator,
            "passed": bool(passed),
            "note": "Evaluated by Fortress proof semantics.",
        }

        evidence_line = _legacy_evidence(stdout, stderr, int(res.code))

        remediation_display = list(getattr(proof_def, "remediation", []) or [])
        remediation_argv: List[List[str]] = []
        for item in remediation_display:
            argv = _remediation_to_argv(item)
            if argv:
                remediation_argv.append(argv)

        if (not passed) and remediation_argv:
            _sync_set_job(jid, {"status": "Remediating", "step": "Healing: Applying Fix"})
            for argv in remediation_argv:
                run_az(argv, timeout_sec=timeout_sec)

            verify_res = run_az(proof_def.script, timeout_sec=timeout_sec)
            v_stdout = (verify_res.stdout or "").strip()
            v_stderr = (verify_res.stderr or "").strip()
            v_eval, v_obs, v_exp, v_passed = _evaluate(prf_k, cmd_str, int(verify_res.code), v_stdout, v_stderr)
            att_status = "Execution Error" if int(verify_res.code) != 0 else ("Passed (Auto-Remediated)" if v_passed else "Failed")

            evidence_block = {
                "proof": prf_k,
                "env": env_k,
                "command": cmd_str,
                "return_code": int(verify_res.code),
                "observed": v_obs,
                "expected": v_exp,
                "stdout": v_stdout or None,
                "stderr": v_stderr or None,
                "evaluator": v_eval,
                "passed": bool(v_passed),
                "note": "Verification run after remediation.",
            }
            evidence_line = _legacy_evidence(v_stdout, v_stderr, int(verify_res.code))

        _sync_set_job(
            jid,
            {
                "status": "Completed",
                "step": "Finished",
                "completed_at_utc": _now_utc(),
                "result": {
                    "attestation": {
                        "claim": getattr(proof_def, "description", prf_k),
                        "status": att_status,
                        "evidence": [evidence_line],
                        "evidence_blocks": [evidence_block],
                    },
                    "remediation": remediation_display,
                },
            },
        )
    except Exception as e:
        _sync_set_job(jid, {"status": "Failed", "error": str(e), "completed_at_utc": _now_utc()})


async def _run_baseline_task(bid: str, env: str):
    """Full Policy Audit with semantics and optional self-healing."""
    try:
        p = load_policy()
        results: Dict[str, Any] = {}
        passed_count = 0
        failed_count = 0

        for k, proof in p.proofs.items():
            res = run_az(proof.script, timeout_sec=30)
            cmd_str = _extract_command_str(proof.script)
            stdout = (res.stdout or "").strip()
            stderr = (res.stderr or "").strip()

            evaluator, observed, expected, ok = _evaluate(k, cmd_str, int(res.code), stdout, stderr)
            status = "Execution Error" if int(res.code) != 0 else ("Passed" if ok else "Failed")

            remediation_display = list(getattr(proof, "remediation", []) or [])
            remediation_argv: List[List[str]] = []
            for item in remediation_display:
                argv = _remediation_to_argv(item)
                if argv:
                    remediation_argv.append(argv)

            if (not ok) and remediation_argv:
                for argv in remediation_argv:
                    run_az(argv, timeout_sec=30)
                v_res = run_az(proof.script, timeout_sec=30)
                v_stdout = (v_res.stdout or "").strip()
                v_stderr = (v_res.stderr or "").strip()
                v_eval, v_obs, v_exp, v_ok = _evaluate(k, cmd_str, int(v_res.code), v_stdout, v_stderr)
                status = "Execution Error" if int(v_res.code) != 0 else ("Passed (Auto-Remediated)" if v_ok else "Failed")
                evaluator, observed, expected = v_eval, v_obs, v_exp

            if str(status).lower().startswith("passed"):
                passed_count += 1
            else:
                failed_count += 1

            results[k] = {
                "proof": k,
                "status": status,
                "observed": observed,
                "expected": expected,
                "evaluator": evaluator,
                "evidence": _legacy_evidence(stdout, stderr, int(res.code)),
                "command": cmd_str,
                "remediation": remediation_display,
            }

        total = passed_count + failed_count
        score = f"{int(round((passed_count / total) * 100))}%" if total else None
        compliant = (failed_count == 0) if total else None

        _sync_set_baseline(
            bid,
            {
                "baseline_id": bid,
                "env": env,
                "status": "Completed",
                "results": results,
                "passed": passed_count,
                "failed": failed_count,
                "compliance_score": score,
                "compliant": compliant,
                "completed_at_utc": _now_utc(),
            },
        )
    except Exception as e:
        _sync_set_baseline(bid, {"baseline_id": bid, "env": env, "status": "Failed", "error": str(e), "completed_at_utc": _now_utc()})
