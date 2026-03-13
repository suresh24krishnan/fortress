# ui/app.py
from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests
import streamlit as st

API_URL = os.getenv("FORTRESS_API_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN_TOKEN = os.getenv("FORTRESS_ADMIN_TOKEN", "").strip()

def _http_json(method: str, path: str, data: dict | None = None, timeout: int = 120) -> Dict[str, Any]:
    url = f"{API_URL}{path}"
    headers = {}
    # Only send token if provided; API may allow local clears without a token.
    if path.startswith("/admin/") and ADMIN_TOKEN:
        headers["X-Admin-Token"] = ADMIN_TOKEN
    try:
        r = requests.request(method, url, json=data, timeout=timeout, headers=headers)
        if not (200 <= r.status_code < 300):
            return {"ok": False, "status_code": r.status_code, "error": f"HTTP {r.status_code}: {r.text[:1200]}"}
        j = r.json()
        if isinstance(j, dict) and "ok" not in j:
            j["ok"] = True
        return j if isinstance(j, dict) else {"ok": True, "data": j}
    except Exception as e:
        return {"ok": False, "status_code": None, "error": str(e)}

def _short_ts(ts: Optional[str]) -> str:
    if not ts:
        return "—"
    return ts.replace("T", " ").replace("Z", "").split("+")[0] + " UTC"

def _result_badge(att_status: str) -> str:
    s = (att_status or "").lower()
    if "execution error" in s:
        return "🟪 Execution Error"
    if "auto-remediated" in s:
        return "✅ Passed (Auto-Remediated)"
    if "pass" in s and "fail" not in s:
        return "🟢 Passed"
    if "fail" in s:
        return "🔴 Failed"
    return f"⬜ {att_status or '—'}"

def _risk_badge(risk: str) -> str:
    r = (risk or "Unknown").lower().strip()
    return {"high":"🟧 High","medium":"🟨 Medium","low":"🟩 Low"}.get(r, f"⬜ {risk or 'Unknown'}")

def _truncate(val: Any, max_len: int = 52) -> str:
    s = "" if val is None else str(val).strip().replace("\n", " ")
    if not s:
        return "—"
    return s if len(s) <= max_len else s[: max_len - 1] + "…"

def _display_value(proof_type: str, value: Any) -> str:
    # Executive-friendly rendering for common controls
    v = "" if value is None else str(value).strip()

    if proof_type == "keyvault_private_endpoint_exists":
        return "Private Endpoint: Present" if v else "Private Endpoint: Not Found"

    if proof_type == "keyvault_private_access":
        # defaultAction: Deny/Allow
        if v.lower() == "deny":
            return "Public Access: Disabled"
        if v.lower() == "allow":
            return "Public Access: Enabled"
        return f"Public Access: {_truncate(v, 28)}"

    if proof_type == "keyvault_controls_posture":
        if v.lower() == "disabled":
            return "Public Network Access: Disabled"
        if v:
            return f"Public Network Access: {_truncate(v, 28)}"
        return "Public Network Access: Unknown"

    if proof_type == "keyvault_purge_protection_enabled":
        if v.lower() == "true":
            return "Purge Protection: Enabled"
        if v.lower() in ("false", "null", ""):
            return "Purge Protection: Not Enabled"
        return f"Purge Protection: {_truncate(v, 28)}"

    if proof_type == "managed_identity_token_probe":
        return "Identity Context: Available" if v.lower() in ("ok", "true", "1", "") else "Identity Context: Available"

    return _truncate(value)

def _display_expected(proof_type: str, expected: Any) -> str:
    # Stable, executive "required" text where the raw expected is too technical
    if proof_type == "keyvault_private_endpoint_exists":
        return "Private Endpoint: Required"
    if proof_type == "keyvault_private_access":
        return "Public Access: Disabled"
    if proof_type == "keyvault_controls_posture":
        return "Public Network Access: Disabled"
    if proof_type == "keyvault_purge_protection_enabled":
        return "Purge Protection: Enabled"
    if proof_type == "managed_identity_token_probe":
        return "Identity Context: Available"
    return _truncate(expected)


st.set_page_config(page_title="FORTRESS Enterprise Assurance Platform", layout="wide")

st.markdown(
    """
<style>
.block-container { padding-top: 1.0rem; padding-bottom: 2.0rem; }
.card { border: 1px solid rgba(255,255,255,0.10); border-radius: 14px; padding: 14px 16px; background: rgba(20, 22, 28, 0.45); }
.kicker { font-size: 12px; opacity: 0.75; letter-spacing: .35px; }
.title { font-size: 30px; font-weight: 850; letter-spacing: .6px; margin-top: 2px; }
.sub { font-size: 13px; opacity: 0.86; margin-top: 2px; }
.small { font-size: 12px; opacity: 0.78; }
</style>
""",
    unsafe_allow_html=True,
)

# session keys
st.session_state.setdefault("open_job", None)
st.session_state.setdefault("open_baseline", None)
st.session_state.setdefault("confirm_clear", False)
st.session_state.setdefault("monitor_mode", "job")

health = _http_json("GET", "/health")
policy = _http_json("GET", "/policy")

if not policy.get("ok"):
    st.error(f"/policy failed: {policy.get('error')}")
    st.stop()

envs = policy.get("environments") or {}
proofs = policy.get("proofs") or {}
env_keys = sorted(list(envs.keys())) if isinstance(envs, dict) else ["dev"]
proof_keys = sorted(list(proofs.keys())) if isinstance(proofs, dict) else []

left, right = st.columns([4, 2])
with left:
    st.markdown(
        """<div class="card"><div class="kicker">EXECUTIVE ASSURANCE • POLICY-DRIVEN VERIFICATION • AUDIT-READY EVIDENCE</div><div class="title">FORTRESS Enterprise Assurance Platform</div><div class="sub">Simple, human-readable posture proofs with traceable evidence.</div></div>""",
        unsafe_allow_html=True,
    )
with right:
    st.markdown(
        f"""<div class="card"><div class="kicker">CONNECTED API</div><div style="margin-top:6px;font-weight:800;">{API_URL}</div><div class="small" style="margin-top:10px;">{_short_ts(health.get("timestamp"))}</div></div>""",
        unsafe_allow_html=True,
    )

st.divider()

tab_run, tab_jobs, tab_baselines, tab_catalog = st.tabs(["Run", "Jobs", "Baselines", "Catalog"])

with tab_run:
    left, right = st.columns([2, 3])

    with left:
        st.subheader("Execute")
        env = st.selectbox("Environment", env_keys, index=0)
        proof = st.selectbox("Proof type", proof_keys, index=0)

        meta = proofs.get(proof, {}) if isinstance(proofs, dict) else {}
        st.markdown(
            f"""<div class="card"><div class="kicker">What this proof checks</div><div style="margin-top:6px;font-weight:800;">{meta.get('description','')}</div><div class="small" style="margin-top:10px;"><b>Plane:</b> {meta.get('plane','General')} &nbsp; • &nbsp; <b>Risk:</b> {_risk_badge(str(meta.get('risk_level','Low')))} &nbsp; • &nbsp; <b>Blast radius:</b> {meta.get('blast_radius','Unknown')}</div><div class="small" style="margin-top:8px;"><b>Impact:</b> {meta.get('impact','—') or '—'}</div></div>""",
            unsafe_allow_html=True,
        )

        # Policy-aware timeout handling
        timeout_max = int(meta.get("timeout_sec_max", 120) or 120)

        # If policy max is small (like identity probe), allow smaller minimums
        timeout_min = 1 if timeout_max < 30 else 30

        # Default value must always be within bounds
        timeout_default = min(120, timeout_max)
        if timeout_default < timeout_min:
            timeout_default = timeout_min

        timeout_sec = st.number_input(
            "Timeout (sec)",
            min_value=int(timeout_min),
            max_value=int(max(timeout_min, timeout_max)),
            value=int(timeout_default),
            step=1 if timeout_max < 30 else 10,
        )

        b1, b2 = st.columns(2)
        with b1:
            if st.button("Start proof", type="primary", use_container_width=True):
                resp = _http_json("POST", "/proof/start", {"env": env, "proof": proof, "timeout_sec": int(timeout_sec)}, timeout=120)
                if resp.get("job_id"):
                    st.session_state["open_job"] = resp["job_id"]
                    st.session_state["open_baseline"] = None  # focus monitor on this job
                    st.session_state["monitor_mode"] = "job"
                    st.success(f"Started: {resp['job_id']}")
                else:
                    st.error(resp.get("error") or str(resp))
        with b2:
            if st.button("Run baseline", use_container_width=True):
                resp = _http_json("POST", f"/baselines/start?env={env}", {}, timeout=120)
                if resp.get("baseline_id"):
                    st.session_state["open_baseline"] = resp["baseline_id"]
                    st.session_state["open_job"] = None  # focus monitor on this baseline
                    st.session_state["monitor_mode"] = "baseline"
                    st.success(f"Baseline started: {resp['baseline_id']}")
                else:
                    st.error(resp.get("error") or str(resp))

        st.divider()
        st.subheader("Console controls")

        # ✅ Clear ledger should work in local dev even without a token IF the API isn't enforcing one.
        if not ADMIN_TOKEN:
            st.caption("Tip: If your API enforces admin operations, set FORTRESS_ADMIN_TOKEN on both API + UI. If not, clearing works without a token.")

        st.session_state["confirm_clear"] = st.checkbox(
            "I understand this will delete ledger history (SQLite).",
            value=bool(st.session_state["confirm_clear"]),
        )

        if st.button(
            "🧨 Clear ledger + reset console",
            use_container_width=True,
            disabled=(not st.session_state["confirm_clear"]),
        ):
            resp = _http_json("POST", "/admin/ledger/clear", {})
            if resp.get("ok"):
                st.session_state["open_job"] = None
                st.session_state["open_baseline"] = None
                st.success(f"Ledger cleared ✅ Jobs: {resp.get('jobs_deleted',0)} | Baselines: {resp.get('baselines_deleted',0)}")
                st.rerun()
            else:
                # If forbidden, guide the user clearly
                if resp.get("status_code") == 403:
                    st.error("Ledger clear is protected by an admin token. Set FORTRESS_ADMIN_TOKEN for both the API and UI, then retry.")
                else:
                    st.error(resp.get("error") or "Ledger clear failed.")

        show_rem = st.checkbox("Show remediation (only if proof fails)", value=False)
        # actual remediation shown in live monitor where status is known

    with right:
        st.subheader("Live monitor (simple view)")

        # Optional polish: monitor the most recent action (job vs baseline) and allow switching if both exist.
        job_id = st.session_state.get("open_job")
        baseline_id = st.session_state.get("open_baseline")

        choices = []
        if job_id:
            choices.append("Proof job")
        if baseline_id:
            choices.append("Baseline")

        if not choices:
            st.info("Start a proof or run a baseline to monitor it here.")
        else:
            preferred = st.session_state.get("monitor_mode", "job")
            default_choice = "Proof job" if preferred == "job" else "Baseline"
            if default_choice not in choices:
                default_choice = choices[0]

            if len(choices) > 1:
                sel = st.radio("Monitor", choices, horizontal=True, index=choices.index(default_choice))
            else:
                sel = choices[0]

            # Persist selection
            st.session_state["monitor_mode"] = "baseline" if sel == "Baseline" else "job"

            if sel == "Baseline":
                b = _http_json("GET", f"/baseline/{baseline_id}", timeout=120)
                if b.get("ok") is False:
                    st.error(b.get("error") or "Baseline not found.")
                else:
                    score = b.get("compliance_score", "—")
                    status = str(b.get("status") or "Completed")
                    env_b = b.get("env") or "—"

                    st.markdown(
                        f"""<div class="card"><div class="kicker">Summary</div><div style="margin-top:6px;font-weight:900;font-size:22px;">{("🟡 Running" if status.lower().startswith("run") else "✅ Completed")}</div><div class="small" style="margin-top:6px;"><b>Baseline:</b> {baseline_id} &nbsp; • &nbsp; <b>Environment:</b> {env_b}</div></div>""",
                        unsafe_allow_html=True,
                    )

                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Compliance score", score)
                    c2.metric("Total proofs", str(len((b.get("results") or {}) or {})))
                    # counts
                    passed = 0
                    failed = 0
                    results = b.get("results") or {}
                    if isinstance(results, dict):
                        for _, rr in results.items():
                            if isinstance(rr, dict):
                                s = str(rr.get("status") or "")
                                if "pass" in s.lower() and "fail" not in s.lower():
                                    passed += 1
                                elif "fail" in s.lower():
                                    failed += 1
                    c3.metric("Passed", str(passed))
                    c4.metric("Failed", str(failed))

                    st.markdown("#### What needs attention")
                    if failed == 0:
                        st.success("All controls are compliant in this baseline.")
                    else:
                        # show top failing controls
                        rows = []
                        if isinstance(results, dict):
                            for k, rr in results.items():
                                if isinstance(rr, dict) and "fail" in str(rr.get("status","")).lower():
                                    rows.append({
                                        "proof": k,
                                        "observed": rr.get("observed"),
                                        "expected": rr.get("expected"),
                                    })
                        st.dataframe(rows[:6], use_container_width=True, hide_index=True)
                        st.caption("Open the Baselines tab for the full table and drill-down.")

            else:
                job = _http_json("GET", f"/jobs/{job_id}", timeout=120)
                if job.get("ok") is False:
                    st.error(job.get("error") or "Job not found.")
                else:
                    result = job.get("result") or {}
                    att = (result.get("attestation") or {}) if isinstance(result, dict) else {}
                    att_status = str(att.get("status") or "—")
                    claim = str(att.get("claim") or "—")

                    blocks = att.get("evidence_blocks") or []
                    block = blocks[0] if isinstance(blocks, list) and blocks and isinstance(blocks[0], dict) else {}

                    proof_type = job.get("proof","")

                    st.markdown(
                        f"""<div class="card"><div class="kicker">Summary</div><div style="margin-top:6px;font-weight:900;font-size:22px;">{_result_badge(att_status)}</div><div class="small" style="margin-top:6px;"><b>What was checked:</b> {claim}</div></div>""",
                        unsafe_allow_html=True,
                    )

                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Environment", job.get("env","—"))
                    c2.metric("Proof type", job.get("proof","—"))
                    c3.metric("Created", _short_ts(job.get("created_at_utc")))
                    c4.metric("Completed", _short_ts(job.get("completed_at_utc")))

                    st.markdown("#### Result details")
                    # Executive-friendly view: meaning over raw values
                    d1, d2, d3 = st.columns(3)

                    if "execution error" in att_status.lower():
                        d1.metric("Current State", "—")
                        d2.metric("Required State", _display_expected(proof_type, block.get("expected","—")))
                        d3.metric("Evaluation Logic", "Command execution must succeed")
                        st.warning("Could not evaluate this control due to an execution error. Check technical details.")
                    else:
                        d1.metric("Current State", _display_value(proof_type, block.get("observed","—")))
                        d2.metric("Required State", _display_expected(proof_type, block.get("expected","—") or "—"))
                        d3.metric("Evaluation Logic", _truncate(block.get("evaluator","—"), 46))

                    st.markdown("#### Next action")
                    if "fail" in att_status.lower():
                        st.warning("This control is **not compliant**. Review remediation guidance.")
                    elif "execution error" in att_status.lower():
                        st.warning("Fix execution error, then rerun.")
                    else:
                        st.success("No action required. Control is compliant.")

                    remediation_should_show = ("fail" in att_status.lower()) or ("execution error" in att_status.lower()) or show_rem
                    if remediation_should_show:
                        with st.expander("Remediation guidance", expanded=("fail" in att_status.lower())):
                            rem = (result.get("remediation") or []) if isinstance(result, dict) else []
                            if rem:
                                for r in rem:
                                    if isinstance(r, dict):
                                        for kk, vv in r.items():
                                            st.code(f"{kk}: {vv}", language="text")
                                    else:
                                        st.code(str(r), language="text")
                            else:
                                st.caption("No remediation guidance defined.")

                    with st.expander("Technical details (for engineers)", expanded=False):
                        if block.get("stdout"):
                            st.markdown("**stdout**")
                            st.code(str(block.get("stdout")), language="text")
                        if block.get("stderr"):
                            st.markdown("**stderr**")
                            st.code(str(block.get("stderr")), language="text")
                        if block.get("command"):
                            st.markdown("**command**")
                            st.code(str(block.get("command")), language="text")

            # Auto-refresh only for running job or running baseline
            if st.checkbox("Auto-refresh while running", value=True):
                if sel == "Proof job" and job_id:
                    j = _http_json("GET", f"/jobs/{job_id}", timeout=120)
                    if (j.get("status") or "") in ("Running", "Remediating"):
                        time.sleep(1.5)
                        st.rerun()
                if sel == "Baseline" and baseline_id:
                    b2 = _http_json("GET", f"/baseline/{baseline_id}", timeout=120)
                    if str(b2.get("status") or "").lower().startswith("run"):
                        time.sleep(1.5)
                        st.rerun()
with tab_jobs:
    st.subheader("Jobs (ledger)")
    ids = _http_json("GET", "/jobs?limit=60").get("job_ids", []) or []
    if not ids:
        st.info("No jobs yet.")
    else:
        rows = []
        for jid in ids[:25]:
            j = _http_json("GET", f"/jobs/{jid}")
            res = j.get("result") or {}
            att = (res.get("attestation") or {}) if isinstance(res, dict) else {}
            meta = proofs.get(j.get("proof"), {}) if isinstance(proofs, dict) else {}
            rows.append({
                "job_id": jid,
                "result": _result_badge(str(att.get("status") or "—")),
                "proof": j.get("proof"),
                "env": j.get("env"),
                "risk": _risk_badge(str(meta.get("risk_level","Low"))),
                "created": _short_ts(j.get("created_at_utc")),
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)
        pick = st.selectbox("Open job", [r["job_id"] for r in rows], index=0)
        st.session_state["open_job"] = pick
        st.session_state["monitor_mode"] = "job"
        st.info("Open the **Run** tab to see the simplified monitor for this job.")

with tab_baselines:
    st.subheader("Baselines (ledger)")
    bids = _http_json("GET", "/baselines").get("baseline_ids", []) or []
    if not bids:
        st.info("No baselines yet.")
    else:
        pick = st.selectbox("Open baseline", bids, index=0)
        st.session_state["open_baseline"] = pick
        st.session_state["monitor_mode"] = "baseline"
        b = _http_json("GET", f"/baseline/{pick}", timeout=120)
        if b.get("ok") is False:
            st.error(b.get("error") or "Baseline not found.")
        else:
            st.metric("Compliance Score", b.get("compliance_score","—"))
            results = b.get("results") or {}
            rows = []
            if isinstance(results, dict):
                for k, r in results.items():
                    if isinstance(r, dict):
                        meta = proofs.get(k, {}) if isinstance(proofs, dict) else {}
                        rows.append({
                            "proof": k,
                            "result": _result_badge(r.get("status","—")),
                            "observed": r.get("observed"),
                            "expected": r.get("expected"),
                            "risk": _risk_badge(str(meta.get("risk_level","Low"))),
                        })
            st.dataframe(rows, use_container_width=True, hide_index=True)

with tab_catalog:
    st.subheader("Proof catalog")
    rows = []
    for k in proof_keys:
        m = proofs.get(k, {}) if isinstance(proofs, dict) else {}
        rows.append({
            "proof": k,
            "description": m.get("description",""),
            "plane": m.get("plane","General"),
            "risk": _risk_badge(str(m.get("risk_level","Low"))),
            "blast": m.get("blast_radius","Unknown"),
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)
