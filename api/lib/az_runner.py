from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Union


@dataclass
class AzResult:
    ok: bool
    code: int
    stdout: str
    stderr: str
    argv: Optional[List[str]] = None  # helpful for debugging


def _resolve_az_path() -> Optional[str]:
    override = os.getenv("AZ_CLI_PATH")
    if override and os.path.exists(override):
        return override

    found = shutil.which("az")
    if found:
        return found

    candidates = [
        r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
        r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def _kill_process_tree_windows(pid: int) -> None:
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            shell=False,
        )
    except Exception:
        pass


# -------------------------
# Fortress Boundary Guardrails (fail-closed)
# -------------------------
def _violates_boundary(argv: List[str]) -> Optional[str]:
    """
    Returns a reason string if the command violates Fortress boundary rules.
    These guardrails prevent secret/PII exfiltration *at execution time*.
    """
    lower = [a.lower() for a in argv]

    # ---- Guardrail: Key Vault secret value retrieval ----
    if "keyvault" in lower and "secret" in lower:
        # az keyvault secret show ... --query value
        if "show" in lower and "--query" in lower:
            try:
                q_idx = lower.index("--query") + 1
                if q_idx < len(lower) and lower[q_idx].strip().lower() == "value":
                    return "Blocked: Key Vault secret value retrieval is not allowed (--query value)."
            except Exception:
                pass

        # az keyvault secret download ...
        if "download" in lower:
            return "Blocked: Key Vault secret download is not allowed."

    # ---- Guardrail: Token extraction patterns ----
    if "--query" in lower:
        try:
            q_idx = lower.index("--query") + 1
            if q_idx < len(lower):
                q = lower[q_idx].strip().lower()
                if q in ("accesstoken", "refreshtoken", "value"):
                    return f"Blocked: sensitive query target is not allowed (--query {q})."
        except Exception:
            pass

    # ---- Guardrail: Identity context dumps (PII risk) ----
    # Block `az account show -o json` unless it uses a restrictive --query subset.
    if "account" in lower and "show" in lower:
        # NEW GUARDRAIL: block tabular outputs that commonly leak PII (email)
        if "-o" in lower:
            try:
                o_idx = lower.index("-o") + 1
                fmt = lower[o_idx] if o_idx < len(lower) else ""
                if fmt in ("tsv", "table"):
                    return f"Blocked: 'az account show -o {fmt}' may expose PII. Use '-o json' with a safe --query subset."
                if fmt == "json" and "--query" not in lower:
                    return "Blocked: 'az account show -o json' without '--query' may expose PII. Use a safe --query subset."
            except Exception:
                pass

    return None


def run_az(cmd: Union[List[str], str], timeout_sec: int = 60, cwd: Optional[str] = None) -> AzResult:
    """
    STRICT argv-only runner.

    Why: allowing string commands causes Windows space-splitting bugs,
    e.g. 'C:\\Program' is not recognized...
    """
    # ---------------------------------------
    # DEMO MODE (used in HF Spaces)
    # ---------------------------------------
    if os.getenv("FORTRESS_DEMO_MODE", "").lower() == "true":
        return AzResult(
            ok=True,
            code=0,
            stdout="Deny",
            stderr="",
            argv=["demo-mode"]
        )
    az_path = _resolve_az_path()
    if not az_path:
        return AzResult(ok=False, code=127, stdout="", stderr="Azure CLI not found on PATH (or AZ_CLI_PATH).", argv=None)

    # 🚫 Fail fast if caller passes a string (forces you to fix the call site)
    if isinstance(cmd, str):
        return AzResult(
            ok=False,
            code=2,
            stdout="",
            stderr="run_az() requires argv List[str]. String command detected; fix caller to pass a list.",
            argv=None,
        )

    argv = [str(x) for x in cmd if str(x).strip() != ""]
    if not argv:
        return AzResult(ok=False, code=2, stdout="", stderr="Empty az command argv.", argv=[])

    # Replace leading 'az' with absolute path
    if argv[0].lower() == "az":
        argv[0] = az_path

    # If az entrypoint is .cmd/.bat, run via cmd.exe /c <az.cmd> <args...>
    az0 = (argv[0] or "").lower()
    if az0.endswith(".cmd") or az0.endswith(".bat"):
        argv = ["cmd.exe", "/c"] + argv

    # Enforce boundary guardrails BEFORE execution
    violation = _violates_boundary(argv)
    if violation:
        return AzResult(
            ok=False,
            code=3,  # distinct "blocked by Fortress" code
            stdout="",
            stderr=f"FORTRESS BLOCKED: {violation}",
            argv=argv,
        )

    p = None
    try:
        p = subprocess.Popen(
            argv,
            cwd=cwd or os.getcwd(),  # ✅ never None
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,  # ✅ critical
        )
        try:
            out, err = p.communicate(timeout=timeout_sec)
            rc = p.returncode if p.returncode is not None else 1
            return AzResult(ok=(rc == 0), code=rc, stdout=out or "", stderr=err or "", argv=argv)
        except subprocess.TimeoutExpired:
            if os.name == "nt" and p.pid:
                _kill_process_tree_windows(p.pid)
            else:
                try:
                    p.kill()
                except Exception:
                    pass

            try:
                out, err = p.communicate(timeout=5)
            except Exception:
                out, err = "", ""

            suffix = f"TIMEOUT after {timeout_sec}s"
            err_clean = (err or "").strip()
            err_final = (err_clean + ("\n" if err_clean else "") + suffix)

            return AzResult(ok=False, code=124, stdout=out or "", stderr=err_final, argv=argv)

    except Exception as e:
        return AzResult(ok=False, code=1, stdout="", stderr=f"ERROR: {e!r}", argv=argv)
    finally:
        try:
            if p and p.poll() is None:
                p.kill()
        except Exception:
            pass