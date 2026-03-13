from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple

import yaml


# -----------------------------
# Data model (what API expects)
# -----------------------------
@dataclass
class EnvironmentDef:
    subscription_name: str
    resource_group: str
    location: Optional[str] = None
    keyvault_name: Optional[str] = None


@dataclass
class ProofDef:
    description: str
    timeout_sec_max: int
    script: List[str]

    # Backward-compatible display strings (UI-friendly)
    remediation: List[str]

    # Preferred execution-safe argv steps (for future-proof engine)
    remediation_argv: List[List[str]]

    # Optional metadata (high-signal UI grouping)
    plane: str = "General"
    risk_level: str = "Low"
    blast_radius: str = "Unknown"
    impact: str = ""


@dataclass
class Policy:
    environments: Dict[str, EnvironmentDef]
    proofs: Dict[str, ProofDef]
    controls: Dict[str, Any]


# -----------------------------
# Helpers
# -----------------------------
def _policy_path() -> str:
    """
    Resolve policy file location.
    Priority:
      1) FORTRESS_POLICY env var
      2) repo_root/policy/policy.yaml
    """
    override = os.getenv("FORTRESS_POLICY")
    if override and os.path.exists(override):
        return override

    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    fallback = os.path.join(repo_root, "policy", "policy.yaml")

    if os.path.exists(fallback):
        return fallback

    raise FileNotFoundError(
        f"policy.yaml not found. Checked env override={override!r} and fallback={fallback!r}"
    )


def _as_list(val: Any) -> List[Any]:
    """
    We allow:
      - list[str]
      - list[list[str]]  (for remediation argv)
      - single str
    """
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _is_json_expr(token: str) -> bool:
    t = (token or "").strip()
    return t.startswith("{") and t.endswith("}")


def _validate_argv_split(proof_key: str, argv: List[str], field: str) -> None:
    """
    Enforce "argv-split" policy for executable argv lists.
    Reject elements that contain spaces (single-line commands),
    except JSON-ish query blocks like "{tenantId:tenantId,id:id}".
    """
    if not argv:
        raise ValueError(f"Proof '{proof_key}' must define a non-empty '{field}' list")

    for token in argv:
        t = (str(token) or "").strip()
        if not t:
            continue

        if (" " in t) and (not _is_json_expr(t)):
            raise ValueError(
                f"Proof '{proof_key}' {field} must be argv-split (one token per '-' line). "
                f"Invalid element: {t!r}"
            )


def _normalize_remediation(
    proof_key: str, remediation_raw: Any
) -> Tuple[List[str], List[List[str]]]:
    """
    Returns:
      - remediation_display: List[str] (UI display; backward compatible)
      - remediation_argv:    List[List[str]] (execution-safe argv)
    Accepts remediation entries as:
      - "Escalate: ..."                         -> display-only
      - "az keyvault update ..."                -> display + argv (parsed via shlex)
      - ["az", "keyvault", "update", ...]       -> display + argv (preferred)
    """
    remediation_display: List[str] = []
    remediation_argv: List[List[str]] = []

    items = _as_list(remediation_raw)
    for item in items:
        # Preferred: explicit argv list
        if isinstance(item, list):
            argv = [str(x).strip() for x in item if str(x).strip()]
            if argv:
                _validate_argv_split(proof_key, argv, "remediation")
                remediation_argv.append(argv)
                remediation_display.append(" ".join(argv))
            continue

        # String form
        s = str(item).strip()
        if not s:
            continue

        remediation_display.append(s)

        # If it's an az command string, also make it executable argv
        if s.lower().startswith("az "):
            argv = shlex.split(s, posix=False)
            argv = [str(x).strip() for x in argv if str(x).strip()]
            if argv:
                # Validate argv tokens (no embedded spaces)
                _validate_argv_split(proof_key, argv, "remediation")
                remediation_argv.append(argv)

    return remediation_display, remediation_argv


# -----------------------------
# Public API
# -----------------------------
def load_policy() -> Policy:
    path = _policy_path()
    if not os.path.exists(path):
        raise FileNotFoundError(f"policy.yaml not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    envs_raw = data.get("environments") or {}
    proofs_raw = data.get("proofs") or {}
    controls_raw = data.get("controls") or {}

    if not envs_raw:
        raise ValueError("policy.yaml has no environments configured.")
    if not proofs_raw:
        raise ValueError("policy.yaml has no proofs configured.")

    environments: Dict[str, EnvironmentDef] = {}
    for env_key, cfg in envs_raw.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"Environment '{env_key}' must be a mapping")

        sub = str(cfg.get("subscription_name") or "").strip()
        rg = str(cfg.get("resource_group") or "").strip()
        if not sub or not rg:
            raise ValueError(f"Environment '{env_key}' must include subscription_name and resource_group")

        environments[str(env_key)] = EnvironmentDef(
            subscription_name=sub,
            resource_group=rg,
            location=cfg.get("location"),
            keyvault_name=cfg.get("keyvault_name"),
        )

    proofs: Dict[str, ProofDef] = {}
    for proof_key, cfg in proofs_raw.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"Proof '{proof_key}' must be a mapping")

        description = str(cfg.get("description") or "").strip()
        timeout_sec_max = int(cfg.get("timeout_sec_max") or 120)

        # Script: MUST be argv-split list[str]
        script_raw = _as_list(cfg.get("script"))
        script = [str(s).strip() for s in script_raw if str(s).strip()]
        _validate_argv_split(str(proof_key), script, "script")

        # Metadata (optional)
        plane = str(cfg.get("plane") or "General").strip() or "General"
        risk_level = str(cfg.get("risk_level") or "Low").strip() or "Low"
        blast_radius = str(cfg.get("blast_radius") or "Unknown").strip() or "Unknown"
        impact = str(cfg.get("impact") or "").strip()

        # Remediation: flexible input, normalized to display + argv
        remediation_display, remediation_argv = _normalize_remediation(str(proof_key), cfg.get("remediation"))

        proofs[str(proof_key)] = ProofDef(
            description=description,
            timeout_sec_max=timeout_sec_max,
            script=script,
            remediation=remediation_display,
            remediation_argv=remediation_argv,
            plane=plane,
            risk_level=risk_level,
            blast_radius=blast_radius,
            impact=impact,
        )

    return Policy(environments=environments, proofs=proofs, controls=controls_raw)