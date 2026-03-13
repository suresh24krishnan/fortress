from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


class ControlsResponse(BaseModel):
    ok: bool = True
    keyvault: Optional[str] = None
    public_network_access: Optional[str] = None
    rbac_enabled: Optional[bool] = None
    error: Optional[str] = None


class ProofStartRequest(BaseModel):
    env: str = Field(..., description="Environment key (e.g., dev)")
    proof: str = Field(..., description="Proof key (e.g., keyvault_controls_posture)")
    timeout_sec: Optional[int] = Field(None, description="Optional override, capped by policy")


class ProofStartResponse(BaseModel):
    job_id: str
    status: str


class EvidenceBlock(BaseModel):
    """Structured evidence designed for UI clarity."""
    proof: Optional[str] = None
    env: Optional[str] = None

    command: Optional[str] = None
    return_code: Optional[int] = None

    observed: Optional[Any] = None
    expected: Optional[Any] = None

    stdout: Optional[str] = None
    stderr: Optional[str] = None

    evaluator: Optional[str] = None  # human readable rule
    passed: Optional[bool] = None
    note: Optional[str] = None


class Attestation(BaseModel):
    claim: str
    status: str
    evidence: List[str] = Field(default_factory=list)

    # New, preferred structured evidence
    evidence_blocks: List[EvidenceBlock] = Field(default_factory=list)


class ProofResult(BaseModel):
    compliance_score: Optional[str] = None
    attestation: Attestation
    remediation_required: bool = False
    remediation: List[str] = Field(default_factory=list)


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    created_at_utc: str
    started_at_utc: Optional[str] = None
    completed_at_utc: Optional[str] = None

    env: Optional[str] = None
    proof: Optional[str] = None
    timeout_sec: int = 300

    step: Optional[str] = None
    diag: Optional[Dict[str, Any]] = None

    result: Optional[ProofResult] = None
    error: Optional[str] = None

    jira_ticket_id: Optional[str] = None
    jira_ticket_url: Optional[str] = None
