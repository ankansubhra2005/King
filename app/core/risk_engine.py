"""
Phase 2 - Module 8: Risk Prioritization Engine
Scores all findings based on signal strength, severity, and context.
"""
from typing import List, Dict
from app.models.models import Severity


# ── Weights ────────────────────────────────────────────────────────────────

SEVERITY_SCORES = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}

TYPE_MODIFIERS = {
    # API / Auth
    "SSRF (Confirmed)":            2.0,
    "JWT: Weak Secret":            2.0,
    "JWT: Algorithm Confusion":    1.8,
    "AWS Access Key":              2.0,
    "RSA Private Key":             2.0,
    "Stripe Secret Key":           2.0,
    # Access Control
    "IDOR (Potential)":            1.5,
    "Mass Assignment (Potential)": 1.4,
    "403/401 Bypass":              1.3,
    # Injection
    "Reflected XSS":               1.5,
    "DOM XSS (Potential)":         1.3,
    "Blind XSS (Injected)":        1.4,
    # Logic
    "CSRF (Missing Token)":        1.2,
}

# Finding types that indicate internet-exposed sensitive endpoints
HIGH_VALUE_PATTERNS = [
    "admin", "payment", "billing", "checkout", "user", "account",
    "password", "reset", "token", "secret", "config", "debug",
    "internal", "api", "graphql",
]


def score_finding(finding: Dict) -> Dict:
    """
    Compute risk_score (0-10) and annotate with why_it_matters and suggested_next_step.
    """
    finding_type = finding.get("type", "")
    severity_str = finding.get("severity", "info").lower()
    confidence = float(finding.get("confidence", 0.5))
    url = finding.get("url", "").lower()

    # Map severity string → Severity enum
    severity_map = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "low":      Severity.LOW,
        "info":     Severity.INFO,
    }
    severity = severity_map.get(severity_str, Severity.INFO)
    base = SEVERITY_SCORES[severity]

    # Type modifier
    type_mod = 1.0
    for key, mod in TYPE_MODIFIERS.items():
        if key.lower() in finding_type.lower():
            type_mod = mod
            break

    # Confidence modifier
    confidence_mod = 0.5 + confidence

    # High-value URL modifier
    url_mod = 1.2 if any(p in url for p in HIGH_VALUE_PATTERNS) else 1.0

    raw_score = base * type_mod * confidence_mod * url_mod
    risk_score = min(round(raw_score, 1), 10.0)

    # Why it matters
    why = _build_why(finding, severity, confidence)
    next_step = finding.get("suggested_next_step") or _default_next_step(finding_type)

    return {
        **finding,
        "risk_score": risk_score,
        "severity": severity.value,
        "why_it_matters": why,
        "suggested_next_step": next_step,
    }


def _build_why(finding: Dict, severity: Severity, confidence: float) -> str:
    t = finding.get("type", "")
    url = finding.get("url", "")
    conf_label = "High" if confidence >= 0.8 else "Medium" if confidence >= 0.5 else "Low"

    if "SSRF" in t:
        return f"SSRF can expose cloud metadata credentials (IAM keys), leading to full cloud account takeover."
    if "XSS" in t:
        return f"XSS enables session hijacking, credential theft, and malware delivery to users."
    if "JWT" in t and "Weak" in t:
        return f"Weak JWT secrets allow forging authentication tokens, bypassing identity checks."
    if "IDOR" in t:
        return f"IDOR allows unauthorized access to other users' data — a top-tier bug bounty bug."
    if "Mass Assignment" in t:
        return f"Mass assignment can promote a normal user to admin without authorization."
    if "403" in t or "Bypass" in t:
        return f"Bypassing 403 may expose admin panels, config files, or user data."
    if "CSRF" in t:
        return f"CSRF allows attackers to perform actions on behalf of authenticated users."
    if "Secret" in t or "Key" in t:
        return f"Leaked credentials may give direct access to cloud, database, or payment services."
    return f"{t} detected at {url[:60]} with {conf_label} confidence."


def _default_next_step(finding_type: str) -> str:
    if "SSRF" in finding_type:
        return "Probe /latest/meta-data/iam/security-credentials/ for cloud credentials."
    if "XSS" in finding_type:
        return "Record proof-of-concept video showing cookie exfiltration."
    if "IDOR" in finding_type:
        return "Access another user's resource and capture the response as evidence."
    if "JWT" in finding_type:
        return "Forge a token and test access to privileged endpoints."
    if "403" in finding_type or "Bypass" in finding_type:
        return "Capture HTTP request/response and confirm access to restricted resource."
    if "CSRF" in finding_type:
        return "Build a minimal HTML PoC page and test from a different origin."
    return "Validate finding manually and document evidence for report."


def prioritize(findings: List[Dict]) -> List[Dict]:
    """Score and sort all findings by risk_score descending."""
    scored = [score_finding(f) for f in findings]
    # Deduplicate by (type, url)
    seen = set()
    unique = []
    for f in scored:
        key = f.get("type", "") + f.get("url", "")
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return sorted(unique, key=lambda x: x.get("risk_score", 0), reverse=True)
