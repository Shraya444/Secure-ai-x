"""
SecureAI X — Vulnerability Scanner Engine
------------------------------------------
Static regex/heuristic based analyzer for PHP source code.
Detects common OWASP-class issues and returns structured findings
with line numbers, severity, snippets and CWE references.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Finding:
    id: str
    type: str
    severity: str          # critical | high | medium | low
    line: int
    snippet: str
    cwe: str
    description: str
    recommendation: str
    confidence: int = 80    # heuristic confidence percentage


# ---------------------------------------------------------------------------
# Rule definitions
# Each rule = (name, severity, cwe, regex, description, recommendation)
# ---------------------------------------------------------------------------

TAINT_SOURCES = r"(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER\[['\"]HTTP_)"

RULES = [
    dict(
        type="SQL Injection",
        severity="critical",
        cwe="CWE-89",
        pattern=re.compile(
            r"(mysqli?_query|->query|->exec|->prepare)\s*\([^;]*" + TAINT_SOURCES,
            re.IGNORECASE,
        ),
        description=(
            "User-controlled input is passed directly into a database query "
            "without parameterization or escaping. An attacker can alter the "
            "structure of the SQL statement."
        ),
        recommendation=(
            "Use prepared statements with bound parameters "
            "(PDO::prepare / mysqli prepared statements) instead of concatenating "
            "raw input into SQL strings."
        ),
    ),
    dict(
        type="SQL Injection (String Concatenation)",
        severity="critical",
        cwe="CWE-89",
        pattern=re.compile(
            r"(SELECT|INSERT|UPDATE|DELETE)[^;\"]*\.\s*" + TAINT_SOURCES,
            re.IGNORECASE,
        ),
        description=(
            "A SQL statement is being built by concatenating raw request data "
            "directly into the query string."
        ),
        recommendation=(
            "Never build SQL with string concatenation. Use prepared statements "
            "or an ORM/query builder that parameterizes input automatically."
        ),
    ),
    dict(
        type="Cross-Site Scripting (XSS)",
        severity="high",
        cwe="CWE-79",
        pattern=re.compile(
            r"(echo|print)\s+.*" + TAINT_SOURCES,
            re.IGNORECASE,
        ),
        description=(
            "User-controlled data is written directly to the HTML response "
            "without output encoding, allowing injected scripts to execute in "
            "the victim's browser."
        ),
        recommendation=(
            "Escape all output with htmlspecialchars($data, ENT_QUOTES, 'UTF-8') "
            "or a templating engine that auto-escapes by default."
        ),
    ),
    dict(
        type="Hardcoded Credentials",
        severity="high",
        cwe="CWE-798",
        pattern=re.compile(
            r"\$(password|pwd|passwd|secret|api_key|apikey|db_pass|token)\s*=\s*['\"][^'\"]{3,}['\"]",
            re.IGNORECASE,
        ),
        description=(
            "A credential or secret is embedded directly in the source code. "
            "Anyone with read access to the repository can retrieve it."
        ),
        recommendation=(
            "Move secrets to environment variables or a secrets manager "
            "(e.g. .env + getenv(), Vault, AWS Secrets Manager). Rotate any "
            "credential that has already been committed."
        ),
    ),
    dict(
        type="Insecure File Inclusion",
        severity="critical",
        cwe="CWE-98",
        pattern=re.compile(
            r"(include|include_once|require|require_once)\s*\(?\s*.*" + TAINT_SOURCES,
            re.IGNORECASE,
        ),
        description=(
            "A file path passed to include/require is influenced by user input, "
            "which can allow local or remote file inclusion (LFI/RFI)."
        ),
        recommendation=(
            "Never pass user input to include/require. Use a fixed allow-list "
            "of file names mapped internally instead of user-supplied paths."
        ),
    ),
    dict(
        type="Weak Cryptographic Hash",
        severity="medium",
        cwe="CWE-327",
        pattern=re.compile(r"\b(md5|sha1)\s*\(", re.IGNORECASE),
        description=(
            "A cryptographically broken hash function is used, which is unsuitable "
            "for password storage or integrity guarantees."
        ),
        recommendation=(
            "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID for "
            "passwords, and hash_hmac('sha256', ...) for integrity checks."
        ),
    ),
    dict(
        type="Insecure Deserialization",
        severity="high",
        cwe="CWE-502",
        pattern=re.compile(r"unserialize\s*\(\s*.*" + TAINT_SOURCES, re.IGNORECASE),
        description=(
            "Untrusted data is passed to unserialize(), which can lead to "
            "PHP object injection and remote code execution via gadget chains."
        ),
        recommendation=(
            "Use json_decode()/json_encode() for data interchange instead of "
            "PHP's native serialization when the source is untrusted."
        ),
    ),
    dict(
        type="Code Injection (eval)",
        severity="critical",
        cwe="CWE-95",
        pattern=re.compile(r"\beval\s*\(", re.IGNORECASE),
        description=(
            "eval() executes a string as PHP code. If any part of that string "
            "is influenced by user input, an attacker can run arbitrary code."
        ),
        recommendation=(
            "Avoid eval() entirely. Replace dynamic logic with explicit "
            "functions, match/switch statements, or a safe expression parser."
        ),
    ),
    dict(
        type="Command Injection",
        severity="critical",
        cwe="CWE-78",
        pattern=re.compile(
            r"(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*.*" + TAINT_SOURCES,
            re.IGNORECASE,
        ),
        description=(
            "User input is passed to a shell command execution function, "
            "allowing an attacker to inject and run arbitrary OS commands."
        ),
        recommendation=(
            "Avoid shelling out with user input. If unavoidable, use "
            "escapeshellarg()/escapeshellcmd() and validate against an allow-list."
        ),
    ),
    dict(
        type="Missing CSRF Protection",
        severity="low",
        cwe="CWE-352",
        pattern=re.compile(r"<form[^>]*method=['\"]post['\"][^>]*>", re.IGNORECASE),
        description=(
            "A POST form was found with no visible CSRF token field, which may "
            "allow cross-site request forgery if the backend does not validate one."
        ),
        recommendation=(
            "Include a per-session CSRF token as a hidden field and verify it "
            "server-side on every state-changing request."
        ),
        needs_secondary_check=True,  # only flag if no csrf token nearby
    ),
]


def _severity_weight(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 0)


def scan_php_source(source: str, filename: str = "uploaded.php") -> List[Finding]:
    """Run all rules against PHP source, line by line, and return findings."""
    findings: List[Finding] = []
    lines = source.splitlines()
    counter = 1

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue

        for rule in RULES:
            if rule["pattern"].search(raw_line):
                # secondary heuristic for CSRF: skip if a csrf token appears nearby
                if rule.get("needs_secondary_check"):
                    window = "\n".join(
                        lines[max(0, idx - 1): min(len(lines), idx + 4)]
                    )
                    if re.search(r"csrf", window, re.IGNORECASE):
                        continue

                findings.append(
                    Finding(
                        id=f"VULN-{counter:04d}",
                        type=rule["type"],
                        severity=rule["severity"],
                        line=idx,
                        snippet=raw_line.strip()[:160],
                        cwe=rule["cwe"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        confidence=_confidence_for(rule["severity"]),
                    )
                )
                counter += 1

    findings.sort(key=lambda f: (-_severity_weight(f.severity), f.line))
    return findings


def _confidence_for(severity: str) -> int:
    return {"critical": 94, "high": 87, "medium": 78, "low": 65}.get(severity, 70)


def findings_to_dicts(findings: List[Finding]) -> List[Dict]:
    return [f.__dict__ for f in findings]
