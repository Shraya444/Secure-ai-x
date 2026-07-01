"""
SecureAI X — AI Explanation Layer
Turns a raw finding into a plain-English explanation a beginner can learn from.

By default this runs fully offline using curated templates (no API key needed).
If an ANTHROPIC_API_KEY environment variable is present, it will instead ask
Claude to generate a tailored explanation for extra polish. Everything still
works with zero configuration.
"""

import os
from typing import Dict

_client = None
_AI_AVAILABLE = False

try:
    if os.environ.get("ANTHROPIC_API_KEY"):
        import anthropic
        _client = anthropic.Anthropic()
        _AI_AVAILABLE = True
except Exception:
    _AI_AVAILABLE = False


TEMPLATES = {
    "SQL Injection": (
        "This line hands attacker-controlled text straight to the database. "
        "By typing something like ' OR 1=1 -- into the form, an attacker can "
        "change what the query actually does — for example, logging in as any "
        "user without a password."
    ),
    "SQL Injection (String Concatenation)": (
        "The SQL command is being glued together as plain text using request "
        "data. Anything the visitor types becomes part of the command itself, "
        "so a crafted input can rewrite the query's logic."
    ),
    "Cross-Site Scripting (XSS)": (
        "Whatever the visitor types is echoed back into the page as-is. If they "
        "submit a <script> tag instead of normal text, the browser will run it — "
        "which can steal cookies or hijack the session of anyone who views it."
    ),
    "Hardcoded Credentials": (
        "A real password or key is sitting in plain text inside the source file. "
        "Anyone who can read the code — a teammate, a leaked repo, a backup — "
        "gets the credential for free."
    ),
    "Insecure File Inclusion": (
        "The file being loaded is decided by user input. An attacker can point "
        "this at an unexpected file on the server, or in some setups at a remote "
        "URL, to get their own code executed."
    ),
    "Weak Cryptographic Hash": (
        "md5/sha1 were broken long ago and can be reversed with lookup tables in "
        "seconds. Using them for passwords means a stolen database is basically "
        "a plaintext password list."
    ),
    "Insecure Deserialization": (
        "unserialize() rebuilds PHP objects from raw text. If that text comes "
        "from the user, a crafted payload can trick the app into instantiating "
        "objects it never intended to — a classic path to remote code execution."
    ),
    "Code Injection (eval)": (
        "eval() runs a string as if it were code you wrote yourself. If any part "
        "of that string can be influenced by a request, the attacker is now "
        "writing PHP that runs on your server."
    ),
    "Command Injection": (
        "This line asks the operating system to run a shell command built with "
        "user input. A crafted value can chain on extra commands (e.g. ; rm -rf) "
        "that the server will happily execute."
    ),
    "Missing CSRF Protection": (
        "This form changes state (POST) but doesn't appear to check a per-session "
        "token. A malicious site could auto-submit this form from a logged-in "
        "victim's browser without their knowledge."
    ),
}


def explain(finding: Dict) -> str:
    """Return a beginner-friendly explanation for a finding."""
    if _AI_AVAILABLE:
        try:
            return _explain_with_claude(finding)
        except Exception:
            pass  # fall back silently to template
    return TEMPLATES.get(
        finding["type"],
        "This pattern is commonly associated with a security weakness — review "
        "the flagged line and validate/sanitize any external input involved.",
    )


def _explain_with_claude(finding: Dict) -> str:
    msg = _client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=180,
        messages=[{
            "role": "user",
            "content": (
                "You are a security tutor. In under 60 words, plainly explain to "
                "a junior developer why this PHP code is a "
                f"{finding['type']} vulnerability and what an attacker could do "
                f"with it. Code line: {finding['snippet']}"
            ),
        }],
    )
    return "".join(block.text for block in msg.content if block.type == "text").strip()
