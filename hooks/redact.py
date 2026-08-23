#!/usr/bin/env python3
"""Mask credential-shaped values in tool output before the model reads them.

Two events, two jobs:
  PostToolUse    -- replaces the value in the tool result, so the secret never
                    enters the model's context in the first place.
  MessageDisplay -- replaces only what is rendered on screen.

Never logs its input. A redactor that writes what it redacted to a log file has
simply moved the leak somewhere with fewer eyes on it.

Also usable as a plain filter:  some-command | python3 redact.py
"""
from __future__ import annotations

import json
import re
import sys

REPLACEMENT = "<CREDENTIAL_REDACTED>"

# Patterns that replace the whole match.
FULL = [
    re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\b\d{7,12}:[A-Za-z0-9_-]{20,}\b"),                    # bot token
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]
# Patterns that keep their label and replace only the value. Losing the label
# would hide *that* a credential was there, which is worth knowing.
LABELLED = [
    re.compile(r"(?i)(\bAuthorization\s*:\s*(?:Bearer|Basic)\s+)[^\s,;]+"),
    # No required prefix character: `API_KEY=x` must match, not just `MY_API_KEY=x`.
    re.compile(r"(?i)(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|"
               r"PRIVATE_?KEY)\s*[:=]\s*)[^\s,;]+"),
]
# user:password@host -- keep the scheme and the user, drop the password.
URL_CREDENTIALS = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^:/@\s'\"]+):([^@/\s'\"]+)@")


def redact_text(value):
    for pattern in FULL:
        value = pattern.sub(REPLACEMENT, value)
    for pattern in LABELLED:
        value = pattern.sub(lambda m: m.group(1) + REPLACEMENT, value)
    return URL_CREDENTIALS.sub(lambda m: m.group(1) + ":" + REPLACEMENT + "@", value)


def redact_value(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        sys.stdout.write(redact_text(raw))    # plain filter mode
        return 0
    if not isinstance(data, dict):
        sys.stdout.write(redact_text(raw))
        return 0

    event = data.get("hook_event_name")
    if event == "MessageDisplay":
        original = str(data.get("delta", ""))
        redacted = redact_text(original)
        if redacted != original:
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "MessageDisplay",
                "displayContent": redacted,
            }}, ensure_ascii=False))
    elif event == "PostToolUse":
        original = data.get("tool_response")
        redacted = redact_value(original)
        if redacted != original:
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": redacted,
                "additionalContext": "Credentials were removed from this result. "
                                     "Do not try to reconstruct or display them.",
            }}, ensure_ascii=False))
    else:
        sys.stdout.write(redact_text(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
