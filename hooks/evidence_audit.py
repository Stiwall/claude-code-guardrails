#!/usr/bin/env python3
"""Stop hook: refuse completion claims that have no evidence in this turn.

An agent that says "deployed and verified" after a turn containing neither a
deploy nor a check is not lying on purpose -- it is pattern-matching on what a
finished task usually sounds like. This hook reads the current turn from the
transcript and compares what the message *claims* against what the turn
actually *did*.

It never prints transcript text, commands, paths or tool output: only which
claim lacks backing.

Returning {"decision": "block", "reason": ...} sends the reason back to the
model and asks it to keep working.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# --- what the user asked for -------------------------------------------------
ACTION_REQUEST = re.compile(
    r"\b(fix|build|create|change|configure|implement|install|delete|modify|"
    r"update|add|push|send|deploy|publish|write|rename|migrate|refactor)\b", re.I)
# A verb after a question word is a QUESTION, not an order: "what does update do"
# asks for an explanation; "update the config" asks for work.
INTERROGATIVE_LEAD = re.compile(
    r"(what|which|how|why|when|where|who)(?:\s+\w+){0,3}\s*$", re.I)

# --- what the message claims -------------------------------------------------
COMPLETION_CLAIM = re.compile(
    r"\b(done|finished|completed|fixed|implemented|configured|updated|installed|"
    r"created|ready|all set|i (?:have|'ve) (?:done|created|fixed|configured|"
    r"updated|implemented|installed))\b", re.I)
TEST_CLAIM = re.compile(
    r"\b(tests?|test suite|lint|build|suite)\b.{0,45}\b(pass(?:ed|ing|es)?|green|"
    r"ok|successful|succeeded)\b|\b\d+\s*/\s*\d+\b.{0,30}\b(pass(?:ed|ing)?)\b",
    re.I | re.S)
VERIFY_CLAIM = re.compile(r"\b(verified|validated|confirmed|checked)\b", re.I)
DEPLOY_CLAIM = re.compile(r"\b(deployed|published|shipped|in production|live)\b", re.I)
PUSH_CLAIM = re.compile(r"\b(pushed|merged)\b", re.I)
SEND_CLAIM = re.compile(r"\b(sent|delivered|emailed|uploaded)\b", re.I)
# Hedged language is not a claim. "not verified" must never trip the verify rule.
# Every negation form that is missing turns a sentence that DENIES into one that
# asserts -- the worst direction for this to fail in. neither/nor/none were
# missing and cost a false block.
NEGATION = re.compile(
    r"\b(no|not|never|neither|nor|none|without|pending|partial|partially|"
    r"unverified|couldn'?t|could not|cannot|can'?t|unable|failed|incomplete|"
    r"still|yet)\b", re.I)

# Quoting a claim is not making one. This hook once blocked a turn because the
# message contained the example "I pushed to origin" while explaining a test --
# the same mistake guard.py made until it learned to strip heredoc bodies.
# Only SHORT spans are stripped: a whole paragraph in quotes is still a claim
# wearing a costume.
QUOTED_SPAN = re.compile(
    "`[^`\n]{1,80}`"
    "|\u00ab[^\u00bb\n]{1,80}\u00bb"
    "|[\u201c\"][^\u201d\"\n]{1,80}[\u201d\"]"
    "|[\u2018'][^\u2019'\n]{1,80}[\u2019']")


def strip_quotes(text):
    return QUOTED_SPAN.sub(" ", text)

# --- the closing receipt -----------------------------------------------------
RECEIPT_FIELDS = {
    "changes": re.compile(r"(?:^|\n)\s*[-*#]*\s*(?:changes?|artifacts?)\s*:", re.I),
    "evidence": re.compile(r"(?:^|\n)\s*[-*#]*\s*(?:evidence|verification)\s*:", re.I),
    "location": re.compile(r"(?:^|\n)\s*[-*#]*\s*(?:location|destination|where)\s*:", re.I),
    "pending": re.compile(r"(?:^|\n)\s*[-*#]*\s*(?:pending|limitations?|not done)\s*:", re.I),
}

# --- what a tool call actually is --------------------------------------------
SHELL_MUTATION = re.compile(
    r"(^|[;&|]\s*)(apply_patch|sed\s+-i|cp\s|mv\s|touch\s|mkdir\s|chmod\s|chown\s|"
    r"ln\s|git\s+(?:add|commit|push|merge)|npm\s+(?:install|publish)|pip\s+install|"
    r"docker\s+(?:run|compose\s+up)|systemctl\s+(?:restart|start|stop|enable)|scp\s|"
    r"rsync\s|curl\s+.*(?:-X\s+(?:POST|PUT|PATCH|DELETE)|--request\s+"
    r"(?:POST|PUT|PATCH|DELETE)))\b", re.I)
# Python counts as a check only when it reads. If it writes, it is a mutation.
PY_WRITE = re.compile(
    r"python3?\b.{0,400}?(open\([^)]*['\"][wax]|\.write\(|os\.replace|"
    r"shutil\.(copy|move)|os\.(remove|unlink|rename|mkdir)|json\.dump\(|writelines)",
    re.I | re.S)
PY_READ = re.compile(
    r"python3?\b.{0,400}?(open\(|\.read\(|readlines|json\.load|os\.listdir|os\.stat|"
    r"os\.path\.exists|glob\.|hashlib|print\()", re.I | re.S)
SHELL_VERIFY = re.compile(
    r"\b(pytest|unittest|jest|playwright|npm\s+(?:test|run\s+(?:test|lint|build|check))|"
    r"cargo\s+test|go\s+test|node\s+--check|py_compile|bash\s+-n|git\s+(?:diff|status|"
    r"log|show|rev-parse)|sha256sum|cmp|rg|grep|sed\s+-n|head|tail|curl|journalctl|"
    r"systemctl\s+status|health|check)\b", re.I)
SHELL_TEST = re.compile(
    r"\b(pytest|unittest|jest|playwright|npm\s+(?:test|run\s+(?:test|lint|build|check))|"
    r"cargo\s+test|go\s+test|node\s+--check|py_compile|bash\s+-n)\b", re.I)
# Publishing is not always `git push`. A whole repository was created and made
# public with `gh repo create --push`, and the audit asked for \"a deploy action\"
# that had in fact happened. Package publishing counts the same way.
SHELL_DEPLOY = re.compile(
    r"\b(railway\s+(?:up|redeploy)|vercel\s+deploy|fly\s+deploy|docker\s+compose\s+up|"
    r"kubectl\s+(?:apply|rollout)|systemctl\s+restart|git\s+push\b|"
    r"gh\s+repo\s+create[^|;&]*--push|gh\s+release\s+create|npm\s+publish|"
    r"twine\s+upload|cargo\s+publish)", re.I)
SHELL_PUSH = re.compile(r"\bgit\s+push\b", re.I)
SHELL_SEND = re.compile(r"\b(sendMessage|sendDocument|scp\s|rsync\s|mail\s)", re.I)


def _text(content):
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(block.get("text", "") for block in content
                     if isinstance(block, dict) and block.get("type") == "text")


def _positive(pattern, message):
    """True when the pattern fires in a sentence that is not hedged.

    Sentence-level, deliberately: "tests pass" and "tests did not pass" differ
    by one word, and a whole-message check would treat them the same.
    """
    return any(pattern.search(part) and not NEGATION.search(part)
               for part in re.split(r"(?<=[.!?])\s+|\n+", strip_quotes(message)))


def _asks_for_action(prompt):
    for match in ACTION_REQUEST.finditer(prompt):
        if not INTERROGATIVE_LEAD.search(prompt[:match.start()]):
            return True
    return False


def _tool_kind(name, tool_input):
    """Classify one call: (mutation, verification, test, deploy, push_or_send)."""
    low = name.lower()
    command = str(tool_input.get("command", "")) if isinstance(tool_input, dict) else ""
    if low == "bash":
        py_write = bool(PY_WRITE.search(command))
        py_read = bool(PY_READ.search(command)) and not py_write
        return (bool(SHELL_MUTATION.search(command)) or py_write,
                bool(SHELL_VERIFY.search(command)) or py_read,
                bool(SHELL_TEST.search(command)),
                bool(SHELL_DEPLOY.search(command)),
                bool(SHELL_PUSH.search(command) or SHELL_SEND.search(command)))
    mutation = low in {"write", "edit", "multiedit", "notebookedit"}
    if low not in {"todowrite", "updateplan"}:
        mutation |= bool(re.search(
            r"(?:^|__)(create|update|delete|remove|send|merge|deploy|set|push|"
            r"upload|post|publish|write|edit)(?:_|$)", low))
    verification = low in {"read", "grep", "glob", "webfetch", "websearch"} or bool(
        re.search(r"(?:^|__)(get|list|search|check|status|logs?|read|inspect)(?:_|$)", low))
    return (mutation, verification,
            bool(re.search(r"(?:^|__)(test|lint|build|check)(?:_|$)", low)),
            bool(re.search(r"(?:^|__)(deploy|publish|redeploy)(?:_|$)", low)),
            bool(re.search(r"(?:^|__)(push|send|upload|post)(?:_|$)", low)))


def _current_turn(path):
    """Read the transcript back to the last real user message.

    A user row carrying a tool_result is the harness returning output, not the
    person speaking -- treating those as new turns would reset the evidence
    counter halfway through the work.
    """
    prompt, tools, by_id = "", [], {}
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except Exception:
        return prompt, tools
    for raw in lines:
        try:
            row = json.loads(raw)
        except Exception:
            continue
        message = row.get("message") if isinstance(row.get("message"), dict) else {}
        role, content = message.get("role"), message.get("content")
        if role == "user" and not row.get("isMeta") and not row.get("isSidechain"):
            has_result = isinstance(content, list) and any(
                isinstance(b, dict) and b.get("type") == "tool_result" for b in content)
            user_text = _text(content)
            if user_text and not has_result:
                prompt, tools, by_id = user_text, [], {}
        if role == "assistant" and isinstance(content, list):
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                item = {"id": str(block.get("id", "")), "name": str(block.get("name", "")),
                        "input": block.get("input") if isinstance(block.get("input"), dict) else {},
                        "success": None}
                tools.append(item)
                if item["id"]:
                    by_id[item["id"]] = item
        if role == "user" and isinstance(content, list):
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                item = by_id.get(str(block.get("tool_use_id", "")))
                if item is not None:
                    item["success"] = not bool(block.get("is_error", False))
    return prompt, tools


def audit(data):
    message = str(data.get("last_assistant_message", ""))
    prompt, tools = _current_turn(str(data.get("transcript_path", "")))
    successful = [t for t in tools if t.get("success") is not False]
    kinds = [(_tool_kind(t["name"], t["input"]), position)
             for position, t in enumerate(successful)]

    def positions(index):
        return [position for kind, position in kinds if kind[index]]

    mutations, verifications, tests = positions(0), positions(1), positions(2)
    deploys, push_or_sends = positions(3), positions(4)
    claims_complete = _positive(COMPLETION_CLAIM, message)
    problems = []

    running = [t for t in data.get("background_tasks", [])
               if t.get("status") in {"running", "pending", "in_progress"}]
    if running and claims_complete:
        problems.append("Background work is still running, but the message says it finished.")
    if _asks_for_action(prompt) and claims_complete and not mutations:
        problems.append("The request needed an action, but this turn contains no successful change.")
    # The core rule: a check that ran BEFORE the last edit proves nothing about
    # what the edit did. Order matters, not mere presence.
    if mutations and not any(p > max(mutations) for p in verifications):
        problems.append("There were changes, but no successful check ran after the last one.")
    if _positive(TEST_CLAIM, message) and not tests:
        problems.append("The message says tests passed, but no test run succeeded this turn.")
    if _positive(VERIFY_CLAIM, message) and not verifications:
        problems.append("The message says it was verified, but no check ran this turn.")
    if _positive(DEPLOY_CLAIM, message) and not deploys:
        problems.append("The message claims a deploy or publish, but none happened this turn.")
    if _positive(DEPLOY_CLAIM, message) and deploys and not any(p > max(deploys) for p in verifications):
        problems.append("The deploy was never checked at its destination afterwards.")
    if (_positive(PUSH_CLAIM, message) or _positive(SEND_CLAIM, message)) and not push_or_sends:
        problems.append("The message claims something was pushed or sent, with no matching action.")
    if mutations and claims_complete:
        missing = [name for name, pattern in RECEIPT_FIELDS.items()
                   if not pattern.search(message)]
        if missing:
            problems.append("The closing receipt is missing: " + ", ".join(missing) + ".")
    return problems


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    problems = audit(data)
    if problems:
        reason = ("EVIDENCE AUDIT: not done yet. " +
                  " ".join(f"{i + 1}) {p}" for i, p in enumerate(problems)) +
                  " Do the missing action or check. If it cannot be completed, say so "
                  "as pending or unverified and explain what blocked it -- do not "
                  "claim it is finished.")
        print(json.dumps({"decision": "block", "reason": reason}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
