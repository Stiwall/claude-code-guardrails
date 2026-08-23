#!/usr/bin/env python3
"""PreToolUse guard: refuse dangerous shell commands before they run.

Exit 2 with a message on stderr tells Claude Code to block the command and hand
the message back to the model. Exit 0 lets it through.

Every rule here exists because something actually broke. When a rule produces a
false positive, tighten the pattern -- do not remove the hook. A guard you
disabled because it annoyed you is a guard that was not there when it mattered.

Config: guardrails.json next to this file, or $GUARDRAILS_CONFIG, or
~/.claude/guardrails.json. Anything you omit falls back to the defaults below.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

DEFAULTS = {
    # Branches nobody pushes to without a deliberate, logged override.
    "protected_branches": ["main", "master"],
    # Typing this literal string in the command allows one push to a protected
    # branch and records it. It never appears by accident: you have to mean it.
    "override_token": "APPROVED_PUSH=1",
    "override_log": "~/.claude/protected-push.log",
    # Repos or paths exempt from branch protection (static sites, scratch repos).
    "unprotected_repos": [],
    # Recursive deletes are refused when the DELETE TARGET matches one of these.
    "protected_paths": [
        r"\.ssh", r"\bvenv\b", r"\.git\b", r"node_modules/\.\.",
    ],
    # Files whose *name* suggests credentials, whatever tool reads them.
    "secret_file_pattern": (
        r"[\w./-]*(token|secret|credential|apikey|api_key|passwd|password)[\w./-]*"
        r"\.(json|ya?ml|conf|cfg|ini|txt|sh|env)"
    ),
    # The command that masks secrets in a pipeline. Commands that dump raw
    # config are only allowed when their output goes through it.
    "redactor": "redact",
    # Your own scars. Each entry: {"pattern": regex, "message": what to say}.
    "extra_rules": [],
}


def load_config():
    here = Path(__file__).resolve().parent
    for candidate in (
        os.environ.get("GUARDRAILS_CONFIG"),
        here / "guardrails.json",
        Path.home() / ".claude" / "guardrails.json",
    ):
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        try:
            return {**DEFAULTS, **json.loads(path.read_text())}
        except Exception:
            continue
    return dict(DEFAULTS)


def block(message):
    print(f"BLOCKED by guardrails: {message}", file=sys.stderr)
    sys.exit(2)


def strip_heredocs(command):
    """Remove heredoc bodies before matching anything.

    A heredoc body is text being *written*, not a command being run. Without
    this, writing documentation about your own rules trips your own hook -- the
    first false positive this guard ever produced. `[^\\n]*` after the delimiter
    catches pipes and redirects on the same line, so `cat <<'EOF' | ssh host`
    is stripped too.
    """
    return re.sub(r"<<-?\s*'?\"?(\w+)'?\"?[^\n]*\n.*?\n\1\b",
                  "<<HEREDOC_OMITTED", command, flags=re.S)


def check_git_push(cmd, cfg):
    if not re.search(r"\bgit\b[^|;&]*\bpush\b", cmd):
        return
    if re.search(r"\bpush\b[^|;&]*(\s--force\b|\s-f\b|--force-with-lease)", cmd):
        block("force-push is never allowed from an agent. If it is truly "
              "necessary, a human runs it by hand.")
    branches = "|".join(re.escape(b) for b in cfg["protected_branches"])
    if not branches or not re.search(rf"\bpush\b[^|;&]*\b({branches})\b", cmd):
        return
    for exempt in cfg["unprotected_repos"]:
        if re.search(exempt, cmd):
            return
    if cfg["override_token"] and cfg["override_token"] in cmd:
        log = Path(cfg["override_log"]).expanduser()
        try:
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a") as handle:
                handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {cmd[:300]}\n")
        except Exception:
            pass
        return
    block("push to a protected branch. Go through your review flow, and when it "
          f"is approved add {cfg['override_token']} to the command so the "
          "override is recorded.")


def check_recursive_delete(cmd, cfg):
    """Inspect only what the delete is aimed at, never the whole command.

    An earlier version scanned the entire command string. Since every ssh
    invocation carries `-i ~/.ssh/id_ed25519`, that made *every* remote
    `rm -r` look like it was deleting your keys. The risk lives in the
    destination, not in the flags that happen to sit beside it.
    """
    for match in re.finditer(r"\brm\b((?:\s+-[a-zA-Z]+)*)((?:\s+[^\s;|&]+)*)", cmd):
        flags, targets = match.group(1) or "", match.group(2) or ""
        if "r" not in flags.replace("-", ""):
            continue
        for pattern in cfg["protected_paths"]:
            if re.search(pattern, targets):
                block(f"recursive delete aimed at a protected path ({pattern}). "
                      "Confirm with a human before removing it.")


def check_config_dumps(cmd, cfg):
    """Commands whose *output* tends to carry credentials.

    A hook cannot mask what a command prints; it can only refuse to run the
    command unmasked. These three leaked real tokens on separate days:
    `git remote -v` (token inside the remote URL), `systemctl cat` (token in
    the unit's ExecStart), and a plain-looking .json config read with
    `python -c "json.load(open(...))"` -- which is why the file pattern below
    matches on the *name*, not on which tool does the reading.
    """
    dumps = [
        (r"\bsystemctl\s+cat\b", "systemctl cat"),
        (r"\bgit\b[^|;&]*\bremote\b[^|;&]*(-v|--verbose|get-url)", "git remote -v"),
        (r"\bcrontab\s+-l\b", "crontab -l"),
        (r"(?:^|[|;&]\s*)(env|printenv)(\s+\||\s*$)", "env / printenv"),
        (r"\b(cat|less|more|head|tail|bat)\b[^|;&\n]*"
         r"(\.env\b|auth\.json|\.envrc|\.npmrc|id_[er]sa\b)", "reading a secrets file"),
        (cfg["secret_file_pattern"], "reading a config file that holds credentials"),
    ]
    redactor = re.escape(cfg["redactor"])
    for pattern, name in dumps:
        if not re.search(pattern, cmd):
            continue
        # Allowed when the output is already filtered, or when the command only
        # counts or checks rather than printing the content.
        if re.search(rf"\b{redactor}\b", cmd) or re.search(r"\|\s*(grep\s+-c|wc\b)", cmd):
            continue
        block(f"'{name}' can print credentials. Pipe it through the redactor: "
              f"<command> | {cfg['redactor']}")


def check_inline_credentials(cmd):
    """A credential inside the command is a credential you will have to rotate.

    This is not about typing it wrong. It is about what happens when the
    quoting breaks: the shell prints the entire failing command, credential
    included, into an error message that then lands in a log, a transcript and
    a scrollback buffer. Read secrets inside the script instead.
    """
    if re.search(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s'\"]+:[^@/\s'\"]+@", cmd):
        block("there is a credential inside the command (user:password@host). "
              "If anything fails, the shell prints the whole command and burns "
              "it. Read it inside the script from an env file instead.")
    # No required prefix character before the keyword: a bare `API_KEY=...` is
    # the most common shape of all, and demanding one letter in front of it
    # (so only `MY_API_KEY=...` matched) let the common case straight through.
    if re.search(r"(?:^|[\s;|&])[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY)="
                 r"(?!\$|[\"']?\s*$)[^\s;|&]{8,}", cmd):
        block("a secret is being passed as a variable on the command line. It "
              "stays in shell history and is visible in `ps`. Export it from an "
              "env file or read it inside the script.")


def check_literal_tokens(cmd):
    if not re.search(r"\bgit\b[^|;&]*\b(add|commit|push)\b", cmd):
        return
    if re.search(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                 r"|\d{8,10}:AA[A-Za-z0-9_-]{30,}|sk-[A-Za-z0-9]{20,})", cmd):
        block("a literal token appears in a git command. If it reaches a commit "
              "it is burned. Use an environment variable.")


def check_relative_path_over_ssh(cmd):
    """`ssh host 'some-indexer .'` does not run where you think it does.

    ssh always starts in the remote home directory, so `.` is the home, not the
    project. An indexer pointed at a home directory once walked 37,000 files,
    drove load average past 70 and took the box off the network -- six times in
    a row, because the `pwd` that would have revealed it was never read.
    """
    if not re.search(r"\bssh\b", cmd):
        return
    if re.search(r"\bssh\b[^|;&]*['\"][^'\"]*\b\w+\s+\S+\s+\.(?=\s|['\"]|$)", cmd):
        if not re.search(r"\bcd\s+[^\s;|&]+[^;|]*&&", cmd):
            block("a relative path is being used inside an ssh command. Over "
                  "ssh the working directory is the remote home, so '.' is not "
                  "your project. Put `cd /path/to/project &&` in the same command.")


def main():
    try:
        data = json.load(sys.stdin)
        cmd = data.get("tool_input", {}).get("command", "") or ""
    except Exception:
        return 0                      # unparseable input should never block work
    if not cmd:
        return 0

    cfg = load_config()
    cmd = strip_heredocs(cmd)

    check_git_push(cmd, cfg)
    check_recursive_delete(cmd, cfg)
    check_config_dumps(cmd, cfg)
    check_inline_credentials(cmd)
    check_literal_tokens(cmd)
    check_relative_path_over_ssh(cmd)

    for rule in cfg["extra_rules"]:
        try:
            if re.search(rule["pattern"], cmd):
                block(rule["message"])
        except (KeyError, re.error):
            continue                  # a broken custom rule must not break the guard
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
