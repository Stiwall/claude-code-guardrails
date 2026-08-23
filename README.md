# claude-code-guardrails

[![tests](https://github.com/Stiwall/claude-code-guardrails/actions/workflows/tests.yml/badge.svg)](https://github.com/Stiwall/claude-code-guardrails/actions/workflows/tests.yml)

Three hooks that stop an AI coding agent from leaking your secrets, pushing to
a protected branch, or telling you it is done when it is not.

Every rule in here exists because something broke first. The comments carry the
incident, not just the regex — because the incident is the part you need in
order to decide whether the rule is worth keeping.

No dependencies. Python 3.9+. Three files.

---

## The three hooks

### `guard.py` — refuse the command before it runs

A `PreToolUse` hook. Exit code 2 blocks the command and hands the reason back to
the model, which then has to find another way.

It refuses:

- **push to a protected branch**, and force-push always — with a deliberate,
  logged override string for the one time you really mean it
- **recursive deletes aimed at protected paths**
- **commands whose output tends to carry credentials** (`git remote -v`,
  `systemctl cat`, `crontab -l`, `env`, reading a `.env`) unless the output is
  piped through a redactor
- **credentials inside the command itself** — `user:password@host` URLs, or a
  secret passed as `SOMETHING_TOKEN=... command`
- **literal provider tokens in a git command**, where they would be burned the
  moment they reach a commit
- **relative paths inside an ssh command**, which do not resolve where you think

### `evidence_audit.py` — refuse the completion claim

A `Stop` hook. It reads the current turn from the transcript and compares what
the final message *claims* against what the turn actually *did*.

It blocks when:

- the message says **"done"** but the turn contains no successful change
- there were changes, but **no check ran after the last one**
- the message says **tests passed** with no test run in the turn
- the message says **deployed** with no deploy — or a deploy that was never
  checked at its destination afterwards
- the message says **pushed** or **sent** with no matching action
- something changed and the message has no closing receipt
  (*changes / evidence / location / pending*)

It never prints transcript text, commands, paths, or tool output. Only which
claim lacks backing.

### `redact.py` — mask the secret before the model reads it

A `PostToolUse` hook that rewrites the tool result, plus a `MessageDisplay` hook
for what reaches the screen. It also works as a plain filter:

```bash
git remote -v | python3 hooks/redact.py
```

It keeps labels and drops values — `API_KEY=<CREDENTIAL_REDACTED>` — because
knowing *that* a credential was there is worth keeping.

---

## Install

```bash
git clone https://github.com/Stiwall/claude-code-guardrails
cd claude-code-guardrails
python3 -m unittest discover -s tests     # 34 tests, no dependencies
```

Wire them up in `~/.claude/settings.json` (see `settings.example.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "python3 /path/to/hooks/guard.py" }] }
    ],
    "PostToolUse": [
      { "matcher": "*",
        "hooks": [{ "type": "command", "command": "python3 /path/to/hooks/redact.py" }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "python3 /path/to/hooks/evidence_audit.py" }] }
    ]
  }
}
```

Copy `guardrails.example.json` to `hooks/guardrails.json` and edit it. Anything
you leave out falls back to the defaults. Your own rules go in `extra_rules`:

```json
{
  "protected_branches": ["main", "release"],
  "protected_paths": ["\\.ssh", "\\bvenv\\b", "/srv/data"],
  "redactor": "redact",
  "extra_rules": [
    { "pattern": "\\bterraform\\s+destroy\\b",
      "message": "terraform destroy from an agent: run it yourself." }
  ]
}
```

---

## The incidents

This is the part worth reading. Each of these produced a rule, and several
produced a *correction* to a rule that was already there.

**A database password, burned by a quoting error.** The password was not typed
wrong. It was passed inside the command, the quoting broke, and the shell did
what shells do: printed the entire failing command — credential included — into
an error message that then lived in a log, a transcript and a scrollback buffer.
The rule is not "be careful with passwords". The rule is that the credential
never travels in the command at all.

**Three token leaks in two days, all from output nobody anticipated.**
`git remote -v` prints the token embedded in the remote URL. `systemctl cat`
prints the token sitting in a unit's `ExecStart`. And an ordinary-looking
`.json` config, read with `python3 -c "json.load(open(...))"`, printed a bot
token — which is why the file rule matches on the *name* of the file and ignores
which tool is doing the reading. Widening that list is cheaper than rotating a
token.

**A delete guard that blocked every remote delete.** The first version scanned
the whole command for protected paths. Every `ssh` invocation carries
`-i ~/.ssh/id_ed25519`, so every remote `rm -r` looked like it was deleting SSH
keys. The fix was not a longer pattern: it was realising that the risk lives in
the *delete target*, not in the flags standing next to it.

**A guard that blocked its own documentation.** Writing notes that quoted the
forbidden commands tripped the hook, because a heredoc body looks exactly like
a command. Heredoc bodies are text being written, not commands being run, so
they are stripped before anything else is matched.

**An indexer that took a server off the network.** Run over ssh with a relative
path — `ssh host 'indexer update .'` — where `.` is the remote *home*, not the
project. Thirty-seven thousand files, load average past 70, box unreachable. It
happened six times in a row, because the `pwd` that would have revealed it was
printed and never read.

**Two commits that vanished without an error.** After a merge you are left on
`main`. Two commits landed there, then `git push origin develop` pushed the
unchanged `develop` branch and exited zero. Nothing failed. The work simply was
not anywhere, and everything on screen said it was.

**`API_KEY=` — the case the guard was missing.** Found while writing the tests
for this repo: the pattern required at least one character before the keyword,
so `MY_API_KEY=secret` was blocked and a plain `API_KEY=secret` sailed straight
through. The most common shape of all was the one not covered. Both the guard
and the redactor had it. That is what the false-positive tests below are for —
and what a test suite is for.

---

## Why the evidence audit exists

An agent that reports "deployed and verified" after a turn containing neither a
deploy nor a check is not lying on purpose. It is completing a pattern: this is
what a finished task usually sounds like. The words are generated from the shape
of the work, not from the result of it.

You cannot prompt that away reliably, because the prompt is processed by the
same thing doing the pattern-matching. What does work is checking the claim
against the transcript, mechanically, every time — and the check that matters
most is **ordering**:

> A verification that ran *before* the last edit proves nothing about what the
> edit did.

Presence is not enough. `grep` then `edit` is not evidence. `edit` then `grep`
is. That single rule catches more overclaiming than every other check here
combined.

The hook is deliberately blunt about hedged language: "the tests did not pass"
must never trip the tests-passed rule, so claims are matched sentence by
sentence rather than across the whole message.

---

## False positives are the real design problem

A guard that cries wolf gets switched off, and then it is not there on the day
it matters. Roughly half the test suite exists to pin down cases the guard used
to block wrongly:

- a heredoc that documents the forbidden commands
- `ssh -i ~/.ssh/id_ed25519 host 'rm -rf /tmp/cache'`
- `cat .env | wc -l` — counting lines reveals nothing
- `ls /srv/app/.env.example` — `env` inside a path is not the `env` command
- `API_KEY=$SOME_VAR ./deploy.sh` — a reference, not a secret

When a rule misfires, tighten the pattern and add the case to the tests. Do not
delete the rule.

---

## What this is not

It is not a sandbox and not a permission system. A hook sees the command, not
the intent, and anything expressible in a way the patterns do not match will get
through. Treat it as the last of several layers: least-privilege credentials
first, isolated environments second, this third.

It also cannot mask what a command has already printed. That is why `guard.py`
refuses the unfiltered command instead of trying to clean up afterwards.

---

## License

MIT.
