#!/usr/bin/env python3
"""Tests for the three hooks.

Half of these are regression tests for false positives -- cases the guard used
to block wrongly. Those matter more than the happy path: a guard that cries
wolf gets switched off, and then it is not there on the day it counts.

    python3 -m unittest discover -s tests
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS))

import evidence_audit          # noqa: E402
import redact                  # noqa: E402


def run_guard(command):
    """Run the guard on one command. Returns (exit_code, stderr)."""
    payload = json.dumps({"tool_input": {"command": command}})
    result = subprocess.run([sys.executable, str(HOOKS / "guard.py")],
                            input=payload, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stderr


class GuardBlocks(unittest.TestCase):
    def assertBlocked(self, command):
        code, _ = run_guard(command)
        self.assertEqual(code, 2, f"should have been blocked: {command!r}")

    def test_push_to_main(self):
        self.assertBlocked("git push origin main")

    def test_force_push(self):
        self.assertBlocked("git push --force origin feature")

    def test_force_with_lease_is_still_a_force_push(self):
        self.assertBlocked("git push --force-with-lease origin feature")

    def test_credential_inside_a_url(self):
        self.assertBlocked("psql postgresql://admin:hunter2@db.example.com/app -c 'select 1'")

    def test_secret_as_a_command_line_variable(self):
        self.assertBlocked("API_KEY=abcdef0123456789 ./deploy.sh")

    def test_config_dump_without_a_redactor(self):
        self.assertBlocked("git remote -v")

    def test_reading_an_env_file(self):
        self.assertBlocked("cat /srv/app/.env")

    def test_config_file_named_like_a_secret_read_by_any_tool(self):
        # The reader is irrelevant. A token leaked once through
        # `python3 -c "json.load(open('tokens.json'))"`, which no cat-based
        # rule would ever have caught.
        self.assertBlocked("python3 -c \"import json;print(json.load(open('bot_tokens.json')))\"")

    def test_recursive_delete_of_a_protected_path(self):
        self.assertBlocked("rm -rf ~/.ssh")

    def test_literal_token_in_a_git_command(self):
        self.assertBlocked("git commit -m 'ghp_" + "A" * 30 + "'")


class GuardAllows(unittest.TestCase):
    """Regression tests. Every one of these was once blocked by mistake."""

    def assertAllowed(self, command):
        code, err = run_guard(command)
        self.assertEqual(code, 0, f"false positive on {command!r}: {err}")

    def test_heredoc_body_is_text_not_commands(self):
        # Writing documentation that quotes your own rules must not trip them.
        self.assertAllowed(
            "cat > notes.md <<'EOF'\n"
            "Never run: git push origin main\n"
            "Never run: rm -rf ~/.ssh\n"
            "EOF")

    def test_ssh_identity_flag_is_not_a_delete_target(self):
        # Every ssh call carries `-i ~/.ssh/id_ed25519`. Scanning the whole
        # command made every remote recursive delete look like key deletion.
        self.assertAllowed("ssh -i ~/.ssh/id_ed25519 host 'rm -rf /tmp/build-cache'")

    def test_push_to_a_normal_branch(self):
        self.assertAllowed("git push origin feature/login")

    def test_config_dump_through_the_redactor(self):
        self.assertAllowed("git remote -v | redact")

    def test_counting_lines_of_a_secrets_file_reveals_nothing(self):
        self.assertAllowed("cat .env | wc -l")

    def test_env_inside_a_path_is_not_the_env_command(self):
        self.assertAllowed("ls /srv/app/.env.example")

    def test_non_recursive_remove(self):
        self.assertAllowed("rm ~/.ssh/known_hosts.old")

    def test_variable_reference_is_not_a_literal_secret(self):
        self.assertAllowed("API_KEY=$SOME_KEY ./deploy.sh")


class EvidenceAudit(unittest.TestCase):
    def audit(self, message, tools, prompt="update the config", background=()):
        """Drive audit() directly with a synthetic turn."""
        original = evidence_audit._current_turn
        evidence_audit._current_turn = lambda _path: (prompt, list(tools))
        try:
            return evidence_audit.audit({
                "last_assistant_message": message,
                "transcript_path": "",
                "background_tasks": list(background),
            })
        finally:
            evidence_audit._current_turn = original

    @staticmethod
    def call(name, command="", success=True):
        return {"id": name, "name": name, "input": {"command": command}, "success": success}

    def test_check_before_the_edit_does_not_count(self):
        # This is the whole point: a check that ran before the last change
        # says nothing about what the change did.
        problems = self.audit(
            "Done, the config is updated.",
            [self.call("Bash", "grep -n timeout config.yml"), self.call("Edit")])
        self.assertTrue(any("after the last one" in p for p in problems))

    def test_check_after_the_edit_satisfies_it(self):
        problems = self.audit(
            "Done. Changes: config. Evidence: grep. Location: repo. Pending: none.",
            [self.call("Edit"), self.call("Bash", "grep -n timeout config.yml")])
        self.assertFalse(any("after the last one" in p for p in problems))

    def test_claiming_tests_passed_without_running_any(self):
        problems = self.audit("All 40 tests pass.", [self.call("Edit")])
        self.assertTrue(any("tests passed" in p for p in problems))

    def test_saying_tests_did_not_pass_is_not_a_claim(self):
        problems = self.audit("The tests did not pass yet.", [self.call("Read")])
        self.assertFalse(any("tests passed" in p for p in problems))

    def test_claiming_a_deploy_without_deploying(self):
        problems = self.audit("Deployed to production.", [self.call("Edit")])
        self.assertTrue(any("deploy" in p for p in problems))

    def test_deploy_needs_a_check_afterwards(self):
        problems = self.audit(
            "Deployed. Changes: x. Evidence: y. Location: prod. Pending: none.",
            [self.call("Bash", "git push origin main")])
        self.assertTrue(any("destination" in p for p in problems))

    def test_receipt_is_required_when_something_changed(self):
        problems = self.audit(
            "Done, I fixed it.",
            [self.call("Edit"), self.call("Bash", "grep -n x file")])
        self.assertTrue(any("receipt" in p for p in problems))

    def test_a_question_does_not_demand_an_action(self):
        problems = self.audit("Here is what update does.", [self.call("Read")],
                              prompt="what does update do")
        self.assertFalse(any("needed an action" in p for p in problems))

    def test_failed_tool_calls_are_not_evidence(self):
        problems = self.audit(
            "Done. Changes: x. Evidence: y. Location: z. Pending: none.",
            [self.call("Edit"), self.call("Bash", "grep -n x file", success=False)])
        self.assertTrue(any("after the last one" in p for p in problems))

    def test_clean_turn_passes(self):
        # The receipt fields are matched at the start of a line, so a real
        # receipt is a list, not a sentence with colons buried in it.
        problems = self.audit(
            "Done.\n"
            "Changes: config.yml\n"
            "Evidence: grep confirms the new value\n"
            "Location: local repo\n"
            "Pending: none\n",
            [self.call("Edit"), self.call("Bash", "grep -n timeout config.yml")])
        self.assertEqual(problems, [])


class Redaction(unittest.TestCase):
    def test_provider_tokens(self):
        for fake in ("ghp_" + "A" * 32, "sk-proj-" + "B" * 32, "AIza" + "C" * 35,
                     "xoxb-" + "1" * 24, "123456789:" + "D" * 24):
            self.assertNotIn(fake, redact.redact_text(f"token is {fake} ok"))

    def test_label_survives_the_value(self):
        out = redact.redact_text("API_KEY=supersecretvalue123")
        self.assertIn("API_KEY=", out)
        self.assertNotIn("supersecretvalue123", out)

    def test_url_password_goes_but_user_stays(self):
        out = redact.redact_text("postgresql://appuser:hunter2@db.internal/app")
        self.assertIn("appuser", out)
        self.assertNotIn("hunter2", out)

    def test_private_key_block(self):
        blob = ("-----BEGIN RSA PRIVATE KEY-----\n" + "Z" * 40 +
                "\n-----END RSA PRIVATE KEY-----")
        self.assertNotIn("Z" * 40, redact.redact_text(blob))

    def test_ordinary_text_is_untouched(self):
        text = "the build finished in 42 seconds"
        self.assertEqual(redact.redact_text(text), text)

    def test_nested_structures(self):
        payload = {"logs": ["ghp_" + "E" * 32, "fine"], "n": 3}
        out = redact.redact_value(payload)
        self.assertNotIn("ghp_", json.dumps(out))
        self.assertEqual(out["n"], 3)


if __name__ == "__main__":
    unittest.main()
