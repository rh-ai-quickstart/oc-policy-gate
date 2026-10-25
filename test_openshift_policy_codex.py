"""Exercise the real shared checker through Codex's documented hook contracts.

Commands under review are JSON data only; no cluster commands are executed.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


GATE = Path(__file__).resolve().parent
CHECKER = GATE / "openshift-policy.sh"
BASH = shutil.which("bash")
EVENTS = ("PermissionRequest",)
POLICY = """namespaces:
  my-app-dev:
    oc: [read, write, exec]
    helm: [read, write]
  my-app-prod:
    oc: [read]
    helm: [read]
"""


class CodexPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="codex-policy-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.policy = self.directory / "policy.yaml"
        self.policy.write_text(POLICY)
        self.env = {**os.environ, "OPENSHIFT_POLICY_FILE": str(self.policy)}

    def invoke(self, event, command="oc get pods -n my-app-dev", **kwargs):
        payload = {
            "hook_event_name": event,
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(GATE),
        }
        payload.update(kwargs.pop("payload", {}))
        return subprocess.run(
            [BASH, str(CHECKER), "--client", "codex"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=kwargs.pop("env", self.env),
            **kwargs,
        )

    def decision(self, result, event):
        self.assertEqual(result.returncode, 0, result.stderr)
        if not result.stdout.strip():
            return "defer"
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], event)
        if event == "PermissionRequest":
            self.assertNotIn("permissionDecision", output)
            return output["decision"]["behavior"]
        return output["permissionDecision"]

    def test_namespace_and_verb_policy(self):
        cases = [
            ("oc get pods -n my-app-dev", "allow"),
            ("kubectl get pods -n my-app-dev", "allow"),
            ("oc delete pod app -n my-app-dev", "allow"),
            ("oc exec app -n my-app-dev -- ls", "allow"),
            ("oc rollout status deployment/app -n my-app-prod", "allow"),
            ("helm install app chart -n my-app-dev", "allow"),
            ("oc version", "allow"),
            ("helm template chart", "allow"),
            ("oc get pods -nmy-app-dev | grep Running", "allow"),
            ("oc get pods", "deny"),
            ("helm install app chart", "deny"),
            ("oc get pods -n my-app-dev > output.txt", "deny"),
            ("oc delete pod app -n my-app-prod", "defer"),
            ("helm uninstall app -n my-app-dev", "defer"),
            ("oc get pods -n unknown-ns", "defer"),
            ("oc get pods -A", "defer"),
            ("oc get pods -n my-app-dev && oc get pods -n unknown-ns", "defer"),
            ("ls -la", "defer"),
            ("", "defer"),
        ]
        for event in EVENTS:
            for command, expected in cases:
                with self.subTest(event=event, command=command):
                    self.assertEqual(self.decision(self.invoke(event, command), event), expected)

    def test_denial_reason_is_preserved(self):
        payload = {"tool_input": {"command": "oc get pods"}}
        original = subprocess.run(
            ["bash", str(GATE / "openshift-policy.sh")],
            input=json.dumps(payload), capture_output=True, text=True, env=self.env,
        )
        reason = json.loads(original.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
        for event in EVENTS:
            with self.subTest(event=event):
                result = self.invoke(event, "oc get pods")
                self.assertEqual(self.decision(result, event), "deny")
                output = json.loads(result.stdout)["hookSpecificOutput"]
                actual = output["decision"]["message"] if event == "PermissionRequest" else output["permissionDecisionReason"]
                self.assertEqual(actual, reason)

    def test_other_tools_never_get_automatic_approval(self):
        for event in EVENTS:
            result = self.invoke(event, "oc version", payload={"tool_name": "mcp__example__run"})
            self.assertEqual(self.decision(result, event), "defer")

    def test_unrelated_commands_skip_policy_dependencies(self):
        bin_dir = self.directory / "minimal-bin"
        bin_dir.mkdir()
        for dependency in ("dirname", "jq", "grep"):
            (bin_dir / dependency).symlink_to(shutil.which(dependency))
        env = {**self.env, "PATH": str(bin_dir)}
        for command in ("ls -la", "git status", "printf hello", "helmfile version", "", "   "):
            with self.subTest(command=command):
                result = self.invoke("PermissionRequest", command, env=env)
                self.assertEqual(self.decision(result, "PermissionRequest"), "defer")
        result = self.invoke("PermissionRequest", "oc version", env=env)
        self.assertEqual(self.decision(result, "PermissionRequest"), "deny")

    def test_missing_or_non_string_command_defers(self):
        for event in EVENTS:
            for tool_input in (None, {}, {"command": None}, {"command": []}, {"command": {}}, {"command": 7}, {"command": False}, "oc version"):
                with self.subTest(event=event, tool_input=tool_input):
                    result = self.invoke(event, payload={"tool_input": tool_input})
                    self.assertEqual(self.decision(result, event), "defer")

    def test_invalid_or_unrelated_event_input_defers(self):
        for payload in ("not json", "[]", "{}", '{"hook_event_name":"PostToolUse"}'):
            with self.subTest(payload=payload):
                result = subprocess.run(
                    [BASH, str(CHECKER), "--client", "codex"], input=payload,
                    capture_output=True, text=True, env=self.env,
                )
                self.assertEqual(result.returncode, 0)
                self.assertFalse(result.stdout)

    def test_missing_dependencies_get_explicit_denials(self):
        for missing in ("jq", "yq"):
            bin_dir = self.directory / missing
            bin_dir.mkdir()
            for dependency in ("bash", "dirname", "jq", "grep"):
                if dependency != missing:
                    executable = shutil.which(dependency)
                    self.assertIsNotNone(executable, dependency)
                    (bin_dir / dependency).symlink_to(executable)
            env = {**self.env, "PATH": str(bin_dir)}
            for event in EVENTS:
                with self.subTest(missing=missing, event=event):
                    result = self.invoke(event, env=env)
                    self.assertEqual(self.decision(result, event), "deny")

    def test_checker_failure_cannot_turn_into_approval(self):
        # Fail during classification, after a valid command and policy load.
        bin_dir = self.directory / "broken-bin"
        bin_dir.mkdir()
        awk = bin_dir / "awk"
        awk.write_text(
            f'#!{BASH}\nif [[ "${{1:-}}" == -v ]]; then exit 19; fi\n'
            f'exec "{shutil.which("awk")}" "$@"\n'
        )
        awk.chmod(0o755)
        env = {**self.env, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"]}
        result = self.invoke("PermissionRequest", env=env)
        self.assertEqual(self.decision(result, "PermissionRequest"), "deny")

    def test_explicit_claude_mode_preserves_default_response(self):
        payload = json.dumps({"tool_input": {"command": "oc get pods"}})
        results = [subprocess.run(
            [BASH, str(CHECKER), *args], input=payload,
            capture_output=True, text=True, env=self.env,
        ) for args in ([], ["--client", "claude"])]
        self.assertEqual(results[0].returncode, 0)
        self.assertEqual(results[1].returncode, 0)
        self.assertEqual(results[0].stdout, results[1].stdout)

    def test_invalid_client_arguments_fail(self):
        for args in (["--client"], ["--client", "unknown"], ["--wrong", "codex"]):
            with self.subTest(args=args):
                result = subprocess.run(
                    [BASH, str(CHECKER), *args], input="{}",
                    capture_output=True, text=True, env=self.env,
                )
                self.assertEqual(result.returncode, 2)
                self.assertFalse(result.stdout)


if __name__ == "__main__":
    unittest.main()
