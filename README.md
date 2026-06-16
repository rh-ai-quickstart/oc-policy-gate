# oc-policy-gate

Namespace-scoped access control for AI coding agents (Claude Code, Cursor) operating on OpenShift/Kubernetes clusters.

A **PreToolUse hook** that intercepts `oc`, `kubectl`, and `helm` commands and enforces verb-level permissions per namespace — before the command ever runs.

## Why

AI agents need cluster access to debug and deploy. Unrestricted access is dangerous — an agent can delete resources in namespaces it shouldn't touch. This hook enforces boundaries without restricting the agent's native tooling.

- **Zero token overhead** — no MCP schemas loaded into context
- **Hard enforcement** — blocks commands even with `--dangerously-skip-permissions`
- **Native tooling** — agents use `oc`/`kubectl`/`helm` directly, no wrappers

## Quick Start

### 1. Copy files into your project

```bash
# Option A: git subtree (recommended — enables pulling updates)
git remote add oc-policy-gate git@github.com:rh-ai-quickstart/oc-policy-gate.git
git subtree add --prefix=.claude/hooks oc-policy-gate master --squash

# Option B: manual copy
mkdir -p .claude/hooks
cp openshift-policy.sh openshift-policy.yaml test-openshift-policy.sh .claude/hooks/
```

### 2. Configure your policy

Edit `.claude/hooks/openshift-policy.yaml` with your namespaces and permissions:

```yaml
namespaces:
  my-app-dev:
    oc: [read, write, exec]
    helm: [read, write]
  my-app-staging:
    oc: [read, write]
    helm: [read]
  my-app-prod:
    oc: [read]
    helm: [read]
```

**Permission groups:**

| Tool | Group | Verbs |
|------|-------|-------|
| oc | `read` | get, describe, logs, status, rollout status, auth can-i, ... |
| oc | `write` | apply, create, delete, scale, rollout restart, ... |
| oc | `exec` | exec, debug, port-forward, cp |
| helm | `read` | list, status, get, show, history, search, dependency list, ... |
| helm | `write` | install, upgrade, dependency update/build |
| helm | `destructive` | uninstall, rollback, delete |

### 3. Wire up the hook

Add to your `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "if": "Bash(oc *)",
            "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/openshift-policy.sh",
            "timeout": 5
          },
          {
            "type": "command",
            "if": "Bash(kubectl *)",
            "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/openshift-policy.sh",
            "timeout": 5
          },
          {
            "type": "command",
            "if": "Bash(helm *)",
            "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/openshift-policy.sh",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

## Pulling Updates (git subtree)

```bash
git subtree pull --prefix=.claude/hooks oc-policy-gate master --squash
```

## How It Works

Every command in Claude Code / Cursor passes through a gate pipeline:

```mermaid
flowchart TD
    A["Agent decides to run a command"] --> B["PreToolUse Hook"]
    B -->|"exit: deny"| X["BLOCKED - Command never runs"]
    B -->|"exit: allow"| E["Command Executes"]
    B -->|"exit: ask / defer"| C["Permission Rules<br/>(settings.json)"]
    C -->|Denied| X
    C -->|Allowed| E
    C -->|Needs asking| D["User Prompt"]
    D -->|Approve| E
    D -->|Deny| X
    E --> F["PostToolUse Hook"]
    F --> G["Results to Agent"]

    style B fill:#6366f1,color:#fff,stroke:#4f46e5,stroke-width:2px
    style C fill:#f39c12,color:#fff
    style D fill:#3498db,color:#fff
    style X fill:#1e293b,color:#fff
    style E fill:#27ae60,color:#fff
```

1. **allow** — command runs without user prompt
2. **deny** — command is blocked (missing namespace, output redirect)
3. **ask** — falls through to Claude Code's normal permission prompt (unknown namespace, unrecognized verb)

**Always denied:** commands without `-n <namespace>`, output redirects (`> file`)

**Auto-allowed (no namespace needed):** `oc version`, `oc whoami`, `helm template`, `helm version`, etc.

## Running Tests

```bash
bash test-openshift-policy.sh
```

39 test cases covering read/write/exec verbs, namespace enforcement, pipes, compound commands, redirects, multi-word verbs, and edge cases.

## Requirements

- `jq` — used for JSON input/output parsing
- `bash` 4+ — uses associative arrays

## Customization

Set `OPENSHIFT_POLICY_FILE` environment variable to use a policy file from a different location:

```bash
OPENSHIFT_POLICY_FILE=/path/to/my-policy.yaml
```

## License

Apache-2.0
