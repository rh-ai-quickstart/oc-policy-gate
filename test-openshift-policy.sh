#!/usr/bin/env bash
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="${SCRIPT_DIR}/openshift-policy.sh"

TEST_POLICY=$(mktemp /tmp/test-policy-XXXXXX.yaml)
cat > "$TEST_POLICY" <<'YAML'
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
YAML
export OPENSHIFT_POLICY_FILE="$TEST_POLICY"
EMPTY_POLICY="" MOCK_DIR=""
trap 'rm -f "$TEST_POLICY" "$EMPTY_POLICY"; rm -rf "$MOCK_DIR"' EXIT

passed=0 failed=0

run_test() {
  local num="$1" expected="$2" cmd="$3" desc="$4"
  local output
  output=$(jq -n --arg c "$cmd" '{"tool_input":{"command":$c}}' | "$HOOK" 2>/dev/null) || true

  local result="ASK"
  if [[ -n "$output" ]]; then
    if echo "$output" | grep -q '"allow"'; then result="ALLOW"
    elif echo "$output" | grep -q '"deny"'; then result="DENY"
    fi
  fi

  if [[ "$result" == "$expected" ]]; then
    printf "\033[32mPASS\033[0m #%-2s %s\n" "$num" "$desc"
    ((passed++))
  else
    printf "\033[31mFAIL\033[0m #%-2s %s\n" "$num" "$desc"
    echo "       Expected: $expected  Got: $result"
    [[ -n "$output" ]] && echo "       Output: $output"
    ((failed++))
  fi
}

echo "=== OpenShift Policy Hook Tests ==="
echo "Policy: my-app-dev oc:[read,write,exec] helm:[read,write]"
echo "        my-app-staging oc:[read,write] helm:[read]"
echo "        my-app-prod oc:[read] helm:[read]"
echo ""

# oc read/write/exec basics
run_test 1  ALLOW "oc get pods -n my-app-dev" \
  "oc read verb + valid ns with read access"
run_test 2  ALLOW "oc delete pod mypod -n my-app-dev" \
  "oc write verb + valid ns with write access"
run_test 3  ASK   "oc delete pod mypod -n my-app-prod" \
  "oc write verb + valid ns with only read access"

# Missing namespace
run_test 4  DENY  "oc apply -f manifest.yaml" \
  "oc write verb, no -n flag"
run_test 5  DENY  "oc get pods" \
  "oc read verb, no -n flag"

# All namespaces
run_test 6  ASK   "oc get pods -A" \
  "-A flag"
run_test 7  ASK   "oc get pods --all-namespaces" \
  "--all-namespaces flag"

# Unknown namespace
run_test 8  ASK   "oc get pods -n unknown-ns" \
  "namespace not in policy"

# Pipes with safe utilities
run_test 9  ALLOW "oc get pods -n my-app-dev | grep Error" \
  "valid oc read + safe pipe (grep)"
run_test 10 ALLOW "oc get pods -n my-app-dev | wc -l" \
  "valid oc read + safe pipe (wc)"

# Compound commands
run_test 11 ALLOW "oc get pods -n my-app-dev && oc logs mypod -n my-app-dev" \
  "two valid oc reads chained with &&"

# Redirect
run_test 12 DENY  "oc get pods -n my-app-dev > output.txt" \
  "output redirect to file"

# Auto-allowed oc verbs
run_test 13 ALLOW "oc version" \
  "oc version (auto-allowed, no ns needed)"
run_test 14 ALLOW "oc whoami" \
  "oc whoami (auto-allowed, no ns needed)"

# Unrecognized verbs
run_test 15 ASK   "oc config view" \
  "unrecognized verb (config)"

# Helm basics
run_test 16 ALLOW "helm list -n my-app-dev" \
  "helm read subcommand + valid ns"
run_test 17 ALLOW "helm install myrelease mychart -n my-app-dev" \
  "helm write subcommand + valid ns with write access"
run_test 18 ASK   "helm uninstall myrelease -n my-app-dev" \
  "helm destructive, ns has no destructive access"

# Helm auto-allowed
run_test 19 ALLOW "helm template mychart" \
  "helm template (auto-allowed, no ns needed)"
run_test 20 ALLOW "helm version" \
  "helm version (auto-allowed, no ns needed)"

# Helm missing namespace
run_test 21 DENY  "helm install myrelease mychart" \
  "helm write, no -n flag"

# Non-cluster command
run_test 22 ASK   "ls -la" \
  "not a cluster command (normal flow)"

# Env var prefix
run_test 23 ALLOW "KUBECONFIG=/path oc get pods -n my-app-dev" \
  "env var prefix, still valid"

# Namespace before verb
run_test 24 ALLOW "oc -n my-app-dev get pods" \
  "namespace flag before verb"

# Unsafe piped utility
run_test 25 ASK   "oc get pods -n my-app-dev | python3 -c 'import sys'" \
  "safe oc but unsafe piped utility"

# Exec verb
run_test 26 ALLOW "oc exec -it mypod -n my-app-dev -- bash" \
  "exec verb + valid ns with exec access"

# Unrecognized verb (cluster-info)
run_test 27 ASK   "oc cluster-info" \
  "unrecognized verb (cluster-info)"

# Auto-allowed (api-resources)
run_test 28 ALLOW "oc api-resources" \
  "api-resources (auto-allowed, no ns needed)"

# Full path
run_test 29 ALLOW "/usr/local/bin/oc get pods -n my-app-dev" \
  "full path to oc binary"

# --- Extra: multi-word verb tests ---
echo ""
echo "=== Multi-word verb tests ==="

run_test 30 ALLOW "oc rollout status deployment/myapp -n my-app-dev" \
  "oc rollout status (multi-word read verb)"
run_test 31 ALLOW "oc rollout restart deployment/myapp -n my-app-dev" \
  "oc rollout restart (multi-word write verb)"
run_test 32 ALLOW "oc auth can-i get pods -n my-app-dev" \
  "oc auth can-i (multi-word read verb)"
run_test 33 ALLOW "helm dependency list -n my-app-dev" \
  "helm dependency list (multi-word read verb)"
run_test 34 ALLOW "helm dependency update -n my-app-dev" \
  "helm dependency update (multi-word write verb)"
run_test 35 DENY  "helm repo list" \
  "helm repo list (requires namespace)"
run_test 36 ASK   "helm repo add myrepo https://example.com" \
  "helm repo add (unrecognized verb, falls to ask)"
run_test 37 ALLOW "kubectl get pods -n my-app-dev" \
  "kubectl normalized to oc"
run_test 38 ALLOW "oc -n my-app-dev -o json get pods" \
  "multiple flags before verb"
run_test 39 DENY  "oc rollout restart deployment/myapp" \
  "multi-word write verb, no namespace"

echo ""
echo "=== Namespace -nfoo (no space) tests ==="

run_test 40 ALLOW "oc get pods -nmy-app-dev" \
  "-nfoo form: oc read with valid ns"
run_test 41 ALLOW "oc delete pod mypod -nmy-app-dev" \
  "-nfoo form: oc write with valid ns"
run_test 42 ASK   "oc get pods -nunknown-ns" \
  "-nfoo form: namespace not in policy"
run_test 43 DENY  "oc get pods -nmy-app-dev > out.txt" \
  "-nfoo form: redirect still denied"
run_test 44 ASK   "oc apply -f manifest.yaml -nmy-app-prod" \
  "-nfoo form: write verb on read-only ns (ask, not deny)"
run_test 45 DENY  "oc get pods -n" \
  "-n with nothing after it"

echo ""
echo "=== Subshell / path bypass tests ==="

run_test 46 ALLOW 'echo $(oc delete pod mypod -n my-app-dev)' \
  "subshell: oc delete in dev ns correctly evaluated (write allowed)"
run_test 47 ASK   'x=$(oc get pods -n my-app-dev)' \
  "variable capture: oc inside \$()"
run_test 48 DENY  'echo $(oc get pods)' \
  "subshell: oc get without namespace correctly denied"
run_test 49 ASK   'echo $(oc get pods -A)' \
  "subshell wrapping: -A flag"

echo ""
echo "=== Subshell & embedding edge cases ==="

run_test 50 ALLOW 'echo `oc delete pod -n my-app-dev`' \
  "backtick subshell: oc delete in dev (write allowed)"
run_test 51 ASK   'echo $(echo $(oc delete pod -n my-app-prod))' \
  "nested subshell: oc delete in prod (only read allowed)"
run_test 52 ALLOW 'grep foo $(oc get pods -n my-app-dev -o name)' \
  "subshell in pipe arg: oc get in dev (read allowed)"
run_test 53 ALLOW 'echo pod-name | xargs oc delete -n my-app-dev' \
  "xargs: classify_segment scans all words, finds oc delete, policy allows"
run_test 54 ALLOW 'echo $(helm install myrelease mychart -n my-app-dev)' \
  "subshell with helm: helm install in dev (write allowed)"
run_test 55 ASK   'echo $(oc delete pod mypod -n my-app-prod)' \
  "subshell write on read-only ns: oc delete in prod (only read)"
run_test 56 ALLOW 'echo $(kubectl get pods -n my-app-dev)' \
  "kubectl in subshell: normalized to oc, read in dev"
run_test 57 DENY  'echo "run oc get pods"' \
  "oc in string literal: false positive edge case, strict-by-default for safety"
run_test 58 DENY  'echo `oc apply -f file.yaml`' \
  "backtick with no namespace: oc write denied without ns"
run_test 59 ALLOW 'echo $(oc get pods -n my-app-dev) $(oc get svc -n my-app-dev)' \
  "multiple subshells: both reads in dev allowed"

echo ""
echo "=== SAFE_UTILS behavior tests ==="

run_test 60 ALLOW "oc get pods -n my-app-dev | grep Running" \
  "SAFE_UTIL grep in pipe with granted cluster cmd -> allow"
run_test 61 ALLOW "oc get pods -n my-app-dev | jq '.items[]'" \
  "SAFE_UTIL jq in pipe with granted cluster cmd -> allow"
run_test 62 ALLOW "oc get pods -n my-app-dev | head -5 | wc -l" \
  "chained SAFE_UTILs in pipe with granted cluster cmd -> allow"
run_test 63 ASK   "oc get pods -n my-app-dev | python3 script.py" \
  "non-SAFE_UTIL in pipe -> ask"
run_test 64 ASK   "oc get pods -n my-app-dev && rm -rf /tmp/data" \
  "dangerous non-cluster cmd (rm not in SAFE_UTILS) -> ask"
run_test 65 ASK   "oc get pods -n my-app-dev && curl https://example.com" \
  "dangerous non-cluster cmd (curl not in SAFE_UTILS) -> ask"
run_test 66 ASK   'echo $(oc get pods -n my-app-dev) && echo $(rm -r)' \
  "subshell rm -r: rm not in SAFE_UTILS -> ask"

echo ""
echo "=== No-verb / tool-only tests ==="

run_test 67 ASK   "oc" \
  "bare oc with no verb -> ask"
run_test 68 ASK   "oc --help" \
  "oc --help: flags only, no verb found -> ask"
run_test 69 ASK   "kubectl" \
  "bare kubectl with no verb -> ask"
run_test 70 ASK   "helm --help" \
  "helm --help: flags only, no verb found -> ask"
run_test 71 ASK   "oc -n my-app-dev" \
  "oc with namespace but no verb -> ask"

echo ""
echo "=== verb1 vs verb (auto-allow precision) tests ==="

run_test 72 ALLOW "oc version --client" \
  "auto-allow verb with trailing flag: verb1=version matches OC_AUTO"
run_test 73 ALLOW "oc api-versions" \
  "auto-allow: api-versions matches OC_AUTO"
run_test 74 ALLOW "oc rollout status deployment/myapp -n my-app-dev" \
  "multi-word read: full verb 'rollout status' matches OC_READ"
run_test 75 ALLOW "oc rollout restart deployment/myapp -n my-app-dev" \
  "multi-word write: full verb 'rollout restart' matches OC_WRITE"
run_test 76 ALLOW "oc rollout status deployment/myapp -n my-app-prod" \
  "multi-word read on read-only ns: rollout status granted"
run_test 77 ASK   "oc rollout restart deployment/myapp -n my-app-prod" \
  "multi-word write on read-only ns: rollout restart denied"

echo ""
echo "=== Default-allow safety tests ==="

run_test 78 ASK   "ls -la" \
  "pure non-cluster cmd: early gate skips loop, falls to ask"
run_test 79 ASK   "rm -rf /" \
  "dangerous non-cluster cmd: early gate skips loop, falls to ask"
run_test 80 ASK   "   " \
  "whitespace-only command: empty after trim -> ask"
run_test 81 ALLOW "oc get pods -n my-app-dev && oc describe pod mypod -n my-app-dev" \
  "all segments policy-granted -> allow"
run_test 82 ASK   "oc get pods -n my-app-dev && oc delete pod mypod -n my-app-prod" \
  "one granted + one not granted segment -> ask"

echo ""
echo "=== Backtick arg & nested exec edge cases ==="

run_test 83 ALLOW 'grep `oc get secret -n my-app-dev`' \
  "backtick subshell as arg to safe utility: read in dev allowed"
run_test 84 DENY  'grep `oc get secret`' \
  "backtick subshell without namespace: oc read denied without -n"
run_test 85 ALLOW 'echo $(echo $(oc exec -n my-app-dev mypod -- cat /etc/passwd))' \
  "nested subshell + exec verb + post--- args: exec allowed in dev"
run_test 86 ASK   'echo "you should use oc to check pods"' \
  "false positive: oc in prose string, non-verb word after oc -> ask"

echo ""
echo "=== Default namespace derivation tests ==="

# Save original policy and create empty one
EMPTY_POLICY=$(mktemp /tmp/test-empty-policy-XXXXXX.yaml)
echo "namespaces:" > "$EMPTY_POLICY"
export OPENSHIFT_POLICY_FILE="$EMPTY_POLICY"

# Compute expected default namespace using the same formula
_repo_base=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")")
_user=$(whoami)
_repo_base=$(echo "${_repo_base:0:30}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g; s/-\+/-/g; s/-$//')
_user=$(echo "${_user:0:20}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g; s/-\+/-/g; s/-$//')
DEFAULT_NS="opg-${_repo_base}-${_user}"
DEFAULT_NS=$(echo "$DEFAULT_NS" | sed 's/-$//')

echo "Derived default namespace: $DEFAULT_NS"

run_test 87 ALLOW "oc get pods -n $DEFAULT_NS" \
  "default ns: oc read on derived ns -> allow"
run_test 88 ALLOW "oc delete pod mypod -n $DEFAULT_NS" \
  "default ns: oc write on derived ns -> allow"
run_test 89 ALLOW "oc exec -it mypod -n $DEFAULT_NS -- bash" \
  "default ns: oc exec on derived ns -> allow"
run_test 90 ALLOW "helm install myrelease mychart -n $DEFAULT_NS" \
  "default ns: helm write on derived ns -> allow"
run_test 91 ALLOW "helm uninstall myrelease -n $DEFAULT_NS" \
  "default ns: helm destructive on derived ns -> allow"
run_test 92 ASK   "oc get pods -n some-other-ns" \
  "default ns: unknown ns still asks"
run_test 93 DENY  "oc get pods" \
  "default ns: missing -n still denied"

echo ""
echo "=== derive_default_ns() function alignment test ==="

# Extract function body from openshift-policy.sh and README.md, compare
FUNC_FROM_HOOK=$(sed -n '/^derive_default_ns()/,/^}/p' "$HOOK")
FUNC_FROM_README=$(sed -n '/^derive_default_ns()/,/^}/p' "${SCRIPT_DIR}/README.md")

if [[ "$FUNC_FROM_HOOK" == "$FUNC_FROM_README" ]]; then
  printf "\033[32mPASS\033[0m #%-2s %s\n" "94" "derive_default_ns() in openshift-policy.sh matches README.md"
  ((passed++))
else
  printf "\033[31mFAIL\033[0m #%-2s %s\n" "94" "derive_default_ns() differs between openshift-policy.sh and README.md"
  diff <(echo "$FUNC_FROM_HOOK") <(echo "$FUNC_FROM_README") | head -20
  ((failed++))
fi

echo ""
echo "=== derive_default_ns() sanitization tests ==="

# Extract function from hook, then run with mocked git/whoami to test various inputs.
MOCK_DIR=$(mktemp -d /tmp/test-mock-XXXXXX)
FUNC_BODY=$(sed -n '/^derive_default_ns()/,/^}/p' "$HOOK")

# Helper: run derive_default_ns with controlled repo path and username.
# Mocks: git rev-parse → returns $1, whoami → returns $2.
run_derive_test() {
  local num="$1" mock_repo="$2" mock_user="$3" expected="$4" desc="$5"

  mkdir -p "${MOCK_DIR}/bin"
  cat > "${MOCK_DIR}/bin/git" <<SCRIPT
#!/bin/bash
if [[ "\$1" == "rev-parse" ]]; then echo "$mock_repo"; exit 0; fi
exec /usr/bin/git "\$@"
SCRIPT
  cat > "${MOCK_DIR}/bin/whoami" <<SCRIPT
#!/bin/bash
echo "$mock_user"
SCRIPT
  chmod +x "${MOCK_DIR}/bin/git" "${MOCK_DIR}/bin/whoami"

  local actual
  actual=$(PATH="${MOCK_DIR}/bin:$PATH" bash -c "${FUNC_BODY}"$'\nderive_default_ns' 2>/dev/null)

  if [[ "$actual" == "$expected" ]]; then
    printf "\033[32mPASS\033[0m #%-2s %s\n" "$num" "$desc"
    ((passed++))
  else
    printf "\033[31mFAIL\033[0m #%-2s %s\n" "$num" "$desc"
    echo "       Expected: '$expected'  Got: '$actual'"
    ((failed++))
  fi
}

# Basic case
run_derive_test 95 "/home/user/nvidia-rag-blueprint" "jdoe" \
  "opg-nvidia-rag-blueprint-jdoe" \
  "basic: simple repo + user"

# Uppercase → lowercase
run_derive_test 96 "/home/user/My-Cool-Repo" "JDoe" \
  "opg-my-cool-repo-jdoe" \
  "uppercase repo and user lowercased"

# Dots → hyphens
run_derive_test 97 "/home/user/my.repo.name" "j.doe" \
  "opg-my-repo-name-j-doe" \
  "dots replaced with hyphens"

# Underscores → hyphens
run_derive_test 98 "/home/user/my_repo_name" "j_doe" \
  "opg-my-repo-name-j-doe" \
  "underscores replaced with hyphens"

# Consecutive special chars → single hyphen
run_derive_test 99 "/home/user/my...repo" "j___doe" \
  "opg-my-repo-j-doe" \
  "consecutive special chars collapsed to single hyphen"

# Trailing special char → stripped
run_derive_test 100 "/home/user/my-repo-" "jdoe." \
  "opg-my-repo-jdoe" \
  "trailing special chars stripped from both parts"

# Long repo name → truncated to 30 chars
run_derive_test 101 "/home/user/abcdefghijklmnopqrstuvwxyz12345678" "u" \
  "opg-abcdefghijklmnopqrstuvwxyz1234-u" \
  "repo basename truncated to 30 chars"

# Long username → truncated to 20 chars
run_derive_test 102 "/home/user/r" "abcdefghijklmnopqrstuvwxyz" \
  "opg-r-abcdefghijklmnopqrst" \
  "username truncated to 20 chars"

# Both at max length → total ≤ 55 chars (opg- + 30 + - + 20)
run_derive_test 103 "/home/user/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "bbbbbbbbbbbbbbbbbbbb" \
  "opg-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbb" \
  "max lengths: total namespace ≤ 55 chars"

# Mixed special chars
run_derive_test 104 "/home/user/My_Repo.v2" "Jane.Doe_Admin" \
  "opg-my-repo-v2-jane-doe-admin" \
  "mixed special chars: uppercase + dots + underscores"

# Repo name ending with truncation at special char
run_derive_test 105 "/home/user/abcdefghijklmnopqrstuvwxyz123.remaining" "u" \
  "opg-abcdefghijklmnopqrstuvwxyz123-u" \
  "truncation at 30 leaves trailing dot -> hyphen -> stripped"

# Single-char names
run_derive_test 106 "/home/user/x" "y" \
  "opg-x-y" \
  "single-char repo and user"

# Username ending with hyphen → trailing hyphen stripped from final namespace
run_derive_test 107 "/home/user/repo" "jdoe-" \
  "opg-repo-jdoe" \
  "username ending with hyphen: trailing hyphen stripped"
# Restore original policy
export OPENSHIFT_POLICY_FILE="$TEST_POLICY"

echo ""
echo "=== Results ==="
echo "Passed: $passed  Failed: $failed  Total: $((passed + failed))"
[[ $failed -eq 0 ]] && echo "All tests passed!" || exit 1
