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
trap 'rm -f "$TEST_POLICY"' EXIT

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
run_test 35 ALLOW "helm repo list" \
  "helm repo list (auto-allowed via repo prefix)"
run_test 36 ALLOW "helm repo add myrepo https://example.com" \
  "helm repo add (auto-allowed via repo prefix)"
run_test 37 ALLOW "kubectl get pods -n my-app-dev" \
  "kubectl normalized to oc"
run_test 38 ALLOW "oc -n my-app-dev -o json get pods" \
  "multiple flags before verb"
run_test 39 DENY  "oc rollout restart deployment/myapp" \
  "multi-word write verb, no namespace"

echo ""
echo "=== Results ==="
echo "Passed: $passed  Failed: $failed  Total: $((passed + failed))"
[[ $failed -eq 0 ]] && echo "All tests passed!" || exit 1
