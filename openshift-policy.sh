#!/usr/bin/env bash
# PreToolUse hook: gate oc/kubectl/helm commands against namespace policy.
#
# Exit outcomes (stdout):
#   allow  — JSON {"permissionDecision":"allow"}     → run without prompt
#   deny   — JSON {"permissionDecision":"deny"}      → block command
#   ask    — no JSON, exit 0                         → defer to IDE/user prompt
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_FILE="${OPENSHIFT_POLICY_FILE:-${SCRIPT_DIR}/openshift-policy.yaml}"

# Hook responses — tell Cursor to allow, deny (with reason), or fall back to user prompt.
allow() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}\n'
  exit 0
}

deny() {
  jq -n --arg r "$1" \
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$r}}'
  exit 0
}

ask() { exit 0; }

# Read command from hook input; skip if empty or not a cluster tool.
command -v jq &>/dev/null || { echo "Error: jq is required but not installed." >&2; exit 2; }

COMMAND=$(jq -r '.tool_input.command // empty' 2>/dev/null) || ask
[[ -z "$COMMAND" ]] && ask
echo "$COMMAND" | grep -qwE '(oc|kubectl|helm)' || ask

# Derive a deterministic default namespace from repo name + OS user.
derive_default_ns() {
  local repo_root repo_base user default_ns
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || repo_root="$PWD"
  repo_base="$(basename "$repo_root")"
  user="$(whoami)"
  repo_base="$(echo "${repo_base:0:30}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g; s/-\+/-/g; s/-$//')"
  user="$(echo "${user:0:20}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g; s/-\+/-/g; s/-$//')"
  default_ns="opg-${repo_base}-${user}"
  echo "$default_ns" | sed 's/-$//'
}

# Load per-namespace permission groups from openshift-policy.yaml.
declare -A OC_GROUPS HELM_GROUPS

if [[ -f "$POLICY_FILE" ]]; then
  current_ns=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]{2}([a-zA-Z0-9][a-zA-Z0-9._-]*):[[:space:]]*$ ]]; then
      current_ns="${BASH_REMATCH[1]}"
    elif [[ -n "$current_ns" && "$line" =~ ^[[:space:]]+(oc|helm):[[:space:]]*\[([^\]]*)\] ]]; then
      groups=$(echo "${BASH_REMATCH[2]}" | tr -d ' ')
      if [[ "${BASH_REMATCH[1]}" == "oc" ]]; then
        OC_GROUPS["$current_ns"]="$groups"
      else
        HELM_GROUPS["$current_ns"]="$groups"
      fi
    fi
  done < "$POLICY_FILE"
fi

# Fallback: derive default namespace when policy has no namespaces configured.
if [[ ${#OC_GROUPS[@]} -eq 0 && ${#HELM_GROUPS[@]} -eq 0 ]]; then
  _default_ns="$(derive_default_ns)"
  OC_GROUPS["$_default_ns"]="read,write,exec"
  HELM_GROUPS["$_default_ns"]="read,write,destructive"
fi

# Comma-separated namespace list for deny messages.
ns_list=""
declare -A _seen_ns
for ns in ${!OC_GROUPS[@]} ${!HELM_GROUPS[@]}; do
  [[ -n "${_seen_ns[$ns]:-}" ]] && continue
  [[ -n "$ns_list" ]] && ns_list+=", "
  ns_list+="$ns"
  _seen_ns["$ns"]=1
done
[[ -z "$ns_list" ]] && ns_list="(none configured in policy)"

# Verb buckets: auto-allowed, read, write, exec/destructive.
OC_AUTO="|version|whoami|api-resources|api-versions|"
OC_READ="|get|describe|logs|events|top|explain|status|diff|wait|auth can-i|rollout status|rollout history|"
OC_WRITE="|apply|create|patch|delete|scale|label|annotate|set|run|edit|replace|expose|autoscale|rollout restart|rollout undo|rollout pause|rollout resume|"
OC_EXEC="|exec|debug|port-forward|cp|attach|"

HELM_AUTO="|version|env|template|lint|"
HELM_READ="|template|list|status|get|show|history|search|verify|dependency list|repo list|plugin list|"
HELM_WRITE="|install|upgrade|dependency update|dependency build|"
HELM_DESTRUCTIVE="|uninstall|rollback|delete|"

MW_PREFIXES="|rollout|auth|dependency|repo|plugin|"
SAFE_UTILS="|grep|wc|head|tail|cut|tr|column|jq|cat|fmt|base64|echo|diff|printf|"

# Check if verb appears in a pipe-delimited list.
verb_in() { [[ "$2" == *"|$1|"* ]]; }

# Parse one command chunk into "tool:verb" (e.g. oc:get pods), skipping flags.
classify_segment() {
  echo "$1" | \
    sed 's/^[A-Z_][A-Z_0-9]*=[^ ]* *//g' | \
    awk -v p="$MW_PREFIXES" '{
      for (i = 1; i <= NF; i++) {
        cmd = $i; gsub(/.*\//, "", cmd)           # Get base command, no path
        if (cmd ~ /^(oc|kubectl|helm)$/) {        # Found cluster tool
          tool = (cmd == "kubectl") ? "oc" : cmd  # Treat kubectl as oc
          j = i + 1
          while (j <= NF) {
            if ($j !~ /^-/) {                     # Not a flag: treat as verb or start of multi-word verb
              v = $j
              if (index(p, "|" v "|") > 0 && j+1 <= NF && $(j+1) !~ /^-/) {
                printf "%s:%s %s", tool, v, $(j+1); exit   # Multi-word verb
              }
              printf "%s:%s", tool, v; exit       # Single verb
            } else if ($j ~ /=/) { j++ }          # Flag=val, skip pair
            else {
              f = $j; gsub(/^-+/, "", f)   # Strip leading dashes from flag (e.g. -n or --namespace)
              # Skip next if flag expects a value
              if (f ~ /^(n|o|c|f|l|s|context|cluster|user|kubeconfig|namespace|output|selector|field-selector|server)$/)
                j += 2
              else j++
            }
          }
          printf "%s:", tool; exit                # Only tool found
        }
      }
    }'
}

# Extract -n/--namespace; __ALL__ if -A/--all-namespaces.
extract_namespace() {
  if echo "$1" | grep -qE '(^|[[:space:]])(-A|--all-namespaces)([[:space:]]|$)'; then
    echo "__ALL__"; return
  fi
  local ns
  ns=$(echo "$1" | grep -oE -- '-n[[:space:]]+[^[:space:]]+' | head -1 | awk '{print $2}')
  if [[ -n "$ns" ]]; then echo "$ns"; return; fi
  ns=$(echo "$1" | grep -oE -- '-n[^[:space:]-][^[:space:]]*' | head -1 | sed 's/^-n//')
  if [[ -n "$ns" ]]; then echo "$ns"; return; fi
  ns=$(echo "$1" | grep -oE -- '--namespace[=[:space:]][^[:space:]]+' | head -1 | sed 's/--namespace[= ]*//')
  [[ -n "$ns" ]] && echo "$ns"
  return 0
}

# Split compound command and check each segment; deny > ask > allow.
has_deny=false deny_reason="" has_ask=false

while IFS= read -r segment; do
  segment=$(echo "$segment" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [[ -z "$segment" ]] && continue

  # Hard deny: shell output redirection.
  if echo "$segment" | sed 's/>=/___/g' | grep -qE '(^|[^&0-9])>>?'; then
    has_deny=true
    deny_reason="Output redirection not allowed. Command output is captured automatically by Claude Code."
    continue
  fi

  result=$(classify_segment "$segment")

  # Unrecognized segment: allow only if whitelisted utility; else ask.
  if [[ -z "$result" ]]; then
    first_word=$(echo "$segment" | awk '{cmd=$1; gsub(/.*\//, "", cmd); print cmd}')
    if echo "$segment" | grep -qwE 'oc|kubectl|helm'; then
      has_ask=true; continue
    fi
    if verb_in "$first_word" "$SAFE_UTILS"; then continue
    else has_ask=true; continue; fi
  fi

  tool="${result%%:*}"
  verb="${result#*:}"
  [[ -z "$verb" ]] && { has_ask=true; continue; }
  verb1="${verb%% *}"

  # oc: require namespace, match verb against policy groups for that namespace.
  if [[ "$tool" == "oc" ]]; then
    verb_in "$verb1" "$OC_AUTO" && continue
    if ! verb_in "$verb" "$OC_READ" && ! verb_in "$verb" "$OC_WRITE" && ! verb_in "$verb" "$OC_EXEC"; then
      has_ask=true; continue
    fi
    ns=$(extract_namespace "$segment")
    [[ "$ns" == "__ALL__" ]] && { has_ask=true; continue; }
    [[ -z "$ns" ]] && { has_deny=true; deny_reason="Namespace required. Add -n <namespace>. Allowed: ${ns_list}"; continue; }
    [[ -z "${OC_GROUPS[$ns]:-}" ]] && { has_ask=true; continue; }
    allowed="${OC_GROUPS[$ns]}"
    granted=false
    verb_in "$verb" "$OC_READ" && [[ ",$allowed," == *",read,"* ]] && granted=true
    verb_in "$verb" "$OC_WRITE" && [[ ",$allowed," == *",write,"* ]] && granted=true
    verb_in "$verb" "$OC_EXEC" && [[ ",$allowed," == *",exec,"* ]] && granted=true
    $granted || { has_ask=true; continue; }

  # helm: same flow — namespace required, verb checked against policy groups.
  elif [[ "$tool" == "helm" ]]; then
    verb_in "$verb1" "$HELM_AUTO" && continue
    if ! verb_in "$verb" "$HELM_READ" && ! verb_in "$verb" "$HELM_WRITE" && ! verb_in "$verb" "$HELM_DESTRUCTIVE"; then
      has_ask=true; continue
    fi
    ns=$(extract_namespace "$segment")
    [[ "$ns" == "__ALL__" ]] && { has_ask=true; continue; }
    [[ -z "$ns" ]] && { has_deny=true; deny_reason="Namespace required. Add -n <namespace>. Allowed: ${ns_list}"; continue; }
    [[ -z "${HELM_GROUPS[$ns]:-}" ]] && { has_ask=true; continue; }
    allowed="${HELM_GROUPS[$ns]}"
    granted=false
    verb_in "$verb" "$HELM_READ" && [[ ",$allowed," == *",read,"* ]] && granted=true
    verb_in "$verb" "$HELM_WRITE" && [[ ",$allowed," == *",write,"* ]] && granted=true
    verb_in "$verb" "$HELM_DESTRUCTIVE" && [[ ",$allowed," == *",destructive,"* ]] && granted=true
    $granted || { has_ask=true; continue; }
  fi

done < <(echo "$COMMAND" | sed $'s/\\$(/\\\n/g; s/`/\\\n/g; s/)/\\\n/g' | awk '{gsub(/\|\|/, "\n"); gsub(/&&/, "\n"); gsub(/;/, "\n"); gsub(/\|/, "\n"); print}')

# Emit final decision to Cursor.
if $has_deny; then deny "$deny_reason"
elif $has_ask; then ask
else allow
fi
