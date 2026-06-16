#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_FILE="${OPENSHIFT_POLICY_FILE:-${SCRIPT_DIR}/openshift-policy.yaml}"

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

command -v jq &>/dev/null || { echo "Error: jq is required but not installed." >&2; exit 2; }

COMMAND=$(jq -r '.tool_input.command // empty' 2>/dev/null) || ask
[[ -z "$COMMAND" ]] && ask
echo "$COMMAND" | grep -qwE '(oc|kubectl|helm)' || ask

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

ns_list=""
declare -A _seen_ns
for ns in ${!OC_GROUPS[@]} ${!HELM_GROUPS[@]}; do
  [[ -n "${_seen_ns[$ns]:-}" ]] && continue
  [[ -n "$ns_list" ]] && ns_list+=", "
  ns_list+="$ns"
  _seen_ns["$ns"]=1
done
[[ -z "$ns_list" ]] && ns_list="(none configured in policy)"

OC_AUTO="|version|whoami|api-resources|api-versions|"
OC_READ="|get|describe|logs|events|top|explain|status|diff|wait|auth can-i|rollout status|rollout history|"
OC_WRITE="|apply|create|patch|delete|scale|label|annotate|set|run|edit|replace|expose|autoscale|rollout restart|rollout undo|rollout pause|rollout resume|"
OC_EXEC="|exec|debug|port-forward|cp|attach|"

HELM_AUTO="|version|env|repo|template|lint|"
HELM_READ="|template|lint|list|status|get|show|history|search|verify|dependency list|repo list|plugin list|"
HELM_WRITE="|install|upgrade|dependency update|dependency build|"
HELM_DESTRUCTIVE="|uninstall|rollback|delete|"

MW_PREFIXES="|rollout|auth|dependency|repo|plugin|"
SAFE_UTILS="|grep|wc|head|tail|cut|tr|column|jq|cat|fmt|base64|echo|diff|printf|"

verb_in() { [[ "$2" == *"|$1|"* ]]; }

classify_segment() {
  echo "$1" | \
    sed 's/^[A-Z_][A-Z_0-9]*=[^ ]* *//g' | \
    awk -v p="$MW_PREFIXES" '{
      for (i = 1; i <= NF; i++) {
        cmd = $i; gsub(/.*\//, "", cmd)
        if (cmd ~ /^(oc|kubectl|helm)$/) {
          tool = (cmd == "kubectl") ? "oc" : cmd
          j = i + 1
          while (j <= NF) {
            if ($j !~ /^-/) {
              v = $j
              if (index(p, "|" v "|") > 0 && j+1 <= NF && $(j+1) !~ /^-/) {
                printf "%s:%s %s", tool, v, $(j+1); exit
              }
              printf "%s:%s", tool, v; exit
            } else if ($j ~ /=/) { j++ }
            else {
              f = $j; gsub(/^-+/, "", f)
              if (f ~ /^(n|o|c|f|l|s|context|cluster|user|kubeconfig|namespace|output|selector|field-selector|server)$/)
                j += 2
              else j++
            }
          }
          printf "%s:", tool; exit
        }
      }
    }'
}

extract_namespace() {
  if echo "$1" | grep -qE '(^|[[:space:]])(-A|--all-namespaces)([[:space:]]|$)'; then
    echo "__ALL__"; return
  fi
  local ns
  ns=$(echo "$1" | grep -oE -- '-n[[:space:]]+[^[:space:]]+' | head -1 | awk '{print $2}')
  if [[ -n "$ns" ]]; then echo "$ns"; return; fi
  ns=$(echo "$1" | grep -oE -- '--namespace[=[:space:]][^[:space:]]+' | head -1 | sed 's/--namespace[= ]*//')
  [[ -n "$ns" ]] && echo "$ns"
  return 0
}

has_deny=false deny_reason="" has_ask=false

while IFS= read -r segment; do
  segment=$(echo "$segment" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [[ -z "$segment" ]] && continue

  if echo "$segment" | sed 's/>=/___/g' | grep -qE '(^|[^&0-9])>>?'; then
    has_deny=true
    deny_reason="Output redirection not allowed. Command output is captured automatically by Claude Code."
    continue
  fi

  result=$(classify_segment "$segment")

  if [[ -z "$result" ]]; then
    first_word=$(echo "$segment" | awk '{cmd=$1; gsub(/.*\//, "", cmd); print cmd}')
    if verb_in "$first_word" "$SAFE_UTILS"; then continue
    else has_ask=true; continue; fi
  fi

  tool="${result%%:*}"
  verb="${result#*:}"
  [[ -z "$verb" ]] && { has_ask=true; continue; }
  verb1="${verb%% *}"

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

done < <(echo "$COMMAND" | awk '{gsub(/\|\|/, "\n"); gsub(/&&/, "\n"); gsub(/;/, "\n"); gsub(/\|/, "\n"); print}')

if $has_deny; then deny "$deny_reason"
elif $has_ask; then ask
else allow
fi
