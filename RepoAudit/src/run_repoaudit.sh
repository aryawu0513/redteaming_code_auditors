#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# --- Defaults ---
LANGUAGE="${LANGUAGE:-Python}"
MODEL="${MODEL:-anthropic/claude-3.5-sonnet}"
DEFAULT_PROJECT_NAME="inject"
DEFAULT_BUG_TYPE="NPD"     # allowed: MLK, NPD, UAF
SCAN_TYPE="dfbscan"

# Construct the default project *path* from LANGUAGE + DEFAULT_PROJECT_NAME
DEFAULT_PROJECT_PATH="../benchmark/${LANGUAGE}/${DEFAULT_PROJECT_NAME}"

show_usage() {
  cat <<'EOF'
Usage: run_scan.sh [PROJECT_PATH] [BUG_TYPE] [FILES]

Arguments:
  PROJECT_PATH   Optional absolute/relative path to the subject project.
                 Defaults to: ../benchmark/Python/inject
  BUG_TYPE       Optional bug type. One of: MLK, NPD, UAF. Defaults to: NPD
  FILES          Optional comma-separated glob patterns to restrict which files
                 are scanned. E.g. 'attack_B*.py,attack_E*.py'. Defaults to all files.

Bug type meanings:
  MLK  - Memory Leak
  NPD  - Null Pointer Dereference
  UAF  - Use After Free

Examples:
  ./run_scan.sh
  ./run_scan.sh /path/to/my/project
  ./run_scan.sh ./repos/demo UAF
  ./run_scan.sh ./repos/demo NPD 'attack_B*.py,attack_E*.py'
  ./run_scan.sh --help
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  show_usage
  exit 0
fi

# --- Args ---
PROJECT_PATH="${1:-$DEFAULT_PROJECT_PATH}"
BUG_TYPE_RAW="${2:-$DEFAULT_BUG_TYPE}"
FILES_PATTERN="${3:-}"

# Normalize BUG_TYPE to uppercase (accepts mlk/npd/uaf too)
BUG_TYPE="$(echo "$BUG_TYPE_RAW" | tr '[:lower:]' '[:upper:]')"

# --- Validate BUG_TYPE ---
case "$BUG_TYPE" in
  MLK|NPD|UAF) : ;;
  *)
    echo "Error: BUG_TYPE must be one of: MLK, NPD, UAF (got '$BUG_TYPE_RAW')." >&2
    echo "       MLK = Memory Leak; NPD = Null Pointer Dereference; UAF = Use After Free." >&2
    exit 1
    ;;
esac

# --- Resolve and validate PROJECT_PATH ---
if ! PROJECT_PATH_ABS="$(cd "$(dirname -- "$PROJECT_PATH")" && pwd)/$(basename -- "$PROJECT_PATH")"; then
  echo "Error: Could not resolve PROJECT_PATH: $PROJECT_PATH" >&2
  exit 1
fi

if [[ ! -d "$PROJECT_PATH_ABS" ]]; then
  echo "Error: PROJECT_PATH does not exist or is not a directory: $PROJECT_PATH_ABS" >&2
  exit 1
fi

# --- Run ---
run_once() {
  local pattern="$1"
  local run_id="$2"
  local files_arg=()
  local run_id_arg=()
  if [[ -n "$pattern" ]]; then
    files_arg=(--files "$pattern")
  fi
  if [[ -n "$run_id" ]]; then
    run_id_arg=(--run-id "$run_id")
  fi
  python3 repoaudit.py \
    --language "$LANGUAGE" \
    --model-name "$MODEL" \
    --project-path "$PROJECT_PATH_ABS" \
    --bug-type "$BUG_TYPE" \
    --is-reachable \
    --temperature 0.0 \
    --scan-type "$SCAN_TYPE" \
    --call-depth 3 \
    --max-neural-workers 30 \
    "${files_arg[@]}" \
    "${run_id_arg[@]}"
}

if [[ -z "$FILES_PATTERN" ]]; then
  # No filter: scan everything together (original behaviour).
  run_once "" ""
else
  # Expand every comma-separated glob pattern to individual filenames, then
  # run each file in its own isolated call so files are never analyzed
  # together (avoids cross-file call graph explosion).
  # All per-file runs share one output directory via a single RUN_ID.
  _RUN_ID="$(date +'%Y-%m-%d-%H-%M-%S')-0"
  declare -A _seen
  _files=()
  IFS=',' read -ra _pats <<< "$FILES_PATTERN"
  for _pat in "${_pats[@]}"; do
    _pat="$(echo "$_pat" | tr -d '[:space:]')"
    [[ -z "$_pat" ]] && continue
    while IFS= read -r _fp; do
      _fn="$(basename "$_fp")"
      if [[ -z "${_seen[$_fn]+x}" ]]; then
        _seen[$_fn]=1
        _files+=("$_fn")
      fi
    done < <(find "$PROJECT_PATH_ABS" -name "$_pat" -type f 2>/dev/null | sort)
  done

  if [[ ${#_files[@]} -eq 0 ]]; then
    echo "Error: no files matched '$FILES_PATTERN' under $PROJECT_PATH_ABS" >&2
    exit 1
  fi

  for _fn in "${_files[@]}"; do
    run_once "$_fn" "$_RUN_ID"
  done
fi
