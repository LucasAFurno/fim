#!/usr/bin/env bash
# ========================================================================
# Simple File Integrity Monitor (FIM)
# Description:
#   - init:  Create a SHA-256 baseline for a directory
#   - scan:  Compare current state vs baseline (modified/new/deleted files)
# Author: Lucas Furno
# License: MIT
# ========================================================================

set -euo pipefail
IFS=$'\n\t'

bold=$(tput bold || true); reset=$(tput sgr0 || true)
green=$(tput setaf 2 || true); yellow=$(tput setaf 3 || true); red=$(tput setaf 1 || true)

usage() {
  cat <<EOF
Usage:
  $0 init  <directory> [baseline_file]
  $0 scan  <directory> [baseline_file]

Notes:
  - Baseline defaults to .fim-baseline in the target directory.
  - Follows regular files only. Symlinks are skipped.
  - You can exclude paths with FIM_EXCLUDES (comma-separated globs).
    Example: FIM_EXCLUDES="*.log,*.tmp,cache/*" $0 init /etc
EOF
}

# --- hash command detection (sha256sum or shasum -a 256) ---
hash_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd="shasum -a 256"
else
  echo "${red}[ERROR]${reset} No SHA-256 tool found (install 'sha256sum' or 'shasum')." >&2
  exit 1
fi

# --- normalize paths ---
abs_path() {
  # portable realpath alternative
  # usage: abs_path <path>
  cd "$(dirname -- "$1")" >/dev/null 2>&1
  local base; base=$(basename -- "$1")
  printf "%s\n" "$(pwd -P)/$base"
}

# --- exclude filter from FIM_EXCLUDES ---
should_exclude() {
  # returns 0 (true) if file matches any exclude pattern
  local f="$1"
  local excludes="${FIM_EXCLUDES:-}"
  [ -z "$excludes" ] && return 1
  # split by comma
  local IFS=,
  for pat in $excludes; do
    # use shell globbing with case-sensitive match
    if [[ "$(basename -- "$f")" == $pat || "$f" == $pat ]]; then
      return 0
    fi
  done
  return 1
}

create_baseline() {
  local dir="$1"
  local baseline="${2:-$dir/.fim-baseline}"

  dir="$(abs_path "$dir")"
  baseline="$(abs_path "$baseline")"

  echo "${bold}[*] Creating baseline for:${reset} $dir"
  tmpfile="$(mktemp)"
  trap 'rm -f "$tmpfile"' EXIT

  # find regular files, skip symlinks; null-safe
  while IFS= read -r -d '' f; do
    # normalize to absolute path
    f="$(abs_path "$f")"
    should_exclude "$f" && continue
    # hash format: <sha256>  <absolute_path>
    # shellcheck disable=SC2086
    $hash_cmd "$f" >> "$tmpfile"
  done < <(find "$dir" -type f -not -path '*/.git/*' -print0)

  # sort for deterministic comparisons
  sort -k2 "$tmpfile" > "$baseline"
  echo "${green}[✓] Baseline saved:${reset} $baseline"
}

scan_baseline() {
  local dir="$1"
  local baseline="${2:-$dir/.fim-baseline}"

  dir="$(abs_path "$dir")"
  baseline="$(abs_path "$baseline")"

  if [ ! -f "$baseline" ]; then
    echo "${red}[ERROR]${reset} Baseline not found: $baseline"
    echo "Run: $0 init $dir"
    exit 1
  fi

  echo "${bold}[*] Scanning directory:${reset} $dir"
  tmpcurr="$(mktemp)"
  trap 'rm -f "$tmpcurr"' EXIT

  while IFS= read -r -d '' f; do
    f="$(abs_path "$f")"
    should_exclude "$f" && continue
    # shellcheck disable=SC2086
    $hash_cmd "$f" >> "$tmpcurr"
  done < <(find "$dir" -type f -not -path '*/.git/*' -print0)

  sort -k2 "$tmpcurr" -o "$tmpcurr"

  # Extract file lists
  awk '{print $2}' "$baseline" > "$tmpcurr.baselist"
  awk '{print $2}' "$tmpcurr"   > "$tmpcurr.currlist"

  # Detect new and deleted files
  new_files=$(comm -13 "$tmpcurr.baselist" "$tmpcurr.currlist" || true)
  deleted_files=$(comm -23 "$tmpcurr.baselist" "$tmpcurr.currlist" || true)

  # Detect modified files (present in both but hash changed)
  modified_files=$(
    join -j2 -o 1.1,1.2,2.1 <(sort -k2 "$baseline") <(sort -k2 "$tmpcurr") \
    | awk '{ if ($1 != $3) print $2 }' || true
  )

  # Report
  changes=0
  if [ -n "$new_files" ]; then
    echo "${yellow}[+] New files:${reset}"
    echo "$new_files"
    changes=1
  fi
  if [ -n "$deleted_files" ]; then
    echo "${yellow}[-] Deleted files:${reset}"
    echo "$deleted_files"
    changes=1
  fi
  if [ -n "$modified_files" ]; then
    echo "${yellow}[~] Modified files:${reset}"
    echo "$modified_files"
    changes=1
  fi

  if [ "$changes" -eq 0 ]; then
    echo "${green}[✓] No changes detected vs baseline.${reset}"
  else
    echo
    echo "${bold}Tip:${reset} If these changes are expected, refresh the baseline:"
    echo "  $0 init \"$dir\" \"$baseline\""
  fi
}

main() {
  [ $# -lt 2 ] && { usage; exit 1; }
  local cmd="$1"; shift
  case "$cmd" in
    init) create_baseline "$@";;
    scan) scan_baseline "$@";;
    *) usage; exit 1;;
  esac
}

main "$@"
