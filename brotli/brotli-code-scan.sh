#!/usr/bin/env bash
# Brotli CVE-2026-111497: does your own code call the Brotli decoder? Runs JFrog's source scanners
# (JS, Python, ELF, shell scripts) over every git repo found under the given dirs.
# usage: ./brotli-code-scan.sh [-q] [dir...]     (default: current dir)
#   -q   print only repos with findings
# exit: 0 = nothing found, 2 = at least one repo applicable, 3 = nothing found but some files unreadable, 1 = setup error
# Credit: detection is JFrog's (github.com/jfrog/vulnerability_scanners, Apache-2.0); this only wraps it.
# Needs python3 >= 3.10, curl, git-style .git dirs. Fetches JFrog's scripts (pinned commit, Apache-2.0)
# into a temp dir plus a throwaway venv for tree-sitter; nothing is installed system-wide and your repos are only read.
# A finding means "code reaches a Brotli API", not "exploitable". Pair with brotli-cve-check.sh for versions.
set -uo pipefail

# https://github.com/jfrog/vulnerability_scanners/tree/main/brotli2shell_cve_2026_111497
JF_SHA=93a2ac57d47a31950dca952c689d35e1e0fbe8fa
JF_RAW=https://raw.githubusercontent.com/jfrog/vulnerability_scanners/$JF_SHA/brotli2shell_cve_2026_111497
FILES="cve_2026_111497.py brotli_scan_common.py scan_brotli_js.py scan_brotli_python.py scan_brotli_elf.py scan_brotli_scripts.py"

QUIET=0
[ "${1:-}" = -q ] && { QUIET=1; shift; }
[ $# -gt 0 ] || set -- .
die() { echo "$*" >&2; exit 1; }

PY=$(command -v python3) || die "python3 not found"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "python3 >= 3.10 required"
command -v curl >/dev/null || die "curl not found"

W=$(mktemp -d) && trap 'rm -rf "$W"' EXIT
for f in $FILES; do curl -fsSL "$JF_RAW/$f" -o "$W/$f" || die "download failed: $f"; done
"$PY" -m venv "$W/venv" && "$W/venv/bin/pip" install -q --disable-pip-version-check tree-sitter==0.26.0 tree-sitter-javascript==0.25.0 \
  || die "venv/pip setup failed (tree-sitter wheels needed)"
SCAN="$W/venv/bin/python $W/cve_2026_111497.py"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' N=$'\e[0m'; else R= G= Y= N=; fi

# repos = dirs holding a .git dir; skip dependency/venv trees so we don't crawl them
mapfile -t REPOS < <(find "$@" \( -name node_modules -o -name site-packages -o -name .venv -o -name venv \) -prune \
  -o -type d -name .git -prune -print 2>/dev/null | sed 's#/\.git$##' | sort -u)
[ ${#REPOS[@]} -gt 0 ] || die "no git repos under: $*"

RC=0 ROWS=()
for repo in "${REPOS[@]}"; do
  ex=()  # nested repos get their own scan: don't count them twice
  for o in "${REPOS[@]}"; do case $o in "$repo"/*) ex+=(--exclude "$o");; esac; done
  out=$($SCAN "$repo" ${ex[@]+"${ex[@]}"} --quiet 2>&1); rc=$?
  case $rc in
    0) v="${G}not applicable${N}";;
    1) v="${R}APPLICABLE${N}"; RC=2;;
    3) v="${Y}incomplete${N}"; [ $RC -eq 0 ] && RC=3;;
    *) v="${Y}error($rc)${N}"; [ $RC -eq 0 ] && RC=3;;
  esac
  [ $rc -ne 0 ] && { echo "== $repo"; echo "$out"; echo; }
  ROWS+=("$rc|$repo|$v")
done

echo "Brotli CVE-2026-111497 code scan: ${#REPOS[@]} repos"
printf '%s\n' "${ROWS[@]}" | sort -t'|' -k1,1nr | while IFS='|' read -r rc repo v; do
  [ $QUIET -eq 1 ] && [ "$rc" = 0 ] && continue
  printf '  %-60s %s\n' "$repo" "$v"
done
exit $RC
