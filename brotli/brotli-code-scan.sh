#!/usr/bin/env bash
# Brotli CVE-2026-111497: does your own code call the Brotli decoder? Runs JFrog's source scanners
# (JS, Python, ELF, shell scripts) over every git repo found under the given dirs, plus two extras of ours:
#   - the same JFrog JS analysis on TypeScript/ESM/CJS/JSX files, which JFrog skips (.ts .tsx .mts .cts .mjs .cjs .jsx)
#   - a REVIEW list of files in other languages (Java, Go, Rust, Ruby, PHP, C/C++, C#...) that mention brotli
# usage: ./brotli-code-scan.sh [-q] [dir...]     (default: current dir)
#   -q   print only repos with findings
# exit: 0 = nothing found, 2 = at least one repo applicable, 3 = nothing found but some files unreadable, 1 = setup error
#       (REVIEW mentions alone do not change the exit code)
# Credit: detection is JFrog's (github.com/jfrog/vulnerability_scanners, Apache-2.0); this wraps it.
# Needs python3 >= 3.10, curl, git. Fetches JFrog's scripts (pinned commit) into a temp dir plus a throwaway
# venv for tree-sitter; nothing is installed system-wide and your repos are only read.
# A finding means "code reaches a Brotli API", not "exploitable". Pair with brotli-cve-check.sh for versions.
set -uo pipefail

# https://github.com/jfrog/vulnerability_scanners/tree/main/brotli2shell_cve_2026_111497
JF_SHA=93a2ac57d47a31950dca952c689d35e1e0fbe8fa
JF_RAW=https://raw.githubusercontent.com/jfrog/vulnerability_scanners/$JF_SHA/brotli2shell_cve_2026_111497
FILES="cve_2026_111497.py brotli_scan_common.py scan_brotli_js.py scan_brotli_python.py scan_brotli_elf.py scan_brotli_scripts.py"
OTHER_EXT='java|kt|kts|scala|groovy|go|rs|rb|php|c|cc|cpp|cxx|h|hh|hpp|cs|swift|m|mm|dart|ex|exs|lua|zig'

QUIET=0
[ "${1:-}" = -q ] && { QUIET=1; shift; }
[ $# -gt 0 ] || set -- .
die() { echo "$*" >&2; exit 1; }

PY=$(command -v python3) || die "python3 not found"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "python3 >= 3.10 required"
command -v curl >/dev/null || die "curl not found"
command -v git >/dev/null || die "git not found"

W=$(mktemp -d) && trap 'rm -rf "$W"' EXIT
for f in $FILES; do curl -fsSL --connect-timeout 10 --max-time 60 --retry 3 "$JF_RAW/$f" -o "$W/$f" || die "download failed: $f"; done
"$PY" -m venv "$W/venv" && "$W/venv/bin/pip" install -q --disable-pip-version-check \
  tree-sitter==0.26.0 tree-sitter-javascript==0.25.0 tree-sitter-typescript==0.23.2 \
  || die "venv/pip setup failed (tree-sitter wheels needed)"

# Our extra scanner: JFrog's JS finder, fed TypeScript/ESM/CJS/JSX files with the matching grammar.
cat > "$W/scan_brotli_ts.py" <<'PY'
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import brotli_scan_common as common
import scan_brotli_js as js
import tree_sitter_typescript as ts
from tree_sitter import Language, Parser

TS = {".ts": ts.language_typescript, ".mts": ts.language_typescript,
      ".cts": ts.language_typescript, ".tsx": ts.language_tsx}
JS_ONLY = (".mjs", ".cjs", ".jsx")  # plain-JS grammar already handles JSX
_parsers = {}

def wants(path):
    return path.endswith(tuple(TS) + JS_ONLY) and not path.endswith(".d.ts")

def scan_file(path):
    ext = os.path.splitext(path)[1]
    if ext not in _parsers:
        _parsers[ext] = Parser(Language(TS[ext]())) if ext in TS else js._get_parser()
    js._parser = _parsers[ext]
    return js.scan_file(path)

scanner = types.SimpleNamespace(NAME="TypeScript/ESM", wants=wants, scan_file=scan_file)
sys.exit(common.main([scanner], "TypeScript/ESM Brotli scan", sys.argv[1:]))
PY
VPY="$W/venv/bin/python"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' N=$'\e[0m'; else R= G= Y= N=; fi

# repos = dirs holding a .git dir; skip dependency/venv trees so we don't crawl them
mapfile -t REPOS < <(find "$@" \( -name node_modules -o -name site-packages -o -name .venv -o -name venv \) -prune \
  -o -type d -name .git -prune -print 2>/dev/null | sed 's#/\.git$##' | sort -u)
[ ${#REPOS[@]} -gt 0 ] || die "no git repos under: $*"

# severity: 0 clean, 1 review (mentions only), 2 incomplete/error, 3 applicable
sev_of() { case $1 in 0) echo 0;; 1) echo 3;; *) echo 2;; esac; }

RC=0 ROWS=()
for repo in "${REPOS[@]}"; do
  ex=()  # nested repos get their own scan: don't count them twice
  for o in "${REPOS[@]}"; do case $o in "$repo"/*) ex+=(--exclude "$o");; esac; done
  # git-ignored dirs (.next, dist, build...) are generated code, not ours: skip them
  while IFS= read -r -d '' d; do [ -d "$repo/$d" ] && ex+=(--exclude "$repo/$d"); done < <(
    git -C "$repo" ls-files -z --others --ignored --exclude-standard --directory 2>/dev/null)
  out1=$($VPY "$W/cve_2026_111497.py" "$repo" ${ex[@]+"${ex[@]}"} --quiet 2>&1); rc1=$?
  out2=$($VPY "$W/scan_brotli_ts.py" "$repo" ${ex[@]+"${ex[@]}"} --quiet 2>&1); rc2=$?
  # other languages: tracked + untracked-not-ignored files only, so vendored/ignored trees are skipped
  mentions=$(cd "$repo" && git ls-files -z --cached --others --exclude-standard 2>/dev/null \
    | grep -zE "\.($OTHER_EXT)$" | xargs -0 grep -Iil brotli 2>/dev/null | head -20)
  s1=$(sev_of $rc1) s2=$(sev_of $rc2) sev=0
  [ -n "$mentions" ] && sev=1
  [ "$s1" -gt $sev ] && sev=$s1; [ "$s2" -gt $sev ] && sev=$s2
  case $sev in
    0) v="${G}not applicable${N}";;
    1) v="${Y}REVIEW (brotli mentioned in $(echo "$mentions" | wc -l) file(s))${N}";;
    2) v="${Y}incomplete${N}"; [ $RC -eq 0 ] && RC=3;;
    3) v="${R}APPLICABLE${N}"; RC=2;;
  esac
  if [ $sev -ge 1 ]; then
    echo "== $repo"
    [ $rc1 -ne 0 ] && echo "$out1"
    [ $rc2 -ne 0 ] && echo "$out2"
    [ -n "$mentions" ] && printf '[Other languages, not analysed: review by hand]\n%s\n' "$mentions"
    echo
  fi
  ROWS+=("$sev|$repo|$v")
done

echo "Brotli CVE-2026-111497 code scan: ${#REPOS[@]} repos"
printf '%s\n' "${ROWS[@]}" | sort -t'|' -k1,1nr | while IFS='|' read -r sev repo v; do
  [ $QUIET -eq 1 ] && [ "$sev" = 0 ] && continue
  printf '  %-60s %s\n' "$repo" "$v"
done
exit $RC
