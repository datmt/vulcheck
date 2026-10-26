# Brotli decoder CVE-2026-111497 (GHSA-9v8h-qqgm-4m35, "Node2Shell")

Out-of-bounds write in the Brotli C decoder, reachable through Node.js, the Python `Brotli` / `brotlicffi` packages and anything linking `libbrotlidec`. Two complementary checks:

| Script | Question |
|---|---|
| [`brotli-cve-check.sh`](brotli-cve-check.sh) | Is a vulnerable decoder **installed** (hosts, containers, images, pods, project dependency files)? |
| [`brotli-code-scan.sh`](brotli-code-scan.sh) | Does **our own code** call a Brotli API that can reach it, in every git repo under a directory? |

> **Credits:** the code scan is a wrapper around the source scanners published by **JFrog** in [jfrog/vulnerability_scanners](https://github.com/jfrog/vulnerability_scanners/tree/main/brotli2shell_cve_2026_111497) (Apache-2.0, © JFrog Ltd.). All detection logic is theirs; this repo only fetches their scripts at a pinned commit and runs them per repo. Not affiliated with JFrog. Read their [README](https://github.com/jfrog/vulnerability_scanners/blob/main/brotli2shell_cve_2026_111497/README.md) for what each scanner matches and its limitations.

> **Disclaimer:** Provided as is, without warranty. Both scripts only read, except `brotli-cve-check.sh --fix`, which upgrades pip venvs after a y/N prompt. Try on a non-production machine first.

## Installed versions: `brotli-cve-check.sh`

[`brotli-cve-check.sh`](brotli-cve-check.sh) looks for the Brotli decoder out-of-bounds write ("Node2Shell") on hosts, in running containers, local images and Kubernetes pods. It only reads: each target is probed with a short `sh` script (run locally, over `ssh`, via `docker exec`, or in a throwaway `docker run --network none --cap-drop ALL` for images).

| Finds | Status |
|---|---|
| PyPI `brotli` >= 1.0.3, < 1.2.1 / `brotlicffi` >= 1.0.3, < 1.2.1.0 (any venv, found by `*.dist-info`) | `VULNERABLE` |
| Node.js 22 / 24 / 26 below 22.23.4 / 24.22.1 / 26.12.1 (bundled decoder) | `VULNERABLE` |
| Java Brotli4j (`com.aayushatharva.brotli4j`: `brotli4j`, `all`, `native-*` jars) <= 1.23.0; it bundles its own C decoder, so patching the OS `libbrotli` does not help | `VULNERABLE` (fixed in 1.24.0, [advisory](https://github.com/hyperxpro/Brotli4j/security/advisories/GHSA-x524-jrqf-vwq6)) |
| Other jars named `*brotli*` (e.g. `org.brotli:dec`, a pure-Java port), npm `iltorb` / `brotli-wasm`, native `libbrotlidec.so*` | `REVIEW` (check the vendor or distro advisory; backports keep old version numbers) |

One-liners, no clone needed (read the script first; only `--fix` changes anything):

```bash
B=https://raw.githubusercontent.com/datmt/vulcheck/main/brotli/brotli-cve-check.sh
curl -fsSL $B | bash -s -- dir                      # dependency files under the current dir
curl -fsSL $B | bash -s -- host                     # this machine
curl -fsSL $B | bash -s -- ssh:user@server          # another machine over ssh
curl -fsSL $B | bash -s -- -q all                   # containers + images, VULNERABLE rows only
curl -fsSL $B | bash -s -- k8s                      # pods in the current kubectl context
curl -fsSL $B | bash -s -- --fix host               # also upgrade vulnerable pip venvs (asks y/N)
curl -fsSL $B | SCAN_ROOT=/data bash -s -- host     # env vars go on bash, not curl
```

Or from a clone:

```bash
./brotli-cve-check.sh dir                   # dependency files under the current dir (recursive)
./brotli-cve-check.sh dir:~/code/app        # or under another directory
./brotli-cve-check.sh host                                                      # this machine (run as root to see everything)
./brotli-cve-check.sh ssh:user@server                                           # another machine over ssh, nothing installed there
./brotli-cve-check.sh --fix host                                                # also upgrade vulnerable pip venvs here (asks y/N; -y skips)
SCAN_ROOT=/data ./brotli-cve-check.sh host                                      # limit the file search to one directory
./brotli-cve-check.sh containers                                                # every running container
./brotli-cve-check.sh images                                                    # every local image
./brotli-cve-check.sh all                                                       # containers and images
./brotli-cve-check.sh k8s                                                       # every image used by pods in the current kubectl context
KCTX=prod K8S_NS=apps ./brotli-cve-check.sh k8s                                 # other context / one namespace
KUBECTL='docker exec k3d-mycluster-server-0 kubectl' ./brotli-cve-check.sh k8s  # k3d/k3s: kubectl only inside the node container
./brotli-cve-check.sh -q all                                                    # summary table with only the VULNERABLE rows (cron)
./brotli-cve-check.sh my-api python:3.12                                        # specific containers or images
```

Each target gets a block with every finding, then a summary table sorted worst first. Colour shows on a terminal; `NO_COLOR=1` turns it off. Exit code is 2 if anything is `VULNERABLE`, 3 if nothing is but some Java projects could not be resolved (see below), 0 otherwise.

`host` and `ssh:` run the same probe on a plain machine (Linux, macOS, BSD; needs only `sh` and `find`). Besides every Python venv, Node and jar on disk (skipping `/proc`, `/sys`, `/dev`, `/run`, `/mnt`, `/media` and container storage: `/var/lib/docker`, `containerd`, `containers`, `kubelet`, `rancher`; use `containers` / `images` for those), they check `curl -V` for the libbrotli it links and the installed `libbrotli*` package (dpkg, rpm, apk, pacman, brew). Distros often backport the fix without changing the version, so curl, packages and native libraries are `REVIEW` (vulnerable only if your distro hasn't patched; check its security tracker), while Python and Node versions are decisive. Over `ssh:` the probe is piped to `sh -s`; use your usual ssh keys or agent.

`k8s` lists pod and init-container images with `kubectl`, pulls each unique image locally if it isn't already there (`docker login` first for a private registry; images that can't be pulled show `PULL-FAILED`, not checked), scans it, then prints a per-pod table. It checks what the image contains, not what a pod mounts or installs at start-up, and scans the local platform's variant of a multi-arch image.

**`dir` (the practical fix).** An in-place upgrade is undone by the next `uv sync` or image build, so scan what your projects *would install*: `dir` walks the current directory (or `dir:<path>`; skips `node_modules`, `.git`, venvs, `.cache`) and reports one row per project directory. It reads, without installing anything (Java build tools excepted, see below):

| File | Verdict |
|---|---|
| `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock` | exact locked `brotli` / `brotlicffi` version: `VULNERABLE` if in range |
| `requirements*.txt`, `requirements/*.txt`, `requirements*.in` (only if no compiled `.txt` beside it), `pyproject.toml` with a `[project]` table, `setup.cfg` `install_requires`; and no lock file next to them | resolved with `uv pip compile` to the full tree a fresh install would get, including transitive `brotli` / `brotlicffi` (`httpx[brotli]`, ...): version in range `VULNERABLE`, else `ok`. The FIX column names the package that pulls it in |
| `constraints*.txt`, `Pipfile`, `environment*.yml`, or any of the above when `uv` is unavailable | text rules: `==` pin in range: `VULNERABLE`; floor below the fix, `<` caps, `~=`: `REVIEW`; unpinned or `>=` fixed: ok |
| `.nvmrc`, `.node-version`, `.tool-versions`, `Dockerfile* FROM node:X.Y.Z` | Node below 22.23.4 / 24.22.1 / 26.12.1: `VULNERABLE`; floating tags like `24`: `REVIEW`; end-of-life lines (20, 23, 25 and older, which get no fix): `REVIEW`, move to 22/24/26 |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` | `iltorb`, `brotli-wasm`, `brotli-dec-wasm`: `REVIEW` |
| `pom.xml`, `build.gradle*`, `settings.gradle*` | resolved with `mvn dependency:tree` / a Gradle dependency report (see below): `brotli4j` <= 1.23.0, direct or transitive: `VULNERABLE`; `org.brotli`: `REVIEW` |
| `gradle.lockfile`, `libs.versions.toml` (no build file next to them) | `brotli4j` with a literal or catalog-resolved version <= 1.23.0: `VULNERABLE`; version held in a variable or BOM: `REVIEW` |

**Python projects without a lock file are resolved with `uv`.** A lock file (`uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`) already lists the whole tree, so those projects are read as before. For `requirements*.txt` and `pyproject.toml` alone, `dir` runs `uv pip compile --universal` (it resolves and installs nothing), so a transitive `brotli` shows up and you see which package pulled it in; an unpinned dependency resolves to today's latest, which is what a fresh install would get. `setup.cfg` is read for `install_requires` only (not run). A Poetry project (`[tool.poetry.dependencies]`, no `[project]` table) without a `poetry.lock` is resolved with `poetry lock` in a temporary copy of its `pyproject.toml`, so your project is never modified and you need `poetry` installed; a project whose only dependency is `python` is skipped. These cases show `ERROR` and exit 3, like Java: `uv` is missing, resolution fails (offline, private index, unsatisfiable pins), a Poetry project has no `poetry.lock` and `poetry` is missing or fails to solve, a `Pipfile` lists packages but has no `Pipfile.lock`, or a project declares dependencies only in `setup.py` (resolving would run it; add a `pyproject.toml` `[project]` table, a lock file or a compiled `requirements.txt`). conda `environment*.yml` files are still read as text only. Caveats: it needs network access, and resolving can build source distributions to read their metadata, which runs their `setup.py`, so only scan code you trust.

**Java projects are resolved with Maven or Gradle.** Reading `pom.xml` text misses `brotli4j` pulled in transitively (a framework that depends on it), so for each Java project `dir` runs `mvn dependency:tree` (using `./mvnw` if present) and/or a Gradle dependency report for all subprojects (using `./gradlew` if present), once at the top of each module tree. If `mvn` / `gradle` is not available and the project has no wrapper, or the build fails (offline, private repository, broken build), the target shows `ERROR`, a red "could NOT be fully checked" banner lists it, and the exit code is 3 (2 still wins if something is `VULNERABLE`). It never reports such a project as `ok`. Caveats: this needs network access, it runs build tooling on the project (Gradle evaluates the repo's build scripts and a wrapper is the repo's own script, so only scan code you trust), and it can take minutes on a large tree. `host`, `containers` and `images` scans still only read files.

The how-to-fix block is a table (REPO, FILE, NOW, FIX), one row per file or line, grouped by git repo, and names the exact edit: the `Dockerfile` line (`FROM node:24-alpine` -> `node:24.22.1-alpine`, or rebuild with `--pull --no-cache`), the `.nvmrc` change, the requirements/pyproject line, and one merged lock command per project. It gives the project-level command: `uv lock --upgrade-package brotli && uv sync`, `poetry update brotli`, `pdm update brotli`, `pipenv update brotli`, or which line to edit in a requirements/pyproject file. It sees direct and locked dependencies only; a package that is only pulled in by something without a lock file is not visible, so pair it with `host` or `images`.

**Fixes.** Whenever something is `VULNERABLE` the script ends with a "how to fix" block: the exact `<venv>/bin/python -m pip install -U 'brotli>=1.2.1'` per venv, `conda install -p <env>` for conda envs (not pip), `uv cache clean` for uv caches, rebuild instructions for containers and images, and the Node versions to move to. `--fix` applies only the host venv upgrades (`pip`, or `uv pip` for uv-created venvs that have no pip; a failure shows pip's last error line), after listing them and asking `[y/N]` (`-y` skips the question). It never touches conda envs, caches, Node, OS packages, containers or `ssh:` targets. Restart the services using an upgraded venv, then re-run the check.

Limits: it doesn't open jars nested inside fat jars (a Spring Boot `BOOT-INF/lib/brotli4j-*.jar` is not seen; check the build files with `dir`), and doesn't see statically linked binaries. Container and image scans stay inside the container's own filesystem (not mounted volumes), and a host scan skips network mounts under `/mnt` and `/media`, so a clean result isn't proof. The Node fix versions come from the [Node.js October 2026 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases); confirm them there. A stopped container can't be exec'd; scan its image instead.

## Your own code: `brotli-code-scan.sh`

[`brotli-code-scan.sh`](brotli-code-scan.sh) answers "does our own code call the Brotli decoder?" for every git repo under a directory. It wraps [JFrog's source scanners](https://github.com/jfrog/vulnerability_scanners/tree/main/brotli2shell_cve_2026_111497) (JS, Python, ELF binaries, shell scripts), which otherwise have to be run per repo. It finds each directory holding a `.git` dir (skipping `node_modules`, `site-packages`, venvs), scans each repo once (nested repos are scanned on their own), and prints a summary table. Findings are candidates for review, not proof of exploitability.

```bash
S=https://raw.githubusercontent.com/datmt/vulcheck/main/brotli/brotli-code-scan.sh
curl -fsSL $S | bash -s --                  # repos under the current dir
curl -fsSL $S | bash -s -- ~/code ~/work    # repos under other dirs
curl -fsSL $S | bash -s -- -q ~/code        # only repos with findings (cron)
```

Needs `python3` >= 3.10, `curl` and `git`. JFrog's scripts are downloaded from a pinned commit into a temp dir, with `tree-sitter` in a throwaway venv; both are deleted on exit. Your repos are only read. Exit code is 2 if any repo is `APPLICABLE`, 3 if nothing was found but some files could not be checked, 0 otherwise. Run `brotli-cve-check.sh` too: this one checks code, that one checks installed versions.

**VERSIONS column.** Each repo also gets the worst `dir` result from `brotli-cve-check.sh` for its dependency files: `VULNERABLE` (a vulnerable Brotli or Node version is pinned), `review`, `ok`, or `-` (no dependency files found). Repos that are `APPLICABLE` and `VULNERABLE` sort first, since that is where a code path meets a vulnerable decoder. It reads declared and locked versions, not what is installed on this machine; use `brotli-cve-check.sh host` for that. When run from a clone it uses the sibling `brotli-cve-check.sh`, otherwise it fetches it from this repo.

**What is scanned**

| Layer | Files | Source |
|---|---|---|
| JavaScript, Python, ELF binaries, shell scripts | `.js`, `.py`, any ELF, `.sh .bash .rb .pl` | JFrog, unchanged |
| TypeScript / ESM / CJS / JSX | `.ts .tsx .mts .cts .mjs .cjs .jsx` (not `.d.ts`) | JFrog's JS analysis, run by us with the TypeScript grammar (`tree-sitter-typescript`), because JFrog only reads `.js` |
| Other languages | `.java .kt .scala .go .rs .rb .php .c .cc .cpp .h .cs .swift .dart .ex .lua .zig` and similar | ours: any file that mentions `brotli` is listed as `REVIEW`. Mentions only, nothing is analysed, and the exit code is unchanged |

The other-languages layer reads tracked and untracked-but-not-ignored files (`git ls-files`), so vendored or ignored trees are skipped. Still not covered: Python/JS dependencies (`node_modules`, `site-packages` are skipped, use `brotli-cve-check.sh`), Mach-O and PE binaries, stripped static binaries, and any language not listed.
