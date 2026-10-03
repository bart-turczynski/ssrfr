#!/usr/bin/env bash
# shellcheck disable=SC2086,SC2016 # lists split on purpose; setup is literal
# Bounded load test: runs the test files that start processes N times under a
# controlled CPU load, inside one capped container, and counts the failures by
# class. Every timing fix is proved with it (SSRF-azjgcwjt).
#
#   scripts/load-test.sh [options]
#
#   -n, --runs N             runs per cell (default 10)
#   -l, --load LIST          load levels, comma-separated multiples of the
#                            container's CPU cap: 0 (none), 1, 2 (default 1)
#   -c, --cpus N             the container's --cpus cap (default 4); refused
#                            unless it is below the Docker VM's CPU count
#   -m, --memory SIZE        the container's --memory cap (default 4g)
#   -t, --start-timeout LIST SSRFR_TEST_START_TIMEOUT values, comma-separated,
#                            passed through to the tests; "default" leaves it
#                            unset (helper-transport.R's 60000). Default: the
#                            caller's SSRFR_TEST_START_TIMEOUT, else "default"
#       --only LIST          run only these of the discovered files (names
#                            without test- and .R, comma-separated)
#       --probe              run the forced-failure probe (load-test-probe.R)
#                            instead of the suite: one failure per class
#       --out DIR            where run logs go (default
#                            tmp/load-test/<timestamp>, git-ignored)
#       --rebuild            rebuild the image first
#       --list               print the discovered test files and exit
#
# Every (load, start timeout) pair is a cell; cells run one after another, in
# one container, N runs each, and the summary prints, per cell and per class,
# the runs with at least one failure of that class out of the runs. The
# classes (load-test-run.R): start-timeout (a webfakes app process did not
# start: callr's "Could not start R session" or webfakes' own wait),
# raw-server (local_server_process()'s readiness wait ran out, or a refused
# connection), other.
#
# Design. The protocol never loads the host. The maintainer's other sessions
# share the machine, and load started there by hand pushed it to ~56 on
# 2026-09-30. So everything this script starts, the load generator included,
# runs inside ONE container capped with --cpus below the Docker VM's CPU
# count: the cap bounds what the whole protocol can take from the host,
# whatever the load multiple. The load is `yes > /dev/null`, multiple x cap
# processes, started inside the container after setup and killed when the
# cell ends, so "2x" means twice as many runnable processes as the container
# may run at once. The image is the CI image, rocker/r-ver at the R_VERSION
# .gitlab-ci.yml sets, with CI's repositories: the P3M snapshot it pins
# first, CRAN behind it, so a raised DESCRIPTION floor resolves from CRAN.
# On arm64 P3M serves no Linux binaries and everything compiles from source;
# the library lives in a named volume keyed by R_VERSION, so that is paid
# once. Each invocation installs the dependency closure (Suggests included,
# as CI's .install-deps does, with its pslr pin while .gitlab-ci.yml has
# one) and the package itself, from a copy of the tree made inside the
# container (the tree is mounted read-only). Tests run against the installed
# package with testthat::test_dir(), as R CMD check runs them, under
# NOT_CRAN=true, as rcmdcheck sets it. The test files are discovered, not
# listed: every helper that calls a process starter (local_app_server(),
# local_server_process(), webfakes' process starters, callr::r_bg(),
# processx::process$new()), transitively, and every test file that calls one
# of those.
#
# Kill guarantees. A trap on EXIT, INT and TERM removes the container with
# `docker rm -f`, which kills every process in it (the load generator, R,
# webfakes and callr children); the container also runs with --rm and
# --init. docker exec runs in the background and the script waits on it, so
# an interrupt reaches the trap at once instead of after the current run. The
# only host processes the script starts are docker, uptime and sleep, and it
# waits for each. Containers carry the label ssrfr-loadtest; after a run,
# `docker ps -a --filter label=ssrfr-loadtest` must be empty.
#
# Left behind for reuse: the image ssrfr-loadtest:r<R_VERSION> and the volume
# ssrfr-loadtest-lib-r<R_VERSION>. Remove them with
#   docker rmi ssrfr-loadtest:r4.5.1; docker volume rm ssrfr-loadtest-lib-r4.5.1

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)

runs=10
loads=1
cpus=4
memory=4g
timeouts=${SSRFR_TEST_START_TIMEOUT:-default}
only=
probe=0
out=
rebuild=0
list=0

die() {
  echo "load-test: $*" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    -n | --runs) runs=$2; shift 2 ;;
    -l | --load) loads=$2; shift 2 ;;
    -c | --cpus) cpus=$2; shift 2 ;;
    -m | --memory) memory=$2; shift 2 ;;
    -t | --start-timeout) timeouts=$2; shift 2 ;;
    --only) only=$2; shift 2 ;;
    --probe) probe=1; shift ;;
    --out) out=$2; shift 2 ;;
    --rebuild) rebuild=1; shift ;;
    --list) list=1; shift ;;
    -h | --help) sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$runs" in '' | *[!0-9]*) die "--runs must be a positive integer" ;; esac
[ "$runs" -ge 1 ] || die "--runs must be a positive integer"
case "$cpus" in '' | *[!0-9]*) die "--cpus must be a whole number" ;; esac
loads=${loads//,/ }
timeouts=${timeouts//,/ }
for l in $loads; do
  case "$l" in '' | *[!0-9]*) die "--load takes whole multiples: $l" ;; esac
done
for t in $timeouts; do
  case "$t" in default) ;; '' | *[!0-9]*) die "--start-timeout takes ms or default: $t" ;; esac
done

# --- the test files ----------------------------------------------------------

tests="$root/tests/testthat"
# ERE alternation of the calls that start a process, extended below by every
# helper that calls one, until nothing new turns up.
starters="local_app_server local_server_process webfakes::local_app_process webfakes::new_app_process callr::r_bg processx::process\$new"
call_pattern() {
  local p='' n
  for n in "$@"; do
    n=${n//./\\.}
    n=${n//\$/\\\$}
    p="$p${p:+|}$n"
  done
  printf '(^|[^A-Za-z0-9_.])(%s)\\(' "$p"
}
# Prints each top-level function of the given files whose body, comments
# aside, matches PAT.
callers() {
  PAT=$(call_pattern $1) awk '
    /^[A-Za-z_.][A-Za-z0-9_.]* <- function/ { fn = $1; next }
    /^[A-Za-z_.][A-Za-z0-9_.]* <- / { fn = ""; next }
    /^[ \t]*#/ { next }
    fn != "" && $0 ~ ENVIRON["PAT"] { print fn }
  ' "${@:2}" | sort -u
}
names=$starters
while :; do
  more=$(callers "$names" "$tests"/helper-*.R)
  grown=$(printf '%s\n' $names $more | sort -u | tr '\n' ' ')
  [ "$(printf '%s\n' $grown | wc -l)" -eq "$(printf '%s\n' $names | sort -u | wc -l)" ] && break
  names=$grown
done
pattern=$(call_pattern $names)
files=$(
  for f in "$tests"/test-*.R; do
    # Not grep -q: under pipefail its early exit fails the pipeline.
    if grep -vE '^[[:space:]]*#' "$f" | grep -E "$pattern" > /dev/null; then
      basename "$f" .R | sed 's/^test-//'
    fi
  done
)
[ -n "$files" ] || die "no test file starts a process; the discovery is broken"
if [ -n "$only" ]; then
  for f in ${only//,/ }; do
    printf '%s\n' $files | grep -x "$f" > /dev/null || die "--only: $f is not a discovered file"
  done
  files=${only//,/ }
fi
if [ "$probe" -eq 1 ]; then
  files=zzz-load-probe
fi
filter="^($(printf '%s\n' $files | tr '\n' '|' | sed 's/|$//'))\$"
if [ "$list" -eq 1 ]; then
  printf '%s\n' $files
  exit 0
fi

# --- docker, the CI image, the output directory -------------------------------

command -v docker > /dev/null || die "docker not found; do NOT fall back to the host"
vm_cpus=$(docker info --format '{{.NCPU}}' 2> /dev/null) ||
  die "docker is not answering; do NOT fall back to the host"
[ "$cpus" -ge 1 ] && [ "$cpus" -lt "$vm_cpus" ] ||
  die "--cpus $cpus must be at least 1 and below the Docker VM's $vm_cpus CPUs"

ci="$root/.gitlab-ci.yml"
civar() {
  sed -n "s/^ *$1: \"\\([^\"]*\\)\".*/\\1/p" "$ci" | head -n 1
}
r_version=$(civar R_VERSION)
p3m_snapshot=$(civar P3M_SNAPSHOT)
pslr_sha=$(civar PSLR_SHA)
[ -n "$r_version" ] || die "no R_VERSION in .gitlab-ci.yml"
[ -n "$p3m_snapshot" ] || die "no P3M_SNAPSHOT in .gitlab-ci.yml"

image="ssrfr-loadtest:r$r_version"
volume="ssrfr-loadtest-lib-r$r_version"
name="ssrfr-loadtest-$$"
stamp=$(date +%Y%m%d-%H%M%S)
out=${out:-"$root/tmp/load-test/$stamp"}
mkdir -p "$out"
out=$(cd "$out" && pwd)
log="$out/load-test.log"

say() {
  echo "$*" | tee -a "$log"
}

# --- cleanup -----------------------------------------------------------------

child=
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$child" ]; then
    kill "$child" 2> /dev/null || true
  fi
  docker rm -f "$name" > /dev/null 2>&1 || true
  wait 2> /dev/null || true
  echo "load-test: removed container $name (exit $status)" | tee -a "$log" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Runs a command in the background and waits for it, so a signal reaches the
# trap at once. With a sample command as $1 (or ""), runs it every 30 s
# while the command runs.
waited() {
  local sample=$1 t=0
  shift
  "$@" &
  child=$!
  while kill -0 "$child" 2> /dev/null; do
    sleep 1
    t=$((t + 1))
    if [ -n "$sample" ] && [ $((t % 30)) -eq 0 ]; then
      $sample
    fi
  done
  local rc=0
  wait "$child" || rc=$?
  child=
  return "$rc"
}

host_uptime() {
  echo "host uptime ($1): $(uptime)" >> "$out/uptime.txt"
}
during_sample() {
  host_uptime "during: $cell run $i"
  docker stats --no-stream --format "container cpu ($cell run $i): {{.CPUPerc}}" \
    "$name" >> "$out/uptime.txt" 2> /dev/null || true
}

# --- image and container -----------------------------------------------------

say "load-test: $(date -u +%Y-%m-%dT%H:%M:%SZ) R $r_version, cap --cpus=$cpus of $vm_cpus, --memory=$memory"
say "load-test: runs=$runs load=[$loads]x start-timeout=[$timeouts] probe=$probe"
say "load-test: files: $(printf '%s ' $files)"
say "load-test: output in $out"
host_uptime "before"

if [ "$rebuild" -eq 1 ] || ! docker image inspect "$image" > /dev/null 2>&1; then
  # apt only: everything that compiles does so in the capped container below.
  say "load-test: building $image"
  mkdir -p "$out/image"
  printf '%s\n' \
    "FROM rocker/r-ver:$r_version" \
    "ENV LANG=C.UTF-8 LC_ALL=C.UTF-8" \
    "RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates git procps libcurl4-openssl-dev libssl-dev libxml2-dev libgit2-dev zlib1g-dev libfontconfig1-dev libfreetype6-dev libharfbuzz-dev libfribidi-dev libpng-dev libtiff5-dev libjpeg-dev && rm -rf /var/lib/apt/lists/*" \
    > "$out/image/Dockerfile"
  waited "" docker build -t "$image" "$out/image" >> "$log" 2>&1 ||
    die "image build failed; see $log"
fi

waited "" docker run -d --rm --init --name "$name" --label ssrfr-loadtest=1 \
  --cpus "$cpus" --memory "$memory" \
  -v "$volume:/opt/ssrfr" -v "$root:/src:ro" -v "$out:/out" \
  -e R_LIBS_USER=/opt/ssrfr/lib -e PKG_CACHE_DIR=/opt/ssrfr/pak-cache \
  -e P3M_SNAPSHOT="$p3m_snapshot" -e PSLR_SHA="$pslr_sha" \
  -e MAKEFLAGS="-j$cpus" -e NOT_CRAN=true \
  "$image" sleep infinity > /dev/null

# The setup, as CI's before_script and .install-deps do it, minus what only
# R CMD check needs (LaTeX, pandoc, tidy, the hostile locales).
setup='
set -eu
mkdir -p "$R_LIBS_USER" "$PKG_CACHE_DIR"
. /etc/os-release
stamp="$R_LIBS_USER/.toolchain-stamp"
want="$(Rscript -e "cat(R.version\$major, R.version\$minor, R.version\$platform, sep = \"-\")")-${ID}-${VERSION_ID}"
have="$(cat "$stamp" 2>/dev/null || echo none)"
if [ "$have" != "$want" ]; then
  echo "library: built by $have, this is $want -- starting it afresh"
  rm -rf "$R_LIBS_USER" "$PKG_CACHE_DIR"
  install -d "$R_LIBS_USER" "$PKG_CACHE_DIR"
  printf "%s" "$want" > "$stamp"
fi
repo="https://p3m.dev/cran/__linux__/${UBUNTU_CODENAME}/${P3M_SNAPSHOT}"
if [ "$(uname -m)" = "aarch64" ]; then repo="https://p3m.dev/cran/${P3M_SNAPSHOT}"; fi
echo "options(repos = c(P3M = \"${repo}\", CRAN = \"https://cloud.r-project.org\"), Ncpus = '"$cpus"'L)" >> "${R_HOME}/etc/Rprofile.site"
echo ".libPaths(c(Sys.getenv(\"R_LIBS_USER\"), .libPaths()))" >> "${R_HOME}/etc/Rprofile.site"
Rscript -e "print(getOption(\"repos\")); print(.libPaths())"
Rscript -e "if (!requireNamespace(\"pak\", quietly = TRUE)) install.packages(\"pak\", repos = \"https://cloud.r-project.org\")"
mkdir -p /work/ssrfr
tar -C /src --exclude=./.git --exclude=./tmp -cf - .| tar -C /work/ssrfr -xf -
cd /work/ssrfr
Rscript -e "pak::local_install_deps(dependencies = TRUE)"
if [ -n "$PSLR_SHA" ]; then
  Rscript -e "pak::pak(paste0(\"gitlab::bart-turczynski/pslr@\", Sys.getenv(\"PSLR_SHA\")))"
  Rscript -e "d <- packageDescription(\"pslr\"); if (!identical(d\$RemoteSha, Sys.getenv(\"PSLR_SHA\"))) stop(\"pslr is not the pinned commit\")"
fi
R CMD INSTALL --library="$R_LIBS_USER" .
cp scripts/load-test-helper.R tests/testthat/helper-zzz-load-test.R
cp scripts/load-test-probe.R tests/testthat/test-zzz-load-probe.R
Rscript scripts/load-test-run.R selftest
'
say "load-test: setting up the container (first run on a fresh volume compiles everything)"
waited "" docker exec "$name" sh -c "$setup" >> "$log" 2>&1 ||
  die "container setup failed; see $log"
docker exec -w /work/ssrfr "$name" Rscript \
  -e 'cat("load-test:", R.version.string, "| libcurl", curl::curl_version()$version, "\n")' \
  -e 'p <- c("ssrfr", "testthat", "webfakes", "callr", "processx", "curl", "rurl", "raddr")' \
  -e 'cat("load-test: packages:", paste(p, vapply(p, function(x) format(packageVersion(x)), "")), "\n")' \
  2>&1 | tee -a "$log"
docker exec -w /work/ssrfr "$name" Rscript scripts/load-test-run.R selftest |
  sed 's/^/load-test: /' | tee -a "$log"

# --- the cells ---------------------------------------------------------------

for load in $loads; do
  procs=$((load * cpus))
  if [ "$procs" -gt 0 ]; then
    docker exec -d "$name" sh -c "i=0; while [ \$i -lt $procs ]; do yes > /dev/null & i=\$((i + 1)); done; wait"
    sleep 10
  fi
  say "load-test: load ${load}x: $procs yes processes in the container"
  for timeout in $timeouts; do
    cell="load${load}x-timeout${timeout}"
    [ "$probe" -eq 1 ] && cell="probe-$cell"
    env=()
    [ "$timeout" = default ] || env=(-e "SSRFR_TEST_START_TIMEOUT=$timeout")
    i=1
    while [ "$i" -le "$runs" ]; do
      run=$(printf '%s.run%02d' "$cell" "$i")
      host_uptime "start: $cell run $i"
      rc=0
      waited during_sample docker exec -w /work/ssrfr ${env[@]+"${env[@]}"} "$name" \
        Rscript scripts/load-test-run.R run "/out/$run" "$filter" \
        > "$out/$run.log" 2>&1 || rc=$?
      say "$cell run $i/$runs (exit $rc): $(grep '^run:' "$out/$run.log" | tail -n 1)"
      grep '^  \[' "$out/$run.log" | tee -a "$log" || true
      if [ ! -f "$out/$run.tsv" ]; then
        printf 'run\t0\ttests=0\tcrashed\tfailures=1\nfailure\t(runner)\t(Rscript)\tother\texit %s\n' \
          "$rc" > "$out/$run.tsv"
      fi
      i=$((i + 1))
    done
  done
  if [ "$procs" -gt 0 ]; then
    docker exec "$name" pkill -x yes || true
  fi
done

host_uptime "after"
say ""
docker exec "$name" Rscript /work/ssrfr/scripts/load-test-run.R summarize /out |
  tee "$out/summary.txt" | tee -a "$log"
say ""
cat "$out/uptime.txt" | tee -a "$log" > /dev/null
say "load-test: summary in $out/summary.txt, host load samples in $out/uptime.txt"
