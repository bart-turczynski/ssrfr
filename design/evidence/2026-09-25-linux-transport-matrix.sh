#!/bin/sh
# Runs the 2026-09-25 transport probes on the Linux libcurl builds that
# ssrfr-v1.md §8 items 6, 7 and 16 name, in Docker, and on the host if it has
# Rscript (fp SSRF-rcwugkqo; r-binding.md §9).
#
#   sh design/evidence/2026-09-25-linux-transport-matrix.sh [output-file]
#   sh design/evidence/2026-09-25-linux-transport-matrix.sh --build
#
# Run from anywhere. Needs Docker, and network access for the image builds.
# The probes themselves use no outside network: --network none for the
# platform probes, a private bridge network for the search-domain probe. The
# output defaults to design/evidence/2026-09-25-linux-transport-results.txt.
# --build only builds the images. SSRFR_MATRIX_HOST=0 skips the host run;
# SSRFR_MATRIX_TARGETS limits the Docker targets (space-separated, default
# "ubuntu2204 ubuntu2404 rocky9 rocky9full").
#
# Images, one per libcurl build, each with R, the distro's own libcurl, and
# the curl (built from source against it), webfakes, callr and httpuv
# packages from CRAN:
#   ssrfr-probe:ubuntu2204  rocker/r-ver:4.4.1 (Ubuntu 22.04, libcurl 7.81.0)
#   ssrfr-probe:ubuntu2404  rocker/r-ver:4.6   (Ubuntu 24.04, libcurl 8.5.0)
#   ssrfr-probe:rocky9      rockylinux:9 with R from EPEL; libcurl 7.76.1 as
#                           libcurl-minimal, the image's default build (file
#                           ftp ftps http https only, no IDN), which
#                           libcurl-devel accepts
#   ssrfr-probe:rocky9full  the same with libcurl-minimal swapped for the full
#                           libcurl 7.76.1 build (same soname, no rebuild)
# rocker/r-ver links R's curl package against the system libcurl, as every
# Linux install from source does. Remove the images afterwards with
#   docker rmi ssrfr-probe:ubuntu2204 ssrfr-probe:ubuntu2404 \
#     ssrfr-probe:rocky9full ssrfr-probe:rocky9

set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
ev="$root/design/evidence"
out=${1:-"$ev/2026-09-25-linux-transport-results.txt"}
targets=${SSRFR_MATRIX_TARGETS:-"ubuntu2204 ubuntu2404 rocky9 rocky9full"}
probe=2026-09-25-platform-transport-probes.R
search=2026-09-25-search-domain-probe.R
# Prints the distro package that provides libcurl, before each run.
pkgq="dpkg-query -W 'libcurl4*' 2>/dev/null || rpm -qa 'libcurl*'"

# The CRAN packages every image installs. curl is built from source so that
# it links the distro libcurl whatever binary repository the base image sets.
pkgs='install.packages(c("curl", "webfakes", "callr", "httpuv"), repos = "https://cloud.r-project.org", type = "source", Ncpus = 4); stopifnot(requireNamespace("curl"), requireNamespace("webfakes"), requireNamespace("callr"))'

build() {
  case "$1" in
    ubuntu2204 | ubuntu2404)
      if [ "$1" = ubuntu2204 ]; then from="rocker/r-ver:4.4.1"; else from="rocker/r-ver:4.6"; fi
      printf '%s\n' \
        "FROM $from" \
        "RUN apt-get update && apt-get install -y --no-install-recommends libcurl4-openssl-dev libssl-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*" \
        "RUN Rscript -e '$pkgs'" |
        docker build -q -t "ssrfr-probe:$1" -
      ;;
    rocky9)
      printf '%s\n' \
        "FROM rockylinux:9" \
        "RUN dnf -y install epel-release dnf-plugins-core && dnf config-manager --set-enabled crb && dnf -y install --allowerasing R-core R-core-devel libcurl-devel openssl-devel && dnf clean all" \
        "RUN Rscript -e '$pkgs'" |
        docker build -q -t "ssrfr-probe:$1" -
      ;;
    rocky9full)
      build rocky9
      printf '%s\n' \
        "FROM ssrfr-probe:rocky9" \
        "RUN dnf -y swap --allowerasing libcurl-minimal libcurl && dnf clean all" |
        docker build -q -t "ssrfr-probe:$1" -
      ;;
    *)
      echo "unknown target $1" >&2
      exit 2
      ;;
  esac
}

if [ "$out" = --build ]; then
  for t in $targets; do build "$t"; done
  exit 0
fi

: > "$out"
say() { printf '%s\n' "$*" >> "$out"; }
banner() {
  say ""
  say "################################################################"
  say "## $*"
  say "################################################################"
}

say "# Output of design/evidence/2026-09-25-linux-transport-matrix.sh"
say "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Ports, connection numbers and"
say "# pointers vary between runs; everything else is the observed behaviour."

if [ "${SSRFR_MATRIX_HOST:-1}" = 1 ] && command -v Rscript > /dev/null; then
  banner "host: $(uname -srm)"
  (cd "$root" && Rscript --vanilla "design/evidence/$probe") >> "$out" 2>&1 || say "EXIT $?"
fi

for t in $targets; do
  build "$t" > /dev/null
  banner "docker ssrfr-probe:$t, --network none"
  docker run --rm --network none \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    -v "$ev:/probes:ro" -w /probes "ssrfr-probe:$t" \
    sh -c "$pkgq; Rscript --vanilla /probes/$probe" >> "$out" 2>&1 || say "EXIT $?"
done

# The U-label rows (probes 3a-3e2) again under the other locale: libidn2's
# conversion can depend on it, and the rocker images set LANG=en_US.UTF-8
# where rockylinux:9 sets none.
for tl in "ubuntu2404 C" "rocky9full C.UTF-8"; do
  t=${tl% *}
  l=${tl#* }
  case " $targets " in *" $t "*) ;; *) continue ;; esac
  banner "docker ssrfr-probe:$t, --network none, LANG=$l, U-label rows only"
  docker run --rm --network none -e "LANG=$l" \
    -v "$ev:/probes:ro" -w /probes "ssrfr-probe:$t" \
    Rscript --vanilla "/probes/$probe" 2>&1 |
    grep -E '^(ok|DIFFERS) +3[a-e]|^curl ' >> "$out" || say "EXIT $?"
done

# Search-domain probe (ssrfr-v1.md §5.0 "Names resolve as absolute"). A
# private bridge network whose Docker DNS answers svc.corp.test, and a probe
# container whose resolv.conf searches corp.test. The search list is applied
# by the C library's resolver, which curl::nslookup() and libcurl both call.
net=ssrfr-probe-net
first=$(echo "$targets" | awk '{print $1}')
docker rm -f ssrfr-probe-svc > /dev/null 2>&1 || true
docker network rm "$net" > /dev/null 2>&1 || true
docker network create "$net" > /dev/null
docker run -d --rm --name ssrfr-probe-svc --network "$net" \
  --network-alias svc.corp.test "ssrfr-probe:$first" sleep 600 > /dev/null
for t in $targets; do
  banner "docker ssrfr-probe:$t, network $net, --dns-search corp.test"
  docker run --rm --network "$net" --dns-search corp.test \
    -v "$ev:/probes:ro" -w /probes "ssrfr-probe:$t" \
    sh -c "grep -v '^#' /etc/resolv.conf; Rscript --vanilla /probes/$search" \
    >> "$out" 2>&1 || say "EXIT $?"
done
docker rm -f ssrfr-probe-svc > /dev/null 2>&1 || true
docker network rm "$net" > /dev/null 2>&1 || true

# Trailing blanks from R's cat() off, as the repository's whitespace hook does.
tmp=$(mktemp)
sed 's/[[:space:]]*$//' "$out" > "$tmp" && mv "$tmp" "$out"
echo "wrote $out"
