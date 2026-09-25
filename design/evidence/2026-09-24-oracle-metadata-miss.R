# Probe behind ssrfr-v1.md §5's "[verified] two independent implementations
# missed the same provider's metadata address": Oracle Cloud's 192.0.0.192 is
# classified as allowed by ipaddress::is_global() and by the hand-rolled
# matcher robotstxtr shipped at commit 5b1514c (fp SSRF-ssldkvmd).
#
# Ported from BRAINSTORM §2 and §16 (run 2026-07-25, R 4.6.0, robotstxtr at
# 5b1514c loaded with pkgload from a local checkout). This script fetches that
# commit's R/ssrf.R from the public GitLab repository instead, so it needs
# network access to gitlab.com. The file is self-contained and sources on its
# own. raddr's answer is printed for contrast.
#
# Run from the repository root with ipaddress, raddr and curl installed:
#   Rscript design/evidence/2026-09-24-oracle-metadata-miss.R
#
# Recorded environment: R 4.6.0, ipaddress 1.0.4, raddr 0.1.2, curl 8.0.0,
# macOS 26 (Darwin 25.6). Expected output is in the comment after each block.
# A different answer on another platform or version is a finding, not a
# failure of this script.

x <- c(oracle = "192.0.0.192", aws = "169.254.169.254", alibaba = "100.100.100.200",
       benchmark = "198.18.0.1", public = "8.8.8.8")

# 1. ipaddress: is_global() is TRUE, i.e. allowed, for 192.0.0.192.
ipaddress::is_global(ipaddress::ip_address(x))
# TRUE FALSE FALSE FALSE TRUE

# 2. robotstxtr at 5b1514c: ssrf_classify_ipv4() returns NA (allowed) for it.
src <- paste0("https://gitlab.com/bart-turczynski/robotstxtr/-/raw/",
              "5b1514c14979cd36a12cdfc2b698d457d6092ebc/R/ssrf.R")
f <- tempfile(fileext = ".R")
curl::curl_download(src, f, quiet = TRUE)
robo <- new.env()
sys.source(f, envir = robo)
vapply(x, robo$ssrf_classify_ipv4, character(1))
# oracle NA; aws "cloud-metadata"; alibaba "cloud-metadata" (inside CGNAT
# 100.64.0.0/10); benchmark NA; public NA.

# 3. raddr, driven by the IANA registry, answers FALSE (not globally
#    reachable) for 192.0.0.192 without a provider list.
raddr::addr_global_reachability(raddr::addr_pton(x))
# FALSE FALSE FALSE FALSE TRUE
