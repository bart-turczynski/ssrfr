# Probe behind ssrfr-v1.md §5's rule that gate 2 reads only destination
# embeddings, and its ISATAP residual (fp SSRF-qttneqxp).
#
# Run from the repository root with raddr installed. No network access is
# needed.
#   Rscript design/evidence/2026-09-25-embedding-kinds.R
#
# Recorded environment: R 4.6.0, raddr 0.1.2, macOS 26 (Darwin 25.6). Expected
# output is in the comments after each block. A different answer on another
# platform or version is a finding, not a failure of this script.

library(raddr)
show <- function(a) {
  x <- addr_pton(a)
  e <- addr_embeddings(x)[[1]]
  cat(sprintf(
    "%-26s outer %-5s | %s | embedded %s\n",
    a,
    addr_global_reachability(x),
    paste(capture.output(print(e))[-1], collapse = " / "),
    paste(addr_global_reachability(e), collapse = ",")
  ))
}

# Block 1: the embedding kind raddr reports for each form wrapping
# 169.254.169.254. Destination forms first, then tunnel underlay.
for (a in c(
  "::ffff:169.254.169.254",
  "::ffff:0:a9fe:a9fe",
  "::169.254.169.254",
  "64:ff9b::a9fe:a9fe",
  "2002:a9fe:a9fe::1",
  "2001:0:a9fe:a9fe::1",
  "fe80::5efe:a9fe:a9fe"
)) {
  show(a)
}
# kinds: ipv4_mapped, ipv4_translated, ipv4_compatible, nat64_wk (destination);
#        6to4, teredo/server (+ teredo/client), isatap (underlay).

# Block 2: WireServer 168.63.129.16 inside NAT64 and inside ISATAP.
for (a in c(
  "64:ff9b::a83f:8110",
  "2600::5efe:a83f:8110",
  "fe80::5efe:a83f:8110"
)) {
  show(a)
}
# 64:ff9b::a83f:8110   outer TRUE  | nat64_wk/embedded 168.63.129.16 global | embedded TRUE
# 2600::5efe:a83f:8110 outer TRUE  | isatap/embedded 168.63.129.16 global   | embedded TRUE
# fe80::5efe:a83f:8110 outer FALSE | isatap/embedded 168.63.129.16 global   | embedded TRUE
# Gate 1 refuses none of the first two. Gate 2 catches the NAT64 wrapper
# through its embedding; the ISATAP address under a global prefix passes every
# gate (the documented residual). Under a link-local prefix gate 1a refuses it.
