# Probes behind the 2026-09-24 [verified] claims about ssrfr's dependencies.
#
# Run from the repository root with rurl, raddr and curl installed (or loaded
# with pkgload::load_all() from sibling checkouts):
#   Rscript design/evidence/2026-09-24-dependency-probes.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (libcurl 8.14.1, LibreSSL 3.3.6,
# IDN support off), rurl 3.0.1.9000, raddr 0.1.2.9000, macOS 26 (Darwin 25.6).
# Expected output is in the comment after each block. A different answer on
# another platform or version is a finding, not a failure of this script.

library(raddr)
library(rurl)
library(curl)

cat("curl", as.character(packageVersion("curl")),
    "libcurl", curl_version()$version,
    "idn", curl_version()$idn, "\n")

# 1. raddr answers for the outer address only. The embedded address is a
#    separate question, reached through addr_embeddings().
a <- addr_pton("64:ff9b::a9fe:a9fe")
addr_global_reachability(a)                      # TRUE
addr_embeddings(a)[[1]]                          # nat64_wk/embedded 169.254.169.254
addr_global_reachability(addr_embeddings(a)[[1]])  # FALSE

# 2. Every 6to4 and Teredo outer address is NA (IANA "Globally Reachable: N/A"),
#    whatever it wraps. 64:ff9b:1::/48 is a determinate FALSE.
#    No argument changes this: both functions take only `x`. The registry rows
#    behind it are the four with no globally_reachable value.
x <- c("2002:808:808::1", "2002:c058:6301::", "2001::1",
       "2001:0:4136:e378:8000:63bf:3fff:fdd2", "192.88.99.1", "2001:10::1",
       "64:ff9b:1::1")
data.frame(x, reachable = addr_global_reachability(addr_pton(x)))
# NA NA NA NA NA NA FALSE
r <- addr_registry()
r[is.na(r$globally_reachable), c("block", "name")]
# 192.88.99.0/24, 2001::/32 TEREDO, 2001:10::/28 ORCHID, 2002::/16 6to4
# For 6to4, raddr's intended answer is on the embedding row:
addr_global_reachability(addr_embeddings(addr_pton("2002:808:808::1"))[[1]])
# TRUE (8.8.8.8)

# 3. Multicast is already FALSE under gate 1.
addr_global_reachability(addr_pton(c("ff0e::1", "ff02::1", "224.0.0.1")))
# FALSE FALSE FALSE

# 4. rurl no longer imports curl; its whatwg parse is in-tree.
"curl" %in% tools::package_dependencies("rurl", db = installed.packages(),
                                        which = "Imports")[[1]]   # FALSE

# 5. rurl's parse_status carries PSL annotations, not only syntax. The layered
#    verdicts separate them.
for (u in c("http://internal-api.corp/", "http://localhost/",
            "http://0177.0.0.1/")) {
  r <- safe_parse_url(u, url_standard = "whatwg")
  cat(u, r$host, r$parse_status, "\n")
}
# internal-api.corp warning-invalid-tld / localhost warning-no-tld /
# 127.0.0.1 ok
get_parse_verdicts(c("http://internal-api.corp/", "gopher://x/", "http://[::1/"),
                   url_standard = "whatwg")
# pass/admitted/unknown; pass/rejected-scheme/not-applicable;
# fail/admitted/not-applicable

# 6. libcurl's own parser, as reached from R.
for (u in c("http://0177.0.0.1/", "http://[fd00:0ec2::254]/",
            "http://bücher.example/", "http://[::ffff:127.0.0.1]/")) {
  cat(u, "->", curl_parse_url(u)$host, "\n")
}
# 127.0.0.1 / [fd00:ec2::254] (compressed, contrary to the July note) /
# bücher.example (no IDN conversion in this build) / [::ffff:127.0.0.1]
