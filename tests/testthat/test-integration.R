# L4, the real-network test layer (r-binding.md §7): real DNS, real
# certificate chains, IPv6 pinning and live rebinding against public hosts
# (INV-4, INV-5, INV-9). Every test here runs only when the environment
# variable SSRFR_INTEGRATION_TESTS is set, and never on CRAN or offline.
#
# This file is in .fleet-ci.yml's exclude_tests, so the gate, which fails on
# any skip, never runs it: CI never makes these requests. Run it locally with
#   SSRFR_INTEGRATION_TESTS=true \
#     Rscript -e "testthat::test_local(filter = 'integration')"
#
# Each test makes a few requests with generous timeouts. The hosts are public
# test infrastructure needing no credentials: example.com, badssl.com,
# ipv6.google.com, the 1u.ms rebinding service, and the DNS-over-HTTPS
# endpoints of 1.1.1.1 and 8.8.8.8.

# Skips unless SSRFR_INTEGRATION_TESTS is set, on CRAN, and offline.
skip_unless_integration <- function() {
  skip_if(
    !nzchar(Sys.getenv("SSRFR_INTEGRATION_TESTS")),
    "SSRFR_INTEGRATION_TESTS not set"
  )
  skip_on_cran()
  skip_if_offline()
}

# A policy for the public internet: the defaults, with room for a slow link.
integration_policy <- function(...) {
  ssrf_policy(connect_timeout = 10, total_timeout = 30, ...)
}

# The real resolver behind the internal seam, counting its calls: the guard
# still resolves through the system resolver, and the test sees each query.
local_counting_resolver <- function(env = parent.frame()) {
  real <- ssrfr:::dep_nslookup
  seen <- new.env(parent = emptyenv())
  seen$queries <- character()
  local_mocked_bindings(
    dep_nslookup = function(query) {
      seen$queries <- c(seen$queries, query)
      real(query)
    },
    .package = "ssrfr",
    .env = env
  )
  seen
}

# The address and port of every `Trying` line libcurl traced, brackets
# removed: what the transport dialed, read independently of ssrfr's own
# pin check.
dialed <- function(lines) {
  trying <- grep("^Trying ", lines, value = TRUE)
  target <- sub("^Trying (.*)[.]{3}$", "\\1", trying)
  data.frame(
    address = gsub("^\\[|\\]$", "", sub(":[0-9]+$", "", target)),
    port = as.integer(sub("^.*:", "", target))
  )
}

global <- function(addresses) {
  raddr::addr_global_reachability(raddr::addr_pton(addresses))
}

test_that("real DNS: one resolution, global addresses, the fetch on the pin", {
  skip_unless_integration()
  resolver <- local_counting_resolver()
  trace <- local_trace_recorder()
  b <- ssrf_prepare_hop(
    "https://example.com/",
    integration_policy(),
    request = list()
  )
  expect_s3_class(b, "ssrfr_binding")
  # INV-5: one resolution, absolute, so no search domain applies.
  expect_identical(resolver$queries, "example.com.")
  expect_gt(length(b$validated), 0L)
  expect_true(all(global(b$validated)))
  expect_identical(b$pin, b$validated[[1L]])

  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  # The fetch resolves nothing more, and every address libcurl dialed is the
  # pinned one, on the URL's port.
  expect_identical(resolver$queries, "example.com.")
  expect_identical(b$state$pin_used, b$pin)
  expect_identical(b$state$attempts, paste(b$pin, "connected"))
  tried <- dialed(trace$lines)
  expect_gt(nrow(tried), 0L)
  expect_identical(unique(tried$address), b$pin)
  expect_identical(unique(tried$port), 443L)
})
