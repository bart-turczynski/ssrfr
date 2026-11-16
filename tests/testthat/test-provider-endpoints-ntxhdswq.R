# The opt-in allow_provider_endpoints policy field (ssrfr-v1.md §5.0, §5.3,
# §2.3; SSRF-ntxhdswq): only it reopens a provider endpoint, never an
# allow_ranges entry, and a caller deny range still wins.

test_that("allow_provider_endpoints takes table addresses, in any spelling", {
  expect_identical(ssrf_policy()$allow_provider_endpoints, character())
  p <- ssrf_policy(
    allow_provider_endpoints = c(
      "169.254.169.254",
      "FD00:EC2:0:0::254",
      "169.254.169.254"
    )
  )
  # Stored as the table's rows, once each.
  expect_identical(
    p$allow_provider_endpoints,
    c("169.254.169.254", "fd00:ec2::254")
  )
  table <- ssrf_vocabulary("provider_endpoints")$address
  expect_identical(
    ssrf_policy(allow_provider_endpoints = table)$allow_provider_endpoints,
    table
  )
  for (bad in list(
    "10.0.0.1",
    "169.254.169.254/32",
    "169.254.0.0/16",
    "metadata.google.internal",
    "",
    NA_character_,
    1
  )) {
    expect_error(
      ssrf_policy(allow_provider_endpoints = bad),
      class = "ssrfr_error_invalid_policy",
      label = format(bad)
    )
  }
})

test_that("a failing raddr makes the field an error, never empty", {
  # INV-11: the markers and the address gate read the validated field, so
  # construction is where a raddr failure must refuse.
  local_mocked_bindings(dep_raddr_pton = function(...) stop("raddr"))
  expect_error(
    ssrf_policy(allow_provider_endpoints = "169.254.169.254"),
    class = "ssrfr_error_invalid_policy"
  )
})

test_that("an allow_ranges entry equal to a provider endpoint is an error", {
  for (entry in c(
    "169.254.169.254/32",
    "fd00:ec2::254/128",
    "100.100.100.200/32",
    "168.63.129.16/32"
  )) {
    err <- expect_error(
      ssrf_policy(allow_ranges = entry),
      class = "ssrfr_error_invalid_policy",
      label = entry
    )
    expect_match(
      conditionMessage(err),
      "allow_provider_endpoints",
      fixed = TRUE
    )
    # Also when the endpoint is reopened: the entry would still do nothing.
    expect_error(
      ssrf_policy(
        allow_ranges = entry,
        allow_provider_endpoints = sub("/.*$", "", entry)
      ),
      class = "ssrfr_error_invalid_policy",
      label = entry
    )
  }
  # Ranges that hold an endpoint but name other addresses too stay valid,
  # and so does an exact entry for an address on no list.
  expect_s3_class(
    ssrf_policy(
      allow_ranges = c("169.254.0.0/16", "100.64.0.0/10", "fd00::/8")
    ),
    "ssrfr_policy"
  )
  expect_s3_class(
    ssrf_policy(allow_ranges = c("100.100.100.201/32", "10.0.0.5/32")),
    "ssrfr_policy"
  )
})

test_that("only allow_provider_endpoints reopens a provider endpoint", {
  code <- function(url, policy = ssrf_policy()) {
    ssrf_inspect_url(url, policy)$code
  }
  broad <- ssrf_policy(allow_ranges = c("169.254.0.0/16", "100.64.0.0/10"))
  expect_identical(code("http://169.254.169.254/"), "cloud-metadata")
  expect_identical(code("http://169.254.169.254/", broad), "cloud-metadata")
  expect_identical(code("http://100.100.100.200/", broad), "cloud-metadata")
  # The rest of the range is open.
  expect_identical(code("http://100.100.100.201/", broad), NA_character_)

  open <- ssrf_policy(allow_provider_endpoints = "169.254.169.254")
  expect_identical(code("http://169.254.169.254/", open), NA_character_)
  # One endpoint opens no other, nor the link-local block around it.
  expect_identical(code("http://[fd00:ec2::254]/", open), "cloud-metadata")
  expect_identical(code("http://100.100.100.200/", open), "cloud-metadata")
  expect_identical(code("http://169.254.169.253/", open), "link-local")

  # A caller deny range still wins (tier 2).
  denied <- ssrf_policy(
    allow_provider_endpoints = "169.254.169.254",
    deny_ranges = "169.254.0.0/16"
  )
  expect_identical(code("http://169.254.169.254/", denied), "range-denied")

  # An endpoint inside another address is tier 1, which nothing reopens.
  expect_identical(
    code("http://[64:ff9b::a9fe:a9fe]/", open),
    "cloud-metadata"
  )
})

test_that("a metadata hostname also needs allow_hosts", {
  mock_answers("169.254.169.254")
  url <- "http://metadata.google.internal/"
  inspect <- function(policy) {
    ssrf_inspect_url(url, policy, layer = "L1")$code
  }
  # The name refuses at gate 5; its address at gate 2.
  expect_identical(
    inspect(ssrf_policy(allow_provider_endpoints = "169.254.169.254")),
    "cloud-metadata"
  )
  expect_identical(
    inspect(ssrf_policy(allow_hosts = "metadata.google.internal")),
    "cloud-metadata"
  )
  expect_identical(
    inspect(ssrf_policy(
      allow_hosts = "metadata.google.internal",
      allow_provider_endpoints = "169.254.169.254"
    )),
    NA_character_
  )
})
