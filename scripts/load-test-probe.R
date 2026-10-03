# The forced failures of `scripts/load-test.sh --probe`: one test per failure
# class, each built to fail in that class, so a probe run shows every counter
# of the classifier go non-zero. The script copies this file into its
# container's copy of the tree as tests/testthat/test-zzz-load-probe.R and
# runs it alone; it never lands in the repository's tests.

test_that("load-test probe: start-timeout", {
  skip_if_no_webfakes()
  # 1 ms for both start waits of local_app_server(): no R session starts
  # that fast.
  withr::local_envvar(SSRFR_TEST_START_TIMEOUT = "1")
  web <- local_test_server()
  expect_gt(web$get_port(), 0)
})

test_that("load-test probe: raw-server", {
  # callr starts its sessions with user_profile = "project", so a .Rprofile
  # in the working directory delays the server process by 25 s: past the
  # readiness wait at the 20000 ms --probe runs with by default, and within
  # it at the 60000 default (SSRF-ptkasofy).
  dir <- withr::local_tempdir()
  writeLines("Sys.sleep(25)", file.path(dir, ".Rprofile"))
  withr::local_dir(dir)
  mock_answers("127.0.0.1")
  server <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  ))
  r <- guarded_get(pinned_url(server$port), loopback_policy(server$port))
  expect_identical(r$status, 200L)
})

test_that("load-test probe: other", {
  expect_identical("load-test probe", "a failure of no known class")
})
