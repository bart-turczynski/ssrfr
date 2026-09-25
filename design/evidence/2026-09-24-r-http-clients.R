# Probes behind the 2026-09-24 re-check of "curl is R's default HTTP path"
# (fp SSRF-rcwugkqo, S5 and r-binding.md §5 inputs).
#
# Run from the repository root with curl, httr2, httr, crul, webfakes, jsonlite
# and data.table installed, and network access to CRAN for block 1:
#   Rscript design/evidence/2026-09-24-r-http-clients.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1), httr2
# 1.3.0, macOS 26 (Darwin 25.6). Expected output is in the comment after each
# block. A different answer on another platform or version is a finding, not a
# failure of this script.

options(repos = c(CRAN = "https://cloud.r-project.org"))

# 1. Reverse dependencies (strong: Depends, Imports, LinkingTo).
db <- available.packages()
pk <- c("curl", "httr", "httr2", "RCurl", "crul", "nanonext")
strong <- c("Depends", "Imports", "LinkingTo")
d <- tools::package_dependencies(pk, db = db, which = strong, reverse = TRUE)
dr <- tools::package_dependencies(
  pk,
  db = db,
  which = strong,
  reverse = TRUE,
  recursive = TRUE
)
print(
  data.frame(pkg = pk, direct = lengths(d[pk]), recursive = lengths(dr[pk])),
  row.names = FALSE
)
ur <- unique(unlist(dr[c("curl", "RCurl")]))
cat("libcurl clients, recursive:", length(ur), "of", nrow(db), "\n")
# 2026-09-24, 25,155 packages: curl 475/3804, httr 1017/2277, httr2 481/792,
# RCurl 115/325, crul 40/105, nanonext 8/132; libcurl clients 4003 (15.9%).

# 2. Base R's default method is libcurl, and its url() takes no curl options.
cat(
  "download.file.method option:",
  format(getOption("download.file.method")),
  "\n"
)
cat("url() formals:", names(formals(url)), "\n")
# NULL (so "auto" -> libcurl for all but file://);
# description open blocking encoding method headers

# 3. Base R links a different libcurl from the curl package (macOS).
cat("base R libcurl:", libcurlVersion(), "\n")
cat("curl pkg libcurl:", curl::curl_version()$version, "\n")
if (Sys.info()[["sysname"]] == "Darwin") {
  so <- file.path(R.home("modules"), "internet.so")
  print(system2("otool", c("-L", so), stdout = TRUE))
}
# 8.7.1 (Apple /usr/lib/libcurl.4.dylib) vs 8.14.1 (statically bundled).

# 4. httr2, httr and crul accept a connect_to pin and followlocation = 0, so a
#    guard can own the redirect loop per hop. Base R cannot be pinned.
suppressMessages(library(webfakes))
app <- new_app()
app$get("/r", function(req, res) res$redirect("/ok", 302L))
app$get("/ok", function(req, res) {
  res$send(paste("host:", req$get_header("Host")))
})
srv <- local_app_process(app)
port <- sub(".*:(\\d+)/?$", "\\1", srv$url())
u <- sprintf("http://pinned.example.invalid:%s/r", port)
pin <- "pinned.example.invalid::127.0.0.1:"

r <- httr2::request(u) |>
  httr2::req_options(connect_to = pin, followlocation = 0L) |>
  httr2::req_perform()
cat(
  "httr2 nofollow:",
  httr2::resp_status(r),
  httr2::resp_header(r, "location"),
  "\n"
)
r <- httr2::request(u) |>
  httr2::req_options(connect_to = pin) |>
  httr2::req_perform()
cat("httr2 follow:", httr2::resp_status(r), httr2::resp_body_string(r), "\n")
cat("req_perform formals:", names(formals(httr2::req_perform)), "\n")
r <- httr::GET(u, httr::config(connect_to = pin, followlocation = 0L))
cat("httr nofollow:", httr::status_code(r), httr::headers(r)$location, "\n")
cli <- crul::HttpClient$new(
  u,
  opts = list(connect_to = pin, followlocation = 0L)
)
r <- cli$get()
cat("crul nofollow:", r$status_code, r$response_headers$location, "\n")
r <- tryCatch(
  readLines(sprintf("http://127.0.0.1:%s/r", port), warn = FALSE),
  error = function(e) conditionMessage(e)
)
cat("base readLines follows the redirect:", r, "\n")
# httr2 nofollow: 302 /ok; httr2 follow: 200 host: pinned.example.invalid:<port>;
# req_perform has no handle argument; httr and crul nofollow: 302 /ok;
# base readLines returns the /ok body.

# 5. Popular readers reach base R, not the curl package.
for (fn in c("jsonlite::fromJSON", "data.table::fread")) {
  b <- deparse(eval(parse(text = fn)))
  cat(
    fn,
    "calls:",
    unique(unlist(regmatches(
      b,
      gregexpr("download\\.file|\\burl\\(|curl::[a-z_]+", b)
    ))),
    "\n"
  )
}
# jsonlite::fromJSON calls url(); data.table::fread calls download.file().
