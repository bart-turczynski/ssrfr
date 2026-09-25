# Harness for the guarded fetch (r-binding.md §7): loopback servers, a raw
# listener, the resolver mock, the test-policy recipe, and the tripwires.
#
# Every server listens on loopback, on an ephemeral port, and every hostname
# is an RFC 2606 `.invalid` name, so a fetch that reaches a server proves the
# pin was used. webfakes apps run in a subprocess with two threads (CRAN's
# limit); the tests of the transport itself replace internal functions with
# testthat::local_mocked_bindings(), never a public argument.

# The pinned test host.
pinned_host <- "pinned.example.invalid"

# The recipe a consumer's test uses to reach a loopback server through the
# guard (ssrfr-v1.md §9): reopen loopback, and allow the server's port.
loopback_policy <- function(port = NULL, ...) {
  ssrf_policy(
    allow_ranges = c("127.0.0.0/8", "::1/128"),
    allow_ports = c(80, 443, port),
    ...
  )
}

# Answers every resolver query with `answers` (a character vector or a
# function of the query) and records the queries.
mock_answers <- function(answers, env = parent.frame()) {
  seen <- new.env(parent = emptyenv())
  seen$queries <- character()
  local_mocked_bindings(
    dep_nslookup = function(query) {
      seen$queries <- c(seen$queries, query)
      if (is.function(answers)) answers(query) else answers
    },
    .package = "ssrfr",
    .env = env
  )
  seen
}

# A free TCP port on loopback.
free_port <- function() {
  for (p in sample(30000:60000, 50)) {
    s <- tryCatch(serverSocket(p), error = function(e) NULL)
    if (!is.null(s)) {
      close(s)
      return(p)
    }
  }
  stop("no free port")
}

# A URL on the pinned test host.
pinned_url <- function(port, path = "/", scheme = "http", host = pinned_host) {
  paste0(scheme, "://", host, ":", port, path)
}

# Prepares and fetches in one call; the binding is returned as an attribute.
guarded_get <- function(url, policy, request = list()) {
  binding <- ssrf_prepare_hop(url, policy, request = request)
  if (!inherits(binding, "ssrfr_binding")) {
    return(binding)
  }
  out <- ssrf_fetch(binding)
  attr(out, "binding") <- binding
  out
}

body_text <- function(response) {
  rawToChar(response$body)
}

# --- webfakes apps ------------------------------------------------------------

skip_if_no_webfakes <- function() {
  skip_if_not_installed("webfakes")
  skip_if_not_installed("callr")
}

# The app most L2 tests use.
test_app <- function() {
  app <- webfakes::new_app()
  app$locals$hits <- 0L
  app$get("/", function(req, res) {
    res$send(paste0("host=", req$get_header("Host")))
  })
  app$post("/post", function(req, res) {
    res$send("posted")
  })
  app$get("/echo-headers", function(req, res) {
    h <- req$headers
    res$send(paste0(names(h), "=", unlist(h), collapse = "\n"))
  })
  app$get("/chunked", function(req, res) {
    for (i in 1:50) {
      res$send_chunk(strrep("y", 5000))
    }
  })
  app$get("/bomb", function(req, res) {
    res$set_header("Content-Encoding", "gzip")
    res$set_type("application/octet-stream")
    res$send(memCompress(raw(2e6), "gzip"))
  })
  app$get("/deflate", function(req, res) {
    # HTTP's `deflate` is the zlib format, which memCompress() writes.
    res$set_header("Content-Encoding", "deflate")
    res$set_type("text/plain")
    res$send(memCompress(charToRaw(strrep("deflated ", 1000)), "gzip"))
  })
  app$get("/many-headers", function(req, res) {
    for (i in 1:50) {
      res$add_header(paste0("X-Field-", i), strrep("v", 40))
    }
    res$send(if (identical(req$query$big, "1")) strrep("b", 50000) else "ok")
  })
  app$get("/two-locations", function(req, res) {
    res$set_status(302L)
    res$add_header("Location", "/a")
    res$add_header("Location", "/b")
    res$send("")
  })
  app$get("/redirect", function(req, res) {
    res$redirect("/next?x=1", 302L)
  })
  app$get("/slow", function(req, res) {
    if (is.null(res$locals$waited)) {
      res$locals$waited <- TRUE
      res$delay(5)
    } else {
      res$send("late")
    }
  })
  app$get("/auth", function(req, res) {
    req$app$locals$hits <- req$app$locals$hits + 1L
    auth <- req$get_header("Authorization")
    res$set_status(401L)
    res$add_header("WWW-Authenticate", 'Digest realm="x", nonce="n"')
    res$add_header("WWW-Authenticate", 'Basic realm="x"')
    res$send(paste0(
      "hits=",
      req$app$locals$hits,
      " auth=",
      if (is.null(auth)) "none" else auth
    ))
  })
  app$get("/alt-svc", function(req, res) {
    req$app$locals$hits <- req$app$locals$hits + 1L
    res$set_header(
      "Alt-Svc",
      paste0('h2="127.0.0.1:', req$query$dead, '"; ma=3600, h3=":443"')
    )
    res$send(paste0("hit ", req$app$locals$hits))
  })
  app
}

local_test_server <- function(
  app = test_app(),
  tls = FALSE,
  keep_alive = FALSE,
  env = parent.frame()
) {
  opts <- webfakes::server_opts(
    num_threads = 2,
    enable_keep_alive = keep_alive,
    error_log_file = FALSE,
    ssl_certificate = if (tls) test_path("certs", "alpha.pem")
  )
  webfakes::local_app_process(
    app,
    port = if (tls) "0s" else NULL,
    opts = opts,
    .local_envir = env
  )
}

# --- TLS ----------------------------------------------------------------------
# ssrfr never takes a CA bundle from its caller (§14), so a test trusts the
# fixture CA by adding `cainfo` to the options the builder returns.

local_trust_test_ca <- function(env = parent.frame()) {
  builder <- ssrfr:::transport_options
  ca <- test_path("certs", "ca.crt")
  local_mocked_bindings(
    transport_options = function(...) c(builder(...), list(cainfo = ca)),
    .package = "ssrfr",
    .env = env
  )
}

# Records libcurl's text trace of every attempt, alongside ssrfr's own
# debug callback, which still runs.
local_trace_recorder <- function(env = parent.frame()) {
  transfer <- ssrfr:::dep_curl_transfer
  seen <- new.env(parent = emptyenv())
  seen$lines <- character()
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug) {
      transfer(opts, data, function(type, msg) {
        if (type == 0L) {
          text <- tryCatch(rawToChar(msg), error = function(e) "")
          lines <- strsplit(text, "\n", fixed = TRUE)[[1L]]
          seen$lines <- c(seen$lines, trimws(lines))
        }
        debug(type, msg)
      })
    },
    .package = "ssrfr",
    .env = env
  )
  seen
}

# --- the raw listener (L3) ----------------------------------------------------

# Whether a connection arrives at `listener` within `secs`. Polls across the
# whole window: one socketSelect() can return FALSE at once with a client
# about to connect (r-binding.md §7, Rules).
connection_arrives <- function(listener, secs) {
  t0 <- Sys.time()
  repeat {
    if (socketSelect(list(listener), timeout = 0.2)) {
      return(TRUE)
    }
    if (difftime(Sys.time(), t0, units = "secs") >= secs) {
      return(FALSE)
    }
  }
}

# A listener on a free port, closed when the calling test ends.
local_listener <- function(env = parent.frame()) {
  port <- free_port()
  listener <- serverSocket(port)
  withr::defer(close(listener), envir = env)
  list(port = port, socket = listener)
}

# A raw HTTP server for responses webfakes cannot send (obs-text, trailers,
# a header that never ends). It runs in a background process, accepts one
# connection, reads the request head and any body its Content-Length
# declares, and records those bytes. `response` is then either raw bytes,
# written before the connection closes, or a self-contained function of the
# connection, run in the server process. Returns the port and `request()`,
# the recorded request bytes (NULL until they arrive).
local_raw_server <- function(response, env = parent.frame()) {
  skip_if_not_installed("callr")
  port <- free_port()
  ready <- tempfile("raw-listening-")
  recorded <- tempfile("raw-request-")
  if (is.function(response)) {
    environment(response) <- globalenv()
  }
  server <- callr::r_bg(
    function(port, ready, recorded, response) {
      s <- serverSocket(port)
      on.exit(close(s))
      file.create(ready)
      con <- socketAccept(s, blocking = TRUE, open = "r+b", timeout = 30)
      on.exit(close(con), add = TRUE)
      end <- charToRaw("\r\n\r\n")
      head <- raw()
      repeat {
        b <- readBin(con, raw(), 1L)
        if (!length(b)) {
          break
        }
        head <- c(head, b)
        n <- length(head)
        if (n >= 4L && identical(head[(n - 3L):n], end)) {
          break
        }
      }
      text <- rawToChar(head)
      declared <- regmatches(
        text,
        regexpr("(?i)\r\ncontent-length: *[0-9]+", text, perl = TRUE)
      )
      want <- if (length(declared)) {
        as.numeric(sub("^.*: *", "", declared))
      } else {
        0
      }
      body <- raw()
      while (length(body) < want) {
        chunk <- readBin(con, raw(), want - length(body))
        if (!length(chunk)) {
          break
        }
        body <- c(body, chunk)
      }
      writeBin(c(head, body), paste0(recorded, ".part"))
      file.rename(paste0(recorded, ".part"), recorded)
      if (is.raw(response)) {
        writeBin(response, con)
        flush(con)
      } else {
        response(con)
      }
      "done"
    },
    args = list(
      port = port,
      ready = ready,
      recorded = recorded,
      response = response
    )
  )
  withr::defer(server$kill(), envir = env)
  t0 <- Sys.time()
  while (!file.exists(ready) && difftime(Sys.time(), t0, units = "secs") < 20) {
    Sys.sleep(0.05)
  }
  list(
    port = port,
    request = function() {
      if (!file.exists(recorded)) {
        return(NULL)
      }
      readBin(recorded, raw(), file.size(recorded))
    }
  )
}

# Bytes from strings, with \r\n written out by the caller.
wire <- function(...) {
  charToRaw(paste0(...))
}

# --- tripwires (r-binding.md §7, Rules) --------------------------------------

# The functions named in call position anywhere in `expr`, nested closures
# included, with `pkg::fun` reduced to `fun`.
call_heads <- function(expr) {
  if (is.function(expr)) {
    return(call_heads(body(expr)))
  }
  if (is.pairlist(expr) || is.list(expr)) {
    return(unlist(lapply(expr, call_heads)))
  }
  if (!is.call(expr)) {
    return(character())
  }
  head <- expr[[1L]]
  name <- if (is.name(head)) {
    as.character(head)
  } else if (is.call(head) && deparse(head[[1L]]) %in% c("::", ":::")) {
    as.character(head[[3L]])
  }
  c(name, call_heads(as.list(expr)[-1L]))
}

network_calls <- c(
  "curl_fetch_memory",
  "curl_fetch_disk",
  "curl_fetch_stream",
  "curl_fetch_multi",
  "curl_fetch_echo",
  "curl",
  "curl_download",
  "curl_upload",
  "curl_echo",
  "multi_add",
  "multi_run",
  "multi_download",
  "new_handle",
  "handle_setopt",
  "handle_reset",
  "nslookup",
  "ie_get_proxy_for_url",
  "url",
  "download.file",
  "socketConnection",
  "addr_getaddrinfo"
)

# The closures in `env` that call a network entry point, as a named character
# vector of the entry points each calls.
network_callers <- function(env) {
  fns <- Filter(
    is.function,
    mget(ls(env, all.names = TRUE), envir = env, inherits = FALSE)
  )
  hits <- vapply(
    fns,
    function(f) paste(intersect(call_heads(f), network_calls), collapse = ","),
    character(1)
  )
  hits[nzchar(hits)]
}

# What is wrong with one attempt's option list (r-binding.md §5, §7): an
# empty vector when every row holds.
option_problems <- function(opts, host, address) {
  found <- new.env(parent = emptyenv())
  found$problems <- character()
  want <- function(name, value) {
    if (!identical(opts[[name]], value)) {
      found$problems <- c(found$problems, name)
    }
  }
  target <- if (grepl(":", address, fixed = TRUE)) {
    paste0("[", address, "]")
  } else {
    address
  }
  want("connect_to", paste0(host, "::", target, ":"))
  for (name in names(ssrfr:::fixed_transport_options)) {
    if (!name %in% names(opts)) {
      found$problems <- c(found$problems, paste("missing", name))
    }
  }
  want("followlocation", 0L)
  want("forbid_reuse", 1L)
  want("dns_cache_timeout", 0L)
  want("dns_shuffle_addresses", 0L)
  want("proxy", "")
  want("noproxy", "*")
  want("unrestricted_auth", 0L)
  want("httpauth", 1L)
  want("netrc", 0L)
  want("path_as_is", 1L)
  want("ssl_verifypeer", 1L)
  want("ssl_verifyhost", 2L)
  problems <- found$problems
  if (!"cookiefile" %in% names(opts) || !is.null(opts$cookiefile)) {
    problems <- c(problems, "cookiefile")
  }
  restricted <- identical(opts$protocols_str, "http,https") &&
    identical(opts$redir_protocols_str, "http,https") ||
    identical(opts[["protocols"]], 3L) &&
      identical(opts[["redir_protocols"]], 3L)
  if (!restricted) {
    problems <- c(problems, "protocols")
  }
  for (name in c("ssl_verifypeer", "ssl_verifyhost")) {
    if (isTRUE(opts[[name]] == 0)) {
      problems <- c(problems, paste(name, "weakened"))
    }
  }
  for (name in c("accept_encoding", "connecttimeout_ms", "timeout_ms")) {
    if (is.null(opts[[name]])) {
      problems <- c(problems, paste("missing", name))
    }
  }
  set_never <- intersect(names(opts), ssrfr:::never_set_options)
  if (length(set_never)) {
    problems <- c(problems, paste("sets", set_never))
  }
  problems
}
