# Every call ssrfr makes into rurl, libcurl's URL parser, raddr and the system
# resolver goes through one of the internal wrappers below (ssrfr-v1.md §4,
# §5.3, INV-11). A wrapper is the call and nothing else, so a test can replace
# it with testthat::local_mocked_bindings(); callers therefore look each
# wrapper up by name at call time (r-binding.md §7, Rules).
#
# No caller uses a wrapper's value directly. It goes through dep_call(), which
# turns an error, a NULL or a value of the wrong shape into NULL, and callers
# read NULL as a refusal: `parse` for a parser (§5.3), `malformed-address` for
# raddr (§6.5, §8 item 32), and the operational cause `unresolvable` for the
# resolver (§6.6). Warnings and messages from a dependency are muffled: they
# are not refusals (r-binding.md §2.2), and their text can quote the URL,
# userinfo included, which ssrfr never relays (§2.3).

# The fixed rurl bundle (r-binding.md §2.1). It is internal and not
# caller-configurable (INV-1): every argument is passed on every call that
# takes it, including those equal to today's defaults.
rurl_verdict_args <- list(
  url_standard = "whatwg",
  scheme_policy = "require",
  scheme_relative_handling = "error",
  scheme_acceptance = "web",
  protocol_handling = "keep"
)

rurl_parse_args <- c(
  rurl_verdict_args,
  list(
    www_handling = "none",
    index_page_handling = "keep",
    profile = NULL,
    host_encoding = "idna"
  )
)

# Calls `fn(...)` and returns its value when `valid()` accepts it, else NULL.
dep_call <- function(fn, ..., valid) {
  out <- tryCatch(
    withCallingHandlers(
      fn(...),
      warning = function(w) invokeRestart("muffleWarning"),
      message = function(m) invokeRestart("muffleMessage")
    ),
    error = function(e) NULL
  )
  ok <- !is.null(out) && isTRUE(tryCatch(valid(out), error = function(e) FALSE))
  if (ok) out else NULL
}

is_string <- function(x) {
  is.character(x) && length(x) == 1L && !is.na(x)
}

# NULL, or a single string, for an optional component of curl_parse_url().
is_optional_string <- function(x) {
  is.null(x) || is_string(x)
}

# --- rurl -------------------------------------------------------------------

dep_rurl_verdicts <- function(url) {
  do.call(rurl::get_parse_verdicts, c(list(url), rurl_verdict_args))
}

dep_rurl_parse <- function(url) {
  do.call(rurl::safe_parse_url, c(list(url), rurl_parse_args))
}

dep_rurl_serialize <- function(url) {
  rurl::serialize_url(url, standard = "whatwg")
}

dep_rurl_resolve <- function(reference, base) {
  rurl::resolve_url(
    reference,
    base,
    url_standard = "whatwg",
    output = "serialized"
  )
}

dep_rurl_diagnostics <- function(url) {
  rurl::get_url_diagnostics(
    url,
    url_standard = "whatwg",
    scheme_policy = "require",
    scheme_acceptance = "web"
  )
}

# --- libcurl's parse ----------------------------------------------------------

dep_curl_parse <- function(url) {
  curl::curl_parse_url(url)
}

# --- raddr --------------------------------------------------------------------

dep_raddr_pton <- function(text) {
  raddr::addr_pton(text)
}

dep_raddr_reachability <- function(x) {
  raddr::addr_global_reachability(x)
}

dep_raddr_category <- function(x) {
  raddr::addr_category(x)
}

dep_raddr_family <- function(x) {
  raddr::addr_family(x)
}

dep_raddr_embeddings <- function(x) {
  raddr::addr_embeddings(x)
}

dep_raddr_within_any <- function(x, blocks) {
  raddr::addr_within_any(x, blocks)
}

dep_raddr_format <- function(x) {
  raddr::addr_format(x)
}

# --- the system resolver ------------------------------------------------------
# The only DNS call in ssrfr (r-binding.md §3). `multiple = TRUE` keeps every
# address the one resolver call returns (INV-4). It is unexported and no
# function takes a resolver argument (INV-5); tests replace it with
# testthat::local_mocked_bindings().

dep_nslookup <- function(query) {
  curl::nslookup(query, ipv4_only = FALSE, multiple = TRUE, error = TRUE)
}

# --- the transport ------------------------------------------------------------
# The only place ssrfr dials (r-binding.md §7, "One place dials"): one
# connection attempt of the guarded fetch (R/fetch.R). `opts` is the option
# list transport_options() builds (R/transport.R), pin included; `data`,
# `debug` and `progress` are the per-delivery, trace and progress callbacks.
# libcurl calls `progress` as bytes arrive, the header's included, and
# whenever it waits. Each attempt gets a new handle in a private pool, so no
# DNS cache, connection or cookie is shared with another attempt or with
# other curl users in the process (r-binding.md §4.1). handle_reset() is
# never used.
#
# `data` ends the transfer by raising a condition of class
# `ssrfr_transfer_abort`. The callback fails, so libcurl stops the transfer,
# and curl then either re-raises the condition from multi_run() or reports a
# write error. `progress` ends it by returning FALSE; libcurl reports an
# abort by callback, which curl raises as an interrupt from multi_run(). That
# interrupt, and only that one, is caught here: a user's interrupt still
# propagates. A `progress` that fails or answers anything but TRUE ends the
# transfer too. Either way the caller reads which limit ended it from its own
# record.
# Error printing is switched off while libcurl runs, because curl evaluates
# callbacks as a top-level call that would print that condition. However the
# call ends, an interrupt included, every handle still in the pool is
# cancelled, which closes its connection.
#
# Returns a list: `aborted` (TRUE when a callback ended the transfer and curl
# raised it), `error` (the curl error class of a failed transfer, or NULL),
# `status`, `headers` (the raw response header bytes), and `connect` (seconds
# until the TCP connection was established; 0 when it never was).
dep_curl_transfer <- function(opts, data, debug, progress) {
  pool <- curl::new_pool(total_con = 1L, host_con = 1L, multiplex = FALSE)
  on.exit(
    for (h in curl::multi_list(pool)) {
      curl::multi_cancel(h)
    },
    add = TRUE
  )
  outcome <- new.env(parent = emptyenv())
  outcome$stopped <- FALSE
  watch <- function(down, up) {
    go <- tryCatch(isTRUE(progress(down, up)), error = function(e) FALSE)
    if (!go) {
      outcome$stopped <- TRUE
    }
    go
  }
  handle <- curl::new_handle()
  curl::handle_setopt(handle, .list = opts)
  curl::handle_setopt(
    handle,
    verbose = TRUE,
    debugfunction = debug,
    noprogress = 0L,
    xferinfofunction = watch
  )
  curl::multi_add(
    handle,
    done = function(res) outcome$done <- res,
    fail = function(msg) outcome$fail <- msg,
    data = data,
    pool = pool
  )
  quiet <- options(show.error.messages = FALSE)
  on.exit(options(quiet), add = TRUE)
  aborted <- withRestarts(
    tryCatch(
      withCallingHandlers(
        {
          curl::multi_run(pool = pool)
          FALSE
        },
        interrupt = function(i) {
          if (outcome$stopped) invokeRestart("ssrfr_stopped")
        }
      ),
      ssrfr_transfer_abort = function(e) TRUE
    ),
    ssrfr_stopped = function() TRUE
  )
  info <- curl::handle_data(handle)
  list(
    aborted = aborted,
    error = if (is.null(outcome$fail)) NULL else class(outcome$fail)[[1L]],
    status = info$status_code,
    headers = info$headers,
    connect = unname(info$times[["connect"]])
  )
}

# libcurl's version and capabilities, for the option builder.
dep_curl_version <- function() {
  curl::curl_version()
}

dep_curl_options <- function() {
  names(curl::curl_options())
}

# --- guarded readings ---------------------------------------------------------
# Each returns the value in the shape ssrfr reads, or NULL.

read_verdicts <- function(url) {
  v <- dep_call(dep_rurl_verdicts, url, valid = function(v) {
    is.data.frame(v) &&
      nrow(v) == 1L &&
      is_string(v$layer1_syntax_verdict) &&
      is_string(v$layer2_policy_verdict)
  })
  if (is.null(v)) {
    return(NULL)
  }
  list(
    layer1 = v$layer1_syntax_verdict,
    layer2 = v$layer2_policy_verdict
  )
}

read_rurl_parse <- function(url) {
  p <- dep_call(dep_rurl_parse, url, valid = function(p) {
    is.list(p) &&
      is.character(p$host) &&
      length(p$host) == 1L &&
      is.logical(p$is_ip_host) &&
      length(p$is_ip_host) == 1L
  })
  if (is.null(p)) {
    return(NULL)
  }
  list(host = p$host, is_ip = isTRUE(p$is_ip_host))
}

read_serialization <- function(url) {
  dep_call(dep_rurl_serialize, url, valid = is_string)
}

read_resolution <- function(reference, base) {
  dep_call(dep_rurl_resolve, reference, base, valid = is_string)
}

read_diagnostics <- function(url) {
  dep_call(dep_rurl_diagnostics, url, valid = function(d) {
    is.character(d) && !anyNA(d)
  })
}

read_curl_parse <- function(url) {
  p <- dep_call(dep_curl_parse, url, valid = function(p) {
    is.list(p) &&
      is_string(p$scheme) &&
      is_optional_string(p$host) &&
      is_optional_string(p$port) &&
      is_optional_string(p$user) &&
      is_optional_string(p$password)
  })
  if (is.null(p)) {
    return(NULL)
  }
  p[c("scheme", "host", "port", "user", "password")]
}

# The resolver's answer set for one query: a character vector, possibly
# empty, or NULL when the resolver errors or returns anything else (§6.6).
read_answers <- function(query) {
  dep_call(dep_nslookup, query, valid = function(a) {
    is.character(a) && !anyNA(a)
  })
}

# One address, parsed from canonical text (r-binding.md §2.6). NULL when raddr
# errors, returns the wrong shape, or cannot read the text (NA).
read_address <- function(text) {
  dep_call(dep_raddr_pton, text, valid = function(a) {
    inherits(a, "raddr_address") && length(a) == 1L && !is.na(a)
  })
}

# Whether raddr reads one resolver answer as an address: TRUE, FALSE when it
# answers NA (the text is not an address), or NULL when the call fails. The
# two failures differ: an answer that is not an address is `unresolvable`
# (§6.6), a raddr call that fails is `malformed-address` (§8 item 32).
read_is_address <- function(text) {
  a <- dep_call(dep_raddr_pton, text, valid = function(a) {
    inherits(a, "raddr_address") && length(a) == 1L
  })
  if (is.null(a)) {
    return(NULL)
  }
  missing <- tryCatch(is.na(a), error = function(e) NULL)
  if (!is.logical(missing) || length(missing) != 1L || is.na(missing)) {
    return(NULL)
  }
  !missing
}

read_format <- function(x) {
  dep_call(dep_raddr_format, x, valid = is_string)
}

read_reachability <- function(x, n = 1L) {
  dep_call(dep_raddr_reachability, x, valid = function(r) {
    is.logical(r) && length(r) == n
  })
}

read_category <- function(x) {
  out <- dep_call(dep_raddr_category, x, valid = function(k) {
    (is.factor(k) || is.character(k)) && length(k) == 1L && !is.na(k)
  })
  if (is.null(out)) NULL else as.character(out)
}

read_family <- function(x) {
  out <- dep_call(dep_raddr_family, x, valid = function(f) {
    (is.factor(f) || is.character(f)) && length(f) == 1L && !is.na(f)
  })
  if (is.null(out)) NULL else as.character(out)
}

# The embedding rows of one address as a data frame: kind, role, address (as
# canonical text) and reachability of the extracted address (§5.2). ssrfr
# reads raddr's extraction; it never extracts an embedding itself. A
# raddr_embedding is a record whose fields are kind, role, address and
# category.
read_embeddings <- function(x) {
  e <- dep_call(dep_raddr_embeddings, x, valid = function(e) {
    is.list(e) && length(e) == 1L && inherits(e[[1L]], "raddr_embedding")
  })
  if (is.null(e)) {
    return(NULL)
  }
  rows <- e[[1L]]
  n <- length(rows)
  fields <- tryCatch(
    {
      f <- unclass(rows)
      shaped <- is.list(f) &&
        all(c("kind", "role", "address") %in% names(f)) &&
        length(f$kind) == n &&
        length(f$role) == n &&
        length(f$address) == n &&
        !anyNA(f$kind)
      if (shaped) {
        list(
          kind = as.character(f$kind),
          role = as.character(f$role),
          address = if (n) format(f$address) else character()
        )
      }
    },
    error = function(e) NULL
  )
  if (is.null(fields) || anyNA(fields$address)) {
    return(NULL)
  }
  reach <- if (n) read_reachability(rows, n) else logical()
  if (is.null(reach)) {
    return(NULL)
  }
  data.frame(
    kind = fields$kind,
    role = fields$role,
    address = fields$address,
    reachability = reach
  )
}

# One transfer through dep_curl_transfer(), or NULL when the wrapper fails or
# answers in the wrong shape. An interrupt is not an error: it propagates, and
# the wrapper has already cancelled the transfer.
read_transfer <- function(opts, data, debug, progress) {
  dep_call(dep_curl_transfer, opts, data, debug, progress, valid = function(t) {
    is.list(t) &&
      is.logical(t$aborted) &&
      length(t$aborted) == 1L &&
      !is.na(t$aborted) &&
      (is.null(t$error) || is_string(t$error)) &&
      is.numeric(t$status) &&
      length(t$status) == 1L &&
      !is.na(t$status) &&
      is.raw(t$headers) &&
      is.numeric(t$connect) &&
      length(t$connect) == 1L &&
      !is.na(t$connect)
  })
}

# What the option builder needs to know about libcurl: its version, whether
# R's curl can set `protocols_str`, and whether libcurl decodes gzip. NULL when
# either call fails; the builder then falls back to the forms every supported
# libcurl accepts (R/transport.R).
read_curl_capabilities <- function() {
  v <- dep_call(dep_curl_version, valid = function(v) {
    is.list(v) && is_string(v$version)
  })
  o <- dep_call(dep_curl_options, valid = is.character)
  if (is.null(v) || is.null(o)) {
    return(NULL)
  }
  version <- tryCatch(
    numeric_version(sub("[^0-9.].*$", "", v$version)),
    error = function(e) NULL
  )
  if (is.null(version)) {
    return(NULL)
  }
  list(
    version = version,
    protocols_str = "protocols_str" %in% o && "redir_protocols_str" %in% o,
    zlib = is_string(v$libz_version) && nzchar(v$libz_version)
  )
}

# libcurl's capabilities cannot change within a session, so a fetch reads
# them once. Only a reading that succeeded is kept; a failed one is tried
# again on the next fetch.
curl_capabilities_cache <- new.env(parent = emptyenv())

session_curl_capabilities <- function() {
  if (is.null(curl_capabilities_cache$value)) {
    curl_capabilities_cache$value <- read_curl_capabilities()
  }
  curl_capabilities_cache$value
}

read_within_any <- function(x, blocks) {
  if (!length(blocks)) {
    return(FALSE)
  }
  dep_call(dep_raddr_within_any, x, blocks, valid = function(w) {
    is.logical(w) && length(w) == 1L && !is.na(w)
  })
}
