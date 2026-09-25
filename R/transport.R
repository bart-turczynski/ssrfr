# The transport of the guarded fetch (ssrfr-v1.md §12 steps 9-12, §14,
# INV-5, INV-6, INV-9, INV-10; r-binding.md §4-§6). Everything here is pure:
# the option list a connection attempt is made with, the reading of libcurl's
# trace that checks the pin held, and the reading of the response header
# bytes. The attempt itself is dep_curl_transfer() (R/dependencies.R), and the
# lifecycle around it is ssrf_fetch() (R/fetch.R).

# The options every attempt carries, whatever the hop (r-binding.md §5).
# ssrfr never relies on a default of curl's new_handle(): each row that the
# package sets is overridden here.
fixed_transport_options <- list(
  followlocation = 0L,
  forbid_reuse = 1L,
  dns_cache_timeout = 0L,
  dns_shuffle_addresses = 0L,
  proxy = "",
  noproxy = "*",
  unrestricted_auth = 0L,
  netrc = 0L,
  cookiefile = NULL,
  path_as_is = 1L,
  ssl_verifypeer = 1L,
  ssl_verifyhost = 2L
)

# Options that no attempt may carry, and that nothing in ssrfr sets
# (r-binding.md §5, "never set"): each would move the connection off the pin,
# widen what is reachable, or read ambient state.
never_set_options <- c(
  "resolve",
  "cookiejar",
  "altsvc",
  "altsvc_ctrl",
  "hsts",
  "hsts_ctrl",
  "unix_socket_path",
  "abstract_unix_socket",
  "doh_url",
  "interface",
  "localport",
  "localportrange",
  "share",
  "proxyport",
  "proxytype",
  "preproxy",
  "netrc_file",
  "default_protocol",
  "ssl_options"
)

# libcurl 7.85 added the string forms of the protocol restriction. Below it,
# or where R's curl does not list them, the bitmasks restrict to the same two
# schemes: CURLPROTO_HTTP (1) and CURLPROTO_HTTPS (2) (r-binding.md §5,
# "Minimum libcurl").
protocols_str_since <- numeric_version("7.85.0")
curlproto_http_https <- 3L

protocol_options <- function(capabilities) {
  modern <- !is.null(capabilities) &&
    isTRUE(capabilities$protocols_str) &&
    capabilities$version >= protocols_str_since
  if (modern) {
    list(protocols_str = "http,https", redir_protocols_str = "http,https")
  } else {
    list(
      protocols = curlproto_http_https,
      redir_protocols = curlproto_http_https
    )
  }
}

# The Accept-Encoding the transport sends, which is also what it decodes
# (§5.3; r-binding.md §5, "accept_encoding"). Never NULL, which would deliver
# compressed bytes past the decoded-byte counter.
accept_encoding_value <- function(capabilities) {
  if (isTRUE(capabilities$zlib)) "gzip, deflate" else "identity"
}

# An address as the target of a connect_to entry: an IPv6 address bracketed.
pin_target <- function(address) {
  if (grepl(":", address, fixed = TRUE)) paste0("[", address, "]") else address
}

# The connect_to entry (r-binding.md §4.2): "HOST::IP:". HOST is libcurl's own
# parse of the wire string, verbatim, so the key names the host libcurl
# requests (INV-6, §4.2); the port fields are empty, so no port key can
# mismatch and the request's own port is kept; the trailing colon keeps the
# port from being rewritten.
pin_entry <- function(host, address) {
  key <- if (grepl(":", host, fixed = TRUE) && !startsWith(host, "[")) {
    paste0("[", host, "]")
  } else {
    host
  }
  paste0(key, "::", pin_target(address), ":")
}

# Milliseconds for a libcurl timeout option: at least 1, at most what an R
# integer holds.
as_timeout_ms <- function(seconds) {
  ms <- ceiling(seconds * 1000)
  as.integer(max(1, min(ms, .Machine$integer.max)))
}

# The request plan as libcurl options (§2.3): the method, the body and the
# caller's header fields. The User-Agent is the policy's (§5.3).
request_options <- function(request, policy) {
  headers <- request$headers
  lines <- if (length(headers)) {
    ifelse(
      nzchar(headers),
      paste0(names(headers), ": ", headers),
      paste0(names(headers), ";")
    )
  } else {
    character()
  }
  body <- request$body
  if (!is.null(body) && !any(tolower(names(headers)) == "content-type")) {
    # libcurl would otherwise send a Content-Type the plan did not carry.
    lines <- c(lines, "Content-Type:")
  }
  opts <- list(useragent = policy$user_agent)
  if (length(lines)) {
    opts$httpheader <- lines
  }
  method <- request$method
  if (!is.null(body)) {
    opts$postfields <- body
    opts$postfieldsize_large <- length(body)
    if (method != "POST") {
      opts$customrequest <- method
    }
  } else if (method == "GET") {
    opts$httpget <- 1L
  } else if (method == "HEAD") {
    opts$nobody <- 1L
  } else if (method == "POST") {
    opts$postfields <- raw()
    opts$postfieldsize_large <- 0
  } else {
    opts$customrequest <- method
  }
  opts
}

# The option list for one attempt at `address` (r-binding.md §5): the pin,
# the protocol restriction, the fixed hardening, the limits and the request.
# `remaining` is the chain's time budget left, in seconds. Pure: every
# attempt's options come from here, so one test checks them all.
transport_options <- function(binding, address, remaining, capabilities) {
  policy <- binding$policy
  c(
    list(
      url = binding$url,
      connect_to = pin_entry(binding$origin$host, address)
    ),
    protocol_options(capabilities),
    fixed_transport_options,
    list(
      accept_encoding = accept_encoding_value(capabilities),
      connecttimeout_ms = as_timeout_ms(min(policy$connect_timeout, remaining)),
      timeout_ms = as_timeout_ms(remaining),
      maxfilesize_large = policy$max_response_size
    ),
    request_options(binding$request, policy)
  )
}

# --- the audit seam: libcurl's trace (INV-5; r-binding.md §6) -----------------
# The trace is observational and cannot veto: by the time libcurl writes
# `Trying`, connect() has been issued. It is a detector; the pin is the
# control. Matching fails safe: no `Trying` line, a line that cannot be read,
# or one naming another address or port is `pin-mismatch` (§6.6).

# Whether every `Trying` line in `lines` names `address` (canonical text) and
# `port`, compared as raddr values (INV-3). Returns "match", or the reason it
# is not: "absent", "garbled" or "other-address".
pin_check <- function(lines, address, port) {
  trying <- grep("^Trying ", lines, value = TRUE)
  if (!length(trying)) {
    return("absent")
  }
  want <- read_address(address)
  want <- if (is.null(want)) NULL else read_format(want)
  if (is.null(want)) {
    return("garbled")
  }
  for (line in trying) {
    dialed <- sub("^Trying ", "", sub("[.]{3}$", "", line))
    shape <- "^(\\[[0-9A-Fa-f:.]+\\]|[0-9A-Fa-f:.]+):([0-9]{1,5})$"
    if (!grepl(shape, dialed)) {
      return("garbled")
    }
    host <- unbracket(sub(shape, "\\1", dialed))
    got <- read_address(host)
    got <- if (is.null(got)) NULL else read_format(got)
    if (is.null(got)) {
      return("garbled")
    }
    if (
      !identical(got, want) || as.integer(sub(shape, "\\2", dialed)) != port
    ) {
      return("other-address")
    }
  }
  "match"
}

# --- response headers --------------------------------------------------------

# The header fields of the final response in `raw` (every header block
# libcurl received, interim 1xx responses included): a character vector of
# values named by the lowercase field name, in order. NULL when the bytes do
# not read as HTTP header lines, which is a `protocol-error` (§6.6).
parse_response_headers <- function(raw) {
  text <- tryCatch(rawToChar(raw), error = function(e) NULL)
  if (is.null(text)) {
    return(NULL)
  }
  lines <- strsplit(text, "\r?\n")[[1L]]
  starts <- grep("^HTTP/", lines)
  if (!length(starts)) {
    return(NULL)
  }
  lines <- lines[-seq_len(max(starts))]
  lines <- lines[nzchar(lines)]
  fields <- character()
  values <- character()
  for (line in lines) {
    if (grepl("^[ \t]", line) && length(values)) {
      # An obsolete line folding continues the previous field (RFC 9112 §5.2).
      values[length(values)] <- paste(values[length(values)], trimws(line))
      next
    }
    if (!grepl("^[!#$%&'*+.^_`|~0-9A-Za-z-]+:", line)) {
      return(NULL)
    }
    fields <- c(fields, ascii_lower(sub(":.*$", "", line)))
    values <- c(values, trimws(sub("^[^:]*:", "", line), whitespace = "[ \t]"))
  }
  stats::setNames(values, fields)
}

# The media type of a Content-Type value for display, without parameters, or
# NA when there is none. A value that is not `type/subtype` in token
# characters is withheld: the header is attacker-chosen and could carry
# terminal control sequences (§2.2).
display_media_type <- function(value) {
  if (!length(value) || is.na(value[[1L]])) {
    return(NA_character_)
  }
  type <- ascii_lower(trimws(sub(";.*$", "", value[[1L]])))
  token <- "[!#$%&'*+.^_`|~0-9a-z-]+"
  if (grepl(paste0("^", token, "/", token, "$"), type)) type else "<withheld>"
}
