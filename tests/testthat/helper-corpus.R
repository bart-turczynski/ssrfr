# Readers for the conformance corpus (ssrfr-v1.md §7; fixtures/README.md).

read_corpus <- function(file) {
  utils::read.delim(
    test_path("fixtures", file),
    quote = "",
    comment.char = "",
    na.strings = character(),
    colClasses = "character",
    encoding = "UTF-8",
    check.names = FALSE
  )
}

# The escapes of fixtures/README.md: \\ \t \n \r \0 and \u{XXXX}. An R string
# cannot hold NUL, so a field using \0 is an error here, not a silent skip.
unescape_field <- function(s) {
  out <- character()
  ch <- strsplit(s, "", fixed = TRUE)[[1L]]
  i <- 1L
  while (i <= length(ch)) {
    if (ch[[i]] == "\\" && i < length(ch)) {
      nx <- ch[[i + 1L]]
      simple <- c("\\" = "\\", t = "\t", n = "\n", r = "\r")
      if (nx %in% names(simple)) {
        out <- c(out, simple[[nx]])
        i <- i + 2L
        next
      }
      if (nx == "0") {
        stop("an R string cannot hold NUL: ", s)
      }
      if (nx == "u") {
        close <- match("}", ch[(i + 3L):length(ch)]) + i + 2L
        hex <- paste(ch[(i + 3L):(close - 1L)], collapse = "")
        out <- c(out, intToUtf8(strtoi(hex, 16L)))
        i <- close + 1L
        next
      }
    }
    out <- c(out, ch[[i]])
    i <- i + 1L
  }
  enc2utf8(paste(out, collapse = ""))
}

# The `policy` column: `default`, or `;`-separated field overrides with `|`
# between the values of one field.
corpus_policy <- function(spec) {
  if (identical(spec, "default")) {
    return(ssrf_policy())
  }
  numeric <- c(
    "allow_ports",
    "max_redirects",
    "connect_timeout",
    "total_timeout",
    "max_response_size",
    "max_header_bytes",
    "max_header_fields",
    "max_url_length"
  )
  args <- list()
  for (pair in strsplit(spec, ";", fixed = TRUE)[[1L]]) {
    field <- sub("=.*$", "", pair)
    values <- strsplit(sub("^[^=]*=", "", pair), "|", fixed = TRUE)[[1L]]
    args[[field]] <- if (field %in% numeric) {
      as.numeric(values)
    } else if (field == "allow_userinfo") {
      as.logical(values)
    } else {
      values
    }
  }
  do.call(ssrf_policy, args)
}

# The previous hop's URL from the `hop` column, or NULL for a first hop.
corpus_base <- function(hop) {
  if (startsWith(hop, "redirect:")) sub("^redirect:", "", hop) else NULL
}

# A verdict-vector row inspected at L0: the reason code, or "-" when nothing
# at L0 applies.
inspect_row <- function(row) {
  res <- ssrf_inspect_url(
    unescape_field(row$input),
    corpus_policy(row$policy),
    base = corpus_base(row$hop)
  )
  if (is.na(res$code)) "-" else res$code
}

# Steps 1-3 of a parse-vector row under the default policy (§7 component 2):
# "parse", "scheme" or "agree", and the host the guard acts on.
parse_row <- function(input) {
  hop <- ssrfr:::parse_hop(unescape_field(input), ssrf_policy())
  code <- hop$finding$code
  step <- hop$finding$detail$step
  outcome <- if (
    !is.null(code) && step <= 3L && code %in% c("parse", "scheme")
  ) {
    code
  } else {
    "agree"
  }
  list(outcome = outcome, host = hop$host)
}

# Two hosts are one value when raddr reads both as the same address, or when
# neither is an address and they are the same lowercase name (§4.1).
same_host_value <- function(a, b) {
  strip <- function(h) sub("^\\[(.*)\\]$", "\\1", h)
  pa <- raddr::addr_pton(strip(a))
  pb <- raddr::addr_pton(strip(b))
  if (!is.na(pa) && !is.na(pb)) {
    return(identical(raddr::addr_format(pa), raddr::addr_format(pb)))
  }
  is.na(pa) && is.na(pb) && identical(tolower(a), tolower(b))
}

# Runs `code` with every network entry point of curl and raddr made to fail,
# so any network call L0 made would raise an error (r-binding.md §7).
network_entry_points <- list(
  curl = c(
    "nslookup",
    "curl_fetch_memory",
    "curl_fetch_disk",
    "curl_fetch_stream",
    "curl_fetch_multi",
    "curl_fetch_echo",
    "curl_download",
    "curl_upload",
    "curl_echo",
    "multi_download",
    "curl",
    "multi_add",
    "multi_run",
    "new_handle",
    "handle_setopt",
    "ie_get_proxy_for_url"
  ),
  raddr = "addr_getaddrinfo"
)

local_no_network <- function(env = parent.frame()) {
  for (pkg in names(network_entry_points)) {
    fns <- network_entry_points[[pkg]]
    tripwires <- lapply(fns, function(fn) {
      force(fn)
      function(...) stop("network entry point called: ", pkg, "::", fn)
    })
    names(tripwires) <- fns
    do.call(
      testthat::local_mocked_bindings,
      c(tripwires, list(.package = pkg, .env = env))
    )
  }
}
