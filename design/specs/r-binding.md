---
status: draft
version: 0.2.0-draft
date: 2026-09-24
tracking: SSRF-ibxdyzcy
---

# `ssrfr` — R binding notes

Evidence, not policy. This file records how each requirement in
[`ssrfr-v1.md`](ssrfr-v1.md) is met in R and libcurl, and the empirical findings
that constrain the implementation. Where it and the spec disagree, the spec wins
and this file has a defect.

**Environments for [verified] claims.** Single platform; Linux and Windows
confirmation is outstanding (`ssrfr-v1.md` §8 item 6).

| Date | Environment | Evidence |
|---|---|---|
| 2026-07-25 | R 4.6.0, `curl` 7.1.0, libcurl 8.14.1 (LibreSSL 3.3.6), macOS / Darwin 25.4.0 | re-run on 2026-09-24 by the transport scripts in §9; the July output is kept in them where it differs |
| 2026-09-24 | R 4.6.0, `curl` 8.0.0, libcurl 8.14.1 (LibreSSL 3.3.6, IDN off), `rurl` 3.0.1.9000, `raddr` 0.1.2.9000, macOS / Darwin 25.6.0 | [`../evidence/`](../evidence/), listed in §9 |

---

## 1. Dependency position

```
ssrfr  ->  raddr   address parse + classify, offline       (spec §5)
       ->  rurl    URL parse, reference resolution, IDNA    (spec §3, §4)
       ->  curl    transport, and libcurl's own URL parse   (spec §4.1, INV-1)
```

All three are hard dependencies (ADR 0002). The July plan to start with a
vendored, zero-dependency base-R core and adopt `raddr` later is withdrawn, and
with it the release-order hazard: `rurl` 3.0.1 (2026-09-09) and `raddr` 0.1.2
(2026-09-21) are both on CRAN **[verified]**.

Measured transitive weight: `raddr` → `rlang`, `vctrs`; `rurl` → `stringi`,
`punycoder` (Rcpp, C++), `pslr` (cpp11, C++, also `digest`). `rurl` is the heavy
one, which inverts the July assumption. `rurl` no longer imports `curl` (§2).

---

## 2. Parsing — INV-1, INV-2

### 2.1 What changed in `rurl` 3.0

Until `rurl` 3.0.0 its `whatwg` mode handed `http`/`https` to
`curl::curl_parse_url()`, and ssrfr's INV-1 argument rested on that. **`rurl`
3.0.0 removed `curl` from its imports and parses those schemes in-tree**
(`rurl/R/parse-web.R`) **[verified]**. The swap was checked against
`curl_parse_url()` on 106,898 inputs with zero component differences at the time;
`rurl`'s own source notes that its serialized `url` field differs from libcurl's
re-serialization in about 20% of a 53k corpus. The July result — 16/16 agreement
with what libcurl dials across the obfuscation corpus, including
`010.0.0.1 → 8.0.0.1` — predates the change. `rurl` still normalizes the same
way on its side (`0177.0.0.1`, `0x7f.1`, `2130706433`, `127.1` → `127.0.0.1`;
`010.0.0.1` → `8.0.0.1`) **[verified]**; the libcurl dial side was not re-run.

The spec replaced its old INV-1 argument with libcurl's own parse as the pin
host (`ssrfr-v1.md` §4.1–§4.2). The R mechanics:

```r
v    <- rurl::get_parse_verdicts(url, <bundle>)                    # gate
p    <- rurl::safe_parse_url(url, <bundle>, host_encoding = "idna") # A-label host
wire <- serialized_sanitized_url                                   # what libcurl gets
host <- curl::curl_parse_url(wire)$host                            # the pin key
```

**The bundle is fixed internally and MUST NOT be exposed.** `ssrfr` passes
every argument below on every call that accepts it, including those equal to
today's default, so a later `rurl` default cannot change the parse. Each row is
**[verified]** on `rurl` 3.0.1:

| Argument | Value | Without it |
|---|---|---|
| `url_standard` | `"whatwg"` | `NULL`, the default of `get_parse_verdicts()`, `safe_parse_url()` and `resolve_url()`, selects `rurl`'s legacy parse (its ADR 0007): `http://0177.0.0.1/` returns `NULL` and fails layer 1. Only `get_url_diagnostics()` and `get_host_type()` refuse to run without it |
| `scheme_policy` | `"require"` | the default `"infer"` grades `h.example/x` `pass`/`admitted`, and `safe_parse_url()` infers `http`: no `parse` refusal for a schemeless first hop (spec §2.6, §3.2) |
| `scheme_relative_handling` | `"error"` | `//h.example/x` grades `admitted-scheme-relative`, refused as `scheme` rather than `parse` |
| `scheme_acceptance` | `"web"` | today's default |
| `protocol_handling` | `"keep"` | `"https"` rewrites the `scheme` column |
| `www_handling` | `"none"` | `"strip"` rewrites the `host` column |
| `index_page_handling` | `"keep"` | `"strip"` rewrites the `path` column |
| `profile` | `NULL` | `"seo"` rewrites `scheme`, `host` and `path` |

`case_handling` and `path_normalization` are left out: under `"whatwg"` the
standard governs them, and `rurl` errors on an explicit `path_normalization`.
`resolve_url()` also takes `output = "serialized"`: its default `"clean"`
resolves `../x?q=1` against `http://h.example:8080/a/b/c` to
`http://h.example/a/x`, without the port or the query. `serialize_url()` names
its argument `standard`, not `url_standard`.

**Never fetch `clean_url`.** It is `rurl`'s lossy policy projection (its ADR
0017): under the defaults
`http://User:pw@www.example.com:8080/A/b//index.html?z=1&a=2#frag` cleans to
`http://www.example.com/A/b//index.html`, without the port, query, fragment and
userinfo, and other cleaning knobs rewrite host and path **[verified]**.
Fetching it requests a different port and resource than the ones validated. If
`rurl` supplies the wire string, it comes from a call that keeps them:
`serialize_url(standard = "whatwg")`, which also emits the A-label host, or
`resolve_url(output = "serialized")` **[verified]**.

### 2.2 The gate is the layered verdict, not `parse_status`

**[verified]** `parse_status` carries Public Suffix List annotations as well as
syntax: `internal-api.corp` returns `warning-invalid-tld` and `localhost`
returns `warning-no-tld`. Blocking on `parse_status != "ok"` would refuse the
internal hosts `allow_ranges` exists to reach. `get_parse_verdicts()` separates
the layers. The resulting codes are `ssrfr-v1.md` §6.5's mapping:

| Column | Blocks when | Code |
|---|---|---|
| `layer1_syntax_verdict` | `"fail"` | `parse` |
| `layer2_policy_verdict` | anything but `"admitted"` (e.g. `"rejected-scheme"` for `gopher:`) | `scheme` |
| `layer3_annotation_state` | never — PSL annotation only | — |

`rfc3986` mode returns the **un-normalized** host (`0177.0.0.1` stays literal),
and that string is what reproduces the silent bypass. It is correct for its own
purpose and unsafe for this one.

### 2.3 Host handling details **[verified]**

- **IDN.** libcurl's IDN support is build-optional and is off in the 2026-09-24
  build: `curl_parse_url("http://bücher.example/")` returns the U-label unchanged.
  `rurl`'s default `host_encoding = "keep"` also returns U-labels. Pass
  `host_encoding = "idna"` and hand libcurl the A-label URL.
- **IPv6 spelling.** `curl_parse_url()` now compresses `fd00:0ec2::254` to
  `[fd00:ec2::254]` (the July note said it did not); it leaves
  `[::ffff:127.0.0.1]` unconverted, where `rurl` gives `[::ffff:7f00:1]`.
  Compare addresses as `raddr` values, never as strings.
- **Brackets.** Both parsers keep IPv6 brackets. `raddr::addr_whatwg("[::1]")`
  silently returns `NA`, so strip brackets, and only when the host type is IPv6.
- **Trailing root dot.** Both keep it; hostname matching strips one
  (`ssrfr-v1.md` §5.0).
- **Scalar vs vector.** `safe_parse_url()` is scalar; vectors need
  `safe_parse_urls()`.
- **Userinfo.** Exposed as the `user` and `password` columns plus the
  `invalid-credentials` diagnostic. `credential_handling = "reject"` only affects
  the cleaned URL; `parse_status` stays `ok`. Userinfo refusal is ssrfr's step 4.
- **Numeric literals.** `rurl` reports the shape (`ipv4-octal`,
  `ipv4-non-dotted`, `ipv4-short-form`, `ipv4-non-decimal`, `ipv4-leading-zero`,
  …) as diagnostics, which can drive the published `numeric-literal` code without
  a separate raw-host argument. The inherited signature's vestigial `is_ip_host`
  argument is dropped (ADR 0001 §2.4).

### 2.4 Reference resolution

`curl` cannot resolve a relative reference: `curl_modify_url()` substitutes
components without merging dot segments, and `curl_parse_url()` rejects a bare
relative reference **[verified]**. `rurl::resolve_url()` performs the RFC 3986
§5.2 merge, and since 3.0.0 parses the reference under the selected standard
first, so `//evil.example/x` resolves to `http://evil.example/x`. The merged URL
is then re-parsed like any other input (`ssrfr-v1.md` §3.2–§3.3).

### 2.5 Never parse addresses with `ipaddress`

**[verified]** `ip_address("0177.0.0.1")` returns `177.0.0.1`, which classifies
as global, so the guard allows — and curl connects to `127.0.0.1`. Confirmed end
to end: `curl -v http://0177.0.0.1/` → `Trying 127.0.0.1:80`.

### 2.6 `raddr` needs a reading

`raddr` classifies a `raddr_address`, not a string or a four-reading
`raddr_parse`. Resolved addresses from `nslookup()` are canonical text: parse them
with `addr_pton()`. Host literals come from libcurl's parse and are parsed the same
way after bracket stripping. `raddr::addr_curl()` is not a substitute for the URL
parse: `rurl`'s ADR 0018 measured it regressing 7 of 18 hosts.

---

## 3. Resolution — INV-4, INV-5

```r
addrs <- curl::nslookup(host, ipv4_only = FALSE, multiple = TRUE)
```

`multiple = TRUE` returns every address the system resolver call yields
**[verified]** (`localhost` → `::1`, `127.0.0.1`). That set is shaped by the hosts
file, the name-service configuration and address-selection filtering; it is the
set the guard validates and the only set the pin draws from (INV-4).

Called through a **3-line internal, unexported wrapper** so tests can mock the
seam (§7). There is **no public resolver argument** (`ssrfr-v1.md` INV-5); R's
mocking facilities need no public seam.

`nslookup()` takes no timeout argument and blocks in the system resolver
**[assumption]**. `total_timeout` therefore cannot bound resolution unless the
implementation finds a way to; this is part of `ssrfr-v1.md` §8 item 3.

**`dns_servers` is listed by `curl_options()` but FAILS at `setopt`**
**[verified]** — it requires a c-ares build. Do not design around it. This also
means the guard cannot pin its own resolver, so a compromised system resolver is
out of scope (spec §11.2).

---

## 4. Pinning — INV-5, INV-6

### 4.1 The primitive: `connect_to`, not `resolve`

Both preserve the hostname for TLS and `Host`. They fail differently.

| Property | `resolve` | `connect_to` |
|---|---|---|
| Multi-address failover in one entry | yes **[verified]** | no — first match wins **[verified]** |
| Survives connection reuse | **no** **[verified]** | yes **[verified]** |
| Leaks into other handles' lookups | **yes** — the shared DNS cache **[verified]** | no **[verified]** |
| Port-key mismatch | fails open **[verified]** | fails open **[verified]** |
| Empty-field wildcard form | — | yes **[verified]** |

libcurl's connection-reuse check runs *before* DNS and is hostname-based; only
`CONNECT_TO` sets the connect-to host and port that check compares. **A
`resolve` pin is never consulted when a pooled connection matches** — a silent
bypass on the second
request to a host, even from a fresh handle, because R's `curl` shares one
connection pool across synchronous fetches. **[verified]** on the R build
(libcurl 8.14.1, LibreSSL), macOS only; `forbid_reuse` closes it. The
`lib/url.c` reading behind it was done at tag `curl-8_14_1`.

**Every hop gets a new handle, and `handle_reset()` is never used.** R's `curl`
runs synchronous fetches in one process-wide multi handle (under the default
`curl_interrupt = TRUE`), and a multi handle owns the DNS cache and connection
pool of every easy handle added to it **[sourced]**. Those caches are shared
with every other `curl`-based client in the process, whichever handle each
uses.

- `handle_reset()` is `curl_easy_reset()`, which keeps live connections, the
  DNS cache, cookies and the alt-svc cache **[sourced]**, followed by the
  package defaults (§5): `followlocation = 1` comes back, and so does netrc when
  `getOption("netrc")` is set **[verified]**. `curl`'s own documentation
  recommends a separate handle per independent request.
- `resolve` writes into the shared DNS cache, and an entry without the `+`
  prefix never expires **[sourced]**. A `resolve` pin set on one handle answered
  the lookup of a later fresh, unpinned handle with `dns_cache_timeout = 0`; the
  same test with `connect_to`, or with `curl_interrupt = FALSE` (a private multi
  per handle), fails with `Could not resolve host` **[verified]**. This is a
  second reason for `connect_to`, independent of reuse: a `resolve` pin would
  also steer later requests made by other code in the process.

A failover retry (§4.3) changes the pin, so it takes a new handle too.

### 4.2 The fail-open, and the form that removes it

**[verified]** Both primitives discard the pin and perform a real, unvalidated
resolution when the key's port does not match the request's port — silently:

```r
connect_to = "h.invalid:443:127.0.0.1:443"   # request on :80
#> Could not resolve host: h.invalid          # pin IGNORED

connect_to = "h.invalid:80:127.0.0.1:80"     # request on :80
#> Trying 127.0.0.1:80...                     # pin honoured
```

`connect_to`'s syntax is `HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT`, and an
empty field means "match anything / keep original" **[verified]**:

```r
connect_to = "h.invalid::127.0.0.1:80"   # request :8080 -> Trying 127.0.0.1:80
connect_to = "h.invalid::127.0.0.1:"     # request :8080 -> Trying 127.0.0.1:8080
```

> **Use `"HOST::IP:"`.** There is no port key, so INV-6's mismatch cannot occur —
> the hazard is designed out rather than guarded against.

Always emit the trailing colon: `"HOST::IP:80"` silently rewrites the port too.

Never leave `HOST` empty: `"::IP:"` matches every host **[verified]**, so the
key would stop naming the host that was validated, and INV-6 requires it to be
libcurl's parse of the requested URL.

The `HOST` field is matched against libcurl's own parse of the request URL. A
host key that differs from it — a U-label where libcurl holds an A-label, a
different IPv6 spelling — disengages the pin the same way a port mismatch does
**[assumption]**, by analogy with the verified port case. This is why the spec
proposes taking the key from `curl_parse_url()` (`ssrfr-v1.md` §4.2).

### 4.3 Failover

`connect_to` does not fail over, so failover is implemented in R by retrying with
the next address from the already-validated set. We own the redirect loop anyway,
so a per-address retry costs little. This matters: through 1.5.0 the reference
Ruby implementation pinned one *randomly sampled* address with no fallback, and a
user measured ~60% of dual-stack fetches failing from an IPv4-only host. 1.6.0
(September 2026) retries the other validated addresses.

`dns_shuffle_addresses` stays off so ordering remains ours.

### 4.4 IPv6

A bracketed literal in the empty-field form, `"HOST::[::1]:"`, pins over IPv6:
the trace reads `Trying [::1]:PORT…` and the app sees the hostname in `Host:`
**[verified]**, macOS only (spec §8 items 6 and 7). The test server is `httpuv`,
because `webfakes` cannot bind `::1` (§7). `httpuv` leaves `REMOTE_ADDR` empty
for a `::1` client, so the dialed address comes from the `debugfunction` trace
(§6), not from the server.

---

## 5. Handle configuration — spec §14

| Option | Value | Requirement met |
|---|---|---|
| `connect_to` | `"HOST::IP:"` | INV-5, INV-6 |
| `protocols_str` | `"http,https"` | scheme enforcement at the transport |
| `redir_protocols_str` | `"http,https"` | removes `ftp`/`ftps` from redirect hops |
| `followlocation` | `0L` | INV-7 |
| `forbid_reuse` | `1L` | reuse must not outlive the pin |
| `dns_cache_timeout` | `0L` | libcurl caches DNS 60 s by default |
| `proxy` | `""` | INV-10 |
| `noproxy` | `"*"` | INV-10 — see the warning below |
| `unrestricted_auth` | `0L` | partial INV-8 — see below |
| `netrc` | `0L` | INV-8, INV-10 — see below |
| `cookiefile` | `NULL` | stops the cookie engine the `curl` package starts — see below |
| `cookiejar` | never set | it writes received cookies to disk at cleanup |
| `connecttimeout`, `timeout` | finite | libcurl's `timeout` default is **0 = never** |
| `maxfilesize` | set, not trusted | see below |
| `path_as_is` | considered | avoid transport-side path rewriting |
| `altsvc`, `hsts` | never set | INV-10 |
| `unix_socket_path`, `abstract_unix_socket` | never set | container control planes |
| `doh_url`, `interface`, `localport`, `localportrange` | never set | see below |
| `dns_shuffle_addresses` | `0L` | ordering stays ours |
| `accept_encoding` | set explicitly, never `NULL` | fixes the request; the package default is build-dependent — see below |

Left at their defaults on purpose: `http_version` — libcurl 8.14.1 reuses a
connection only for the same host name and port, so HTTP/2 coalesces nothing
**[sourced]**, and HTTP/3 is neither in the evidence build (`http_version =
30L` fails at `setopt` **[verified]**) nor reachable without asking or
`Alt-Svc`; `ipresolve` — a literal `connect_to` target overrides it
**[verified]**; `maxage_conn` — under `forbid_reuse` nothing idles in the pool;
`low_speed_limit`/`low_speed_time` — the package's 1 byte/s over 600 s is
inside the finite `timeout` anyway.

### What a new handle already carries

`curl`'s `new_handle()` — and `handle_reset()`, which re-applies the same
function — sets these before `ssrfr` sets anything **[sourced]**:

| Package default | `ssrfr` |
|---|---|
| `followlocation = 1`, `maxredirs = 10` | overridden (`followlocation = 0L`) |
| `accept_encoding = ""`, every built-in encoding: `deflate, gzip` on the evidence build **[verified]** | overridden |
| `cookiefile = ""`, an in-memory cookie engine **[verified]** | overridden (`NULL`) |
| `netrc = CURL_NETRC_OPTIONAL` and `netrc_file`, only when `getOption("netrc")` is set (`curl` ≥ 7.0.0) **[verified]** | overridden (`0L`) |
| `useragent` from `getOption("HTTPUserAgent")` | overridden (spec §5.3 `user_agent`) |
| `connecttimeout = 10` | overridden (`connect_timeout`) |
| `low_speed_limit = 1`, `low_speed_time = 600` | left — inside the finite `timeout` |
| `httpauth = CURLAUTH_ANY` | left — inert without credentials, which `netrc = 0L` removes |
| `pipewait = 1` | left — inert under `forbid_reuse` |

`ssrfr` never relies on a package default for any row of the table above.

### Minimum libcurl

`protocols_str` and `redir_protocols_str` need libcurl 7.85. Below that, `ssrfr`
sets the older `protocols` and `redir_protocols` bitmasks to HTTP and HTTPS
instead. The supported floor is the `curl` package's own, libcurl 7.73; below it
the package builds against a bundled static libcurl. Ubuntu 22.04 ships 7.81 and
RHEL 9 ships 7.76.1 **[sourced]**, and on Linux R's `curl` links the system
libcurl. Below 7.77, libcurl's URL API does not normalize numeric IPv4 hosts; the
`rurl`-versus-libcurl disagreement refusal (spec §4.1) keeps that case
fail-closed, and a test must show it. The floor is conditional on the Linux
matrix (spec §8 items 6 and 16): if the protocol restriction or the pin fails on
Ubuntu 22.04 or Rocky 9, the floor becomes 7.85.

### Traps in this table

- **`noproxy = ""` means the opposite of `proxy = ""`.** Empty `noproxy` proxies
  *everything* and overrides a protective ambient `NO_PROXY`. Want `proxy = ""`
  **and** `noproxy = "*"`.
- **`unrestricted_auth = 0` covers libcurl's own auth only**, not
  caller-supplied `Authorization` headers or bodies. INV-8 must be implemented in
  our redirect loop.
- **`forbid_reuse`, not `fresh_connect`.** `fresh_connect` only stops the next
  transfer taking a pooled connection, libcurl ignores it on a follow-up
  request — a redirect it follows, or an authentication round — and it leaves
  the connection it opened in the shared pool (§4.1) **[sourced]**.
  `forbid_reuse` closes the connection when the transfer ends, so no pinned
  connection outlives its hop (spec §14; **[verified]**, §4.1). The other
  direction needs no option: libcurl never gives a `connect_to` transfer a
  connection opened without a connect-to host, or with a different one
  **[sourced]**.
- **netrc is on whenever `getOption("netrc")` is set.** R 4.6.0 added the
  option for `download.file()`, and `curl` 7.0.0 applies it to every new handle
  as `CURL_NETRC_OPTIONAL` **[sourced]**; libcurl's own default ignores netrc.
  With a `default` entry, libcurl answers a `401` Basic challenge with the
  file's credentials inside one transfer, `followlocation = 0` and
  `unrestricted_auth = 0` notwithstanding **[verified]**: any host the policy
  admits can collect the operator's password, and a `machine` entry
  authenticates the fetch to that host. `netrc = 0L` stops it **[verified]**.
  netrc plus redirects is also a recurring libcurl CVE class
  (`CVE-2024-11053`; `CVE-2026-3783`, whose range includes 8.14.1 but which
  needs libcurl to follow the redirect with an OAuth2 bearer token)
  **[sourced]**.
- **The cookie engine is already on.** `new_handle()` sets `cookiefile = ""`,
  so a handle replays a `Set-Cookie` it received on its next request
  **[verified]** — to the same host, or across origins within the cookie's
  `Domain`. A fresh handle per hop (§4.1) starts empty **[verified]**, and
  `cookiefile = NULL` turns the engine off **[verified]**, so the only `Cookie`
  sent is the request plan's (spec §2.3). A `cookiefile` naming a file would
  read ambient cookies (INV-10); `cookiejar` writes the received ones out when
  the handle is cleaned up **[sourced]**.
- **`maxfilesize` is advisory**: before libcurl 8.4.0 it is a no-op without
  `Content-Length`; from 8.4.0 it also aborts a transfer mid-stream
  (**[verified]** on 8.14.1 with a chunked response, §9). Either way it counts
  wire bytes, so a compressed bomb passes. A real cap needs a write-callback byte
  counter.
- **`accept_encoding` sets what is advertised, not what is decoded.** With any
  non-`NULL` value libcurl decodes every encoding it was built with that the
  response names in `Content-Encoding`: `"gzip"` and `"identity"` both decode a
  `deflate` response **[verified]** (`lib/http.c`, `lib/content_encoding.c`
  **[sourced]**). The decoded-byte cap (spec §5.3) therefore counts in the write
  callback whatever arrives. `NULL` disables decoding and delivers compressed
  bytes **[verified]**. The package default `""` asks for every built-in
  encoding, which differs by build — `deflate, gzip` on the evidence build
  **[verified]** — so `ssrfr` sets the list itself.
- **`redir_protocols_str` is less load-bearing than it looks**: libcurl already
  restricts redirect hops to `http https ftp ftps` **[verified]**, so
  redirect-to-`file://` is already blocked. The exposure is the **first** hop.
- **Four options move resolution or the source of a connection.** `doh_url`
  turns lookups into extra HTTPS requests to its server, whose own name the
  system resolver answers, under verification settings of their own
  **[sourced]**; with a literal pin there is nothing to resolve. `interface`
  and `localport` choose the source address and port, which no policy field
  governs, and a hostname `interface` is resolved outside the pin
  **[sourced]**. `share` would extend DNS, connection and cookie sharing across
  handles **[sourced]**; R's `curl` has no share-handle API and types the option
  as a string **[verified]**, and the sharing that matters already happens in
  the multi handle (§4.1).

### Protocol exposure — the motivating vulnerability

**[verified]** 24 protocols are compiled in and reachable on the first hop:

```
dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt
pop3 pop3s rtsp smb smbs smtp smtps telnet tftp ws wss
```

`curl::curl_fetch_memory("file:///etc/passwd")` reads the file **[verified]**, as
do `httr2`, `httr`, base `readLines()`, and `download.file()`. `gopher://` is
present and libcurl percent-decodes the gopher selector, so `%0d%0a` becomes real
CRLF — the SSRF→Redis-RCE chain, live in R today.

Base `download.file()` and `url()` cannot be guarded by this package; document
them as dangerous primitives (spec §9).

---

## 6. The audit seam — INV-5 verification

`handle_data()` exposes **no peer IP** **[verified]**, and R's `curl` exposes no
`CURLINFO_PRIMARY_IP`. But **`debugfunction` accepts an R closure and fires**
**[verified]**, unlike `prereqfunction`, `opensocketfunction`, and
`sockoptfunction`:

```r
log <- character()
h <- curl::new_handle(connecttimeout = 2, timeout = 3)
curl::handle_setopt(h, verbose = TRUE,
  debugfunction = function(type, msg) { log <<- c(log, rawToChar(msg)); NULL })
try(curl::curl_fetch_memory("http://127.0.0.1:1/", handle = h), silent = TRUE)
log
#> "  Trying 127.0.0.1:1..."
#> "connect to 127.0.0.1 port 1 from 127.0.0.1 port 50518 failed: Connection refused"
```

This is the only way to observe the dialed address from R. It enables INV-5's
verification requirement and the offline pinning proofs in §7.

> **It is observational and cannot veto.** By the time the callback reports
> `Trying …`, `connect()` has been issued. It is a **detector, never the gate** —
> the pin is the control. A reviewer who mistakes this for a gate will build
> something unsafe.

The trace is human-readable diagnostic output, not an API, so its stability
across libcurl versions and platforms is **unverified**. Matching MUST fail safe:
absence of an expected line, or a line that cannot be read, is the operational
cause `pin-mismatch` (`ssrfr-v1.md` §6.6), never evidence of a correct
connection. Prefer confirming the address we pinned appears over extracting an
arbitrary address from prose.

**Not settable** (fail with "unknown or unsupported type") **[verified]**:
`prereqfunction`, `opensocketfunction`, `sockoptfunction`. `opensocketfunction`
is what `safeurl-python` uses via pycurl to validate at socket open, and
`prereqfunction` is the one that also sees reused connections, after connect and
before the request. `sockoptfunction` never sees the address. Reaching either
from R would mean C code in `ssrfr` linking libcurl — the coupling that killed
`advocate`. Escalation path, not a plan.

---

## 7. Testing architecture

These L0–L4 are **test layers**, not the guard layers of the spec. Demonstrated
working in a throwaway package: 9/9 expectations pass.

| Layer | Technique | CRAN |
|---|---|---|
| **L0** | golden tables — verdicts and reason strings as pure functions | always |
| **L1** | `testthat::local_mocked_bindings()` on the internal `nslookup` wrapper; a **counting mock asserting exactly one call** proves INV-5's resolve-once | always |
| **L2** | pin `http://pinned.example.invalid:PORT/` to a loopback `webfakes` app; assert arrival **and** that `Host:` is still the hostname | guard `skip_if_not_installed("webfakes")`, cap threads at 2 |
| **L3** | `base::serverSocket()` + `socketAccept()` — read exact wire bytes, zero dependencies | always |
| **L4** | env-gated `SSRFR_INTEGRATION_TESTS` — real DNS, TLS chains, IPv6 pinning | never |

### Behaviour to test layer

Test layers, as in the table above; the spec's corpus names guard layers.

| Behaviour | Spec | Layer | Technique | On CRAN |
|---|---|---|---|---|
| Verdicts and reason codes | §5, §6.5 | L0 | golden table | runs |
| Guard host equals transport host, by value | INV-1, INV-2 | L0 | parse-vector corpus | runs |
| Every spelling, same verdict | INV-3 | L0 | inherited spelling tables | runs |
| L0 makes no network call | §1 | L0 | both seams mocked to `stop()` | runs |
| Every handle carries the pin; TLS never weakened; §5 "never set" options absent | INV-6, INV-9, §14 | L0 | option-list builder | runs |
| One place dials | INV-5, §14 | L0 | namespace walk | runs |
| One bad address refuses the set | INV-4 | L1 | mock returns mixed sets | runs |
| Empty answer or resolver error refuses as `unresolvable` | INV-11, §6.6 | L1 | mock returns `character(0)` or errors | runs |
| One resolution per hop | INV-5, INV-7 | L1 | counting mock: calls == hops | runs |
| Scheme and port refused before resolution | §12 | L1 | counting mock: zero calls | runs |
| A changed second answer is never used | INV-5 | L1 + L2 | mock flips on the second call; request still lands on the pinned app | if `webfakes` |
| Pin is load-bearing; `Host:` kept | INV-5, INV-6 | L2 | `.invalid` host, `webfakes` app | if `webfakes` |
| Explicit, default and non-default ports | INV-6 | L2 | the same, per port form | if `webfakes` |
| A refusal makes no connection | INV-11 | L3 | honeypot listener | runs |
| Every dimension revalidated per hop | INV-7 | L2 | `webfakes` redirect chain | if `webfakes` |
| Redirect budget refuses as `redirect-limit` | §2.5, §12 | L2 | self-redirecting app | if `webfakes` |
| Credentials absent after a cross-origin hop | INV-8 | L3 | raw request bytes | runs |
| Verification bound to the hostname | INV-9 | L2 | `.invalid` over TLS | `skip_on_cran()` |
| SNI carries the hostname | INV-9 | L2 | two-vhost `s_server` | `skip_on_cran()`; needs `openssl` |
| Proxy variables and CONNECT | INV-10 | L2 + L3 | dead port; listener as proxy | runs |
| `Alt-Svc` has no effect | INV-10 | L2 | served header | if `webfakes` |
| Timeouts; byte cap on a chunked body | §5.3, §14 | L2 | `res$delay()`, `res$send_chunk()` | if `webfakes`; wide margins |
| IPv6 pin | INV-6 | L2 (`httpuv`) | `"HOST::[::1]:"` | if `httpuv` and `::1` bind |
| Real DNS, certificate chains, live rebinding | INV-4, INV-5, INV-9 | L4 | `SSRFR_INTEGRATION_TESTS` | never |

### Why `.invalid`

RFC 2606 guarantees `.invalid` never resolves. A passing L2 test therefore
**proves the pin was load-bearing** rather than incidentally correct — the
negative control is free. Confirmed by the inverse: pinning a `.invalid` host over
HTTPS fails with `no alternative certificate subject name matches`, which is also
an independent demonstration of INV-9 (verification stays bound to the hostname).

### Proving SNI: two virtual hosts on one socket

The `.invalid` test shows that verification is bound to the hostname. It cannot
show what the ClientHello carried, because a `webfakes` server has one
certificate whatever the SNI says (`server_opts(ssl_certificate =)` takes a
single path). `ssrf_filter`'s suite has the stronger test **[sourced]**: two
virtual hosts on one IP and port, each with its own certificate. Only SNI can
select the second, so fetching it through a pin and receiving its certificate
proves the name travelled in the handshake.

`openssl s_server -www -cert alpha.crt -key alpha.key -servername
beta.example.invalid -cert2 beta.crt -key2 beta.key` serves both; OpenSSL 3.6
and macOS's LibreSSL 3.3.6 have these options **[sourced]**. With fixture
certificates that carry DNS SANs only, `cainfo` set to the fixture CA, and pins
of the form `HOST::127.0.0.1:` **[verified]**:

| Request | Certificate served | Result |
|---|---|---|
| `https://alpha.example.invalid`, pinned | `CN=alpha.example.invalid` | 200 |
| `https://beta.example.invalid`, pinned | `CN=beta.example.invalid` | 200 — SNI carried the hostname |
| `https://127.0.0.1` with `Host: beta.example.invalid` | `CN=alpha…`, the default | fails: no SAN matches `127.0.0.1`; an IP literal gets no SNI (RFC 6066 §3) |
| `beta` pinned, server holding `alpha` only | `CN=alpha…` | fails — the control: row 2 passed because of SNI selection |

Read the served subject from the `debugfunction` trace (`subject: CN=…`); a
missing line fails the test. The `openssl` binary is not guaranteed on CRAN's
machines, so the test calls `skip_on_cran()` and skips when
`Sys.which("openssl")` is empty; under the skip rule it must run in the gate.
Commit the fixtures with a long validity (`webfakes`' certificate runs to 2124)
instead of generating them at test time.

### Getting past the guard's own loopback refusal

The policy refuses loopback, so an L2 test that goes through `ssrf_prepare_hop()`
reaches a `webfakes` app only with `allow_ranges` covering `127.0.0.0/8` — which
also exercises tier 3 of `ssrfr-v1.md` §5.0. Tests of the transport itself call
the internal fetch below the policy. `linklint` hit the same problem and splits
its live tests the same way (`node-transport-live.test.ts`).

### Rules

- **No public `resolver` argument, ever.** `local_mocked_bindings()` needs no
  public seam — strictly better than exposing a test-mode toggle as one Go
  implementation does. Add a test asserting the seam cannot be overridden from
  outside the namespace.
- Port the inherited IPv6 **spelling tables** for INV-3 verbatim; they already
  encode the two production bugs.
- **Proxy isolation (INV-10).** Set each proxy variable in turn — `http_proxy`,
  `HTTP_PROXY`, `https_proxy`, `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY`, with
  `http://` and `socks5h://` values — to a dead loopback port, so a leak fails
  at once with a refused connection instead of racing a timeout, and fetch a
  pinned `http://` target and a pinned `https://` one. Without `proxy = ""`,
  every variable libcurl reads sends the fetch to the dead port; with
  `proxy = ""` and `noproxy = "*"`, every fetch succeeds **[verified]**. Both
  schemes are needed: libcurl reads `http_proxy` in lowercase only, and
  `https_proxy`/`HTTPS_PROXY` only for `https://` **[verified]**, but where
  environment names are case-insensitive `HTTP_PROXY` applies too
  **[sourced]**. libcurl reads the variables on every transfer, so
  `withr::local_envvar()` in the test process is enough **[verified]**; keep
  `callr` for anything read at load time. Pattern from `linklint`'s
  `proxy-isolation-harness.ts`.
  - **CONNECT.** Under a `connect_to` pin libcurl switches an HTTP proxy to
    tunnel mode, even for `http://`, and the tunnel target is the pinned
    address, not the hostname (`CONNECT 127.0.0.1:8080 HTTP/1.1`); a SOCKS5
    leak likewise asks for the IPv4 literal **[sourced]** **[verified]**. A leak
    test therefore asserts that *nothing* reaches an L3 listener standing in
    for the proxy. Looking for the hostname in the proxy's request would miss
    the leak.
  - **The system proxy.** libcurl documents environment variables as its only
    ambient proxy source. R's `curl` exposes Windows' proxy settings through
    `ie_proxy_info()` and `ie_get_proxy_for_url()` but never applies them
    **[sourced]**. So there is nothing to neutralize beyond the variables, and
    the one-place-dials tripwire lists `ie_get_proxy_for_url` so no code path
    starts applying it. On webR, `curl`'s `.onLoad` sets `ALL_PROXY` to its
    socket gateway **[sourced]**; `proxy = ""` overrides it.
- **`Alt-Svc` (INV-10):** serve an `Alt-Svc` header and assert it causes no
  resolution, connection or request on the next hop.
- **Look the resolver up at call time.** `local_mocked_bindings()` swaps the
  binding in the package namespace, so a function value captured earlier — a
  default argument, a field of a policy object — still points at the real
  resolver, and the mock never engages **[verified]**. Call the internal
  wrapper by name where it is used. A resolver stored in a policy object would
  also be the public seam INV-5 forbids.
- **Tripwires (INV-5, INV-6, spec §14).** R cannot intercept `connect()` the
  way Advocate's `CheckedSocket` does **[sourced]**, and `handle_data()` does
  not return the options set on a handle **[verified]**, so two tests stand in:
  - *Every handle carries the pin.* Options come from one internal, pure
    option-list builder. An L0 test asserts, for each scheme and for explicit,
    default and non-default ports, that the list holds `connect_to = "HOST::IP:"`,
    `proxy = ""`, `noproxy = "*"`, `followlocation = 0L` and `forbid_reuse =
    1L`, never a zero `ssl_verifypeer` or `ssl_verifyhost`, and none of the
    §5 "never set" options.
  - *One place dials.* Walk the call positions of every closure in the
    installed namespace, nested closures included, and fail if a network entry
    point (`curl_fetch_*`, `curl`, `curl_download`, `multi_add`, `new_handle`,
    `handle_setopt`, `nslookup`, `ie_get_proxy_for_url`, base `url`,
    `download.file`, `socketConnection`) is called outside the internal DNS
    wrapper and the internal fetch **[verified]**. Walk calls, not
    `all.names()`: that also returns plain symbols, so every `curl::` prefix
    and every argument named `url` would trip it **[verified]**. The walk runs
    against the installed package under `R CMD check`, where `R/` is absent,
    and needs no `codetools`. It is a tripwire, not a proof: a call built from
    a string escapes it.
- **L0 does no I/O, and a test proves it** (`ssrfr-v1.md` §1). Mock the
  internal DNS wrapper and the internal fetch to `stop()`, then run the whole L0
  golden table; any network call trips a mock **[verified]**. With the
  one-place-dials tripwire, which shows those two seams are the only way out,
  this covers every network entry point.
- **A refusal makes no connection** (INV-11, `ssrfr-v1.md` §12). Loopback is
  refused by default, so a loopback listener is itself a refused destination:
  mock the resolver to return `127.0.0.1` for `honeypot.invalid`, point the
  port at an L3 `serverSocket()` listener, expect the refusal, and assert that
  no connection arrives. The listener sees a bare TCP connect before any byte
  arrives **[verified]**, which a `webfakes` app, logging requests only, would
  not. Poll `socketSelect()` across the whole window rather than trusting one
  call: a single `socketSelect(timeout = 5)` has returned `FALSE` at once with a
  client about to connect **[verified]**, so a lone `FALSE` proves nothing.
  Refusals at lifecycle steps 3–5 (scheme, userinfo, port) also assert zero
  calls on the counting resolver mock.
- **Enumerate protocols at run time.** The compiled-in list differs by build
  (§5 shows this one's 24), so protocol tests iterate over
  `curl::curl_version()$protocols` minus `http` and `https`. They assert a
  `scheme` refusal from the guard and `Unsupported protocol` from the transport
  under `protocols_str = "http,https"` **[verified]**. Give each scheme a URL it
  accepts: `file://x.invalid/` fails libcurl's URL parse first (`Bad file://
  URL`) and proves nothing about `protocols_str`. Gate capability-dependent
  tests the same way, e.g. on `curl_version()$ipv6`.
- **A skipped security test is a failure** (`ssrfr-v1.md` §7.2). Skips exist
  for CRAN's farm, not for the gate: Advocate's hostname tests skipped silently
  for years behind a broken capability probe **[sourced]**. `testthat` reports a
  skip and a test with no expectations the same way, as `skipped` in
  `as.data.frame()` of the results **[verified]**, and the gate fails when any
  is `TRUE`. It also sets `NOT_CRAN=true`: `skip_on_cran()` skips whenever
  `NOT_CRAN` is unset and R is non-interactive **[sourced]**, and
  `rcmdcheck(args = "--as-cran", error_on = "warning")` passes with such tests
  skipped, because a skip is not a warning **[verified]**.

### Harness notes

**CRAN's check environment.**
- `NOT_CRAN` belongs to `testthat`, not R. Unset in a non-interactive session,
  it makes `testthat`'s internal `on_cran()` `TRUE` **[sourced]**. CRAN leaves
  it unset.
- `--as-cran` sets `_R_CHECK_SUGGESTS_ONLY_=TRUE` and
  `_R_CHECK_NO_RECOMMENDED_=TRUE`: tests see only declared packages, and
  recommended ones only if declared **[sourced]**. `webfakes`, `httpuv`,
  `callr`, `processx` and `withr` therefore go in `Suggests`, and the tripwire
  uses base R rather than `codetools`.
- `_R_CHECK_DEPENDS_ONLY_=true` removes `Suggests`, except test-suite managers,
  so every use of a suggested package sits behind `skip_if_not_installed()`.
  Writing R Extensions recommends checking with each variable set and with
  neither, and extends the conditional-use rule to test-suite managers
  **[sourced]**.
- Neither variable hides a package installed in `.Library`. On the maintainer's
  machine, where all packages live there, `webfakes` and `codetools` stayed
  visible with both set **[verified]**. A local run therefore cannot catch a
  missing `skip_if_not_installed()`; that takes a library holding only base and
  recommended packages.
- `_R_CHECK_LIMIT_CORES_=TRUE` for submissions errors when `parallel` spawns
  more than two children, and CRAN policy caps any package at two threads or
  cores **[sourced]**. The check cannot see `webfakes`' `num_threads`, but the
  policy covers it; hence the L2 cap of 2.

**Servers.**
- **The IP-SAN trap.** `webfakes`' certificate carries `IP Address:127.0.0.1`
  beside `DNS:localhost` **[verified]**, so `https://127.0.0.1:PORT/` verifies.
  It cannot show that rewriting the URL to an IP breaks TLS (INV-9's
  corollary). Use a `.invalid` name, or the two-vhost fixtures, which carry no
  IP SAN. `webfakes` also ships its CA's private key, so trust its `ca.crt` on
  test handles only.
- **`::1` needs `httpuv`.** `webfakes` builds civetweb without `USE_IPV6`
  **[sourced]**, and `serverSocket()` opens an `AF_INET` socket **[sourced]**.
  `httpuv`, which has IPv6 since 1.4.0, binds `::1`, and
  `connect_to = "v6pin.invalid::[::1]:"` reached it with `Host:
  v6pin.invalid:PORT` intact **[verified]** (macOS only). The cost is `Rcpp`,
  `later`, `promises` and `R6` in `Suggests`, for the IPv6 case alone.
- **`serverSocket()` listens on every IPv4 interface** (`INADDR_ANY`), not only
  loopback **[sourced]** **[verified]**. An L3 listener can be reached from the
  network while it is open: keep it short-lived, and answer only with fixture
  bytes.

**Corpora.**
- **Each corpus carries its row count and checksum** (`ssrfr-v1.md` §7.2).
  The test that loads a corpus file first checks both against values committed
  beside it, so a truncated or emptied file fails instead of passing vacuously.
  `linklint` pins the 6,391-row IdnaTestV2 corpus this way **[sourced]**.
  `tools::sha256sum()` arrived in R 4.5.0 **[sourced]**; under the
  `R (>= 4.0.0)` floor, `tools::md5sum()` guards against accidental edits,
  which is the threat here.

### Hard limits

- **No fake DNS server is possible in R** — no UDP in base R, and `dns_servers`
  fails without c-ares. INV-5's rebinding property is proven by the counting
  mock, not by a rebinding server.
- **`webfakes` cannot bind `::1`**; `httpuv` can, which brings the IPv6 pin to
  L2 (Harness notes). Whether CRAN's and CI machines have a usable `::1` is
  **[assumption]**; gate on `curl_version()$ipv6` and on the bind succeeding.
- **`webmockr` / `vcr` / `httptest2` cannot intercept raw `curl`** — they cover
  `crul`/`httr`/`httr2` only. Not usable for this package's transport tests.

---

## 8. Consumers

| Package | Status (2026-09-24) |
|---|---|
| `robotstxtr` | vendored matcher in `R/ssrf.R`, fetches with `httr2`; publishes the 17 reason codes in `ssrfr-v1.md` §6.5; extraction ticket `ROBO-mgumaoyf` closed with a pointer to `ssrfr`; no ticket tracks adopting `ssrfr` |
| `sitemapr` | vendored twin in `R/ssrf.R`, `httr2`; owns ADR-003, which it amended on 2026-07-25 to fail closed on malformed literals and to cover the three transition embeddings; `SITE-yeozymry` closed the same way |
| `mcptools` (Posit) | ships a guard it self-describes as "literal-only block, not a DNS-rebinding defense" — prospective consumer |

Neither existing consumer depends on `raddr` or `ssrfr`. Both call the guard
**once per redirect hop from their own loop**, and both are `R CMD check`-clean
offline. That forces the L0/L1/L2 layering and confirms the spec's §1.3: the guard
must support being called per hop by someone else's loop.

Both also ship a caller-side `ssrf_guard = FALSE` toggle, which is the precedent
for INV-14's explicit off switch.

Positioning: `firesafety` (Posit) is the inbound web-security half for `fiery`.
`ssrfr` is the outbound half. Non-competing, and the cleanest available anchor.

---

## 9. Reproduction

Each script records its environment and expected output; run it with
`Rscript` from the repository root.

| Script | Covers |
|---|---|
| [`2026-09-24-dependency-probes.R`](../evidence/2026-09-24-dependency-probes.R) | `rurl`, `raddr` and `curl_parse_url()` facts (§1, §2) |
| [`2026-09-24-transport-probes.R`](../evidence/2026-09-24-transport-probes.R) | settable options, `dns_servers`, `nslookup()`, protocol exposure on the first and redirect hops, what libcurl dials for `0177.0.0.1`, the pinning primitives (failover, port-key fail-open, empty-field form), the proxy-environment hijack, `resolve` versus connection reuse, the `debugfunction` trace (§2.5, §3–§6) |
| [`2026-09-24-tls-pin-probes.R`](../evidence/2026-09-24-tls-pin-probes.R) | TLS under a pin and INV-9's three methods (§7) |
| [`2026-09-24-hermetic-test-probes.R`](../evidence/2026-09-24-hermetic-test-probes.R) | the L1–L3 mechanics, `maxfilesize`, timeouts, the raw listener, mocking the resolver, `webfakes` and `::1` (§5, §7) |
| [`2026-09-24-curl-callback-options.R`](../evidence/2026-09-24-curl-callback-options.R) | callback options R's `curl` can and cannot set (§6) |
| [`2026-09-24-r-http-clients.R`](../evidence/2026-09-24-r-http-clients.R) | reach of `curl`-based clients on CRAN; which clients accept a pin |
| [`2026-09-24-handle-option-probes.R`](../evidence/2026-09-24-handle-option-probes.R) | what a new handle already carries (Accept-Encoding, cookie engine, netrc), what `handle_reset()` restores, decoding versus `accept_encoding`, the shared DNS cache under `resolve` and `connect_to`, the empty-`HOST` form, `ipresolve` against a literal pin, HTTP/3 and `share` (§4.1, §4.2, §5) |
| [`2026-09-24-rurl-bundle-probes.R`](../evidence/2026-09-24-rurl-bundle-probes.R) | which `rurl` calls default `url_standard`, which knobs change components, `clean_url` and `resolve_url()` output, schemeless and scheme-relative grading (§2.1) |
| [`2026-09-24-proxy-probes.R`](../evidence/2026-09-24-proxy-probes.R) | the proxy variables libcurl reads per scheme, their neutralization, and what an HTTP or SOCKS proxy receives under a `connect_to` pin (§7; `ssrfr-v1.md` INV-10) |
| [`2026-09-24-test-harness-probes.R`](../evidence/2026-09-24-test-harness-probes.R) | the IPv6 pin through `httpuv`, two-vhost SNI, the resolve-time rule and the tripwires, L0 without I/O, the no-connect listener, protocols under `protocols_str`, skip reporting and `rcmdcheck` under CRAN's variables (§4.4, §7) |
| [`2026-09-24-idna-fallback.R`](../evidence/2026-09-24-idna-fallback.R) | hosts whose domain-to-ASCII fails, through `rurl` and `curl_parse_url()` (`ssrfr-v1.md` §5.0) |
| [`2026-09-24-content-fetches.R`](../evidence/2026-09-24-content-fetches.R) | `xml2` external DTDs and entities, `read_xml(url)`, `rurl`'s long-input error, libcurl's URL length limit (`ssrfr-v1.md` §5.3, §9, S5) |
| [`2026-09-24-oracle-metadata-miss.R`](../evidence/2026-09-24-oracle-metadata-miss.R) | `192.0.0.192` against `ipaddress` and a hand-rolled matcher (`ssrfr-v1.md` §5) |

External sources for this file are in [`../references.md`](../references.md).
