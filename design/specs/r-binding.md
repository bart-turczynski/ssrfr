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

**Environments for [verified] claims.** macOS unless a claim carries a
platform tag. The transport findings of §4–§6 were re-run on Linux on
2026-09-25 and on Windows on 2026-09-29 (`ssrfr-v1.md` §8 item 6,
`SSRF-fjgfnaaq`).

| Date | Environment | Evidence |
|---|---|---|
| 2026-07-25 | R 4.6.0, `curl` 7.1.0, libcurl 8.14.1 (LibreSSL 3.3.6), macOS / Darwin 25.4.0 | re-run on 2026-09-24 by the transport scripts in §9; the July output is kept in them where it differs |
| 2026-09-24 | R 4.6.0, `curl` 8.0.0, libcurl 8.14.1 (LibreSSL 3.3.6, IDN off), `rurl` 3.0.1.9000, `raddr` 0.1.2.9000, macOS / Darwin 25.6.0 | [`../evidence/`](../evidence/), listed in §9 |
| 2026-09-25 | **The matrix**: the macOS build above, and in Docker (arm64) with `curl` 8.0.0 built against the distro libcurl: Ubuntu 22.04, R 4.4.1, libcurl 7.81.0 (OpenSSL 3.0.2, IDN on); Ubuntu 24.04, R 4.6.1, libcurl 8.5.0 (OpenSSL 3.0.13, IDN on); Rocky 9.3, R 4.6.1 from EPEL, libcurl 7.76.1 (OpenSSL 3.5.8) both as `libcurl-minimal` (the image default: `file ftp ftps http https`, IDN off) and as the full `libcurl` (IDN on). The rocker images run under `en_US.UTF-8`, the Rocky images under the C locale | [`2026-09-25-platform-transport-probes.R`](../evidence/2026-09-25-platform-transport-probes.R), run by [`2026-09-25-linux-transport-matrix.sh`](../evidence/2026-09-25-linux-transport-matrix.sh); output in [`2026-09-25-linux-transport-results.txt`](../evidence/2026-09-25-linux-transport-results.txt) |
| 2026-09-29 | **Windows**, through R-hub (`windows`, GitHub's `windows-latest`, image `win25-vs2026`, Windows Server build 26100): R-devel 4.7.0 (r90591, UCRT), `curl` 8.0.0 (the CRAN binary), libcurl 8.14.1 (multi-SSL, IDN on through WinIDN), `webfakes` 1.5.0, `httpuv` 1.6.17, under `English_United States.utf8`. Run twice: with the default TLS backend, Schannel, and with `CURL_SSL_BACKEND=openssl` (OpenSSL 3.5.0); `CURL_CA_BUNDLE` was set | the same probe scripts inside `R CMD check`, run by [`2026-09-29-windows-transport-wrapper.R`](../evidence/2026-09-29-windows-transport-wrapper.R); output in [`2026-09-29-windows-transport-results.txt`](../evidence/2026-09-29-windows-transport-results.txt) |

A claim tagged **(matrix)** reproduced on every build of the matrix, and
**(matrix, Windows)** on the Windows build too, under both TLS backends;
otherwise the tag names the builds. Probe numbers such as "probe 3e" are the
rows of the 2026-09-25 results.

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
  (`ssrfr-v1.md` §5.0). Under a DNS search list, `nslookup("svc.")` gets no
  answer where `nslookup("svc")` resolves through the list **[verified]**
  (Ubuntu 22.04, Ubuntu 24.04 and Rocky 9, glibc, Docker `--dns-search`;
  `2026-09-25-search-domain-probe.R`). When libcurl itself resolves
  `http://svc./`, 7.76.1 and 7.81.0 drop the dot and the search list applies;
  8.5.0 keeps it **[verified]** (same run). Under a pin libcurl resolves
  nothing (§4.2).
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
| Multi-address failover in one entry | yes **[verified]** (matrix, Windows, probe 5a) | no — first match wins **[verified]** (matrix, Windows, 5b) |
| Survives connection reuse | **no** **[verified]** (matrix, Windows, 7a–7c) | yes **[verified]** (matrix, Windows, 7d–7f) |
| Leaks into other handles' lookups | **yes** — the shared DNS cache **[verified]** (matrix, Windows, 7g) | no **[verified]** (matrix, Windows, 7h) |
| Port-key mismatch | fails open **[verified]** (matrix, Windows, 2b) | fails open **[verified]** (matrix, Windows, 2d, 2k) |
| Host-key mismatch | — | fails open **[verified]** (matrix, Windows, §4.2) |
| Empty-field wildcard form | — | yes **[verified]** (matrix, Windows, 2e–2j) |

libcurl's connection-reuse check runs *before* DNS and is hostname-based; only
`CONNECT_TO` sets the connect-to host and port that check compares. **A
`resolve` pin is never consulted when a pooled connection matches** — a silent
bypass on the second
request to a host, even from a fresh handle, because R's `curl` shares one
connection pool across synchronous fetches. **[verified]** (matrix, Windows,
probes 7a–7b), and `forbid_reuse` closes it (7c); a changed `connect_to` pin on the
same or a fresh handle opens a new connection to the new address (7d–7f). The
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
  per handle), fails with `Could not resolve host` **[verified]** (the
  `resolve` and `connect_to` halves: matrix, Windows, probes 7g–7h). This is a
  second reason for `connect_to`, independent of reuse: a `resolve` pin would
  also steer later requests made by other code in the process.

A failover retry (§4.3) changes the pin, so it takes a new handle too.

### 4.2 The fail-open, and the form that removes it

**[verified]** (matrix, Windows, probes 2a–2d, 2k) Both primitives discard the pin and
perform a real, unvalidated resolution when the key's port does not match the
request's port — silently:

```r
connect_to = "h.invalid:443:127.0.0.1:443"   # request on :80
#> Could not resolve host: h.invalid          # pin IGNORED

connect_to = "h.invalid:80:127.0.0.1:80"     # request on :80
#> Trying 127.0.0.1:80...                     # pin honoured
```

`connect_to`'s syntax is `HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT`, and an
empty field means "match anything / keep original" **[verified]** (matrix,
Windows, probes 2e–2j, the default `http` and `https` ports included):

```r
connect_to = "h.invalid::127.0.0.1:80"   # request :8080 -> Trying 127.0.0.1:80
connect_to = "h.invalid::127.0.0.1:"     # request :8080 -> Trying 127.0.0.1:8080
```

> **Use `"HOST::IP:"`.** There is no port key, so INV-6's mismatch cannot occur —
> the hazard is designed out rather than guarded against.

Always emit the trailing colon: `"HOST::IP:80"` silently rewrites the port too.

Never leave `HOST` empty: `"::IP:"` matches every host **[verified]** (matrix,
Windows, probe 2g), so the key would stop naming the host that was validated, and INV-6
requires it to be libcurl's parse of the requested URL.

The `HOST` field is matched, case-insensitively, against libcurl's own host
for the request. A host key spelled differently disengages the pin the same
way a port mismatch does: the name is resolved, or an IP-literal host is
dialed as written **[verified]** (matrix, Windows, probes 3b–3s):

| Request host | Key that fails open | Key that engages everywhere |
|---|---|---|
| `xn--bcher-kva.invalid` | the U-label `bücher.invalid` (3b) | the A-label, as `curl_parse_url()` returns it (3a, 3e2) |
| `dot.invalid.` / `dot.invalid` | the other spelling of the root dot (3h, 3i) | the same spelling (3g) |
| `[::1]` | `[0:0:0:0:0:0:0:1]` (3k) | `[::1]` (3j) |
| `[0:0:0:0:0:0:0:1]` | `[0:0:0:0:0:0:0:1]` on libcurl 7.81 and later; `[::1]` on Rocky 9's 7.76.1 (3l, 3m) | `curl_parse_url()`'s host (3n) |
| `[::ffff:127.0.0.1]` | `rurl`'s `[::ffff:7f00:1]` (3o) | `curl_parse_url()`'s host (3p) |
| `0177.0.0.1`, `2130706433` | the literal on 7.81 and later; `127.0.0.1` on 7.76.1, whose URL API keeps the literal (3q, 3r) | `curl_parse_url()`'s host (3s) |

Only the verbatim `curl_parse_url()` host engages on every build; a key
rebuilt from a normalized address string engages on some builds and fails open
on others. This is the case for taking the key from `curl_parse_url()`
(`ssrfr-v1.md` §4.2), with one exception, below.

**A U-label URL can defeat a `curl_parse_url()` key** **[verified]** (probes
3c–3e, and the locale pass of the results file). On Ubuntu 22.04 (7.81.0) and
24.04 (8.5.0), both built with IDN, and on Windows (8.14.1, IDN through
WinIDN, both TLS backends), under a UTF-8 locale, libcurl converts a
U-label host to its A-label before it matches `connect_to`, while
`curl_parse_url()` still returns the U-label: the key taken from it fails open
and libcurl resolves `xn--bcher-kva.invalid` itself. The same URL behaves
three other ways elsewhere: the key engages on the builds without IDN (macOS
8.14.1, Rocky 9 `libcurl-minimal`) and on Rocky 9's full 7.76.1 under
`C.UTF-8`; under the C locale, 8.5.0 and the full 7.76.1 refuse the URL (`URL
using bad/illegal format`). A URL whose host is already the A-label, which
`ssrfr-v1.md` §4.1 says the binding hands libcurl, engages on every build and
locale run (3a, 3e2). `ssrfr-v1.md` §4.1 refuses as `parse` a wire string, or
the host `curl_parse_url()` returns from it, that is not printable ASCII (§8
item 34).

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
**[verified]** (matrix, Windows, probes 4b and 4e; the port-keyed failure
form 4d resolves the name instead). libcurl 7.81.0 and 7.76.1 write the trace line
without brackets, `Trying ::1:PORT…` (§6). The test server is `httpuv`,
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
| `http_version` | `2L` (`CURL_HTTP_VERSION_1_1`) | spec §2.5, the request sent at most once — see below |
| `dns_cache_timeout` | `0L` | libcurl caches DNS 60 s by default |
| `proxy` | `""` | INV-10 |
| `noproxy` | `"*"` | INV-10 — see the warning below |
| `unrestricted_auth` | `0L` | partial INV-8 — see below |
| `netrc` | `0L` | INV-8, INV-10 — see below |
| `cookiefile` | `NULL` | stops the cookie engine the `curl` package starts — see below |
| `cookiejar` | never set | it writes received cookies to disk at cleanup |
| `connecttimeout`, `timeout` | finite | libcurl's `timeout` default is **0 = never** |
| `maxfilesize` | never set | see below |
| `path_as_is` | `1L` | libcurl removes no dot segments; `rurl`'s WHATWG serialization has already removed them, `%2e` forms included (`design/evidence/2026-09-25-dot-segments.R`), so this only makes the serialized path the one sent (`ssrfr-v1.md` §8 item 24). It does not make the whole request line equal the recorded URL |
| `altsvc`, `hsts` | never set | INV-10 |
| `unix_socket_path`, `abstract_unix_socket` | never set | container control planes |
| `doh_url`, `interface`, `localport`, `localportrange` | never set | see below |
| `dns_shuffle_addresses` | `0L` | ordering stays ours |
| `accept_encoding` | set explicitly, never `NULL` | fixes the request; the package default is build-dependent — see below |

Left at their defaults on purpose: `ipresolve` — a literal `connect_to`
target overrides it **[verified]**; `maxage_conn` — under `forbid_reuse` nothing idles in the pool;
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
| `httpauth = CURLAUTH_ANY` | overridden (`1L`, `CURLAUTH_BASIC`). Not inert under `allow_userinfo = TRUE`: URL userinfo is a credential, and a `401` challenge made libcurl send the request a second time within one transfer, against spec §2.5. A regression test pins it (`tests/testthat/test-fetch.R`, "an auth challenge never makes the request a second time"; `SSRF-rgcijatt`); no probe under `../evidence/` yet, so it carries no evidence tag. Basic sends the credentials on the first request, with no challenge round-trip |
| `pipewait = 1` | left — inert under `forbid_reuse` |
| Windows only: `ssl_options = CURLSSLOPT_NO_REVOKE` **[verified]** (Windows, Schannel: the default handle accepts a revoked certificate, as `ssl_options = 2L` does, and `0L` refuses it with `CRYPT_E_REVOKED`), plus `CURLSSLOPT_NATIVE_CA` under OpenSSL when `CURL_CA_BUNDLE` is unset **[sourced]** | left — revocation is outside INV-9 (spec §13). The flag affects Schannel only, and libcurl checks neither OCSP stapling nor a CRL unless asked **[sourced]**, so no platform checks revocation (Windows under OpenSSL accepted the revoked certificate with every `ssl_options` value **[verified]**). Overriding `ssl_options` would also drop `NATIVE_CA`. `NATIVE_CA` is unverified: the Windows run had `CURL_CA_BUNDLE` set |

`ssrfr` never relies on a package default for any row of the table above.

### Minimum libcurl

`protocols_str` and `redir_protocols_str` need libcurl 7.85. Below that, `ssrfr`
sets the older `protocols` and `redir_protocols` bitmasks to HTTP and HTTPS
instead. On libcurl 7.81.0 and 7.76.1 R's `curl` does not list the `_str`
options and `handle_setopt()` fails with `Unknown option: protocols_str`,
while the bitmasks (`3L`) refuse every other compiled-in scheme on the first
hop and on a followed redirect and leave `http` and `https` working; on 8.5.0
and 8.14.1 both forms do **[verified]** (matrix, Windows, probes 6b and 6d). The
supported floor is the `curl` package's own, libcurl 7.73; below it
the package builds against a bundled static libcurl. Ubuntu 22.04 ships 7.81 and
RHEL 9 ships 7.76.1 **[sourced]**, and on Linux R's `curl` links the system
libcurl. Below 7.77, libcurl's URL API does not normalize numeric IPv4 hosts
(**[verified]** on Rocky 9's 7.76.1: `curl_parse_url()` returns `0177.0.0.1`
and `2130706433` as written, and does not compress `[0:0:0:0:0:0:0:1]`, probe
3); the `rurl`-versus-libcurl disagreement refusal (spec §4.1) keeps that case
fail-closed, and a test must show it. That test needs `ssrfr` code and was not
run. The floor is conditional on the Linux matrix (spec §8 items 6 and 16): if
the protocol restriction or the pin fails on Ubuntu 22.04 or Rocky 9, the floor
becomes 7.85. What the matrix found is in spec §8 item 6.

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
  **[sourced]**. Nor can a pooled connection carry a transfer's first
  request, because `dep_curl_transfer()` runs each transfer in a pool of its
  own (`curl::new_pool()`), so its initial connection is always fresh and
  libcurl's retry of a request that a reused connection answered with
  nothing (`Curl_retry_request()`, `lib/transfer.c` at `curl-8_14_1`) never
  applies **[sourced]**; a regression test pins the fresh connection
  (`tests/testthat/test-fetch-limits.R`, "every fetch opens a fresh
  connection"; `SSRF-rgcijatt`), with no probe under `../evidence/` yet.
- **`http_version` is pinned to HTTP/1.1.** Over HTTP/2, a stream the server
  resets with `REFUSED_STREAM` makes libcurl close the connection and send
  the request again on a new one within the same transfer, up to five times
  (`lib/http2.c` sets `refused_stream`, which `Curl_retry_request()` in
  `lib/transfer.c` retries, at `curl-8_14_1`) **[sourced]**, against spec
  §2.5's at-most-once. One request per transfer gains nothing from HTTP/2,
  and libcurl 8.14.1 reuses a connection only for the same host name and
  port, so HTTP/2 would coalesce nothing anyway **[sourced]**. HTTP/3 is
  not in the evidence build (`http_version = 30L` fails at `setopt`
  **[verified]**). The pin also takes `h2` out of the TLS ALPN offer; a
  regression test pins that (`tests/testthat/test-fetch.R`, "HTTP/2 is never
  offered, even over TLS"; `SSRF-rgcijatt`), with no probe under
  `../evidence/` yet.
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
  (**[verified]** with a 250,000-byte chunked response and a 1,000-byte cap:
  delivered in full on 7.76.1 and 7.81.0, aborted on 8.5.0 and 8.14.1, macOS
  and Windows; a `Content-Length` over the cap aborts on all of them; matrix,
  Windows, probes 8a–8b).
  Either way it counts
  wire bytes, so a compressed bomb passes. A real cap needs a write-callback byte
  counter. It also refuses a `HEAD` whose `Content-Length` is over the cap, and a
  compressed body whose wire size is over the cap while its decoded size is
  within it (pinned by `tests/testthat/test-fetch-limits.R`, `SSRF-rgcijatt`; no probe
  under `../evidence/` yet), so
  `ssrfr` never sets it: its own decoded-byte counter is the limit (spec §5.3).
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
  restricts redirect hops to `http https ftp ftps` **[verified]** (matrix,
  Windows: `file`, `gopher` and `dict` refused, `ftp` followed, probe 6c), so
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

That list is the macOS build's. The Linux builds differ **[verified]** (probe
6): Ubuntu 22.04 compiles in 25 (adding `rtmp`, `scp`, `sftp`, without `ws` or
`wss`), Ubuntu 24.04 30 (the `rtmp` family, `scp`, `sftp`), Rocky 9's full
`libcurl` 24 (`scp` and `sftp` in place of `ws` and `wss`) and its default
`libcurl-minimal` five (`file ftp ftps http https`); Windows compiles in 26
(adding `scp` and `sftp`). On every one, each compiled-in scheme is
attempted on the first hop without a restriction (matrix, Windows, 6a).

`curl::curl_fetch_memory("file:///etc/passwd")` reads the file **[verified]**
(matrix, Windows, 6a, with a temporary file), as do `httr2`, `httr`, base
`readLines()`, and `download.file()`. `gopher://` is
present and libcurl percent-decodes the gopher selector, so `%0d%0a` becomes real
CRLF — the SSRF→Redis-RCE chain, live in R today.

Base `download.file()` and `url()` cannot be guarded by this package; document
them as dangerous primitives (spec §9).

---

## 6. The audit seam — INV-5 verification

`handle_data()` exposes **no peer IP** **[verified]** (matrix, Windows, probe 1c), and R's
`curl` exposes no `CURLINFO_PRIMARY_IP`. But **`debugfunction` accepts an R
closure and fires** **[verified]** (matrix, Windows, 1a–1b), unlike `prereqfunction`,
`opensocketfunction`, and `sockoptfunction`:

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

The trace is human-readable diagnostic output, not an API, and it is not
stable across libcurl versions **[verified]** (matrix, Windows, probes 1, 4
and 9).
Every build writes a `Trying ADDRESS:PORT...` line before the connect, but
7.76.1 and 7.81.0 write an IPv6 address without brackets (`Trying ::1:1...`,
where 8.x writes `Trying [::1]:1...`), 7.81.0 writes `Connected to (nil)
(127.0.0.1)` under a `connect_to` pin, and the failure, closing and
connection-reuse lines are worded differently on each (`Re-using existing
connection! (#70) with host` on 7.x, `Re-using existing connection with host`
on 8.5.0, `Re-using existing http: connection with host` on 8.14.1). The
same text can differ by platform: on Windows, 8.14.1 traces a dial to a
closed loopback port as `Connection timed out after 2002 milliseconds`
under a 2-second connect timeout, where macOS and Linux trace `Connection
refused` (probes 1 and 4; its `Trying` line is macOS's).
Matching MUST fail safe:
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
| Parser disagreement refuses as `parse` (a MUST-test): the four fullwidth separators in a host (`design/evidence/2026-09-25-fullwidth-separators.R`), with the refusal asserted whatever `rurl`'s verdict | §4.1 | L0 | named test, beside the corpus rows | runs |
| A wire string or parsed host that is not printable ASCII refuses as `parse` (a MUST-test): a U-label serialization refuses even when a mocked `curl_parse_url()` returns the A-label, before any resolver call; a mocked serialization `http://b%C3%BCcher.invalid/` refuses through the real `curl_parse_url()` (`design/evidence/2026-09-29-wire-ascii.R`) | §4.1, INV-6 | L0 | named test, beside the disagreement test | runs |
| A failing dependency refuses: `get_parse_verdicts`, `safe_parse_url`, `curl_parse_url` and each `raddr` call, through their internal wrappers, made to `stop()` or return `NULL` or a wrong shape | INV-11, §5.3 | L1 + L3 | mocked wrappers; honeypot listener sees no connection | runs |
| Minimized projection and redaction | INV-12, §2.3, §6.4 | L0 | one projected value for every code and cause; `print`, `format` and conditions searched for planted userinfo, header value, body and proxy value | runs |
| Trace matcher fails safe | INV-5, §6.6 | L0 | synthetic `debugfunction` traces (this file §6): none, garbled, another address → `pin-mismatch`; the pinned address → match, an IPv6 compared as a `raddr` value (INV-3) | runs |
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
| Every dimension revalidated per hop | INV-7 | L2 | `webfakes` redirect chain whose second redirect names a target refused on one dimension each: address, provider name, scheme, port, host rule, userinfo, numeric spelling, `downgrade` (`test-redirect.R`); the corpus's redirect rows decided through `from` (`test-corpus.R`) | if `webfakes` |
| Redirect budget refuses as `redirect-limit` | §2.5, §12 | L2 | self-redirecting app under `max_redirects` 0, 3 and 20, counting requests; a `304`, a `Location`-less `302` and a `300` once the budget is spent (`test-redirect.R`) | if `webfakes` |
| Past the budget, a `3xx` is decided at its status line: the header measure reads the final block's status as soon as the status line is in libcurl's header buffer, in the progress or write callback, and records the stop the way a limit is recorded, so the transfer is cancelled between rounds; a completed transfer is decided the same way, ahead of libcurl's own error, the header parse and the `Location` count. The status is transport-observed (§2.3): once the transfer has ended, stopped or completed, libcurl's status is known, and when it reports one (not 0) other than the status line's, step 13 decided nothing, and the transfer ends as any other whose two statuses disagree: `protocol-error` with no status recorded, unless a step 12 limit or a transport error came first. So a second `Location`, a body over `max_response_size`, a body that stalls, or one that never starts, is `redirect-limit`, not `protocol-error`, `response-too-large` or `timeout`. A header limit that the bytes up to the end of the status line passed, in interim `1xx` blocks or in the status line itself, was reached first and wins (the status line is not a field); the pin check (step 11) runs before, so `pin-mismatch` wins too. The refusal records the pinned address | §2.3, §6.6, §12 | L3; L0 for the decision on scripted header buffers | raw server per case under `max_redirects = 0`, asserting the wrapper reports the transfer stopped and not timed out; a mocked pin check; a mocked transfer, stopped in flight or completed, whose status disagrees with its header buffer (`test-redirect.R`) | runs |
| Failover in resolver order | §2.5, §6.6 | L1 + L3 | mock returns two addresses, the first with nothing listening on the port (`::1` against a listener bound to `127.0.0.1` only; macOS configures no `127.0.0.2`), the second the listener; assert the order of `Trying` lines and arrival at the second | runs |
| Exhausted failover cause | §6.6 | L1 | mocked attempt outcomes: every attempt `connect_timeout` → `timeout`; mixed → `connect-failed`; `pin-mismatch` stops at once | runs |
| Credentials absent after a cross-origin hop | INV-8 | L3 | raw request bytes after a cross-origin `307` (`test-redirect.R`); `ssrfr-v1.md` §2.3's status table on the wire, per status, origin and method, through a `webfakes` echo | runs; the table if `webfakes` |
| Verification bound to the hostname | INV-9 | L2 | `.invalid` over TLS | `skip_on_cran()` |
| SNI carries the hostname | INV-9 | L2 | two-vhost `s_server` | `skip_on_cran()`; needs `openssl` |
| Proxy variables and CONNECT | INV-10 | L2 + L3 | dead port; listener as proxy | runs |
| `Alt-Svc` has no effect | INV-10 | L2 | served header | if `webfakes` |
| Timeouts; byte cap on a chunked body | §5.3, §14 | L2 | `res$delay()`, `res$send_chunk()` | if `webfakes`; wide margins |
| Compression bomb: a `gzip` body under `max_response_size` on the wire and over it decoded → `response-too-large`, from `ssrfr`'s own counter, never `maxfilesize`; `total_timeout` re-checked after decoding | §5.3, §14 | L2 | served pre-compressed body | if `webfakes` |
| Accepted residual, decoding after a stop: a limit stop takes effect when the libcurl round it came in ends, because no callback may raise (row below), and within that round libcurl goes on reading and decoding what arrives; `ssrfr` drops it, never keeps or counts it, so the response and its limits hold, but the work is done. Against a 404,282-byte `gzip` bomb stopped at 100,000 decoded bytes, the bytes decoded and dropped after the stop were 178 MB on libcurl 8.14.1, macOS and Windows alike (10 reads of 16 KiB), about 400 MB on 8.5.0 (the whole body), and 16 MB on 7.81.0 and 7.76.1 (the rest of the read in hand) **[verified]** ([`2026-09-26-post-stop-reads.txt`](../evidence/2026-09-26-post-stop-reads.txt); Windows: [`2026-09-29-windows-transport-results.txt`](../evidence/2026-09-29-windows-transport-results.txt)). `buffersize` scales this on every build but bounds it on none. Declined: turning decoding off and refusing compressed responses, which costs every caller the bandwidth compression saves (maintainer, 2026-09-26). The fix is a write callback that can end the transfer without an R error, a short write, which `curl`'s R callback cannot return today (`SSRF-qqfvoxch`) | §5.3, §14 | — | none: a measured residual | — |
| An interrupt mid-transfer leaves the binding spent and no handle open | §2.5 | L2 | `res$send_chunk()` with a delay, and an interrupt raised during the transfer | if `webfakes` |
| `ssrfr` raises no interrupt and no R error of its own inside a `curl` callback, so a limit stop is always a failure, and a stop at a `3xx` past the redirect budget the `redirect-limit` refusal, and every interrupt is the user's and propagates, one pending as `ssrfr` stops a transfer at a limit included. `curl` evaluates each callback as a top-level call, so an R error raised there runs the user's `options(error = )` hook, and libcurl reports a transfer a progress callback aborted as an abort by callback, which `curl` raises as an interrupt. So no callback raises or aborts: a limit reached in the write or the progress callback is recorded, later deliveries are dropped unread, and the transfer is cancelled between libcurl rounds. An error in `ssrfr`'s own write or progress callback is caught and ends the fetch as `protocol-error`, check `callback-error`; one in the trace callback, whose errors `curl` would discard, leaves the pin unconfirmed, so `pin-mismatch`: check `trace-error` when the trace otherwise matches, or the trace's own check when it does not. Either way the failure names every callback that failed, in the order they first failed, and never infers which one cut the trace short. The check is the pin's finding; a callback named beside it is a further defect of `ssrfr`'s own, not an explanation of it, so an `other-address` naming `data` still dialed another address. Route on the cause and the check, never on the callback. Whether a progress callback that fails on its first call ends as `pin-mismatch`, check `absent`, or as `callback-error` is the build's, not the libcurl version's: libcurl 8.14.1 on macOS calls progress a round before it traces `Trying`, so the trace holds no `Trying` and the check is `absent`; 7.76.1, 7.81.0, 8.5.0 and 8.14.1 on Windows trace `Trying` in the round the transfer stops in, so the pin can match **[verified]** for those five builds (`design/evidence/2026-09-28-progress-trace-order.txt`, and the Windows run in `design/evidence/2026-09-29-windows-transport-results.txt`; on the build it runs on, the L3 test that fails progress on its first call asserts the check that follows from the trace). A transfer the wrapper reports stopped with neither a limit record nor a callback failure ends as `protocol-error`, check `aborted`. Callbacks run with interrupts suspended, because a top-level call swallows an interrupt R acts on inside it. Residual: R may act on one in the few evaluations before a callback's suspension takes hold or after it lifts; in the trace or write callback it is then lost, and the transfer goes on or ends as `protocol-error` | §2.5, §6.6 | L3 | the process sends itself `SIGINT`, interrupts suspended, from the progress call that reaches `max_header_bytes`; twenty header-limit stops in a row against a counting server; an `options(error = )` hook that must not run through a size, a `total_timeout` and two header-limit stops; `data`, `progress` and `debug` made to throw, `progress` on its first call | runs; the `SIGINT` test not on Windows |
| The request is sent at most once: a `417` to a body, a `401` challenge with URL credentials, a `3xx` with `Location`, `1xx` before a final response; `Expect` and `h2` are never offered | §2.5 | L3; L2 for the `401` and TLS | a raw server that answers every request on every connection it accepts and keeps them open, counting requests | runs; the `401` and TLS rows if `webfakes` |
| Each transfer's first request goes on a fresh connection | §14 | L3 | two fetches to a server that keeps connections open arrive on two | runs |
| A chunked body's trailer fields count against `max_header_bytes` and `max_header_fields` as they arrive. libcurl writes trailer lines to the header buffer but not to the trace's header lines, so `ssrfr` measures header and trailers alike from the header buffer, never from the trace, and the limits hold in flight even on a build that traces no line for a read of header or trailer bytes. No empty line ends the trailer lines, so one segmenter, shared by the measure and the parse, classifies each line by the block before it: a status line at the start or after an empty line opens a header block, ended or not, unless a complete final block precedes it, and every line after that block is a trailer line, and a field unless it is empty, one shaped like a status line included. A count taken in flight and one taken at the end therefore agree: a header cut short at `max_header_fields` ends with the transfer's own cause, and a status-shaped first trailer counts before any body byte is delivered | §5.3, §6.6 | L3; L0 for the segmenter and the status-shaped line | raw server sending many, wide and never-ending trailers, and a header cut short at the field limit; a never-ending header and never-ending trailers with every trace line but text withheld; a scripted progress call over a final block and a status-shaped trailer; the segmenter and the header measure run on raw buffers | runs |
| Ordinary HTTP still works through the guard: methods, headers, `gzip`, a redirect chain | §2 | L2 | `webfakes::httpbin_app()` via `ssrf_prepare_hop()` / `ssrf_fetch()`; the chain hop by hop through `from` (`test-redirect.R`) and through `ssrf_fetch_chain()` (`test-chain.R`) | if `webfakes` |
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
also exercises tier 3 of `ssrfr-v1.md` §5.0. A consumer's own tests use the same
recipe; v1 exports no test helper (`ssrfr-v1.md` §9). Tests of the transport
itself call the internal fetch below the policy. `linklint` hit the same problem and splits
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
    default and non-default ports, every row of §5's table: each set option has
    its value (`connect_to = "HOST::IP:"`, `proxy = ""`, `noproxy = "*"`,
    `followlocation = 0L`, `forbid_reuse = 1L` and the rest), no zero
    `ssl_verifypeer` or `ssl_verifyhost` appears, and none of the "never set"
    options does.
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
  - *Positive control.* Each tripwire runs once against a planted violation —
    a closure calling `curl::curl_fetch_memory()` for the walk, an option list
    missing `connect_to` for the builder test — and the test fails unless the
    tripwire fires. A walk that silently matches nothing still asserts
    something, so `ssrfr-v1.md` §7.2's no-assertion rule does not catch it.
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
  (from 5 to 30 on the matrix, §5), so protocol tests iterate over
  `curl::curl_version()$protocols` minus `http` and `https`. They assert a
  `scheme` refusal from the guard and `Unsupported protocol` from the transport
  under `protocols_str = "http,https"`, or the `protocols` bitmask below 7.85
  **[verified]** (matrix, Windows, probe 6b). Give each scheme a URL it
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
  v6pin.invalid:PORT` intact **[verified]** (matrix, Windows, probe 4e). The cost is `Rcpp`,
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
  The manifest is `tests/testthat/fixtures/corpus-manifest.tsv`, rewritten
  by `scripts/corpus-manifest.R`.

### Hard limits

- **No fake DNS server is possible in R** — no UDP in base R, and `dns_servers`
  fails without c-ares. INV-5's rebinding property is proven by the counting
  mock, not by a rebinding server.
- **`webfakes` cannot bind `::1`**; `httpuv` can, which brings the IPv6 pin to
  L2 (Harness notes). Whether CRAN's and CI machines have a usable `::1` is
  **[assumption]**; gate on `curl_version()$ipv6` and on the bind succeeding.
  Docker 29.8 containers had `::1` on loopback, on the default bridge network
  and under `--network none`, and `httpuv` bound it in each Linux image of the
  matrix and on R-hub's Windows runner (probe 4e).
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

Both also ship a caller-side `ssrf_guard = FALSE` toggle, which is
INV-14's explicit off switch: `ssrfr` itself has none (ADR 0007).

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
| [`2026-09-25-embedding-kinds.R`](../evidence/2026-09-25-embedding-kinds.R) | the embedding kind `raddr` reports per form, and WireServer inside NAT64 and ISATAP (`ssrfr-v1.md` §5, gate 2) |
| [`2026-09-25-dot-segments.R`](../evidence/2026-09-25-dot-segments.R) | dot segments, `%2e` forms included, through `rurl`'s WHATWG serializer (§5, `path_as_is`) |
| [`2026-09-25-fullwidth-separators.R`](../evidence/2026-09-25-fullwidth-separators.R) | fullwidth `＃ ／ ？ ：` in a host through `rurl`'s verdict, host and serializer, then `curl_parse_url()` (§7; `ssrfr-v1.md` §4.1) |
| [`2026-09-25-parse-vectors.R`](../evidence/2026-09-25-parse-vectors.R) | generates the measured columns of the parse-vector corpus (`ssrfr-v1.md` §7 component 2) and the corpus manifest; opens a connection only to loopback (§7) |
| [`2026-09-25-platform-transport-probes.R`](../evidence/2026-09-25-platform-transport-probes.R) | platform-neutral re-run of the transport findings, one `ok`/`DIFFERS` row per probe: the `debugfunction` seam, key forms and the port-key fail-open, host-key mismatches, the bracketed IPv6 pin, failover, protocol exposure under `protocols_str` and the bitmask, redirect-hop protocols, connection reuse and the DNS cache, `maxfilesize`, the trace text (§4–§6) |
| [`2026-09-25-search-domain-probe.R`](../evidence/2026-09-25-search-domain-probe.R) | a single-label name under a DNS search list, with and without the trailing root dot, through `nslookup()` and libcurl (`ssrfr-v1.md` §5.0) |
| [`2026-09-25-linux-transport-matrix.sh`](../evidence/2026-09-25-linux-transport-matrix.sh) | runs the two scripts above on the host and in Docker on Ubuntu 22.04, Ubuntu 24.04 and Rocky 9 (both libcurl builds); its output is [`2026-09-25-linux-transport-results.txt`](../evidence/2026-09-25-linux-transport-results.txt) |
| [`2026-09-26-post-stop-reads.R`](../evidence/2026-09-26-post-stop-reads.R) | how much libcurl reads and decodes after a write callback records a stop and returns, per `buffersize`, reproduced with `curl` alone; run on the host and in the Docker images above, output in [`2026-09-26-post-stop-reads.txt`](../evidence/2026-09-26-post-stop-reads.txt) (§7) |
| [`2026-09-29-windows-transport-wrapper.R`](../evidence/2026-09-29-windows-transport-wrapper.R) | a `testthat` file that runs the platform transport probes (twice: Schannel, then `CURL_SSL_BACKEND=openssl`), the progress/trace order probe, the post-stop reads probe and the revocation probe in `Rscript` subprocesses and prints their output, so an R-hub `R CMD check` on Windows carries it; output in [`2026-09-29-windows-transport-results.txt`](../evidence/2026-09-29-windows-transport-results.txt) (§4–§7) |
| [`2026-09-29-revocation-probe.R`](../evidence/2026-09-29-revocation-probe.R) | which `ssl_options` bits a new handle carries on Windows, read off by behaviour against a valid and a revoked Let's Encrypt test host; needs outbound HTTPS (§5) |

External sources for this file are in [`../references.md`](../references.md).
