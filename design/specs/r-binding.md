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

The spec suspends its old INV-1 argument and proposes libcurl's own parse as the
pin host (`ssrfr-v1.md` §4.1–§4.2). The R mechanics for that proposal:

```r
v    <- rurl::get_parse_verdicts(url, url_standard = "whatwg")   # gate
p    <- rurl::safe_parse_url(url, url_standard = "whatwg",
                             host_encoding = "idna")              # A-label host
wire <- serialized_sanitized_url                                 # what libcurl gets
host <- curl::curl_parse_url(wire)$host                          # the pin key
```

`url_standard` is **fixed internally and MUST NOT be exposed**. Since `rurl`
3.0.0 it is required, not defaulted.

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
| Port-key mismatch | fails open **[verified]** | fails open **[verified]** |
| Empty-field wildcard form | — | yes **[verified]** |

libcurl's connection-reuse check runs *before* DNS and is hostname-based; only
`CONNECT_TO` creates the peer record that check compares. **A `resolve` pin is
never consulted when a pooled connection matches** — a silent bypass on the second
request to a host, even from a fresh handle, because R's `curl` shares one
connection pool across synchronous fetches. **[verified]** on the R build
(libcurl 8.14.1, LibreSSL), macOS only; `forbid_reuse` closes it. The
`lib/url.c` reading behind it was done at tag `curl-8_14_1`.

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

### 4.4 Outstanding

IPv6 pinning with a bracketed literal (`"HOST::[::1]:"`) is **unverified**, and
`webfakes` cannot bind `::1`, so this needs the integration layer (§7).

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
| `connecttimeout`, `timeout` | finite | libcurl's `timeout` default is **0 = never** |
| `maxfilesize` | set, not trusted | see below |
| `path_as_is` | considered | avoid transport-side path rewriting |
| `altsvc`, `hsts` | never set | INV-10 |
| `unix_socket_path`, `abstract_unix_socket` | never set | container control planes |
| `dns_shuffle_addresses` | `0L` | ordering stays ours |
| `accept_encoding` | set explicitly | the decoded-byte cap (spec §5.3) knows which encodings can arrive |

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
- **`maxfilesize` is advisory**: before libcurl 8.4.0 it is a no-op without
  `Content-Length`; from 8.4.0 it also aborts a transfer mid-stream
  (**[verified]** on 8.14.1 with a chunked response, §9). Either way it counts
  wire bytes, so a compressed bomb passes. A real cap needs a write-callback byte
  counter.
- **`redir_protocols_str` is less load-bearing than it looks**: libcurl already
  restricts redirect hops to `http https ftp ftps` **[verified]**, so
  redirect-to-`file://` is already blocked. The exposure is the **first** hop.

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

### Why `.invalid`

RFC 2606 guarantees `.invalid` never resolves. A passing L2 test therefore
**proves the pin was load-bearing** rather than incidentally correct — the
negative control is free. Confirmed by the inverse: pinning a `.invalid` host over
HTTPS fails with `no alternative certificate subject name matches`, which is also
an independent demonstration of INV-9 (verification stays bound to the hostname).

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
- **Proxy isolation (INV-10):** point every proxy variable at a dead loopback
  port, so a leak fails at once with a refused connection instead of racing a
  timeout; test anything read once at startup in a child R process
  (`callr`). Pattern from `linklint`'s `proxy-isolation-harness.ts`.
- **`Alt-Svc` (INV-10):** serve an `Alt-Svc` header and assert it causes no
  resolution, connection or request on the next hop.

### Hard limits

- **No fake DNS server is possible in R** — no UDP in base R, and `dns_servers`
  fails without c-ares. INV-5's rebinding property is proven by the counting
  mock, not by a rebinding server.
- **`webfakes` cannot bind `::1`**, so IPv6 pinning is L0 strings plus L4 only.
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
| [`2026-09-24-oracle-metadata-miss.R`](../evidence/2026-09-24-oracle-metadata-miss.R) | `192.0.0.192` against `ipaddress` and a hand-rolled matcher (`ssrfr-v1.md` §5) |

External sources for this file are in [`../references.md`](../references.md).
