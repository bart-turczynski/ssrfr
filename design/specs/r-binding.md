# `ssrfr` — R binding notes

- **Status:** DRAFT. Companion to `ssrf-guard-spec.md`; that document is
  language-agnostic, this one is R- and libcurl-specific.
- **Version:** `0.1.0-draft` (2026-07-25)
- **Environment for all [verified] claims:** R 4.6.0, `curl` 7.1.0,
  libcurl 8.14.1 (LibreSSL 3.3.6), macOS / Darwin 25.4.0. **Single platform —
  Linux and Windows confirmation is outstanding.**

This document says how each requirement in the specification is met in R, and
records the empirical findings that constrain the implementation.

---

## 1. Dependency position

```
ssrfr  ->  raddr   IP parse + classify, offline        (spec §6)
       ->  rurl    URL parse/normalize, whatwg mode    (spec INV-1)
       ->  curl    transport
```

The offline core is vendored base R initially — zero dependencies, no compile
step — so `raddr` upgrades the classification tables later rather than blocking
the start. The pitch is a small auditable trust boundary; adding seven transitive
dependencies plus a compile step for classification would undercut it.

**Release-order hazard.** If `ssrfr` depends on `rurl` it inherits `rurl`'s
CRAN-publication status as a blocker, and if published consumers then depend on
`ssrfr` the chain lengthens rather than shortens. This is why the extraction
tickets say keep the existing copies for now.

---

## 2. Parsing — INV-1, INV-2

```r
parsed <- rurl::safe_parse_url(url, url_standard = "whatwg")
```

`url_standard` is **fixed internally and MUST NOT be exposed**. `rurl` is built
on `curl_parse_url`, so `whatwg` mode agrees with what libcurl dials — 16/16
across the obfuscation corpus **[verified]**, including `010.0.0.1 → 8.0.0.1`.
The agreement is architectural, not luck, which is the whole basis of INV-1.

`rfc3986` mode returns the **un-normalized** host (`0177.0.0.1` stays literal),
and that string is what reproduces the silent bypass. It is correct for its own
purpose and unsafe for this one.

`parse_status != "ok"` is a **block** (INV-2). Under `rfc3986` the same inputs
return a warning plus a usable reg-name; that path MUST NOT be accepted.

**Never parse addresses with `ipaddress`.** **[verified]**
`ip_address("0177.0.0.1")` returns `177.0.0.1`, which classifies as global, so
the guard allows — and curl connects to `127.0.0.1`. Confirmed end to end:
`curl -v http://0177.0.0.1/` → `Trying 127.0.0.1:80`. Classification-only use is
acceptable; parsing is not.

**Dual-host requirement.** The numeric-literal check (`numeric-literal`) runs on
the **pre-normalization** host while range checks run on the normalized one. The
L0 entry point therefore takes both, and the inherited signature's vestigial
`is_ip_host` argument (accepted and explicitly ignored) is dropped.

---

## 3. Resolution — INV-4, INV-5

```r
addrs <- curl::nslookup(host, ipv4_only = FALSE, multiple = TRUE)
```

`multiple = TRUE` returns **all** A/AAAA records **[verified]** (`localhost` →
`::1`, `127.0.0.1`). Validating only the first is the classic bug.

Called through a **3-line internal, unexported wrapper** so tests can mock the
seam (§7). There MUST be **no public resolver argument** — an attacker-supplied
resolver would defeat the guard, and R's mocking facilities need no public seam.

**`dns_servers` is listed by `curl_options()` but FAILS at `setopt`**
**[verified]** — it requires a c-ares build. Do not design around it. This also
means the guard cannot pin its own resolver, so a compromised system resolver is
out of scope (spec §1.2).

---

## 4. Pinning — INV-5, INV-6

### 4.1 The primitive: `connect_to`, not `resolve`

Both preserve the hostname for TLS and `Host`. They fail differently.

| Property | `resolve` | `connect_to` |
|---|---|---|
| Multi-address failover in one entry | yes **[verified]** | no — first match wins **[verified]** |
| Survives connection reuse | **no** | yes |
| Port-key mismatch | fails open **[verified]** | fails open **[verified]** |
| Empty-field wildcard form | — | yes **[verified]** |

libcurl's connection-reuse check runs *before* DNS and is hostname-based; only
`CONNECT_TO` creates the peer record that check compares. **A `resolve` pin is
never consulted when a pooled connection matches** — a silent bypass on the second
request to a host. (Established by reading `lib/url.c`; reproduction outstanding.)

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

### 4.3 Failover

`connect_to` does not fail over, so failover is implemented in R by retrying with
the next address from the already-validated set. We own the redirect loop anyway,
so a per-address retry costs little. This matters: the reference Ruby
implementation pinned one *randomly sampled* address with no fallback and broke
~60% of dual-stack fetches from IPv4-only networks.

`dns_shuffle_addresses` stays off so ordering remains ours.

### 4.4 Outstanding

IPv6 pinning with a bracketed literal (`"HOST::[::1]:"`) is **unverified**, and
`webfakes` cannot bind `::1`, so this needs the integration layer (§7).

---

## 5. Handle configuration — spec §7

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

### Traps in this table

- **`noproxy = ""` means the opposite of `proxy = ""`.** Empty `noproxy` proxies
  *everything* and overrides a protective ambient `NO_PROXY`. Want `proxy = ""`
  **and** `noproxy = "*"`.
- **`unrestricted_auth = 0` covers libcurl's own auth only**, not
  caller-supplied `Authorization` headers or bodies. INV-8 must be implemented in
  our redirect loop.
- **`maxfilesize` is advisory**: a no-op without `Content-Length`, and measured on
  wire bytes so a compressed bomb passes. A real cap needs a write-callback byte
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
them as dangerous primitives (spec §13).

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
across libcurl versions and platforms is **unverified**. Any matching MUST fail
safe: absence of an expected line is not evidence of a correct connection. Prefer
confirming the address we pinned appears over extracting an arbitrary address
from prose.

**Not settable** (fail with "unknown or unsupported type") **[verified]**:
`prereqfunction`, `opensocketfunction`, `sockoptfunction`. The last of these is
what `safeurl-python` uses via pycurl to validate at socket open; reaching it from
R would mean C code in `ssrfr` linking libcurl — the coupling that killed
`advocate`. Escalation path, not a plan.

---

## 7. Testing architecture

Five layers. Demonstrated working in a throwaway package: 9/9 expectations pass.

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

### Rules

- **No public `resolver` argument, ever.** `local_mocked_bindings()` needs no
  public seam — strictly better than exposing a test-mode toggle as one Go
  implementation does. Add a test asserting the seam cannot be overridden from
  outside the namespace.
- Port the inherited IPv6 **spelling tables** for INV-3 verbatim; they already
  encode the two production bugs.

### Hard limits

- **No fake DNS server is possible in R** — no UDP in base R, and `dns_servers`
  fails without c-ares. INV-5's rebinding property is proven by the counting
  mock, not by a rebinding server.
- **`webfakes` cannot bind `::1`**, so IPv6 pinning is L0 strings plus L4 only.
- **`webmockr` / `vcr` / `httptest2` cannot intercept raw `curl`** — they cover
  `crul`/`httr`/`httr2` only. Not usable for this package's transport tests.

---

## 8. Consumers

| Package | Status |
|---|---|
| `robotstxtr` | vendored copy of the matcher; extraction ticket open; publishes the reason-code values in its reference docs |
| `sitemapr` | vendored twin; owns the policy ADR |
| `mcptools` (Posit) | ships a guard it self-describes as "literal-only block, not a DNS-rebinding defense" — prospective consumer |

Both existing consumers call the guard **once per redirect hop from their own
loop**, and both are `R CMD check`-clean offline. That forces the L0/L1/L2
layering and confirms spec §2.2: the guard must support being called per hop by
someone else's loop.

Both also ship a caller-side `ssrf_guard = FALSE` toggle, which is the precedent
for spec INV-14's explicit off switch.

Positioning: `firesafety` (Posit) is the inbound web-security half for `fiery`.
`ssrfr` is the outbound half. Non-competing, and the cleanest available anchor.

---

## 9. Reproduction

Probes for every **[verified]** claim above:

```r
# settable options
o <- curl::curl_options(); c("resolve","connect_to","dns_cache_timeout") %in% names(o)

# all A/AAAA records
curl::nslookup("localhost", ipv4_only = FALSE, multiple = TRUE)

# protocol list
curl::curl_version()$protocols

# what does curl ACTUALLY dial?
system("curl -s -v --connect-timeout 2 http://0177.0.0.1/ 2>&1 | grep Trying")

# callback options that fail
curl::handle_setopt(curl::new_handle(), prereqfunction = function(...) 0L)
```

Pin behaviour, the port-key fail-open, and the empty-field form are reproduced in
`_scratch/research/00b-local-empirical.md` §4–§6. The CRAN landscape scan is
`_scratch/research/scan-cran.R`.
