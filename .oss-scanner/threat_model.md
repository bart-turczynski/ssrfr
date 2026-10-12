# Threat model

## What this project does and where untrusted input enters

`ssrfr` is a pure-R server-side request forgery (SSRF) guard for applications that fetch URLs an
attacker can influence: `plumber` endpoints, Shiny apps, webhook receivers, crawlers. It decides
whether a URL may be fetched under a policy, resolves the host once, classifies every address, and
fetches through libcurl (the `curl` package) with the connection pinned to a validated address.
URL parsing comes from `rurl` and from libcurl's own parser (`curl::curl_parse_url()`); address
classification comes from `raddr`. The normative contract is `design/specs/ssrfr-v1.md`: the threat
model is §11, the request lifecycle §12, the invariants INV-1 to INV-14 §13, transport hardening
§14. Guarding is the package's whole purpose, so a bypass of the guard is the headline risk.

Untrusted input:
- The `url` argument of `ssrf_prepare_hop()`, `ssrf_fetch_chain()` and `ssrf_inspect_url()`:
  any byte string, including forms that one parser accepts and another rejects. On a redirect hop,
  `ssrf_prepare_hop(url, policy, from = binding)` takes the `Location` value as `url` and resolves
  a relative one against the previous hop `from`; `ssrf_fetch_chain(url, policy, request)` does
  the same for each hop it follows. Only `ssrf_inspect_url()` takes a `base` argument.
- DNS answers for attacker-owned names: several A/AAAA records, mixed public and private
  records, low TTLs, and a different answer on a second lookup (rebinding).
- Everything a fetched server sends: status line, interim `1xx` blocks, header fields, `Location`
  (relative or absolute), chunked trailers, content encodings, the body, timing, and stalls.
- Redirect chains of any length that end anywhere.

Trusted: the calling R code and the policy it builds with `ssrf_policy()` (allow and deny lists,
ports, schemes, limits); the request plan it passes (`request = list(method, headers, body,
carry)`), though header values must still never leak across origins or into printed output; the
host's system resolver and hosts file; the package's bundled policy data in `R/policy-data.R` and
`raddr`'s IANA registry snapshot. Ambient process configuration (proxy environment variables,
`~/.netrc`, `~/.curlrc`, cookie files, an `Alt-Svc` cache) is not trusted to stay neutral: the
guard must neutralize it (INV-10), so one that takes effect is in scope.

## Components that matter most / least

Most important, the guarded hop (L2), the only layer that is a defense:
- `R/binding.R`: `ssrf_prepare_hop()`, which returns a refusal or an opaque binding.
- `R/parse.R`: the parse boundary, the `rurl`/libcurl host comparison (INV-1, INV-2), the
  printable-ASCII rule for the string handed to libcurl, numeric-literal refusal.
- `R/address.R`: gates 1 to 3, embedded addresses (NAT64, IPv4-mapped, 6to4, Teredo, ISATAP),
  reason-code mapping. `R/hostname.R`: hostname rules and normalization (gates 4 and 5).
- `R/resolve.R`: exactly one resolution per hop, wholesale refusal of the answer set (INV-4, INV-5).
- `R/transport.R`: the libcurl option builder, the `connect_to` pin key, the trace matcher behind
  the peer check (INV-5, INV-6, INV-9, INV-10, §14).
- `R/fetch.R`: `ssrf_fetch()`, failover, size, header and time limits, decoding.
- `R/redirect.R` and `R/chain.R`: `Location` handling, per-hop revalidation (INV-7), credential
  stripping across origins (INV-8), `downgrade`, the redirect budget; `ssrf_fetch_chain()`.
- `R/request.R`: request-plan validation (header syntax, CR/LF/NUL, carryable fields).
- `R/outcome.R`: redaction in `print`/`format` and conditions, `ssrf_public_reason()` (INV-12).
- `R/policy.R`, `R/policy-data.R`, `R/dependencies.R`: policy validation at construction, the
  provider-endpoint and metadata-hostname tables, and the wrappers that turn a dependency error
  into a refusal (INV-11).

Less important: `R/inspect.R` (`ssrf_inspect_url()`, L0/L1 reporting, explicitly not a defense),
`R/vocabulary.R`, `R/conditions.R`, `R/utils.R`.

There is no `src/`: the package ships no native code and no vendored parser or classifier.
Out of scope: `rurl`, `raddr`, `curl` and libcurl themselves, unless `ssrfr` uses them unsafely
(for example a parser disagreement that `ssrfr` should have refused, or a libcurl option it sets
that leaves the pin). Also out of scope: `design/evidence/` probe scripts, `scripts/`, the test
harness, vignettes.

## How to exercise it

The image: source at `/src`, the package installed, every Import and Suggest installed, the
`openssl` command-line tool, `gdb` and `valgrind`, no network. Loopback works.

- Full suite: `Rscript -e 'testthat::test_local("/src")'`. One area:
  `Rscript -e 'testthat::test_local("/src", filter = "redirect")'`. The OSV and OSS Index
  advisory tests (`test-osv.R`, `test-security.R`) skip offline.
- Entry points from `Rscript -e`:
  `library(ssrfr); ssrf_inspect_url("http://0177.0.0.1/")$code`,
  `ssrf_prepare_hop("http://[::ffff:169.254.169.254]/", ssrf_policy(), request = list())`,
  `ssrf_vocabulary()` for the closed sets of reason codes, causes and condition classes.
- A crash of the R process inside libcurl: get a backtrace with
  `R -d gdb --debugger-args='-batch -ex run -ex bt' -e 'library(ssrfr); ssrf_vocabulary()'`, or
  run the same expression under `R -d valgrind -e '…'`.
- With no network, real names resolve to nothing (`unresolvable`). To drive the resolved path,
  mock the internal resolver seam as the tests do (`mock_answers()` in
  `tests/testthat/helper-transport.R`), for example
  `testthat::with_mocked_bindings(ssrf_prepare_hop("http://x.example.invalid/", ssrf_policy(),
  request = list()), dep_nslookup = function(query) c("93.184.216.34", "10.0.0.1"),
  .package = "ssrfr")`.
- Loopback servers: `tests/testthat/helper-transport.R` has `local_test_server()` (webfakes,
  optional TLS), `local_raw_server()` for malformed responses, `loopback_policy()`, `pinned_url()`
  (`.invalid` hostnames, so a fetch that arrives proves the pin was used).
  `pkgload::load_all("/src")` already sources these helpers.
- Corpora worth reusing: `tests/testthat/fixtures/verdict-vectors.tsv` (bypass classes, each with a
  URL, mocked answers, policy, hop and expected code), `parse-vectors.tsv` (inputs where `rurl` and
  libcurl may read different hosts, with the measured hosts), `requirements.tsv`; their format is
  in `fixtures/README.md`. TLS fixtures (a test CA and `.invalid` certificates) are in
  `tests/testthat/certs/`.

## How you rate severity

Where this file and `design/specs/ssrfr-v1.md` disagree, the spec wins: it is the only normative
document (ADR 0003, `AGENTS.md`).

There is no native code here, so the memory-corruption rows of a C library do not apply; a crash
of the R process reached through `ssrfr`'s use of libcurl is still in scope. Severity is about where
a connection goes and what it carries.

- **Critical**: under the default `ssrf_policy()`, or under a policy whose allow fields do not cover
  the target, a URL, DNS answer set or redirect chain makes `ssrf_fetch()` or `ssrf_fetch_chain()`
  open a connection to a loopback address or a cloud-metadata endpoint (gate 2's table, such as
  `169.254.169.254`, `fd00:ec2::254`, `168.63.129.16`, or gate 5's names, such as
  `metadata.google.internal`), whatever the encoding: an embedded or alternative spelling, a
  rebinding answer, a pin that fails open so libcurl resolves the name itself, a host libcurl reads
  differently from the host `ssrfr` checked, a redirect hop that skips revalidation, or an ambient
  proxy that moves the connection off the pinned path. A non-HTTP scheme (`file`, `gopher`, `dict`,
  a Unix socket) reached through the transport is Critical too.
- **High**: the same bypass to private (RFC 1918, ULA), link-local, shared (RFC 6598), reserved or
  multicast space, or past a caller's `deny_ranges` or `deny_hosts`, a disallowed port or scheme,
  embedded userinfo with `allow_userinfo = FALSE`, or an `https` to `http` redirect; an
  `allow_ranges` or `allow_hosts` entry that opens more than it names; a second resolution in one
  hop; a peer check that passes on absent evidence; `Authorization`, `Cookie`,
  `Proxy-Authorization`, a header the plan did not nominate in `carry`, or the body sent across an
  origin boundary; credentials taken from netrc or a cookie store; certificate or hostname
  verification weakened, or bound to the IP instead of the hostname; an inspection or binding
  result that names one host while libcurl dials another.
- **Medium**: denial of service from a small untrusted input or a hostile server: a response body,
  header bytes or header fields past their limit (including a decompression bomb), `total_timeout`
  not bounding a hop or chain (a stall, slow decoding), unbounded CPU or memory on a URL within
  `max_url_length`, a segfault of the R process. Also the oracle: userinfo, request header values,
  bodies or proxy values in `print`, `format` or a condition message, or `ssrf_public_reason()`
  returning anything that distinguishes one refusal or failure from another.
- **Low**: wrong results with no security consequence: the wrong reason code or cause on a request
  that is still refused, a false refusal of a public destination, an `ssrf_inspect_url()` answer that
  differs from the guarded fetch, an R error raised on untrusted input where a refusal is due (no
  connection is made), standards nonconformance in redirect method handling that leaks nothing.
  Problems that need the caller to misuse the API or pass trusted-but-hostile policy options.

## Anything to leave alone

- No off switch: `ssrfr` has none. Consumers such as `robotstxtr` and `sitemapr` expose
  `ssrf_guard = FALSE` as their own documented opt-out; do not report it, or requests made with it.
- Test policies: `loopback_policy()` in `tests/testthat/helper-transport.R` and the vignette's
  recipe (`ssrf_policy(allow_ranges = "127.0.0.0/8", allow_ports = 8080)`) reopen loopback on
  purpose. A connection to loopback under such a policy is intended. The tests reach the resolver
  through `testthat::local_mocked_bindings()` on the internal `dep_nslookup()`; there is no public
  resolver argument, and mocking an internal is not a bypass.
- Documented opt-ins: anything an `allow_ranges`, `allow_hosts`, `allow_userinfo = TRUE`, an added
  scheme or port, or a raised limit admits. Limits have no ceiling by design. `allow_ports` applies
  to every allowed scheme (`http://h:443/` passes), deliberately.
- Documented residuals, each at its section of `ssrfr-v1.md`: the host's own public addresses
  unless listed in `deny_ranges` (§9); operator NAT64 prefixes and ISATAP-wrapped provider
  endpoints (§5); CNAME targets not checked by hostname rules (§5.0); a compromised resolver
  (§9, §11.2); the DNS query itself reaching an attacker's zone (§9); timing differences between
  refusal stages (§6.4); no certificate revocation checking (§13, INV-9); no cycle detection
  beyond `max_redirects` (§5.3); no homograph detection (§9); `Refresh` and
  `<meta http-equiv="refresh">` not followed (§9); anything below the socket, such as NAT,
  transparent proxies or public relays (§9); no proxy support (§13, INV-10); no method allowlist
  and no concurrency limit (§9).
- Unguarded paths: `download.file()`, `url()`, direct `curl` or `httr2` calls and the packages that
  read URLs through them are outside the guard and documented as such.
- Misuse raises a classed R condition (`ssrfr_error_invalid_policy`, `_invalid_request`,
  `_invalid_from`, `_spent_binding`, `_budget_change`, `_invalid_argument`): intended. A malformed
  policy entry is an error by design.
- Outdated dependencies without a reachable path through `ssrfr`; the Windows- and CRAN-only skips.

Patches: minimal R fixes in the package's style (base R, Air formatting, 80 columns, no new
dependency, no vendored parser or classifier: parsing stays with `rurl` and libcurl,
classification with `raddr`), checked against the invariants in `ssrfr-v1.md` §13. Reason codes,
causes and condition classes are public API: do not rename them. Add a `testthat` regression test
next to the existing tests for that area (`tests/testthat/test-<area>.R`); for a bypass, also add a
row to `fixtures/verdict-vectors.tsv` with the next free id, then run
`Rscript scripts/corpus-manifest.R`. Add a `NEWS.md` entry under the development version, citing
the standard and clause when the fix is a conformance fix.
