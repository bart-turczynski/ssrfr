# ADR-001: `ssrfr` network safety policy

- Status: Accepted
- Date: 2026-07-25
- Deciders: Bart Turczyński
- Supersedes: `sitemapr` `docs/decisions/ADR-003-network-safety-policy.md` §1, §4
  — **for `ssrfr`'s scope only.** ADR-003 remains in force for `sitemapr` itself
  (see §0 below).
- Related: `docs/spec/ssrf-guard-spec.md` (the normative contract);
  `docs/spec/r-binding.md` (R/libcurl transport specifics)
- Open decisions referenced here: `SSRF-tnxmqvou`, `SSRF-pffrmkdr`

---

## Context

`ssrfr` extracts the structural SSRF matcher that ships, near-verbatim, in
`robotstxtr/R/ssrf.R` and `sitemapr/R/ssrf.R`, and grows it into a full guard
that owns resolution, pinning, and the fetch. Both sibling matchers were written
against `sitemapr` ADR-003, so ADR-003 is `ssrfr`'s inherited policy by default.

That inheritance needs an explicit decision rather than a silent carry-over,
because **`ssrfr` has a different audience and therefore a different threat
model**. ADR-003 governs a sitemap parser whose caller supplies their own
sitemaps. `ssrfr` targets applications that fetch *attacker-supplied* URLs —
`plumber` endpoints, Shiny apps, webhook receivers. Several of ADR-003's
decisions are correct for the first audience and wrong for the second.

This ADR records which parts carry over, which are reversed, and which inherited
gaps are closed.

---

## 0. Relationship to `sitemapr` ADR-003

| ADR-003 decision | Disposition here |
|---|---|
| §1 structural-only guard; DNS deferred to post-v1 | **Reversed** (§1) |
| §1 blocked-range matrix | **Superseded** by a positive predicate (§2) |
| §1 malformed IPv6 literals fail open | **Reversed** — fail closed (§3) |
| §1 every IPv6 rule matches the expanded address, never the literal | **Carried over**, promoted to INV-3 |
| §1 embedded-IPv4 forms decoded and re-classified | **Carried over and extended** (§2.3) |
| §1 numeric/octal/hex literal rejection on the raw host | **Carried over** (§2.4) |
| §1 opt-out flag, never the default | **Carried over**, with constraints (§5) |
| §2 redirect revalidation on every hop | **Carried over and strengthened** (§4) |
| §3 limits; "no non-overridable hard caps" | **Open** — `SSRF-pffrmkdr` (§6) |
| §4 URL-stack ownership table | **Replaced** by a four-package table (§7) |
| §5 default User-Agent | **Open** (§8) |

ADR-003 is not amended by this document. It stays correct for `sitemapr`, whose
callers fetch their own sitemaps; the divergence below is a scope difference, not
a defect finding against it. Two items are exceptions and *should* be fixed in
`sitemapr` regardless — see §9.

---

## Decisions

### 1. DNS resolution is in scope. The guard resolves, validates, and pins.

`ssrfr` performs resolution itself, classifies **every** returned A/AAAA record,
and connects only to an address from that validated set. Structural matching is
retained as a distinct, explicitly non-security layer (L0 in
`ssrf-guard-spec.md` §2), not as the defense.

This reverses ADR-003 §1. Taking its four deferral reasons in turn:

- *"DNS resolution adds latency, network dependency, and failure modes
  incompatible with a library designed to work offline and pass `R CMD check`
  without network access."* — **Still true, and answered by layering rather than
  by omission.** L0 is pure and testable with literal fixtures; L1/L2 are
  exercised against a local mock resolver and a loopback HTTP server. No CRAN
  check needs the network.
- *"DNS rebinding is primarily a browser/server concern. A library does not run
  a long-lived server; each call is discrete, narrowing the rebinding window to
  near zero."* — **False for this package.** `ssrfr`'s stated audience *is*
  long-lived servers taking attacker-controlled input. The premise that made
  this sound in `sitemapr` is exactly the premise that fails here. Rebinding is
  in `ssrfr`'s threat model as a first-class attack (`ssrf-guard-spec.md` §1.3,
  capability 2).
- *"CRAN test isolation requires offline tests."* — True, and it argues for the
  L0/L1/L2 split, not for omitting DNS. See the first bullet.
- *"The remaining gap … is a threat model that applies more to multi-tenant API
  services than to a single-caller R library."* — This is the same premise as
  the second bullet and fails for the same reason. It is precisely `ssrfr`'s
  threat model.

**ADR-003's own revisit condition is already satisfied.** It requires *"a
reliable, CRAN-safe DNS resolution primitive … that does not depend on `system2`
or `nslookup`."* `curl::nslookup()` is a C-level libcurl call, not a shell-out to
the `nslookup` binary, and returns all A/AAAA records. The condition is met; this
ADR acts on it.

**Resolution is not sufficient on its own.** Resolve-then-fetch-by-hostname is
the documented anti-pattern in `CVE-2026-41488` ("validate-then-fetch with
separate DNS resolution"). The connection MUST target a validated address
(INV-5), via a pin whose engagement cannot silently fail (INV-6).

### 2. Classification gates on a positive routability predicate

An address is refused unless it is affirmatively globally reachable, and is
refused outright if it is multicast, matches a configured deny rule, or embeds an
address that is itself refused. The prohibited set is derived from the IANA
special-purpose address registries, not from a hand-maintained enumeration
(`ssrf-guard-spec.md` §6, INV-13).

ADR-003 §1 specifies a denylist. The inherited matcher implements it faithfully,
and its gaps are exactly the gaps a denylist predicts.

#### 2.1 The IPv6 unique-local gap (the motivating defect)

The inherited matcher blocks IPv4 RFC-1918 space in full, and blocks **one
/32 inside** the IPv6 equivalent:

```r
if (h[1L] == 0xfd00 && h[2L] == 0x0ec2) return("cloud-metadata")
```

`fd00:ec2::/32` is AWS's IPv6 metadata range. It sits inside `fc00::/7`, the
IPv6 unique-local space (RFC 4193) — the direct analogue of RFC 1918. **The rest
of `fc00::/7` is unblocked.** `fd00::1` and `fc00::1` reach the default allow
while `10.0.0.1` is refused, for no reason other than that nobody enumerated
them. `fec0::/10` (deprecated site-local, RFC 3879, still routed on legacy
networks) is likewise absent.

IANA marks `fc00::/7` as *not* globally reachable. A positive predicate closes
this gap without anyone having to notice it first. That is the whole argument for
§2.

The reason code for this space is `private`, not `cloud-metadata`. The inherited
labelling is one of the two misnomers corrected in `ssrf-guard-spec.md` §5.2 (the
other being CGNAT `100.64.0.0/10` reported as `cloud-metadata`).

#### 2.2 Other classes the inherited denylist omits

Not exhaustive — that is the point — but these are the ones already identified
and each MUST have a conformance vector:

| Class | Missing | Reason code |
|---|---|---|
| IPv6 unique-local | `fc00::/7` less the one /32 above | `private` |
| IPv6 site-local (deprecated) | `fec0::/10` | `private` |
| IPv6 multicast | `ff00::/8` | `multicast` |
| IPv4 multicast | `224.0.0.0/4` | `multicast` |
| IPv4 reserved / future use | `240.0.0.0/4`, `255.255.255.255/32` | `private` |
| IPv4 IETF protocol assignments | `192.0.0.0/24` | `private` |
| IPv4 benchmarking | `198.18.0.0/15` | `private` |
| IPv6 transition embeddings | 6to4, Teredo, ISATAP | see §2.3 |

#### 2.3 Transition embeddings are missing decoders, not missing ranges

The inherited matcher decodes five IPv6→IPv4 embedding forms (IPv4-mapped,
IPv4-translated, IPv4-compatible, and both NAT64 prefixes) and re-classifies the
embedded value. **Three further RFC-defined mechanisms are not among them.**

All five implemented decoders read the IPv4 address from the low 32 bits
(`tail32 <- h[7] * 65536 + h[8]`), except the NAT64 local-use case. The three
missing mechanisms put it somewhere else:

| Mechanism | Prefix | Where the IPv4 lives |
|---|---|---|
| 6to4 (RFC 3056) | `2002::/16` | bits 16–47 — hextets 2–3, not the low 32 |
| Teredo (RFC 4380) | `2001::/32` | low 32 bits, **XOR-obfuscated** with `0xffffffff` |
| ISATAP (RFC 5214) | any | interface ID, after a `0000:5efe` / `0200:5efe` marker |

**[verified]** against the shipped matcher — every row below reaches the default
allow today:

```
2002:7f00:1::             6to4   -> 127.0.0.1              allowed
2002:a9fe:a9fe::          6to4   -> 169.254.169.254        allowed
2001:0:0:0:0:0:f5ff:fffe  Teredo -> 10.0.0.1               allowed
2001:0:0:0:0:0:5601:5601  Teredo -> 169.254.169.254        allowed
2001:db8::5efe:a00:1      ISATAP -> 10.0.0.1               allowed
```

ISATAP under a link-local prefix (`fe80::5efe:a00:1`) *is* blocked — but
incidentally, by the outer `fe80::/10` rule rather than by decoding the embedded
value. Under a global site prefix nothing catches it. A rule that happens to
cover a case for an unrelated reason is not coverage.

Adding `2002::/16` and `2001::/32` to a range list does **not** fix this: those
prefixes are legitimately globally reachable, and what matters is the value they
*wrap*. Teredo's XOR obfuscation makes the point sharper still — no range rule
over the literal bits can ever see `10.0.0.1` in `2001:0:0:0:0:0:f5ff:fffe`.

This is the same defect class as `pydantic-ai`'s three CVEs on one blocklist,
each a different IPv6-transition wrapper of the same metadata address. INV-13's
embedded-address corollary is therefore load-bearing: **every form that embeds an
address MUST have the embedded value extracted and classified independently**,
and the list of such forms is a **decoder inventory, not a range table**.

Exploitability against the siblings is deployment-dependent — reaching such an
address requires the host to actually route that transition mechanism, and RFC
7526 deprecated 6to4 anycast. Where it is not routed the connection merely fails,
which is fail-closed by accident rather than by design, and is not a property
`ssrfr` may rely on. Tracked in the siblings as `ROBO-laydgesq` /
`SITE-uxxdadsa`.

#### 2.4 Hostname rules remain a first-class control

Address classification, however good, cannot see metadata services that have no
link-local address and are reached over public DNS and HTTPS (Equinix Metal, IBM
VPC). The inherited `metadata.google.internal` check is not a legacy convenience
to be replaced by better range matching — it is a permanent, separate control.

The raw-host numeric/hex/octal literal rejection (`ssrf_numeric_literal_blocked`)
carries over unchanged in behaviour. It requires the **pre-normalization** host
string, so the dual-host input (`host` + `raw_host`) survives into `ssrfr`'s L0
signature. The vestigial `is_ip_host` parameter — accepted and explicitly ignored
— does not.

### 3. Malformed address literals fail closed

**This closes `ROBO-udnyuuwn` / `SITE-zgufvkks`.** ADR-003 §1 records the
fail-open as deliberately unsettled and notes that failing closed "would add a
reason code to the stable list … and so requires an amendment to this ADR." This
is that decision, taken once, inside `ssrfr`.

A host literal that the address decoder cannot interpret — `fe80:::1`, `::12345`,
`::ffff:999.1.1.1`, an IPv6 literal that does not expand to exactly 8 hextets —
MUST be refused with reason `malformed-address`. Likewise a failed resolution
(`unresolvable`) and an ambiguous parse (`parse`). There is no path from "we
could not determine this" to "proceed" (INV-11).

The inherited posture is safe only because `rurl` rejects such literals before
the guard sees them — i.e. the property is enforced by a layer other than the one
documenting it. `ssrfr` is a security library whose guarantee must not be
contingent on a caller having pre-filtered its input, and `ssrfr` must work for
callers who are not `rurl` consumers at all.

Consequence: reason codes `malformed-address`, `unresolvable`, and `parse` join
the stable vocabulary (`ssrf-guard-spec.md` §5.2).

### 4. Every dimension is revalidated on every hop, and `downgrade` is a refusal cause

ADR-003 §2 revalidates the SSRF guard per redirect hop. `ssrfr` strengthens this
in three ways (INV-7, INV-8):

1. **Every dimension, not just the address.** Scheme, userinfo, port, host rules,
   and address are all re-checked per hop. Revalidating the address alone leaves
   scheme, host rules, and credentials bypassable via redirect — a real defect in
   a mature Go implementation.
2. **A new refusal cause: `downgrade`.** An `https`→`http` redirect is refused by
   default. This cause is recognized at `sitemapr`'s findings layer (ADR-010 §3,
   as `PAGE_SSRF_BLOCKED`) but has no code in the inherited vocabulary. It gets
   one here.
3. **Credentials MUST NOT cross an origin boundary.** `Authorization`, `Cookie`,
   and caller-supplied credential-bearing headers and bodies are dropped on a
   cross-origin redirect. libcurl's own `unrestricted_auth = 0` covers only
   credentials libcurl itself manages, not caller-set headers, so this is
   `ssrfr`'s responsibility and not the transport's.

Transport-level automatic redirect following is disabled; `ssrfr` owns the loop.
Because both existing consumers run their own redirect loops, the guard MUST also
be invocable **per hop by someone else's loop** (`ssrf-guard-spec.md` §2.2).

The refusal taxonomy is two-level, following ADR-010's `PAGE_SSRF_BLOCKED` vs
`PAGE_FETCH_FAILED` split: **refused by policy** and **failed on the wire** are
distinct outcomes above the individual reason codes, and callers MUST be able to
branch on them without string matching.

### 5. Precedence is conjunctive — deny wins — with one explicit off switch

When an allow rule and a deny rule both match, the request is refused (INV-14).
The alternative — allow overrides deny, so that configuring any allowlist
silently flips the whole policy to default-deny — makes the effective policy
unpredictable from the configuration.

This applies uniformly to host rules and range rules: `deny_hosts` beats
`allow_hosts`, `deny_ranges` beats `allow_ranges`, and both beat the built-in
defaults only in the deny direction.

**Ports are an allowlist** (default 80, 443), never a denylist. Browser
"bad port" denylists omit both Redis and Memcached.

**One explicit off switch.** Because deny wins, a caller with legitimate internal
targets cannot escape the defaults by emptying a list — and if no off switch
exists they will discover a worse workaround. `ssrfr` therefore provides exactly
one, and it is constrained:

- A single top-level argument, not a flag buried inside a policy object.
- Named so its effect is unmistakable, with no negation ambiguity.
- Never the default; documented as disabling the guard entirely.

The exact identifier depends on the API shape and is settled with
`SSRF-tnxmqvou`. Note that ADR-003's `ssrf_guard = FALSE` stays with the
consumers: per `ROBO-mgumaoyf` / `SITE-yeozymry`, the matcher moves to `ssrfr`
while per-package fetch integration and the consumer-facing toggle stay put.

### 6. Limits — open

ADR-003 §3 states a design philosophy: *"There are no non-overridable hard caps —
every limit can be raised by the caller if they accept the consequences."*

For a sitemap parser that is right. For a security library the calculus differs:
`max_redirects`, the connect and total timeouts, and the response-size bound are
**controls**, not budgets, and a hard floor may be justified. Two properties are
already fixed regardless of how this resolves:

- Every limit has a **finite default** (`ssrf-guard-spec.md` §8). "Unset" is not
  a value.
- `max_redirects = 0` MUST be supported and MUST mean "refuse any 3xx". Four
  independent OWASP sources and ASVS 5.0 V15.3.2 recommend disabling redirects
  outright; following them with per-hop revalidation is a documented deviation.

Whether any limit is a non-overridable floor is **deliberately left open** and
tracked as **`SSRF-pffrmkdr`**. It blocks the v1 API freeze. ADR-003's two-axis
body-limit model (an inner truncate-and-retain cap inside an outer discard
ceiling) is a pattern worth reusing if `ssrfr` bounds response size, and is
noted here so the decision does not have to rediscover it.

### 7. Ownership across the four-package stack

`ssrfr` sits in the middle of a four-package stack. ADR-003 §4's two-package
table does not describe it.

| Concern | Owner |
|---|---|
| Parse URL components (scheme, host, path, port, query, fragment) | `rurl` |
| IDNA host normalization (Unicode → Punycode) | `rurl` (via `punycoder`) |
| Path normalization and percent-encoding | `rurl` |
| Public suffix / registered domain | `rurl` (via `pslr`) |
| Address parsing and spelling normalization | `raddr` |
| Address classification predicates and registry tables | `raddr` |
| Structural (L0) host/scheme matching | `ssrfr` |
| DNS resolution and answer-set validation (L1) | `ssrfr` |
| Pinning, transport hardening, redirect loop (L2) | `ssrfr` |
| Reason-code vocabulary and result model | `ssrfr` |
| The conformance corpus and parse-vector table | `ssrfr` |
| Whether to fetch a given URL at all | the consumer |
| Consumer-facing opt-out (`ssrf_guard = FALSE`) | the consumer |
| Protocol-layer URL rules (absolute http/https, scoping) | the consumer |

Two constraints on this table:

- **`ssrfr` does not block on `raddr`.** The vendored matcher ships as the L0
  core with zero dependencies; `raddr` later replaces the classification tables
  behind the same seam (`ssrf_in_cidr(n, base, bits)` on integers is that seam).
  This avoids the release-order hazard: a dependency on an unpublished package
  becomes `ssrfr`'s own CRAN blocker, and if `robotstxtr` then depends on
  `ssrfr`, the chain lengthens rather than shortens.
- **`ssrfr` MUST NOT delegate its parse to a foreign parser.** INV-1 requires the
  guard's host to agree with what the transport will actually dial. In R that is
  libcurl. `rurl` components are used where the consumer already has them, but
  the guard's own parse standard is fixed to the transport's and is **not**
  caller-configurable.

### 8. Default User-Agent — open

ADR-003 §5 assembles `sitemapr/<version> (+<contact-url>)` at runtime from
`utils::packageDescription()`, so no URL is hard-coded in source. `ssrfr` owns
the transport, so it owns this question; the runtime-assembly technique carries
over regardless of what string is chosen. Listed as open decision 4 in
`ssrf-guard-spec.md` §12.

---

## Consequences

### Positive

- The guard's guarantee no longer depends on the caller having pre-filtered its
  input through `rurl`. It holds for any caller.
- DNS rebinding and resolve-to-private-address are in scope, which is what makes
  the package usable by its stated audience at all.
- A positive routability predicate makes the `fc00::/7` and 6to4 gaps closed
  properties rather than bugs waiting to be reported.
- The refusal taxonomy (policy vs. wire) and the stable reason-code vocabulary
  are settled before any consumer depends on them.
- The two remaining product decisions are named, ticketed, and scoped, rather
  than resolved by accident during implementation.

### Negative / accepted trade-offs

- **Resolution adds latency, a network dependency, and new failure modes.** L0
  stays available and cheap for callers who genuinely want a pure pre-filter, and
  it is named so it cannot be mistaken for the gate.
- **L2 cannot be tested by pure unit tests.** It needs a mock resolver, a
  loopback HTTP server, and an env-gated integration layer for cases those cannot
  cover (IPv6 pinning in particular — `webfakes` cannot bind `::1`).
- **Failing closed on malformed literals will refuse some inputs that are
  harmless.** Accepted: an undecodable literal is not a thing a legitimate caller
  needs `ssrfr` to fetch.
- **`ssrfr` is defense in depth, not egress control.** It does not replace a
  firewall or a VPC boundary, and MUST NOT be documented as doing so. A caller
  who reaches around the guarded path is unprotected; two-thirds of the surveyed
  CVEs are exactly that.
- **The transport findings behind §1 and §4 are verified on macOS only.** The
  pin fail-open (INV-6) in particular is libcurl-internal and must not be assumed
  portable. Re-verification on Linux and Windows is a v1 blocker.

---

## Revisit conditions

- `raddr` reaches CRAN and can replace the vendored classification tables.
- The IANA special-purpose registries change in a way the predicate does not
  already absorb (this should be a data update, never a code change — if it is a
  code change, §2 has been implemented wrong).
- A transport primitive appears that can **veto** a connection before
  `connect()`. Today's post-connect observation (`debugfunction`) is a detector
  only; a real veto hook would let step 11 of the lifecycle become a control.
- Cross-platform re-verification contradicts any transport finding in
  `docs/spec/r-binding.md`.

---

## 9. Corrections to inherited material

Two items in ADR-003 are wrong on their own terms rather than merely
out-of-scope, and are recorded here so the errors are not propagated:

1. **The `ssrf_guard = FALSE` sentence in "Negative / accepted trade-offs" is
   self-contradictory.** It reads: *"A hostname like `evil.internal.corp` that
   resolves to `10.0.0.1` is not blocked unless `ssrf_guard = FALSE` is set."*
   That flag *disables* the guard; it cannot cause blocking. The sentence
   conflates two separate claims — the hostname is not blocked (true, and
   unconditional), and users on trusted networks should use the opt-out (true,
   and unrelated). `ssrfr` does not carry the sentence into its documentation.
2. **ADR-003's revisit condition for DNS is already met** (§1 above). The ADR
   reads as though no CRAN-safe resolution primitive exists; `curl::nslookup()`
   is one.

Both are harmless in `sitemapr` but should be fixed there. Tracked separately;
no change is made to `sitemapr` by this ADR.
