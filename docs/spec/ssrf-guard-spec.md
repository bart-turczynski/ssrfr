# SSRF guard specification

- **Status:** DRAFT — not frozen. See §12 for the open decisions blocking v1.
- **Version:** `0.1.0-draft` (2026-07-25)
- **Scope:** language-agnostic. Implementation-specific transport detail lives in
  a binding document (`r-binding.md` for `ssrfr`).
- **Evidence base:** `_scratch/research/` (11 research reports, ~15,500 lines)
  and `_scratch/research/SYNTHESIS.md`. Claims marked **[verified]** were tested
  empirically; **[sourced]** cites external evidence; **[assumption]** is
  neither.

Key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are used per RFC 2119.

This document specifies **what a conforming SSRF guard does**. It is written to
be implementable in any language, so that multiple implementations can be checked
against one shared conformance corpus rather than diverging silently. That
divergence is not hypothetical: the same IPv6 string-matching bug shipped twice,
in the same shape, across two sibling R packages, and survived code review, a
test suite, and a first fix.

---

## 1. Threat model

### 1.1 In scope

An attacker controls, wholly or partly, a URL that the host application will
fetch server-side. The attacker's goals are to reach a network position the
application did not intend to expose:

- **Loopback and link-local** services (admin panels, debug endpoints).
- **Private / internal** networks (RFC 1918 and the IPv6 equivalents).
- **Cloud metadata services** — credential theft. The canonical escalation.
- **Container and orchestration control planes** (Docker socket, kubelet, API
  server).
- **Unauthenticated internal services** that tolerate HTTP preamble as protocol
  input (Redis, Memcached) — the SSRF→RCE chain.
- **Non-HTTP protocol reach** via scheme abuse (`file://`, `gopher://`, …).
- **Information disclosure without a successful fetch** — using error shape or
  response timing to port-scan or enumerate internal hosts (blind SSRF).

### 1.2 Out of scope

- **Inbound** request security (CSRF, headers, CORS). Different problem.
- **Network-level egress control.** A guard in a library is defense in depth, not
  a replacement for a firewall or a separate VPC. Implementations MUST NOT claim
  otherwise.
- **Application-layer authorization** of the fetched resource.
- **Content** safety of the response body (malware, XSS in rendered output).
- **DNS integrity.** A compromised resolver defeats any client-side guard.

### 1.3 The adversary's assumed capabilities

A conforming implementation assumes the attacker can:

1. Supply any byte string as the URL, including forms that are legal to one
   parser and illegal to another.
2. Control DNS for a domain they own — including **multiple A/AAAA records**,
   **very low TTLs**, and **changing the answer between two lookups** (rebinding).
3. Control an HTTP server that issues **redirects** to any target.
4. Register hostnames that resemble allowlisted ones.
5. Observe the timing and error output the host application returns.

Capability 2 is the one most implementations get wrong.

---

## 2. Layer model

A conforming implementation MUST expose these as distinct layers. Collapsing them
is the defect described in `CVE-2026-41488`, whose advisory names the
anti-pattern directly: *"validate-then-fetch with separate DNS resolution."*
**[sourced]**

| Layer | Name | I/O | Guarantee |
|---|---|---|---|
| **L0** | structural classification | none | The URL/host is not *self-evidently* prohibited. **Not an SSRF defense.** |
| **L1** | resolved check | DNS | Every address this host currently resolves to is permitted. Still TOCTOU-exposed if the caller then fetches by hostname. |
| **L2** | guarded fetch | DNS + TCP | The connection went to an address that was validated. The only layer that is an SSRF defense. |

### 2.1 L0 naming is normative

L0 MUST be named so it cannot be mistaken for a security gate. Names like
`is_safe()`, `check()`, or `validate()` on L0 are **non-conforming**.
Implementations MUST document L0 as a fast pre-filter and configuration-linting
aid.

Rationale: L0 exists because it is genuinely useful (it is pure, instant, and
testable with no infrastructure) and because existing consumers depend on it. But
a caller who believes L0 is the defense has an SSRF vulnerability. One
maintainer of a mature implementation refuses to ship an L0-equivalent at all,
on the record: *"the checking and fetching have to happen in a single step."*
**[sourced]** That objection is answered by naming and documentation, not by
denying the layer exists.

### 2.2 L2 must be usable inside someone else's loop

Callers with their own redirect loops and per-hop policy MUST be able to invoke
the guard **per hop** rather than surrendering the loop. An implementation that
only offers "we own the fetch" is non-conforming.

---

## 3. Request lifecycle

Per hop, in this order. Order is normative — several published
vulnerabilities are ordering errors.

```
 1. PARSE          with the parser whose result the transport will act on (INV-1)
 2. PARSE STATUS    any ambiguity is a block                              (INV-2)
 3. SCHEME          allowlist; http/https only by default
 4. USERINFO        reject embedded credentials unless explicitly allowed
 5. PORT            allowlist (default 80, 443)
 6. HOST POLICY     deny/allow host rules; deny wins                      (INV-14)
 7. RESOLVE         exactly once; obtain ALL A/AAAA records               (INV-5)
 8. CLASSIFY        every address; reject wholesale on any failure        (INV-4)
 9. PIN             connect only to a validated address, unambiguously    (INV-6)
10. CONNECT         with transport hardening per §9
11. VERIFY          the peer is an address that was validated             (INV-5)
12. RESPONSE        enforce size and time budgets
13. ON 3xx          strip credentials (INV-8), then goto 1 for the new URL (INV-7)
```

### 3.1 Notes on ordering

- **Scheme before resolve.** Resolving a `file://` host is wasted work and can
  itself leak (a DNS query to an attacker-controlled zone confirms reachability).
- **Port before resolve**, same reason.
- **Classification after resolution, never instead of it.** L0 host-string
  classification does not replace step 8.
- **Step 11 is not optional but is also not sufficient.** It is a detector; the
  pin at step 9 is the control. See INV-5.

---

## 4. Load-bearing invariants

These are the safety properties. Each MUST be encoded as a test from the first
commit. Every one of them is a property a well-meaning contributor would
plausibly "simplify" later, and most have a published CVE behind them.

---

### INV-1 — Parse with the parser whose result the transport will act on

The guard MUST derive the host from a parse that agrees with what the transport
layer will actually dial.

**Rationale.** The entire bypass class is validator/client parser disagreement.
An implementation that validates with parser A and fetches with parser B is
insecure by construction regardless of how good its classification is.
**[verified]** in the R stack: `ip_address("0177.0.0.1")` yields `177.0.0.1`
(a public address, allowed) while curl dials `127.0.0.1`. Silent bypass.

**Corollary — the parse standard MUST NOT be caller-configurable.** Exposing it
lets a caller select a mode whose output the transport does not honour.

**Corollary — this is why the parser is not portable.** Each implementation MUST
bind to its own stack's parser and MUST NOT import a foreign one for
"consistency."

**Evidence.** Spring `CVE-2024-22243`/`-22259`/`-22262`; Claroty Team82's
16-library study; Tsai, Black Hat USA 2017. **[sourced]**

**Test.** The parse-vector corpus (§10.2), asserting guard host == transport host
for every vector.

---

### INV-2 — Parse ambiguity is a block, not a warning

If the parse yields anything other than unambiguous success, the request MUST be
refused.

**Rationale.** Hosts like `foo.09`, `0x1.2.3.4.5`, `1.2.3.08` are rejected by a
strict parser *because they are ambiguous*. That rejection **is** the security
signal. A lenient mode that returns a usable host plus a warning converts the
signal into a bypass.

**Test.** Corpus group: ambiguous authorities, all expecting refusal.

---

### INV-3 — Address rules match the decoded value, never the literal string

Every classification rule MUST operate on the numeric value of a parsed address
(for IPv6: the 8 expanded hextets), never on a regex or prefix match against the
literal text.

**Rationale.** The same 128 bits have many spellings. `fd00:0ec2::254` and
`fd00:ec2::254` are one address; a string rule decides them differently. This
shipped **twice** in the sibling packages: `grepl("^fd00:ec2:", low)` allowed a
real metadata endpoint, and `grepl("^fe[89ab][0-9a-f]?:", low)` blocked `fe8::`,
which is nowhere near `fe80::/10`. The second bug survived the first fix.
**[verified]**

**Test.** Spelling tables — for each address, every legal spelling, same verdict.

---

### INV-4 — Validate every resolved address; refuse wholesale on any failure

All A and AAAA records MUST be classified. If **any** is prohibited, the request
MUST be refused. An implementation MUST NOT filter the answer set down to the
permitted subset and proceed.

**Rationale.** Validating only the first record is the classic bug — `january`
`GHSA-4mcc` checked the first answer while the client tried all of them.
**[sourced]** Filtering to the "good" subset is subtler and also wrong: an
attacker who can add a private record to a legitimate hostname's answer set
should get a refusal, not a coin flip. Wholesale refusal also removes any
timing signal about which record was objectionable.

**Test.** Mocked multi-record resolutions: public+private, A public + AAAA `::1`,
all-private, all-public.

---

### INV-5 — Resolve exactly once per hop, and connect only to a validated address

The guard MUST perform exactly one resolution per hop, and the connection MUST
target an address from that validated set. The hostname MUST NOT be handed back
to the transport for re-resolution.

**Rationale.** This is the TOCTOU/DNS-rebinding defense and the single most
important property in this document. Handing the hostname back re-opens the
window between check and connect.

**Verification requirement.** Where the platform permits observing the connected
peer, the implementation MUST compare it against the validated set and fail if it
does not match. This is a **detector, not the control** — it observes after
`connect()` and cannot veto. Implementations MUST NOT present it as the gate.

**Evidence.** WordPress `wp_http_validate_url()` carried this bug for 5+ years;
LangChain `CVE-2026-41488`. **[sourced]**

**Test.** A counting resolver mock asserting exactly one call per hop; plus a
pin-effectiveness test using an unresolvable-by-design hostname
(`.invalid`, RFC 2606) so a passing result proves the pin was load-bearing.

---

### INV-6 — The pin MUST be unambiguous, and MUST NOT fail open

The mechanism binding a hostname to a validated address MUST NOT silently
disengage. Where the platform's pinning primitive is keyed (e.g. by host and
port), the implementation MUST construct the key such that a mismatch is
impossible, or MUST verify the pin engaged.

**Rationale.** **[verified]** in the R stack: both available primitives discard
the pin and perform a *real, unvalidated* resolution when the key's port does not
match the request's port — silently, with no error. A fail-open in the primary
safety mechanism.

**Test.** For each supported scheme and for explicit/default/non-default ports,
assert the connection went to the pinned address.

---

### INV-7 — Every dimension is revalidated on every hop

On redirect, the full §3 lifecycle MUST re-run against the new URL. It is not
sufficient to revalidate the address alone.

**Rationale.** A mature Go implementation revalidates address, port, and family
per hop but checks scheme, host rules, and credentials only once — so all three
are bypassable via redirect. **[sourced]** Five Gitea CVEs and two Grafana CVEs
cluster on redirect-after-validation.

**Corollary.** The guard MUST own the redirect loop or be invoked per hop by a
caller that does (§2.2). Automatic transport-level redirect following MUST be
disabled. A guard attached to a transport *object* can be detached from it —
`CVE-2023-28155` deleted the agent on protocol switch, and the agent was the
guard. **[sourced]**

**Test.** Redirect chains ending at a prohibited target, one per dimension:
address, scheme, port, host rule, credentials.

---

### INV-8 — Credentials MUST NOT cross an origin boundary

On a cross-origin redirect the implementation MUST drop credential-bearing
material: `Authorization`, `Cookie`, and any caller-supplied header or body
carrying a secret.

**Rationale.** A working token-replay PoC was filed against the reference Ruby
implementation, which strips `authorization` and `cookie` but replays `body`,
`params`, and custom headers verbatim cross-origin. **[sourced]** Note the
transport's own "don't send credentials to other hosts" flag typically covers
only credentials the *transport* manages, not ones the caller set.

**SHOULD.** Downgrade the method to GET and drop the body on 301/302/303, per RFC
9110 §15.4. Note 307/308 deliberately replay method *and* body at the new host —
which is precisely why the target must be revalidated first.

---

### INV-9 — Certificate verification MUST NOT be weakened

An implementation MUST NOT disable or relax TLS certificate or hostname
verification, and MUST NOT expose an option to do so.

**Rationale.** Pinning does **not** require it. **[verified]** by three
independent methods: a correct pin changes only the TCP peer, leaving SNI, the
`Host` header, and certificate validation bound to the hostname. What breaks TLS
is rewriting the URL's host to an IP literal — and the usual "fix" for that is
disabling verification, converting an SSRF mitigation into a MITM
vulnerability. Several PHP and Laravel packages ship exactly that trade-off.
**[sourced]**

**Corollary.** The implementation MUST NOT rewrite the URL host to an IP literal.

---

### INV-10 — Ambient transport configuration MUST be neutralized

The implementation MUST disable proxy use unless the caller explicitly opts in,
and MUST neutralize every ambient configuration channel its transport reads:
proxy environment variables, config files, and any cache that can redirect a
later request.

**Rationale.** A proxy resolves the hostname *itself*, discarding the pin
entirely — a total bypass. This went unnoticed for nine years in the reference
Ruby implementation, and exactly one project in the surveyed corpus closes it.
**[sourced]** Beware channels that are not obviously proxies: an
`Alt-Svc` cache remaps an origin to a different protocol, host, and port for
*later* requests and emits no redirect, so a manual redirect loop cannot see it.
**[sourced]**

**Test.** Set each ambient variable to a sentinel and assert the connection still
went to the pinned address.

---

### INV-11 — Fail closed

Any error in parsing, resolution, or classification MUST result in refusal. There
is no path from "we could not determine this" to "proceed".

**Rationale.** A literal that the address decoder cannot interpret MUST NOT fall
through to a default allow. The inherited implementation has exactly this hole
and is currently safe only because the parse layer rejects such inputs first —
i.e. the property is enforced by a different layer than the one that documents
it.

**Test.** Malformed literals and truncated/refused resolutions, all expecting
refusal.

---

### INV-12 — Do not be an oracle (SHOULD)

Refusals SHOULD be indistinguishable in **shape and timing** to the host
application's end user, such that a caller cannot use the guard to enumerate
internal hosts or ports.

**Rationale.** Blind SSRF turns any differential — a distinct error, a faster
failure — into a port scanner. This is essentially unimplemented across the
surveyed field and is a genuine differentiator.

**Tension, to be resolved explicitly.** It conflicts with rich, actionable
diagnostics, which are also a stated goal — SSRF debugging is miserable without
knowing which address and which predicate refused. Implementations SHOULD
therefore separate a **detailed internal verdict** (for logs and the developer)
from a **coarse external result** (for the untrusted caller), and MUST document
which is which.

---

### INV-13 — Denylists are never complete; gate on a positive predicate

Classification MUST be expressed as a positive routability predicate applied to
the resolved address, not as an enumerated list of prohibited ranges.

**Rationale.** `pydantic-ai` shipped **three CVEs against one blocklist in about
four months** (`CVE-2025-25580` → `-46678` → `-48782`), each an IPv6-transition
wrapper of the metadata address, the last unfixable *in principle* because NAT64
prefixes are operator-chosen. **[sourced]**

**Corollary — embedded addresses.** Any address form that embeds another address
MUST have the embedded value extracted and classified independently. A
registry-driven "globally reachable" flag does **not** cover this: IANA correctly
marks the NAT64 well-known prefix as globally reachable, because it maps onto
global IPv4 — so the wrapper is reachable while what it *wraps* may not be.

**Corollary — hostname rules are still required.** Some metadata services have
**no link-local address at all** and are reached over public DNS and HTTPS
(Equinix Metal, IBM VPC **[sourced]**). These are invisible to any address
classifier, including a perfect one. A hostname denylist is therefore a
first-class control, not a convenience.

---

### INV-14 — Deny wins

When both an allow rule and a deny rule match, the request MUST be refused.

**Rationale.** The alternative — allow overrides deny, as one Go implementation
does, where configuring any allowlist silently flips the whole policy to
default-deny — makes the effective policy hard to predict from the
configuration. **[sourced]** A conjunctive model is auditable.

**Corollary.** An implementation SHOULD provide one explicit, unmistakably-named
way to disable the guard entirely, because callers with legitimate internal
targets will otherwise discover that emptying the deny list disables the
defaults.

---

## 5. Reason codes

### 5.1 Requirements

Reason codes are a **public compatibility surface**, not a debugging nicety.
Downstream packages surface them to *their* users as documented values.
Implementations MUST treat them as API: documented, enumerable, and versioned.

- Codes MUST be machine-readable, stable, and enumerable at runtime.
- A refusal MUST report which predicate refused and, where applicable, which
  address and which hop.
- **Policy refusal MUST be distinguishable from operational failure.** "We
  refused this" and "the network failed" are different outcomes with different
  caller responses. No surveyed npm implementation makes this distinction; all
  collapse to a prose error. **[sourced]**

### 5.2 Vocabulary

Normative for `ssrfr` and constrained by existing published consumers — these
values appear in downstream reference documentation and cannot be renamed
without breaking them. **[verified]**

| Code | Meaning |
|---|---|
| `loopback` | loopback address |
| `private` | private / internal address space |
| `link-local` | link-local address |
| `cloud-metadata` | a known metadata endpoint, by address or hostname |
| `unspecified` | the unspecified address |
| `ipv4-mapped` | IPv4-mapped IPv6, prohibited embedded value |
| `ipv4-translated` | IPv4-translated IPv6, prohibited embedded value |
| `ipv4-compatible` | deprecated IPv4-compatible IPv6, prohibited embedded value |
| `nat64` | NAT64-embedded, prohibited embedded value |
| `numeric-literal` | ambiguous numeric host encoding |
| `scheme` | scheme not permitted |

Additions required by this specification:

| Code | Meaning | Source |
|---|---|---|
| `downgrade` | redirect from a secure to an insecure scheme | §4 INV-7; recognized by a sibling ADR but absent from the inherited list |
| `userinfo` | embedded credentials in the URL | §3 step 4 |
| `port` | port not permitted | §3 step 5 |
| `host-denied` | matched a host deny rule | §3 step 6 |
| `parse` | ambiguous or failed parse | INV-2 |
| `malformed-address` | address literal that could not be decoded | INV-11 |
| `unresolvable` | resolution failed | INV-11 |
| `pin-mismatch` | connected peer was not in the validated set | INV-5 |
| `multicast` | multicast address | — |

Two inherited misnomers to correct deliberately rather than propagate:
CGNAT space reported as `cloud-metadata` (it is not metadata; it merely contains
one provider's endpoint), and an AWS IPv6 metadata range reported as
`cloud-metadata` while the unique-local space containing it is unblocked.

### 5.3 Conventions

- Reason codes: `kebab-case`. This diverges from the sibling TypeScript
  project's `snake_case` convention; the divergence is **deliberate**, to
  preserve the published values above.
- Operational-cause codes: a separate closed enum. The token for policy refusal
  MUST be reserved exclusively for policy refusal and MUST NOT be reused for
  network failure.

---

## 6. Classification requirements

Classification is delegated (in `ssrfr`, to a companion package). This
specification constrains the interface, not the tables.

An address MUST be refused if it is not globally reachable, is multicast, matches
a configured deny rule, or embeds an address that is itself refused (INV-13).

Implementations SHOULD drive classification from the IANA special-purpose address
registries rather than a hand-maintained list. Evidence: two independent
hand-rolled implementations missed the *same* provider's metadata address.
**[verified]**

---

## 7. Transport hardening (language-agnostic)

Binding documents specify the concrete option names. Every conforming
implementation MUST achieve these effects:

| Requirement | Attack prevented |
|---|---|
| Scheme allowlist enforced at the transport, not only by the guard | scheme smuggling if a code path bypasses the guard |
| Automatic redirect following disabled | unvalidated hop (INV-7) |
| Connection reuse must not outlive a pin | a pooled connection bypassing this request's validation |
| Resolution caching must not serve an unvalidated later request | stale-answer bypass |
| Proxy and ambient config neutralized | total pin bypass (INV-10) |
| Origin-remapping caches disabled | invisible later redirect (INV-10) |
| Local-socket transports disabled | container control-plane access |
| Connect timeout and total timeout both set | port scanning by timing; resource exhaustion |
| Response size bounded by counting delivered bytes | decompression bombs; header-declared size is advisory only |

**Note.** A declared-size limit is not a size limit: it is typically a no-op when
the server omits a length header, and is measured on wire bytes so a compressed
bomb passes. Count bytes as they are delivered. **[sourced]**

---

## 8. Configuration model

```
allow_schemes     default: http, https
allow_ports       default: 80, 443            allowlist only, never a denylist
deny_hosts        hostname rules (INV-13)
allow_hosts       hostname rules; deny still wins (INV-14)
deny_ranges       additional prohibited ranges
allow_ranges      explicit escapes; deny still wins (INV-14)
allow_userinfo    default: false
max_redirects     default: small; 0 MUST be supported and MUST mean "refuse any 3xx"
connect_timeout   MUST have a finite default
total_timeout     MUST have a finite default
max_response_size MUST have a finite default
```

Ports MUST be an allowlist. Browser "bad port" denylists omit both Redis and
Memcached **[sourced]**, and the reference Ruby implementation has no port
restriction at all. CWE-918's own alternate name is *Cross Site Port Attack*.

`max_redirects = 0` is required because four independent OWASP sources — and
ASVS 5.0 V15.3.2 — recommend disabling redirects outright. Following them with
per-hop revalidation is a deliberate, documented deviation, not the standard
position.

---

## 9. Result model

A result MUST distinguish:

1. **Allowed** — with the validated address set and the pin actually used.
2. **Refused by policy** — with a reason code (§5), the offending address or
   host, and the hop index.
3. **Operationally failed** — network, DNS, or protocol failure, with a cause
   code from a separate enum.

Callers MUST be able to branch on (2) vs (3) without string matching. See
INV-12 on what may be exposed to an untrusted end user.

---

## 10. Conformance

An implementation declares conformance by publishing its results against the
shared corpus. This — not code sharing — is the mechanism keeping multiple
implementations consistent.

### 10.1 Verdict vectors

Inputs with expected verdicts, grouped by bypass class. Each carries: input,
expected outcome, expected reason code, and the layer that must catch it. A
conforming implementation MUST pass all of them at the layer specified or
earlier.

### 10.2 Parse vectors

Inputs where parsers disagree, with a per-parser ground-truth host column. Each
implementation adds a column measured empirically from *its own* stack. This
table is the artifact that makes INV-1 checkable and maps to **ASVS 5.0 V1.5.3**
(parser consistency). Regenerating it in CI turns any upstream parser change into
a visible diff rather than a silent bypass.

### 10.3 Requirement coverage

A mapping from external requirement identifiers (OWASP cheat sheet items, ASVS
requirement IDs, CWE mitigations) to the tests that demonstrate them, marking
each as enforced-by-library, enforced-by-application, or out of scope.

### 10.4 Corpus is the metric, not coverage

The reference Ruby implementation had two bypasses reported by outsiders while
advertising 100% code coverage. **[sourced]** Conformance claims MUST cite corpus
results.

---

## 11. Compliance claims

Permitted, with citation: OWASP SSRF Prevention Cheat Sheet items; ASVS 5.0
V1.3.6, V13.2.4, V13.2.5, V15.3.2, V1.5.3; CWE-918; CAPEC-664; WSTG SSRF tests;
RFC 6874 §4 zone-ID handling.

Explicitly **not** permitted:

- A year-less "OWASP Top 10 A10 = SSRF". In the 2025 edition SSRF is folded into
  A01:2025 Broken Access Control; A10:2025 is a different category. Cite an
  edition.
- "ASVS V50" — no such chapter exists in 5.0.
- PCI DSS or CIS benchmark compliance. Neither has citable SSRF text.
- Any claim that the library replaces network-level egress control (§1.2).
- Any claim that L0 provides SSRF protection (§2.1).

---

## 12. Open decisions blocking v1

| # | Decision | Ticket |
|---|---|---|
| 1 | Component-wise API vs whole-URL API. OWASP advises against accepting complete URLs from users, which is the shape every existing library — and this spec's §3 — assumes. | `SSRF-tnxmqvou` |
| 2 | Whether any limit is a non-overridable floor. A sibling ADR asserts no hard caps; for a security library, redirect and size limits are controls rather than budgets. | `SSRF-pffrmkdr` |
| 3 | Search-domain resolution. A bare hostname can resolve through system DNS search suffixes to something internal. Appending a root dot defeats it but changes the `Host` header and SNI, risking certificate mismatch. | — |
| 4 | Default User-Agent, since the guard owns the transport. | — |

Unverified claims to close before v1: IPv6 pinning with a bracketed literal;
cross-platform behaviour of INV-6's fail-open (verified on one platform only);
the connection-reuse interaction in INV-7's corollary (established by reading
transport source, not by reproduction).

---

## 13. Non-goals

- A general-purpose URL parser or validator.
- A replacement for firewalls, egress proxies, or IMDSv2-style hardening. Those
  are complementary and stronger; this library is defense in depth for
  applications that fetch caller-supplied URLs.
- Protection for callers who bypass the guarded path. Two-thirds of the CVEs
  surveyed were "some code path did not use the guarded client" or "the guard was
  detached." Implementations SHOULD make the guarded path the path of least
  resistance and SHOULD document the unguarded primitives in their ecosystem that
  remain dangerous.

---

## 14. References

Full citations with URLs are in `_scratch/research/`. Primary sources:

- OWASP SSRF Prevention Cheat Sheet; OWASP ASVS 5.0; OWASP WSTG; OWASP API
  Security Top 10 (API7:2023).
- CWE-918; CAPEC-664.
- RFC 3986; WHATWG URL Standard; RFC 9110 §15.4; RFC 6874; RFC 2606; UTS-46.
- Tsai, *A New Era of SSRF — Exploiting URL Parsers*, Black Hat USA 2017.
- Claroty Team82, *Exploiting URL Parsing Confusion*, 2022.
- ONsec/Wallarm, *SSRF Bible*.
- Implementation prior art: `ssrf_filter` (Ruby), `safeurl` (Go/Python),
  `advocate` (Python), Sentry, MLflow, smokescreen (Stripe), Gitea `hostmatcher`.
