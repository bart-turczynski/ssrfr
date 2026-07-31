# `ssrfr` v1 specification

- **Status:** DRAFT. Sections are marked **[ratified]**, **[proposed]**, or
  **[open]**. Only ratified sections may be implemented against.
- **Ratification is structural, not behavioural.** §2's primitive is ratified as a
  *shape* — the branch between refusal and binding, and what a binding carries.
  The gate set that decides which branch is taken is **§5's table, which is
  proposed**, and the codes a refusal reports are **§6.3, which is open**. How the
  gates combine (§5.0) and how indeterminacy is treated (§5.1) *are* ratified. L2
  is therefore implementable as an interface, and blocked on §5's table and §6.3
  for behaviour.
- **Version:** `1.0.0-draft` (2026-07-31)
- **Ticket:** `SSRF-xrlijlqq`

## Relationship to the other documents

| Document | Role | Relationship to this one |
|---|---|---|
| [`ssrf-guard-spec.md`](ssrf-guard-spec.md) | language-agnostic contract: threat model, 14 invariants, lifecycle, conformance method | **Upstream.** This document does not restate the invariants; it cites them. Where the two disagree, §10 lists the amendments that document needs. |
| [`r-binding.md`](r-binding.md) | R/libcurl transport specifics and empirical findings | **Downstream.** Option names and verified transport behaviour stay there. |
| [`../decisions/ADR-001-network-safety-policy.md`](../decisions/ADR-001-network-safety-policy.md) | policy lineage from `sitemapr` ADR-003 | **Partly superseded** by ADR-002. |
| [`../decisions/ADR-002-v1-dependency-and-policy-model.md`](../decisions/ADR-002-v1-dependency-and-policy-model.md) | v1 dependency and exception policy | **Current.** Records the §4 dependency reversal and §5.0 precedence model. |

This document is `ssrfr`'s own normative specification: what it is for, what it
guarantees, what it depends on, and what its primitives are. RFC 2119 keywords
apply.

---

## 0. Foundations **[ratified]**

**S1 — Purpose.** `ssrfr` prevents server-side R applications from issuing
outbound requests to network targets prohibited by policy, when any input
influencing the request may be attacker-controlled.

The widening to *any input* is deliberate. The initial URL is one input among
several: the link graph, the redirect chain, and host or port components
assembled from separate inputs all qualify. A crawler that fetches a hostile page
which redirects into the operator's intranet is squarely in scope, and that case
is the one `ssrfr`'s first consumers actually face.

**S2 — Security boundary.** Only the guarded fetch — resolution, validation of
every resolved address, and a pin to a validated address — is an SSRF defense.
Structural classification (L0) and resolved checking (L1) are inspection layers.
L1's guarantee holds only at the instant of the check; if the caller subsequently
fetches by hostname, it guarantees nothing.

**S3 — Stack role.** `ssrfr` consumes address and URL facts from the stack and
owns security policy, refusal semantics, per-hop revalidation, pinning, and
conformance evidence. The host it acts on MUST derive from a parse that agrees
with what the transport will dial (INV-1), and that parse standard is fixed
internally and is not caller-configurable.

**S4 — Transparency rule.** Facts are preserved in full for trusted operators:
every resolved address, every predicate that fired, every hop, the parse result,
and the pin actually used. Results exposed to untrusted callers are minimized.
Shape minimization is a **MUST**; timing resistance is a **SHOULD** with a
documented limitation (§6.4).

This is the stack's established "facts and transparency over protective
interpretation" principle, made precise for a security library: **transparency
governs reporting; fail-closed governs the gate.** The two do not conflict once
reporting and deciding are separate layers. "Undecodable" is a fact the
classifier reports; "therefore refuse" is a policy the gate applies.

**S5 — Non-goals.** `ssrfr` is not egress control and does not replace firewalls,
VPC boundaries, or IMDSv2-style hardening. It does not protect callers who reach
around the guarded path, and it cannot secure R's unguarded primitives
(`download.file()`, `url()`, `readLines()`, and direct `curl` use). It is not a
general-purpose URL parser or validator. DNS integrity is out of scope: a
compromised resolver defeats it, and `ssrfr` cannot pin its own resolver because
`dns_servers` requires a c-ares build. Inbound request security is a different
problem.

**S6 — Consolidation is the migration path, not the purpose.** The duplicated
matchers in `robotstxtr` and `sitemapr` are `ssrfr`'s first consumers and its
evidence of demand. Their published reason-code vocabulary is a compatibility
obligation. Neither is the reason the package exists.

---

## 1. Layer contracts **[ratified]**

| Layer | I/O | Returns | Guarantee |
|---|---|---|---|
| **L0** structural | none | classification facts | the host/scheme is not *self-evidently* prohibited. **Not a defense.** |
| **L1** resolved | DNS | the resolved address set with per-address classification | every address this host resolved to at check time was **classified**; prohibited and indeterminate outcomes are preserved per address |
| **L2** guarded | DNS + TCP | a refusal or a binding (§2) | the connection went to an address that was validated |

### 1.1 L0 is a reporter, not a gate

L0 MUST return a classification, not a verdict. Names implying a security
decision — `is_safe()`, `check()`, `validate()` — are **non-conforming**.

The rationale in `ssrf-guard-spec.md` §2.1 is that such a name is dangerous. That
is true but secondary. The primary reason is that **L0 does not answer that
question at all.** It reports what a host string is, in the same way `raddr`
reports what an address literal is. Naming it as a gate misdescribes its return
type, and a two-state verdict flag cannot express indeterminacy — the defect that
caused the revert of `a978f8d`.

A derived convenience boolean is permitted at L0 only, for configuration linting,
provided it is documented as derived and is not the primary return.

### 1.2 L1 exposes no roll-up

L1 MUST NOT return a summary "all permitted" boolean as its primary result. Such
a value asserts a permission that is stale the instant it returns, and reads as
authorization. L1 returns evidence: the address set and each address's
classification. Any aggregate field, if present, MUST be documented as derived
and MUST NOT be usable as an authorization token.

### 1.3 L2 must work inside someone else's loop

Callers with their own redirect loops and per-hop policy MUST be able to invoke
L2 per hop. All three known consumers run their own loops. An implementation that
only offers "we own the fetch" is non-conforming (`ssrf-guard-spec.md` §2.2).

---

## 2. The decision primitive **[ratified]**

### 2.1 The question `ssrfr` answers

> For this URL, at this redirect hop, under this policy: produce either a refusal
> with reasons, or the exact connection binding that may be used.

There is **no standalone "allowed to fetch" boolean at L2.** The only positive L2
outcome is a binding that the guarded transport consumes.

**Rationale.** A verdict of "allowed" that does not carry the destination leaves
the caller holding a hostname, and resolve-then-fetch-by-hostname is the
anti-pattern named in `CVE-2026-41488`. A boolean L2 result hands every caller the
vulnerability as the path of least resistance and then relies on documentation to
talk them out of it — the failure mode behind two-thirds of the surveyed CVEs.
Returning connect material makes the anti-pattern unreachable rather than merely
discouraged. This is the same design move as `connect_to = "HOST::IP:"`
(`r-binding.md` §4.2): design the hazard out instead of guarding against it.

### 2.2 Shape

```
L0 / L1 inspection            → facts, no security verdict
ssrf_prepare_hop(url, policy, request = NULL, from = NULL)
                              → refusal  OR  opaque binding
ssrf_fetch(binding)           → response
```

`ssrf_fetch()` takes **one** argument. There is no URL parameter and no header,
method, or body parameter, so there is no substitution surface.

### 2.3 What a binding contains, and what enters at `prepare`

**Security identity** — what was authorized:

- the canonical origin: scheme, hostname, port, **excluding userinfo**
  (INV-8 requires credentials to be droppable, so they MUST NOT be capturable in
  a binding)
- the policy and hop context under which evaluation occurred
- the validated address set, and the selected pinned address
- the TLS verification settings, which MUST remain bound to the hostname (INV-9)

**Request data** — carried, not authorized:

- the exact sanitized URL `ssrf_fetch()` will request, including path and query
- the sanitized request plan: method, headers, body

Binding the full URL closes the substitution surface. The path is not an
independently authorized network target: for `http`/`https` it cannot be one, and
the CRLF-in-selector chain that reaches Redis is a `gopher://` property removed by
scheme allowlisting.

#### The request plan is an input to `prepare`, never to `fetch` **[ratified]**

INV-8 requires dropping `Authorization`, `Cookie`, and any caller-supplied header
or body carrying a secret on a cross-origin redirect. Redirect semantics also
transform the method and body for some status/method combinations. **None of that
is expressible if the binding carries only a URL** — the invariant would have
nothing to act on. And
adding headers as extra `ssrf_fetch()` arguments would recreate exactly the
substitution surface §2.1 exists to remove.

A GET-only v1 does not avoid the problem. `ssrfr` owns the transport, so it owns
the User-Agent (§8 decision 5); headers exist by necessity from the first request.

So the request plan enters at `prepare`. The guard evaluates it as part of the hop
decision — userinfo rejection, credential-bearing headers, method and body
transformation for the status code — and the binding carries the **sanitized**
plan. The credential drop becomes a recorded fact inside the binding rather than a
side effect of the fetch, which is what makes it auditable under S4.

**Consequence: a binding may contain secrets.** Its `print` and `format` methods
MUST redact credential-bearing fields, and §2.4's limits on opacity apply with
more force, not less.

This does not reopen §3.1. A request plan is not URL components; the URL remains a
single string that `ssrfr` parses.

**Redirect status is transport-derived, not caller-asserted.** `ssrf_fetch()`
records the transport-observed response status on the binding as it invalidates
fetchability. On the next hop, `prepare` derives the redirect transformation from
that recorded status. A caller-supplied `status` argument does not exist: accepting
one would let a caller accidentally or deliberately select replay semantics that
the response did not authorize.

The previous binding MUST be spent, MUST record a successful HTTP response, and
MUST record a status that `ssrfr` follows as a redirect before it is accepted as
`from`. Passing an unspent binding, a binding whose fetch failed, or a binding
whose response is not a followed redirect is an operational error.

The deterministic v1 transformation is:

| Status | Next-hop method and body |
|---|---|
| 301 or 302 | `POST` becomes `GET` and its body is dropped; other methods are preserved |
| 303 | `HEAD` remains `HEAD`; every other method becomes `GET`; the body is dropped |
| 307 or 308 | method and body are preserved, subject to the cross-origin rule below |

This is the behavior `ssrfr` chooses from RFC 9110 §15.4. The RFC permits, rather
than requires, the historical POST-to-GET transformation for 301 and 302; 307 and
308 prohibit changing the method during automatic redirection. Whenever a method
transformation drops the body, fields describing that body MUST also be dropped.

**On a redirect hop the request plan is inherited, not re-supplied.** Exactly one
of `request` and `from` is required. `request` supplies the first-hop plan and
MUST NOT be passed together with `from`; `from` supplies the previous binding's
plan and transport-observed status. This is not ergonomics: allowing a caller to
restate the plan on a redirect hop would let them re-add the credentials the
previous hop had just stripped, which is INV-8 defeated by the caller with no
error raised.

**Sensitivity is an allowlist of carryable headers, not a denylist of secrets.**
`ssrfr` cannot infer which of `X-Api-Key` or `X-Internal-Token` holds a secret.
Therefore every caller-supplied header and the body are treated as sensitive and
dropped cross-origin by default. The first-hop request plan MAY nominate specific
headers as safe to carry; nomination is an explicit assertion by the application
that the field contains no credential or origin-scoped secret.

`Authorization`, `Proxy-Authorization`, and `Cookie` are permanently
non-carryable, case-insensitively, and nomination MUST NOT override that rule. A
body is also non-carryable across origins in v1. Transport-controlled routing
fields, including `Host` and `Connection`, MUST NOT be accepted as caller-supplied
headers at all. These fixed rules cover protocol-defined credentials and routing
integrity; the carry allowlist handles unknown application fields without
pretending that `ssrfr` can identify every secret-bearing name.

The inverse — metadata marking headers sensitive — inverts the failure mode:
forgetting to mark a header leaks it silently, whereas forgetting to nominate one
as carryable merely breaks a request, loudly. Relying only on "drop
`Authorization` and `Cookie`" is an enumerated denylist of secrets, and the
working token-replay PoC against the reference Ruby implementation succeeded
precisely because it replayed body, params, and custom headers that the
enumeration did not name (INV-8). The same argument INV-13 makes about address
ranges applies to unknown application header names.

Headers `ssrfr` defines as transport-owned and non-secret, such as the User-Agent,
are not caller-supplied and carry normally.

### 2.4 Opacity is ergonomic, not enforceable

A binding MUST resist casual detachment: accessor discipline, a class, locked
bindings. The specification MUST NOT claim more. R offers no sealed objects and no
capabilities, so a determined caller can reach inside. The value is that the wrong
thing becomes awkward, which is the path-of-least-resistance argument in
`ssrf-guard-spec.md` §13 — not that detachment is impossible.

### 2.5 Lifecycle: single-use publicly, failover internally

A binding has two independent capabilities, and invalidation removes only the
first:

| Capability | Meaning | Lifetime |
|---|---|---|
| **fetchable** | may be passed to `ssrf_fetch()` | single use |
| **referenceable** | may be passed as `from` to describe the previous hop | the life of the redirect chain |

Without that split, §2.5 and §2.6 contradict each other: a chain cannot be built
from bindings that are destroyed by being used. A spent binding remains readable —
it supplies the base URL, the hop index, the previous origin, the sanitized
plan, and the transport-observed response status — and carries no ability to open
a connection.

- **`ssrf_fetch()` MUST invalidate fetchability on entry.** A second call MUST fail
  with an *operational* error, never a policy refusal — the caller did not violate
  policy, they reused a spent object.
- **Failover is not replay.** Retrying the next address from the already-validated
  set happens *inside* one `ssrf_fetch()` call, and is required because
  `connect_to` does not fail over (`r-binding.md` §4.3). Callers never observe it
  as a second use.
- **A binding captures its policy by value** at prepare time. It therefore cannot
  be invalidated by a later policy change, because it holds no reference to one.
- **A wall-clock expiry SHOULD be set, with a short default.** This is
  **correctness, not security**: a stale binding still pins to an address that was
  validated, so using one late is not a bypass. It is a surprise, because the
  host's DNS answer may legitimately have moved since.

### 2.6 The chain

`from = prev_binding` supplies four things at once:

1. the base URL for reference resolution (§3.2),
2. the hop index for the redirect budget,
3. both origins, which is what INV-8 needs to decide whether credentials
   cross an origin boundary,
4. the transport-observed response status that determines method transformation.

The first hop is the call with `from = NULL`, which requires an absolute URL.

---

## 3. Input contract **[ratified]**

### 3.1 URL string, not components

`ssrf_prepare_hop()` accepts a URL string. A components form is **not** in v1.

OWASP advises applications not to accept complete URLs from users, and that
advice is correct at the *application* layer. `ssrfr` is not the application. By
the time the guard runs a URL exists on every real path: sitemaps contain URLs,
`Location` headers are URLs, webhook payloads carry URLs. Accepting components
would make `ssrfr` act on a host string it did not derive from the transport's
parser, violating INV-1's corollary at the front door. The application-layer
advice belongs in documentation, not in an API surface that weakens the
invariant. A components form is addable later without breaking this contract; the
reverse is not true.

### 3.2 Relative references are resolved by `ssrfr`

`Location` headers are commonly relative. `ssrfr` resolves them against the base
carried by `from` (§2.6). Callers MUST NOT be required to resolve references
themselves.

**Not because doing so would be unsafe.** A caller who resolves a reference with
a foreign resolver and passes the resulting absolute URL is still safe: `ssrfr`
re-parses it with the transport-agreeing parser and pins to what it derived, so a
bad resolver produces a crawl-correctness bug, not a bypass. A caller who passes
the relative reference through unresolved gets a `parse` refusal under INV-2,
which is fail-closed.

The reason is duplication. All three consumers follow redirects. If `ssrfr` does
not own reference resolution, each implements RFC 3986 §5.2 — or reaches for
`paste0()`, `xml2::url_absolute()`, or `httr::modify_url()`, three resolvers with
three answers for scheme-relative references like `Location: //evil.example/`.
That is the founding pathology of this package reproduced one layer up.

### 3.3 INV-1 corollary — merge, then re-parse

> Reference resolution MAY be performed by any conforming RFC 3986 §5.2
> implementation, because the merged result MUST then be re-parsed by the
> transport-agreeing parser before any security decision is taken. The merge
> chooses **which** URL is validated; it never determines **how** it is
> interpreted.

**[verified]** Transport-aligned reference resolution is not reachable through R's
`curl`: `curl_modify_url()` performs component substitution, not RFC 3986 §5
resolution — setting `path = "../up"` on `http://base.example/a/b/c` yields
`http://base.example/../up`, with no dot-segment merge — and `curl_parse_url()`
rejects a bare relative reference outright (*Bad scheme*). This corollary is what
licenses the merge to come from elsewhere.

### 3.4 INV-1 corollary — the address layer is downstream

The address layer MUST be fed the transport-agreeing parser's output, never raw
input. `curl_parse_url`(whatwg) resolves `0177.0.0.1` → `127.0.0.1` **[verified]**,
so the numeric-literal ambiguity is gone before address parsing begins. That
ordering is what makes address-layer delegation safe at all.

Canonicality is **not** the precondition — curl does not canonicalize IPv6
spellings, so `fd00:0ec2::254` survives the URL parse intact. Both halves are
load-bearing: correct input source, and value-based matching over the expanded
address (INV-3).

Classifying the raw host directly is the refactor that silently reinstates the
verified `0177.0.0.1` bypass. It MUST have a test asserting it cannot happen.

---

## 4. Dependency contract **[ratified]**

`curl`, `rurl`, and `raddr` are hard dependencies. **`ssrfr` owns no parser and no
classification tables.** It owns policy, refusal semantics, per-hop revalidation,
pinning, and conformance evidence.

| Provider | Supplies |
|---|---|
| `curl` | transport, `curl_parse_url` (the parse libcurl acts on), `nslookup(multiple = TRUE)`, `connect_to` pinning |
| `rurl` | `safe_parse_url(url_standard = "whatwg")`, parse status and verdicts (INV-2), `resolve_url()` (RFC 3986 §5.2 + canonicalization), IDNA via `punycoder` |
| `raddr` | address parsing, `addr_global_reachability()`, `addr_embeddings()`, `addr_within_any()`, IANA registry snapshots |

### 4.1 Why delegation rather than vendoring

`raddr` already implements what a vendored classifier would have to reinvent: a
positive routability predicate driven by IANA registry layers, returning `TRUE` /
`FALSE` / **`NA`**, with embeddings graded by their extracted address and decoders
for RFC 6052 (NAT64), RFC 3056 (6to4), and RFC 4380 (Teredo) — the three
mechanisms ADR-001 §2.3 identifies as missing from the inherited matcher. Its own
documentation states the layer contract this specification requires: *"It is a
fact, not a verdict."*

This reframes the revert of `a978f8d`. The correct fix was never to close the
vendored denylist's gaps range by range; it was to stop having a vendored
classifier.

`rurl` supplies the parse INV-1 requires. Its `whatwg` mode is `curl_parse_url`-backed
and agrees with what libcurl dials 16/16 across the obfuscation corpus
**[verified]**, so it satisfies INV-1 rather than threatening it — the corollary
against foreign parsers targets parsers from *other* stacks, not a wrapper over
the transport's own.

`punycoder` is a strict improvement over the transport here: **libcurl's IDN
support is build-optional**, so relying on the transport alone would mean
refusing all internationalized hosts. That is fail-closed but breaks a crawler
across a large slice of the web.

### 4.2 INV-1 is preserved by construction, not by hope

Delegating the parse would normally risk guard/transport divergence. The binding
design removes the risk: because the binding carries the sanitized URL that
`ssrf_fetch()` requests (§2.3), `ssrfr` hands libcurl the already-normalized URL
it validated. Agreement is structural.

### 4.3 The obligation that travels with a dependency

A dependency's correctness is **asserted by the corpus, never assumed** (§7):

- the parse-vector table MUST pin `rurl`'s host output against what libcurl dials;
- the verdict corpus MUST pin `raddr`'s facts against expected refusals.

`raddr` is version `0.1.0` and `ssrfr`'s guarantee rests on it. That is an argument
for the corpus being the contract between them, not for vendoring a worse copy.

---

## 5. The refusal rule **[proposed — not ratified, except §5.0 and §5.1]**

> The **gate set** below records the recommended position and is the open question
> `SSRF-aqrgqdhi` covers. How the gates **combine** (§5.0) and the treatment of
> indeterminacy (§5.1) are ratified.

Five **independent** gates, not one predicate. Independence matters because they
fail differently and MUST be separately testable.

| Gate | Source | Refuses when |
|---|---|---|
| 1. Reachability | `raddr` fact | `addr_global_reachability()` is `FALSE` **or `NA`** |
| 2. Multicast | `raddr` fact | the address is multicast |
| 3. Range rules | caller policy | matches `deny_ranges` |
| 4. Hostname rules | caller policy | matches `deny_hosts` |
| 5. Metadata hostname | built-in policy | matches the built-in metadata hostname list |

Gate 2 is not redundant with gate 1: "globally reachable" and "not multicast" are
different questions, and `ff0e::` is global-scope multicast.

### 5.0 Precedence **[ratified]**

"Deny wins" (INV-14) presupposes that an allow match does something. Stating only
that allow never overrides deny leaves `allow_hosts` and `allow_ranges`
operationally inert.

Precedence is four-tier and **dimension-local**: each dimension has its own
built-in layer, and an allow rule overrides only the built-in layer of **its own**
dimension.

| Tier | Address dimension | Hostname dimension |
|---|---|---|
| **1. Non-overridable** | reachability `NA` (§5.1) | — |
| **2. Caller deny** | `deny_ranges` | `deny_hosts` |
| **3. Caller allow** | `allow_ranges` — overrides tier 4 for the matched addresses only | `allow_hosts` — overrides tier 4 for the matched name only |
| **4. Built-in** | `addr_global_reachability()` is `FALSE`; multicast | the built-in metadata hostname list |

Evaluation: tier 1 refuses unconditionally; otherwise any tier-2 match refuses;
otherwise a tier-3 match permits **within its own dimension**; otherwise tier 4
applies. A request is permitted only when both dimensions permit.

#### What this settles

- **`allow_hosts = "example.com"` does NOT permit private addresses returned for
  that name.** The dimensions are separate. A hostname allow that authorized
  arbitrary DNS answers would convert a configuration convenience into the
  rebinding attack surface. Reaching an internal target by name requires
  authorizing the address as well.
- **`allow_ranges` overrides multicast.** Multicast is a determinate built-in
  classification, and tier 3 overrides determinate built-ins. Carving it out would
  add a rule with no threat behind it and would push an operator with a genuine
  multicast target toward the off switch, which is strictly worse. This is a MUST
  for conforming v1 implementations, not implementation discretion.
- **Neither allow rule overrides `NA`.** §5.1.
- **Rules are not cross-dimensional.** `allow_ranges` cannot un-deny a hostname;
  `allow_hosts` cannot un-deny an address.

#### The extension worth flagging

A purely dimension-local reading leaves `allow_hosts` inert after all, because the
hostname gate as first drafted refused only on a caller `deny_hosts` match — and
tier 3 cannot override tier 2. So there would be nothing for it to act on.

It has real work because the hostname dimension has a **built-in** denial layer of
its own: the metadata hostname list that ADR-001 §2.4 establishes as a permanent
first-class control, needed for services like Equinix Metal and IBM VPC that have
no link-local address at all. `allow_hosts` overrides that layer, and only that
layer. Splitting built-in from caller-configured *within each dimension* is what
makes the model symmetric.

Consequence: in the ordinary case — `internal-api.corp` resolving to `10.0.0.5` —
only `allow_ranges` is required, because nothing denies the name. `allow_hosts` is
the narrow tool for when the name itself is denied by a built-in rule. Narrow is
not inert.

Gate 4 is a permanent, first-class control, not legacy convenience. Some metadata
services have no link-local address at all and are reached over public DNS and
HTTPS (Equinix Metal, IBM VPC), making them invisible to any address classifier,
including a perfect one.

### 5.1 `NA` refuses, whatever it means upstream

`ssrfr` MUST refuse on `NA` regardless of `raddr`'s intent for that value
(INV-11). There is no path from "we could not determine this" to "proceed."

**No allow rule overrides this** (§5.0, tier 1). An allow rule is a statement about
a *known* range or name; it is not a licence to permit input the classifier could
not decode. Reading it as one would reinstate exactly the malformed-literal
fail-open that ADR-001 §3 closed.

### 5.2 Embeddings belong to `raddr`

`ssrfr` MUST NOT re-extract embedded addresses. `addr_global_reachability()`
already grades an embedding by its extracted address, so a second extraction
would create a second decoder inventory — the duplication this specification
exists to remove. `ssrfr`'s obligations are to refuse when the fact is `FALSE` or
`NA`, and to report which embedding form was involved for the reason code.

**The reviewer's objection to answer:** defense in depth normally argues for
checking twice. It does not here, because two decoder inventories diverge, and
divergence in this exact code is the documented history of the stack.

---

## 6. Result and reason model

### 6.1 Codes are a compatibility surface **[ratified]**

Reason codes are API: `kebab-case`, documented, stable, and enumerable at
runtime. `robotstxtr` and `sitemapr` publish the inherited values in their
reference documentation, so renaming breaks them (S6).

### 6.2 Two outcome classes **[ratified]**

Callers MUST be able to branch on **refused by policy** versus **failed on the
wire** without string matching. The token for policy refusal MUST NOT be reused
for network failure.

### 6.3 Vocabulary alignment **[open]**

Whether `raddr`'s own code vocabulary (`addr_codes`, `addr_category`) aligns with
or conflicts with the published `ssrfr` values is **unverified**. This is the
first thing to check, and it determines whether a mapping layer is needed. Until
it is checked, §5.2's reason-code obligation cannot be specified concretely.

The two inherited misnomers are corrected deliberately rather than propagated:
CGNAT `100.64.0.0/10` reported as `cloud-metadata`, and IPv6 unique-local space
reported as `cloud-metadata` while the space containing it went unblocked
(`ssrf-guard-spec.md` §5.2).

### 6.4 Operator detail versus external result **[ratified, with a documented limit]**

Operators receive the full factual record. Untrusted callers receive a minimized
result.

**The mechanism, since `ssrfr` cannot infer trust.** In R the caller *is* the
application, which is the operator; there is no signal distinguishing a trusted
caller from an untrusted one. Therefore:

- `ssrfr` MUST return the full factual record to its caller.
- `ssrfr` MUST ship a named minimizing projection — e.g.
  `ssrf_public_reason(refusal)` — reducing a refusal to a value carrying no
  predicate, no address, and no hop index.
- Applying that projection at the boundary where an untrusted party receives the
  result is the **application's** obligation, and this specification says so
  explicitly rather than leaving it implied.

Assigning projection to the application boundary *without* shipping the projection
would guarantee that every consumer writes their own and some of them leak. That
is the difference between a requirement and a hope.

- **Shape: MUST.** Refusals MUST NOT expose which predicate fired, which address,
  or which hop to an untrusted caller.
- **Timing: SHOULD, best-effort.** Timing uniformity is in direct conflict with
  the specification's own normative lifecycle order. `ssrf-guard-spec.md` §3.1
  requires scheme and port checks *before* resolution, so that a `file://` host
  never triggers a DNS query to an attacker-controlled zone. That ordering
  guarantees informative timing: a scheme refusal returns in microseconds, an
  address refusal after a DNS round-trip. Equalizing them requires artificial
  padding bounded by DNS timeouts `ssrfr` does not control. The conflict MUST be
  documented as a known limitation rather than papered over.

This resolves the tension `ssrf-guard-spec.md` §4 INV-12 records as unresolved:
it is not a tension between diagnostics and secrecy, it is a question of *who*
receives the facts. An attacker probing an endpoint is not the audience the
transparency principle was written for.

---

## 7. Conformance **[ratified]**

Conformance is declared by publishing results against the corpus, not by code
sharing (`ssrf-guard-spec.md` §10). Coverage is not the metric: the reference Ruby
implementation advertised 100% coverage and had two bypasses reported by
outsiders.

Corpus components:

1. **Verdict vectors** — inputs, expected outcome, expected reason code, and the
   layer that must catch each. Includes the inherited IPv6 spelling tables, which
   already encode two production bugs, ported verbatim.
2. **Parse vectors** — inputs where parsers disagree, with a ground-truth column
   measured from this stack. Regenerating in CI turns an upstream parser change
   into a visible diff instead of a silent bypass.
3. **Requirement coverage** — external requirement IDs mapped to demonstrating
   tests, each marked enforced-by-library, enforced-by-application, or out of
   scope.
4. **Dependency pinning** — §4.3.

### 7.1 The evidence base MUST be committed

Every `[verified]` and `[sourced]` claim in this stack's specifications currently
cites `_scratch/research/`, which is git-ignored by policy. For a security
library whose central claim is that its properties are tested rather than
asserted, the citation chain MUST live in the repository: reproducible probe
scripts, distilled test fixtures, and source citations. Until then the normative
claims are unfalsifiable by anyone but their author.

---

## 8. Open decisions

| # | Decision | Status |
|---|---|---|
| 1 | The refusal rule (§5) | **proposed**, awaiting ratification — `SSRF-aqrgqdhi` |
| 2 | `raddr` ↔ published reason-code alignment (§6.3) | **blocked on verification** |
| 2a | The request plan as an input to `prepare` (§2.3) | **closed — ratified**, with transport-derived redirect status, mandatory plan inheritance, and constrained carryable-header nomination. |
| 2b | Allow/deny precedence (§5.0) | **closed — ratified** as a four-tier, dimension-local matrix; `allow_ranges` overrides determinate multicast classification. |
| 2c | The gate set itself (§5, table) | still **proposed** — `SSRF-aqrgqdhi`. §5.0 settles how gates combine, not which gates exist. |
| 3 | Whether any limit is a non-overridable floor | open — `SSRF-pffrmkdr` |
| 4 | Search-domain resolution: a bare hostname can resolve through DNS search suffixes to something internal; a root dot defeats it but changes `Host` and SNI | open |
| 5 | Default User-Agent | open |
| 6 | Cross-platform re-verification of every transport finding (all are macOS-only; the INV-6 pin fail-open is libcurl-internal and MUST NOT be assumed portable) | open, v1 blocker |
| 7 | IPv6 pinning with a bracketed literal; the connection-reuse interaction in INV-7's corollary | unverified |

**Closed by this document:** component-wise versus whole-URL API (§3.1,
`SSRF-tnxmqvou`); whether the L2 result is a boolean (§2.1); the dependency
posture (§4); whether to build a C core (no — a shared parser would undermine
INV-1, and the only prize is a pre-connect veto, which is better pursued as an
upstream `curl` enhancement exposing `sockoptfunction`).

---

## 9. Non-goals

As S5, plus: `ssrfr` does not attempt to protect against a compromised system
resolver, and does not claim compliance beyond the citations permitted in
`ssrf-guard-spec.md` §11.

---

## 10. Consequential amendments required elsewhere

This document contradicts committed material. The contradictions are deliberate
and MUST be resolved in the source documents rather than left standing.

| Document | Section | Change |
|---|---|---|
| `ADR-001` | §5 and §7 | **Resolved by ADR-002.** It records the four-tier exception model and makes `raddr` and `rurl` hard dependencies; release ordering is a submission-time scheduling concern rather than a design input, and the `ssrf_in_cidr()` seam is unnecessary. |
| `r-binding.md` | §1 | Dependency position reversed: the offline core is no longer vendored base R. Also record the measured weights — `raddr` → `rlang`, `vctrs`; `rurl` → `stringi`, `punycoder` (Rcpp/C++), `pslr` (cpp11/C++) — which invert BRAINSTORM §8's assumption that `raddr` was the heavy one. |
| `r-binding.md` | §2 | Add `resolve_url()` and §3.3's verified finding that `curl` cannot resolve references. |
| `ssrf-guard-spec.md` | §2 | Add the binding to the layer model; L1 exposes no roll-up (§1.2). Its L1 guarantee — *"Every address this host currently resolves to is permitted"* — is a roll-up claim and MUST be restated as *classified*, per §1 above. This document inherited the defective phrasing from there. |
| `ssrf-guard-spec.md` | §8 | **Resolved.** The configuration model now adopts §5.0's four-tier, dimension-local precedence matrix. |
| `ssrf-guard-spec.md` | §4 INV-8 | **Resolved.** The invariant now requires a guarded request plan, transport-derived redirect status, and the constrained cross-origin carry model (§2.3). |
| `ssrf-guard-spec.md` | §2.1 | Replace the L0 naming rationale with §1.1's: L0 is misnamed as a gate because it does not answer that question, not merely because the name is dangerous. |
| `ssrf-guard-spec.md` | §6 | Classification delegation is concrete: `raddr`, per §4. |
| `ssrf-guard-spec.md` | §9 | The result model is superseded by the binding model (§2). |
| `ssrf-guard-spec.md` | §4 INV-12 | The diagnostics tension is resolved by §6.4; record the MUST/SHOULD split and the ordering conflict. |
| `ssrf-guard-spec.md` | §12 | Close decisions 1 and 2 per §8. |
