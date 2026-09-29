---
status: draft
version: 1.6.0-draft
date: 2026-09-25
tracking: SSRF-xrlijlqq, SSRF-ibxdyzcy
---

# `ssrfr` v1 specification

This is `ssrfr`'s **single normative document**: what it is for, what it
guarantees, what it depends on, its primitives, its security invariants, its
reason codes, and how conformance is shown. RFC 2119 keywords apply.

It absorbed the former `ssrf-guard-spec.md` (`0.1.0-draft`, 2026-07-25) on
2026-09-24 (ADR 0003). Part I is the `ssrfr` contract. Part II is the security
contract that Part I cites: threat model, lifecycle, invariants, transport
requirements. §10 maps every section of the retired document to its home here.

| Document | Role |
|---|---|
| this file | **The contract.** Where anything else disagrees, this file wins and the other is a defect. |
| [`r-binding.md`](r-binding.md) | R and libcurl evidence: option names, verified transport behaviour, test layers. States no policy of its own. |
| [`../adr/`](../adr/) | Why decisions were taken. Accepted ADRs are frozen; ADR 0003 records what in 0001 and 0002 is no longer accurate. |
| [`../evidence/`](../evidence/) | Committed probe scripts behind `[verified]` claims dated 2026-09-24 or later (§7.1). |

## Status markers

Only **[ratified]** text may be implemented against.

| Marker | Meaning |
|---|---|
| **[ratified]** | Accepted by the maintainer. |
| **[proposed]** | Recommended position awaiting ratification. None remains since §8 item 34 closed on 2026-09-29. |
| **[open]** | Undecided. |
| **[inherited]** | Carried from the retired guard spec and not separately ratified. None remains since §8 item 14 closed on 2026-09-24. |
| **[suspended]** | A ratified clause whose stated premise has since been found false. It is not implementable until re-ratified. The correction and a **[proposed]** replacement sit directly beside it. None remains since 2026-09-25. |

**Ratified 2026-09-24:** the gate set (§5), the reason-code mapping (§6.5), the
parse boundary (§4.1, §4.2), embedding evaluation (§5.2), limits and policy
fields (§5.3), and Part II, as answered in the v1 decision brief (fp brainstorm
`nftbfuli`; ADR 0004). **Ratified 2026-09-25:** the local research-note
findings proposed on 2026-09-24 (§8 item 23, `SSRF-nbcgyled`), with INV-10's rationale
corrected (ADR 0006). **Ratified 2026-09-25:** §8 items 25–31, by a
unanimous four-model vote during v1 planning (`SSRF-cnljaaek`; ADR 0007), and
items 32–33, two gaps a review of the implementation tickets found.
**Ratified 2026-09-29:** §8 item 34, the printable-ASCII wire string and
parsed host (§4.1, `SSRF-ljqshjmj`).
The transport findings are verified on macOS and Linux (§8 item 7 closed);
Windows is outstanding under §8 item 6 (`SSRF-fjgfnaaq`), a v1 release blocker.

**Evidence tags.** **[verified]** was tested empirically; **[sourced]** cites
external evidence; **[assumption]** is neither. A tag is promoted only with new
evidence. Probe scripts are in [`../evidence/`](../evidence/) and source
citations in [`../references.md`](../references.md); §7.1 makes committing that
base a requirement.

---

# Part I — the `ssrfr` contract

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
(`download.file()`, `url()`, `readLines()`, and direct `curl` use), nor the
packages that read URLs through them: `jsonlite::fromJSON(url)` reaches `url()`
and `data.table::fread(url)` reaches `download.file()` **[verified]**
(`design/evidence/2026-09-24-r-http-clients.R`).
`xml2::read_xml(url)` and `read_html(url)` belong to the same list: they open the
URL with `curl::curl()`, or `url()` without `curl` **[verified]**
(`design/evidence/2026-09-24-content-fetches.R`). So do the `curl`
command-line tool, whether run through `system()` or as
`download.file(method = "curl")`, which also reads the user's `~/.curlrc`;
libcurl itself does not read that file. `ssrfr` therefore offers no "equivalent
`curl` command" helper. *Ratified 2026-09-25* (`SSRF-qttneqxp`). It is not a
general-purpose URL parser or validator. DNS integrity is out of scope: a
compromised resolver defeats it, and `ssrfr` cannot pin its own resolver because
`dns_servers` requires a c-ares build. Inbound request security is a different
problem.

**S6 — Consolidation is the migration path, not the purpose.** The duplicated
matchers in `robotstxtr` and `sitemapr` are `ssrfr`'s first consumers and its
evidence of demand. Their published reason-code vocabulary is a compatibility
obligation (§6.5). Neither is the reason the package exists. They migrate
straight to the guarded fetch, calling `ssrf_prepare_hop()` and `ssrf_fetch()`
from their own loops once L2 ships; `ssrfr` ships no L0 compatibility adapter
for their vendored matchers, which would keep an L0 check running as a gate
(§1.1). Each consumer tracks its migration in its own repository. *Ratified
2026-09-25* (§8 item 31, `SSRF-cnljaaek`, ADR 0007).

---

## 1. Layer contracts **[ratified]**

| Layer | I/O | Returns | Guarantee |
|---|---|---|---|
| **L0** structural | none | classification facts | the host/scheme is not *self-evidently* prohibited. **Not a defense.** |
| **L1** resolved | DNS | the resolved address set with per-address classification | every address this host resolved to at check time was **classified**; prohibited and indeterminate outcomes are preserved per address |
| **L2** guarded | DNS + TCP | a refusal or a binding (§2) | the connection went to an address that was validated |

*Clarified 2026-09-24:* "every address this host resolved to" means every
address the single resolver call returned. That set is shaped by the hosts file,
the name-service configuration and address-selection filtering; `ssrfr` does not
claim it is every record the zone publishes (INV-4).

The layers MUST be exposed as distinct layers. Collapsing them is
the defect described in `CVE-2026-41488`, whose
advisory names the anti-pattern: *"validate-then-fetch with separate DNS
resolution."* **[sourced]**

### 1.1 L0 is a reporter, not a gate

L0 MUST return a classification, not a verdict. Names implying a security
decision — `is_safe()`, `check()`, `validate()` — are **non-conforming**.
Implementations MUST document L0 as a fast pre-filter and
configuration-linting aid.

The primary reason is that **L0 does not answer that question at all.** It
reports what a host string is, in the same way `raddr` reports what an address
literal is. Naming it as a gate misdescribes its return type, and a two-state
verdict flag cannot express indeterminacy — the defect that caused the revert of
`a978f8d`. A secondary reason is that the name is dangerous: a caller who
believes L0 is the defense has an SSRF vulnerability. One maintainer of a mature
implementation refuses to ship an L0-equivalent at all — *"the checking and
fetching have to happen in a single step"* **[sourced]** — an objection answered
by naming and documentation, not by denying the layer exists.

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
only offers "we own the fetch" is non-conforming.

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
ssrf_fetch(binding)           → response  OR  operational failure
                                OR  refusal, `redirect-limit` only (§12 step 13)
```

A redirect past the chain's budget is a policy decision, not a transport fault, so
`ssrf_fetch()` returns it as a refusal with code `redirect-limit` (§6.5, §8 item
33) rather than as a response. *Amended 2026-09-27* (was "→ response";
`SSRF-fvtqbanc`).

`ssrf_fetch()` takes **one** argument. There is no URL parameter and no header,
method, or body parameter, so there is no substitution surface.

**The response owns nothing.** `ssrf_fetch()` reads and decodes the
whole body within `max_response_size` and `total_timeout` before it returns, and
the connection is closed (§14, no reuse). The response is a plain R value —
status, response headers, decoded body — holding no handle, connection or file,
so the caller has nothing to close. The transport facts stay on the spent
binding (§2.5). Streaming the body or writing it to a file is beyond v1.

The response's `print` and `format` methods show the status, the media type
without its parameters, and the decoded body size. They show no body and no
other response header value; the body is read through an accessor. A fetched
body is attacker-chosen: it can carry terminal control sequences, secrets or
megabytes, and a printed response ends up in application logs. *Ratified
2026-09-25* (§8 item 28, `SSRF-cnljaaek`).

**The loop helper.** `ssrf_fetch_chain(url, policy, request)` follows a
redirect chain for a caller without a loop of its own. It is built only on
`ssrf_prepare_hop()` and `ssrf_fetch()`, calling them exactly as a caller's
loop would, and it takes no argument those two do not. It returns what the
chain's last call returned: the final response, or the refusal or operational
failure that ended the chain. It follows only a followed redirect (§2.3). §1.3
still holds: the per-hop primitives stay public, and the helper adds no
capability they lack. Its purpose is §9's path of least resistance for plumber
endpoints, Shiny apps and webhook receivers, which otherwise hand-roll a loop
or skip the guard. *Ratified 2026-09-25* (§8 item 25, `SSRF-cnljaaek`).

### 2.3 What a binding contains, and what enters at `prepare`

**Security identity** — what was authorized:

- the canonical origin: scheme, hostname, port, **excluding userinfo**
  (INV-8 requires credentials to be droppable, so they MUST NOT be capturable in
  a binding)
- the policy and hop context under which evaluation occurred
- the validated address set, and the selected pinned address
- the TLS verification settings, which MUST remain bound to the hostname (INV-9)

Two origins are the same when their schemes are equal, their hosts are equal
after §5.0's hostname normalization (IDNA A-label, ASCII-lowercased, one
trailing root dot removed), and their effective ports are equal, an omitted port
counting as the scheme's default. This is the equality INV-8 and §2.6 apply;
`EXAMPLE.com` and `example.com.:443` are the same `https` origin as
`example.com`. *Ratified 2026-09-25* (`SSRF-qttneqxp`).

**Request data** — carried, not authorized:

- the exact sanitized URL `ssrf_fetch()` will request, including path and query
- the sanitized request plan: method, headers, body

The sanitized URL carries no fragment. A fragment is not part of
the target URI (RFC 9110 §7.1) and is never sent, so `prepare` removes it, from a
first-hop URL and a resolved `Location` alike, before serializing the string
libcurl parses (§4.2). The fragment inheritance RFC 9110 §10.2.2 asks of a user
agent changes only the reference, never the target URI, and `ssrfr` does not
perform it.

Binding the full URL closes the substitution surface. The path is not an
independently authorized network target: for `http`/`https` it cannot be one, and
the CRLF-in-selector chain that reaches Redis is a `gopher://` property removed by
scheme allowlisting.

#### The request plan is an input to `prepare`, never to `fetch` **[ratified]**

INV-8 requires dropping `Authorization`, `Cookie`, and any caller-supplied header
or body carrying a secret on a cross-origin redirect. Redirect semantics also
transform the method and body for some status/method combinations. **None of that
is expressible if the binding carries only a URL** — the invariant would have
nothing to act on. And adding headers as extra `ssrf_fetch()` arguments would
recreate exactly the substitution surface §2.1 exists to remove.

A GET-only v1 does not avoid the problem. `ssrfr` owns the transport, so it owns
the User-Agent (§5.3); headers exist by necessity from the first request.

So the request plan enters at `prepare`. The guard evaluates it as part of the hop
decision — userinfo rejection, credential-bearing headers, method and body
transformation for the status code — and the binding carries the **sanitized**
plan. The credential drop becomes a recorded fact inside the binding rather than a
side effect of the fetch, which is what makes it auditable under S4.

**Consequence: a binding may contain secrets.** Its `print` and `format` methods
MUST redact credential-bearing fields, and §2.4's limits on opacity apply with
more force, not less. The same holds for every refusal,
operational failure and R condition `ssrfr` produces: none quotes userinfo, a
request-plan header value or body, or the value of an ambient proxy setting it
neutralized (INV-10), and a URL in one is rendered without userinfo.

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

A response is a *followed redirect* when its status is 301, 302,
303, 307 or 308 (the Fetch Standard's redirect statuses) and it carries exactly
one `Location` field line. A redirect status without `Location` is a final
response, as in Fetch, so its binding is not accepted as `from`. More than one
`Location` field line is `protocol-error` (§6.6). No other 3xx status is
followed.

Once the chain's redirect budget is spent, including under `max_redirects = 0`,
every 3xx response refuses as `redirect-limit`, whether or not it carries
`Location` and whether or not its status is one `ssrfr` follows: a `304` or a
`Location`-less `302` is then a refusal, not a final response. While budget
remains, the rule above applies. This is §5.3's "refuse any 3xx" read
literally, as the OWASP sources behind it intend; a caller that expects a `304`
raises `max_redirects`. *Ratified 2026-09-25* (§8 item 33, `SSRF-cnljaaek`
review).

The deterministic v1 transformation is:

| Status | Next-hop method and body |
|---|---|
| 301 or 302 | `POST` becomes `GET` and its body is dropped; other methods are preserved |
| 303 | `HEAD` remains `HEAD`; every other method becomes `GET`; the body is dropped |
| 307 or 308 | method and body are preserved, subject to the cross-origin rule below |

This is the behavior `ssrfr` chooses from RFC 9110 §15.4. The RFC permits, rather
than requires, the historical POST-to-GET transformation for 301 and 302; 307 and
308 prohibit changing the method during automatic redirection. Whenever the body
is dropped, whether by a method transformation or by the cross-origin rule below,
fields describing that body (`Content-Type`, `Content-Encoding`,
`Content-Language`, `Content-Length`, and the other content-specific fields RFC
9110 §15.4 names) MUST also be dropped. Nomination as carryable does not survive
the body it describes: a cross-origin 307 or 308 therefore sends the preserved
method with neither the body nor a nominated `Content-Type`.

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
body is also non-carryable across origins in v1. Transport-controlled routing and
framing fields MUST NOT be accepted as caller-supplied headers at all, matched
case-insensitively: `Host`, `Connection`, `Proxy-Connection`, `Keep-Alive`,
`Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Content-Length`,
`Accept-Encoding` (the transport sets it, §5.3, and decodes accordingly) and
`Expect` (the transport suppresses it: under `100-continue` a `417` makes libcurl
send the request a second time, against §2.5), plus any name beginning with `:`
(HTTP/2 and HTTP/3 pseudo-headers). *Amended 2026-09-26* (`Expect` added;
`SSRF-rgcijatt`). A caller-supplied
field whose name is not a valid RFC 9110 token, or whose value contains CR, LF, or
NUL, is refused rather than sanitized. Violations are operational errors raised at
`prepare`. These fixed rules cover protocol-defined credentials and routing
integrity; the carry allowlist handles unknown application fields without
pretending that `ssrfr` can identify every secret-bearing name.

Metadata-service request markers are refused at `prepare` the same
way, unless the policy's `allow_ranges` names a provider endpoint exactly (§5.0):
`Metadata`, `Metadata-Flavor`, `X-Google-Metadata-Request`,
`X-aws-ec2-metadata-token`, `X-aws-ec2-metadata-token-ttl-seconds`,
`X-aliyun-ecs-metadata-token`, `X-aliyun-ecs-metadata-token-ttl-seconds`,
`Metadata-Token` (Linode, Vultr), `Metadata-Token-Expiry-Seconds` (Linode) and
`X-Metadata-Token-Ttl-Seconds` (Huawei Cloud). They exist only to show a
metadata service that a request was meant for it. A name is admitted only when
current vendor documentation shows it sent to an endpoint in gate 2's table
(§5), and it matches exactly, case-insensitively; a header a vendor uses
elsewhere, such as Huawei's `X-Security-Token` for its public APIs or Azure App
Service's `X-IDENTITY-HEADER` for its local identity endpoint, does not qualify.
*Ratified 2026-09-25* (`SSRF-qttneqxp`). The
list cannot be complete: Oracle's marker is `Authorization: Bearer Oracle`, which
no header rule can refuse.

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
thing becomes awkward, which is the path-of-least-resistance argument in §9 — not
that detachment is impossible.

### 2.5 Lifecycle: single-use publicly, failover internally

A binding has two independent capabilities, and invalidation removes only the
first:

| Capability | Meaning | Lifetime |
|---|---|---|
| **fetchable** | may be passed to `ssrf_fetch()` | single use |
| **referenceable** | may be passed as `from` to describe the previous hop | the life of the redirect chain |

Without that split, the single-use rule and the chain (§2.6) contradict each
other: a chain cannot be built from bindings that are destroyed by being used. A
spent binding remains readable — it supplies the base URL, the hop index, the
previous origin, the sanitized plan, and the transport-observed response status —
and carries no ability to open a connection.

- **`ssrf_fetch()` MUST invalidate fetchability on entry.** A second call MUST fail
  with an *operational* error, never a policy refusal — the caller did not violate
  policy, they reused a spent object.
- **Failover is not replay.** Retrying the next address from the already-validated
  set happens *inside* one `ssrf_fetch()` call, and is required because
  `connect_to` does not fail over (`r-binding.md` §4.3). Callers never observe it
  as a second use. Failover advances only after an attempt that
  ended before a connection was established, so no request byte reached any
  peer; an elapsed `connect_timeout` is such an attempt. Every other outcome ends
  the fetch with its own cause (§6.6). `pin-mismatch` is never followed by
  another attempt: it means the pin did not hold, and a further attempt would
  open a further unvalidated connection. Attempts follow the order the resolver
  returned the addresses in (RFC 6724 destination selection); `ssrfr` does not
  interleave address families itself. *Ratified 2026-09-25* (`SSRF-qttneqxp`).
- **No retries.** `ssrf_fetch()` sends the request at most once;
  failover to another validated address after a failed connection is its only
  re-attempt. An application that retries calls `ssrf_prepare_hop()` again,
  which resolves and validates afresh; on a redirect hop it passes the same
  `from`, which stays referenceable. `total_timeout` bounds one pass down the
  chain; it does not count attempts the caller discarded.
- **A binding captures its policy by value** at prepare time. It therefore cannot
  be invalidated by a later policy change, because it holds no reference to one.
- **Per-hop policy, chain-scoped budgets.** On a redirect hop, the `policy`
  argument governs that hop's evaluation; that is what §1.3's per-hop policy
  means, and the caller could have supplied the same rules on the first hop
  anyway. The two chain budgets are not per-hop: `max_redirects` and
  `total_timeout` are fixed by the first hop's policy and inherited through
  `from`, together with the hop index and the time the chain has consumed. A
  redirect-hop policy that states a different `max_redirects` or `total_timeout`
  is an operational error, not a silent override, so a loop cannot extend its own
  budget mid-chain by rebuilding its policy object. `total_timeout` bounds the
  time spent inside the chain's `ssrfr` calls (resolution, connection, transfer,
  decoding), not the caller's own work between hops; `connect_timeout` applies to
  each connection attempt.
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

On a redirect hop, `url` MUST be the `Location` value the previous response
carried, byte for byte, as `from` recorded it; any other value raises
`ssrfr_error_invalid_from`. A redirect goes where the server pointed, and the
caller cannot re-aim it: an application that wants a different URL starts a new
chain with `from = NULL`. *Amended 2026-09-27* (`SSRF-fvtqbanc`).

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

**Not because doing so would be unsafe.** An absolute URL from a foreign resolver
would be safe to decide: `ssrfr` re-parses what it is given with the
transport-agreeing parser and pins to what it derived, so a bad resolver would
produce a crawl-correctness bug, not a bypass. A redirect hop still refuses it:
its `url` is the `Location` byte for byte (§2.6), so a pre-resolved URL raises
`ssrfr_error_invalid_from`. A relative reference passed without `from` gets a
`parse` refusal under INV-2, which is fail-closed. *Amended 2026-09-27* (was "A
caller who resolves a reference with a foreign resolver and passes the resulting
absolute URL is still safe: … A caller who passes the relative reference through
unresolved gets a `parse` refusal"; `SSRF-fvtqbanc`).

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
licenses the merge to come from elsewhere: `rurl::resolve_url()`, which since
`rurl` 3.0.0 parses the reference under the selected standard before merging
**[verified]**, `design/evidence/2026-09-24-dependency-probes.R`.

### 3.4 INV-1 corollary — the address layer is downstream

The address layer MUST be fed the transport-agreeing parser's output, never raw
input. `curl_parse_url` resolves `0177.0.0.1` → `127.0.0.1` **[verified]**, so
the numeric-literal ambiguity is gone before address parsing begins. That
ordering is what makes address-layer delegation safe at all.

Canonicality is **not** the precondition. Both halves are load-bearing: correct
input source, and value-based matching over the expanded address (INV-3).

*Correction 2026-09-24:* the example first given here — that libcurl leaves
`fd00:0ec2::254` uncompressed — does not hold for `curl` 8.0.0 on libcurl 8.14.1,
where `curl_parse_url()` returns `[fd00:ec2::254]` **[verified]** (evidence
script, block 6). `[::ffff:127.0.0.1]` does survive unconverted. The conclusion
is unchanged: spellings vary by parser and version, so matching is by value.

Classifying the raw host directly is the refactor that silently reinstates the
verified `0177.0.0.1` bypass. It MUST have a test asserting it cannot happen.

---

## 4. Dependency contract **[ratified]**

`curl`, `rurl`, and `raddr` are hard dependencies. **`ssrfr` owns no parser and no
general address-classification tables.** It owns policy, refusal semantics,
per-hop revalidation, pinning, and conformance evidence.

`ssrfr` does own *policy data*: the built-in metadata hostname list, and the
provider-endpoint address table of §5, gate 2. Neither is IANA registry data, and
`raddr` assigns both to `ssrfr` (`raddr` `docs/architecture.md`, "Cloud-metadata
endpoint tables | `ssrfr`"). *Amended 2026-09-24* from "no classification
tables" (ADR 0004).

| Provider | Supplies |
|---|---|
| `curl` | transport, `curl_parse_url` (the parse libcurl acts on), `nslookup(multiple = TRUE)`, `connect_to` pinning |
| `rurl` | `safe_parse_url(url_standard = "whatwg")`, parse status and verdicts (INV-2), `resolve_url()` (RFC 3986 §5.2 + canonicalization), IDNA via `punycoder` |
| `raddr` | address parsing, `addr_global_reachability()`, `addr_embeddings()`, `addr_within_any()`, IANA registry snapshots |

As of 2026-09-24 all three are on CRAN: `rurl` 3.0.1 (2026-09-09) and `raddr`
0.1.2 (2026-09-21) **[verified]**. Minimum versions: `rurl (>= 3.0.0)`, the
first release with the parser in-tree, the layered verdicts §4.2 gates on and
standard-aware `resolve_url()`; `raddr (>= 0.1.2)`, its first published release.
`url_standard` still defaults to `NULL` in `rurl` 3.0.0, so `ssrfr` MUST pass
`url_standard = "whatwg"` on every call **[verified]** (`rurl` `R/verdicts.R`,
`R/resolve.R`).

### 4.1 Why delegation rather than vendoring

`raddr` already implements what a vendored classifier would have to reinvent: a
positive routability predicate driven by IANA registry layers, returning `TRUE` /
`FALSE` / **`NA`**, with decoders for the three embedding forms ADR 0001 §2.3
identified as missing from the inherited matcher — RFC 6052 (NAT64), RFC 3056
(6to4), RFC 4380 (Teredo). Its own documentation states the layer contract this
specification requires: *"It is a fact, not a verdict."*

*Clarified 2026-09-24:* this paragraph also said embeddings are "graded by their
extracted address". That holds for an embedding row passed to `raddr`, not for
the outer address; see §5.2. `raddr` 0.1.2 decodes more forms than these three
(ISATAP, the IPv4-mapped family, network-specific NAT64 prefixes).

This reframes the revert of `a978f8d`. The correct fix was never to close the
vendored denylist's gaps range by range; it was to stop having a vendored
classifier.

The host that keys the pin and feeds the address layer is libcurl's own parse:
`curl::curl_parse_url()` applied to the exact URL string the binding will hand to
libcurl. Calling the transport's parser is not vendoring one; it is what INV-1
asks for. `rurl` parses the string `ssrf_prepare_hop()` received, and `ssrfr`
serializes `rurl`'s result into the string libcurl parses (`r-binding.md` §2.1);
*corrected 2026-09-25* (was "`rurl` parses the same string first").
`rurl` supplies what libcurl cannot:
reference resolution (§3.2), UTS-46/IDNA mapping (libcurl's IDN support is
build-optional, and off in the evidence build), numeric-literal shape
diagnostics, and the layered verdicts §4.2 gates on. If `rurl`'s host and
libcurl's host differ in value after normalization (addresses compared as `raddr`
values, names as A-labels), the hop is refused as `parse`: disagreement between
two parsers is the ambiguity INV-2 forbids.

The check is a named test (`r-binding.md` §7), not only a corpus property.
`rurl` 3.0.1 maps a fullwidth `＃`, `／`, `？` or `：` (U+FF03, U+FF0F, U+FF1F,
U+FF1A) in a host to its ASCII form and keeps it there, where WHATWG refuses the
host; libcurl then reads `http://127.0.0.1＃.evil.com/` as host `127.0.0.1`, and
only this check (or libcurl's parse failure, for the colon) refuses the hop
**[verified]** (`design/evidence/2026-09-25-fullwidth-separators.R`; upstream
`RURL-crsrkcoh`). *Ratified 2026-09-25* (`SSRF-qttneqxp`).

*Replaced 2026-09-24* (was **[suspended]**). The ratified text said `rurl`
supplies the parse INV-1 requires, because its `whatwg` mode was
`curl_parse_url`-backed and agreed with what libcurl dials 16/16 across the
obfuscation corpus. `rurl` 3.0.0 removed `curl` from its imports and parses
`http`/`https` in-tree (`rurl` `NEWS.md`, 3.0.0; evidence script, block 4). A
106,898-input comparison found zero component differences at the time of the
swap, and `rurl`'s own source notes that its serialized `url` field differs from
libcurl's re-serialization in about 20% of a 53k corpus. Agreement with libcurl
is therefore a measured property, no longer an architectural one.

`punycoder` is a strict improvement over the transport here: **libcurl's IDN
support is build-optional**, so relying on the transport alone would mean
refusing all internationalized hosts. That is fail-closed but breaks a crawler
across a large slice of the web.

*Clarified 2026-09-24:* it follows that the binding hands libcurl a URL whose host
is already in A-label form; the build used for the 2026-09-24 evidence has IDN
support off.

*Ratified 2026-09-29* (§8 item 34, `SSRF-ljqshjmj`). The string handed to
libcurl, with the fragment removed (§2.3), MUST be printable ASCII (U+0021 to
U+007E); any other string refuses as `parse` before `curl_parse_url()` reads it.
The host `curl_parse_url()` returns from that string, which is the `connect_to`
key (INV-6), MUST be printable ASCII too, or the hop refuses as `parse`: libcurl
percent-decodes the host, so the ASCII string `http://b%C3%BCcher.invalid/`
parses to the host `bücher.invalid` **[verified]**. This turns the clarification
above from a property of construction into a refusal. A U-label that reaches
libcurl can defeat the pin: on builds with IDN support, libcurl matches
`connect_to` against the A-label while `curl_parse_url()` returns the U-label,
so the key misses and libcurl resolves the name itself (INV-6) **[verified]**
(`r-binding.md` §4.2). The agreement check above compares the two parsed hosts,
and a parser that returned the A-label for a U-label string would pass it. The
rule on the string reads the string itself, because finding its host component
would take a third parser; the rule on the host reads libcurl's own parse. Past
`rurl`'s syntax and scheme verdicts, every string `rurl` 3.0.1 serializes from
the parse-vector and verdict corpora and from generated non-ASCII inputs is
printable ASCII, except a host holding a space, which the agreement check
already refuses, and every host `curl_parse_url()` returns for a string
admitted today is printable ASCII. `rurl` decodes a percent-encoded host and
serializes its A-label. The two rules therefore refuse nothing admitted today
**[verified]** (`design/evidence/2026-09-29-wire-ascii.R`). ASCII is not IDNA
validity: the §5.0 A-label rule and its `rurl` gap (`RURL-vicyvlvh`) are
unchanged.

### 4.2 INV-1 is preserved by construction, not by hope

`ssrfr` serializes the sanitized URL, parses that exact string with
`curl_parse_url()`, and uses the resulting host for the `connect_to` key and for
classification. The parse gate is `rurl`'s layered verdict, not `parse_status`:
the hop proceeds only when `layer1_syntax_verdict == "pass"`,
`layer2_policy_verdict == "admitted"` for an allowed scheme, and
`curl_parse_url()` succeeds. `layer3_annotation_state` and `parse_status` values
such as `warning-invalid-tld` and `warning-no-tld` are Public Suffix List
annotations, not ambiguity, and MUST NOT refuse: they would refuse
`internal-api.corp` and `localhost`, which §5.0 expects to reach through
`allow_ranges` **[verified]** (evidence script, block 5). Userinfo is a separate
admission decision (§12 step 4). Parser agreement does not prove the dial matched
the pin; the debug-trace detector (`r-binding.md` §6) and the cross-platform dial
tests (§8 item 6) remain required.

An IPv6 literal carrying a zone identifier (`http://[fe80::1%25eth0]/`) refuses
as `parse`. A zone ID names an interface on the local host, never a remote
destination, and RFC 9844 obsoleted RFC 6874 and with it the URI syntax for one.

*Replaced 2026-09-24* (was **[suspended]**). The ratified text held that handing
libcurl the already-normalized URL made agreement structural. It does not stop
libcurl parsing the string again: the host libcurl dials is libcurl's parse of
that string, so agreement is structural only if the pin key and the address layer
both use that parse.

### 4.3 The obligation that travels with a dependency

A dependency's correctness is **asserted by the corpus, never assumed** (§7):

- the parse-vector table MUST pin `rurl`'s host output against what libcurl
  dials;
- the verdict corpus MUST pin `raddr`'s facts against expected refusals.

The parse-vector table also pins `curl_parse_url()`, and compares address
**values** and A-label names, never host strings, because the two parsers spell
the same IPv6 address differently (`r-binding.md` §2.3).

`ssrfr`'s guarantee rests on a `raddr` that is at 0.1.x. That is an argument for
the corpus being the contract between them, not for vendoring a worse copy.

Registry age is not a refusal. `raddr` stamps its snapshot with
IANA's own "Last Updated" date, so age measures how long IANA has been quiet, not
how stale the copy is **[sourced]**. `ssrfr` does not check age at runtime. When
IANA adds a special-purpose block, `ssrfr` raises its minimum `raddr` version
once `raddr` ships it.

An untested dependency version is not a refusal or a warning either. `ssrfr`
does not compare the installed `curl`, `rurl` or `raddr` against a list of
tested versions at runtime. A major version is a weak proxy for parser drift:
it would refuse compatible releases and miss drift inside a major. The drift
that matters on a request is caught on that request, by the host agreement
check of §4.1, and the rest by the corpus, the parse vectors regenerated on
every dependency update, and published results naming every version (§7).
DESCRIPTION states minimum versions only. *Ratified 2026-09-25* (§8 item 30,
`SSRF-cnljaaek`).

---

## 5. The refusal rule **[ratified]**

*Ratified 2026-09-24* (`SSRF-aqrgqdhi`), after revision against `raddr` 0.1.2
behaviour and the `linklint` provider-endpoint data. Refusal is the default: a
hop proceeds only when every address in the answer set passes every gate.

Classification is delegated to `raddr`, which drives it from the IANA
special-purpose address registries rather than a hand-maintained list. Evidence:
two independent implementations, `ipaddress::is_global()` and a hand-rolled
matcher, missed the *same* provider's metadata address, which `raddr` classifies
correctly **[verified]**.

Independent gates, not one predicate. Independence matters because they fail
differently and MUST be separately testable.

| Gate | Dimension | Source | Refuses when | Tier (§5.0) |
|---|---|---|---|---|
| 1a. Outer reachability | address | `raddr` fact | `addr_global_reachability(addr)` is `FALSE` | 4 |
| 1b. Indeterminate reachability | address | `raddr` fact | the outer address, or any row of `addr_embeddings(addr)`, is `NA` | 1 |
| 1c. Embedded reachability | address | `raddr` fact | any row of `addr_embeddings(addr)` is `FALSE` | 1 |
| 2. Provider endpoints | address | built-in `ssrfr` data | the address is in the provider-endpoint table | 4, exact-entry override only (§5.0) |
| 3. Range rules | address | caller policy | matches `deny_ranges` | 2 |
| 4. Hostname rules | hostname | caller policy | matches `deny_hosts` | 2 |
| 5. Metadata hostnames | hostname | built-in `ssrfr` data | matches the built-in metadata hostname list | 4 |

Every resolved address and every address literal passes through gates 1–3.

**Gate 1 reads the outer address and every embedding.** `addr_global_reachability()`
answers for the address it is given. For `64:ff9b::a9fe:a9fe` it returns `TRUE`,
because the NAT64 well-known prefix is globally reachable; only the embedding row
for `169.254.169.254` returns `FALSE` **[verified]** (evidence script, block 1).
Gate 1 on the outer address alone would admit the `pydantic-ai` NAT64 chain INV-13
cites. A NAT64 address whose embedded IPv4 is globally reachable passes gate 1:
DNS64 hosts see every IPv4-only site as `64:ff9b::/96`, and refusing all of them
would break those hosts. (`linklint` refuses every transition prefix outright;
that is a stricter choice this specification does not adopt.)

**Operator NAT64 prefixes are a documented residual.** Gate 1 grades the
embeddings `raddr` recognizes from the address alone: the well-known and
local-use NAT64 prefixes and the other forms `addr_embeddings()` reports. An
operator's network-specific prefix (RFC 6052 §2.2) is invisible in the address,
so an address under one is graded as its outer address only. `raddr` can read an
address under a prefix the caller asserts, but v1 exposes no policy field for it.
`ssrfr`'s embedding guarantee is limited to recognized prefixes and MUST be
documented that way.

**Multicast is not a separate gate.** `raddr` already returns `FALSE` for
`ff0e::1`, `ff02::1` and `224.0.0.1` **[verified]** (evidence script, block 3), so
gate 1a refuses it. The former claim that gate 1 missed global-scope multicast
was wrong. `multicast` remains a reason code (§6.5), and the ratified rule that
`allow_ranges` overrides multicast (§5.0) is unaffected: it is a tier-4 refusal.

**Gate 2 covers endpoints no registry can see.** Azure's WireServer
`168.63.129.16` is a public address, so no IANA predicate refuses it. Endpoints
inside special-purpose space — `169.254.169.254`, Oracle's `192.0.0.192`,
Alibaba's `100.100.100.200` — are refused by gate 1a, but labelled by their
category. Without an address table `ssrfr` cannot report the published
`cloud-metadata` code for any of them. The table is
vendor-sourced data with its own version stamp, separate from the IANA snapshot;
each row cites current vendor documentation and a kind (`instance-metadata` or
`provider-internal`). Each row also records the date that
documentation was retrieved and quotes, verbatim, the vendor sentence that names
the address. Both kinds report the one public code `cloud-metadata`
(§6.5); the kind is operator detail. `linklint`'s ten-row table
(`packages/core/src/data/cloud-metadata.ts`) is the starting point, plus four
`instance-metadata` rows it lacks: Scaleway's `169.254.42.42` and `fd00:42::42`,
and Linode's `fd00:a9fe:a9fe::1` and `fe80::a9fe:a9fe`. Gate 1a already refuses
all four; the rows give them the `cloud-metadata` code and §5.0's narrowing,
under which only an exact `allow_ranges` entry reopens them. *Ratified 2026-09-25* (`SSRF-qttneqxp`). Ownership:
`ssrfr`, per `raddr`'s architecture and the §4 amendment.

Gate 2 also reads the rows of `addr_embeddings()` whose embedded address is the
destination: the IPv4-mapped, IPv4-translated, IPv4-compatible and NAT64 forms.
An embedded address in the table refuses at tier 1, like any refusal derived
from an embedding (§5.0). Otherwise a NAT64 wrapper of WireServer, whose
embedded address is globally reachable, passes gate 1c and never meets gate 2.
Gate 2 does not read the 6to4, Teredo and ISATAP rows: their embedded address is
tunnel underlay, not a destination (INV-13, corollary), so
`2002:a9fe:a9fe::1` refuses as `6to4`, not `cloud-metadata`. *Amended
2026-09-25* (was "every row"; `SSRF-qttneqxp`).

**ISATAP-wrapped provider endpoints are a documented residual.** An ISATAP
address under a global prefix whose locator is WireServer `168.63.129.16`, such
as `2600::5efe:a83f:8110`, passes every gate: `raddr` 0.1.2 grades both the outer
and the embedded address globally reachable **[verified]**
(`design/evidence/2026-09-25-embedding-kinds.R`). An IPv6 packet to it travels to the locator
encapsulated as IPv4 protocol 41, not as a TCP connection to the locator's
services, so it cannot reach WireServer's HTTP endpoint unless that host
decapsulates tunnel traffic, which nothing documents. `ssrfr` MUST document this
residual. The verdict vectors carry a 6to4, a Teredo and an ISATAP row wrapping
a table address, each expecting its embedding kind's code, and a NAT64 wrapper
of WireServer expecting `cloud-metadata`.

**Gate 5 is justified by endpoint identity, not by missing link-local
addresses.** A hostname entry is admitted only when current vendor documentation
names it as the address of an endpoint in gate 2's table, and it matches by exact
whole-host comparison. IBM Cloud's metadata API may be reached at
`169.254.169.254` or at `api.metadata.cloud.ibm.com`, and over HTTPS it MUST be
the hostname **[sourced]**; a hostname rule sees that request before resolution
and whatever the name resolves to. The earlier justification — that Equinix Metal
and IBM VPC have "no link-local address at all" — was wrong for IBM, and Equinix
Metal was sunset on 2026-06-30 **[sourced]**. `linklint`'s five-name list and its
recorded declined names (bare `metadata`, `instance-data`,
`metadata.azure.internal`) are the starting point.

### 5.0 Precedence **[ratified]**

"Deny wins" (INV-14) presupposes that an allow match does something. Stating only
that allow never overrides deny leaves `allow_hosts` and `allow_ranges`
operationally inert.

Precedence is four-tier and **dimension-local**: each dimension has its own
built-in layer, and an allow rule overrides only the built-in layer of **its own**
dimension.

| Tier | Address dimension | Hostname dimension |
|---|---|---|
| **1. Non-overridable** | reachability `NA` (§5.1); reachability `FALSE` derived from an embedded address (§5.2) | — |
| **2. Caller deny** | `deny_ranges` | `deny_hosts` |
| **3. Caller allow** | `allow_ranges` — overrides tier 4 for the matched addresses only | `allow_hosts` — overrides tier 4 for the matched name only |
| **4. Built-in** | `addr_global_reachability()` is `FALSE`; multicast | the built-in metadata hostname list |

Evaluation: tier 1 refuses unconditionally; otherwise any tier-2 match refuses;
otherwise a tier-3 match permits **within its own dimension**; otherwise tier 4
applies. A request is permitted only when both dimensions permit.

The address dimension's tier-4 built-ins also include the provider-endpoint
table (§5, gate 2), with one narrowing: only an `allow_ranges` entry that names
the endpoint exactly (a /32 or /128 equal to the table row) overrides it. A
broader range, such as `169.254.0.0/16` authorized for a link-local appliance,
leaves the provider endpoints inside it refused: opening a network does not open
its metadata service. *Ratified 2026-09-24* (ADR 0004).

This section is the only statement of precedence. §5.3 and INV-14 refer to it.

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
- **`allow_ranges` does not override a refusal derived from an embedded
  address.** `raddr` grades an embedding by the address it extracts, and §5.2
  forbids `ssrfr` from extracting it again, so an allow range can only ever match
  the outer wrapper. Letting it override would turn `allow_ranges =
  "64:ff9b::/96"` (or `2002::/16`) into permission for every internal target
  wrapped inside that prefix, including `64:ff9b::a9fe:a9fe` → `169.254.169.254`:
  the `pydantic-ai` NAT64 chain INV-13 cites, reopened by configuration. The
  converse is an accepted v1 limit: `allow_ranges = "10.0.0.0/8"` does not
  authorize the NAT64 or 6to4 form of `10.0.0.5`; the caller must use the direct
  address. The rule requires `raddr` to report that a `FALSE` came from an
  embedding. **[verified]** 2026-09-24: `addr_embeddings()` returns each
  embedding's kind and extracted address, and `addr_global_reachability()` grades
  each row (evidence script, block 1). `raddr`'s classify *codes* attribute only
  three kinds, so `ssrfr` reads the embedding rows, not the codes.
- **Rules are not cross-dimensional.** `allow_ranges` cannot un-deny a hostname;
  `allow_hosts` cannot un-deny an address.

#### Hostname matching

Hostname rules match a normalized value, never the literal string, for the same
reason INV-3 forbids literal address matching. Both the rule and the host are
normalized the same way: the host is the one parsed from the URL the transport
dials (INV-1), in IDNA A-label form, **ASCII-lowercased**, with a single trailing
root dot removed. `metadata.google.internal.`, `METADATA.google.internal` and
their U-label spellings therefore all match the built-in entry.

A host with no A-label refuses as `parse`: when domain-to-ASCII
fails, including for a label beginning `xn--` that does not decode, the input
spelling MUST NOT stand in for the A-label, whether in hostname rules, in the
resolver query or in the URL handed to libcurl. The parse-vector table MUST carry
such hosts. `rurl` 3.0.1 passes `xn--a.example` through unchanged, and so does
libcurl, so today neither the layer-1 verdict nor §4.1's disagreement check
refuses it **[verified]** (`design/evidence/2026-09-24-idna-fallback.R`).
`ssrfr` takes the failure signal from `rurl` rather than decoding labels itself
(§4), and raises its minimum `rurl` to the release that gives it
(`RURL-vicyvlvh`).

Case folding MUST be ASCII-only, as WHATWG host processing is, and MUST NOT depend
on the session locale. `rurl` shipped the Turkish-I defect (`RURL-ugfpuotu`), and
`stringi`'s `"root"` locale does not override the ambient one **[sourced]**
(`linklint` `docs/locale-case-mapping.md`).

A rule matches exactly unless it begins with `.`, in which case it matches any
proper subdomain and not the bare name: `.corp` matches `api.corp`, not `corp`.
There are no other wildcards; a rule using any other wildcard form is a
construction error (§5.3). The built-in metadata list is exact names only.

Stripping the trailing dot for matching does not change what is dialed.

Hostname rules see the URL's host only. An alias is not resolved
to its CNAME target for matching: `curl::nslookup()` calls `getaddrinfo()`
without `AI_CANONNAME` and returns addresses only, and that flag would expose only
the final canonical name, not the chain **[sourced]**. A name that aliases a
`deny_hosts` entry or a built-in metadata name is therefore not refused by gate 4
or 5; its addresses meet gates 1–3 like any other answer, and over HTTPS the
certificate must match the alias (INV-9).

#### Names resolve as absolute

The resolver query for a hostname carries a single trailing root dot, so DNS
search suffixes never apply: `http://intranet/` cannot reach
`intranet.corp.example`. The dot goes on the resolver query only. The `Host`
header, SNI, certificate verification (INV-9) and the pin key keep the dotless
name, which the `connect_to` pin preserves naturally. There is no opt-out in v1;
a caller who means an intranet name writes it fully qualified. Prior art: Sentry's
`ensure_fqdn`. That the resolver honours the dot on every supported platform is
an **[assumption]** until `SSRF-rcwugkqo` checks it under `--dns-search`.
*Ratified 2026-09-24* (`SSRF-ighscodn`).

#### The extension worth flagging

A purely dimension-local reading leaves `allow_hosts` inert after all, because the
hostname gate as first drafted refused only on a caller `deny_hosts` match — and
tier 3 cannot override tier 2. So there would be nothing for it to act on.

It has real work because the hostname dimension has a **built-in** denial layer of
its own: the metadata hostname list that ADR 0001 §2.4 establishes as a permanent
first-class control. `allow_hosts` overrides that layer, and only that layer.
Splitting built-in from caller-configured *within each dimension* is what makes
the model symmetric.

Consequence: in the ordinary case — `internal-api.corp` resolving to `10.0.0.5` —
only `allow_ranges` is required, because nothing denies the name. `allow_hosts` is
the narrow tool for when the name itself is denied by a built-in rule. Narrow is
not inert.

Gate 5 is a permanent, first-class control, not legacy convenience.

*Correction 2026-09-24:* "Gate 4" above names the hostname rules of the
original five-gate table; in §5's revised table the built-in metadata list is
gate 5 and the caller's `deny_hosts` gate 4. This passage also first justified
the hostname layer by saying some metadata services "have no link-local address
at all" (Equinix Metal, IBM VPC). That is wrong for IBM and moot for the sunset Equinix Metal; the
justification that holds is in §5, gate 5. The precedence consequence above does
not depend on it.

### 5.1 `NA` refuses, whatever it means upstream **[ratified]**

`ssrfr` MUST refuse on `NA` regardless of `raddr`'s intent for that value
(INV-11). There is no path from "we could not determine this" to "proceed."

**No allow rule overrides this** (§5.0, tier 1). An allow rule is a statement about
a *known* range or name; it is not a licence to permit input the classifier could
not decode. Reading it as one would reinstate exactly the malformed-literal
fail-open that ADR 0001 §3 closed.

*Consequence, recorded 2026-09-24:* `raddr` maps IANA's "Globally Reachable: N/A"
to `NA`, with no argument that changes it. Four registry blocks carry it: 6to4
`2002::/16`, Teredo `2001::/32`, and the deprecated `192.88.99.0/24` and ORCHID
`2001:10::/28` **[verified]** (evidence script, block 2). Every 6to4 and Teredo
address therefore refuses at tier 1, whatever it wraps — `2002:808:808::1`, the
6to4 image of `8.8.8.8`, included — and no allow rule can reach them.

`raddr` does not mean the two `N/A`s the same way. For 6to4 it documents "the
embedded v4 decides" and answers that question on the embedding row
(`addr_global_reachability(addr_embeddings(x)[[1]])` is `TRUE` for
`2002:808:808::1`). For Teredo, relay advertisement is per-deployment and no bits
in the address answer it (`raddr` `R/transition.R`). Refusing both anyway follows
from this ratified section, and it costs little: neither prefix is a direct HTTP
destination (the 6to4 V4ADDR is the encapsulating router; Teredo carries
separate server and client fields). Grading 6to4 by its embedding instead was
considered and declined on 2026-09-24 (`SSRF-foggmyfe`). The reason codes are `6to4` and `teredo`
(§6.5).

### 5.2 Embeddings belong to `raddr`

`ssrfr` MUST NOT decode embedded addresses itself. For every address it MUST
evaluate `addr_global_reachability()` on the outer address **and** on each row of
`raddr::addr_embeddings()`, applying gates 1b and 1c (§5). Reading `raddr`'s
embedding rows consumes `raddr`'s extraction; it is not a second one. `ssrfr`
reports which embedding kind refused, for the reason code (§6.5).

*Replaced 2026-09-24* (was **[suspended]**). The ratified text relied on
`addr_global_reachability()` grading an embedding by its extracted address. It
does so for an *embedding object*, but on the *outer* address it answers for the
prefix alone: `TRUE` for `64:ff9b::a9fe:a9fe` **[verified]** (evidence script,
block 1). Refusing on the outer fact alone admits the wrapped metadata address.

**The reviewer's objection to answer:** defense in depth normally argues for
checking twice. It does not here, because two decoder inventories diverge, and
divergence in this exact code is the documented history of the stack.

### 5.3 Policy fields **[ratified]**

```
allow_schemes     default: http, https
allow_ports       default: 80, 443            allowlist only, never a denylist
deny_hosts        hostname rules (INV-13)
allow_hosts       exceptions to built-in hostname refusals; caller deny still wins
deny_ranges       additional prohibited ranges
allow_ranges      exceptions to determinate built-in address refusals; caller deny still wins
allow_userinfo    default: false
max_redirects     default: 20; 0 MUST be supported and MUST mean "refuse any 3xx"
connect_timeout   default: 3 s, per connection attempt
total_timeout     default: 30 s, for the whole redirect chain (§2.5)
max_response_size default: 10 MiB of decoded body, per hop
max_header_bytes  default: 16 KiB of response header, per hop
max_header_fields default: 128 response header fields, per hop
max_url_length    default: 8000 octets of the URL string, per hop
user_agent        default: "ssrfr/<version> (+https://gitlab.com/bart-turczynski/ssrfr)"
```

`max_header_bytes` and `max_header_fields` also count a chunked body's trailer
fields, which the response header does not otherwise include. *Amended
2026-09-26* (`SSRF-rgcijatt`).

There is no proxy field: v1 has no proxy mode (INV-10). The default `user_agent`
is assembled at runtime from the package's `DESCRIPTION`, so no version or URL is
hard-coded; it is transport-owned and non-secret, so it carries across origins
(§2.3).

Allow fields are exception lists, not default-deny allowlists. How they combine
with deny rules and built-ins is §5.0 and nowhere else.

Three absences are deliberate. *Ratified 2026-09-25* (`SSRF-qttneqxp`).

- An address-literal host is admitted when it passes gates 1–3, like any
  resolved address; there is no field that refuses literal hosts. Only a
  non-canonical spelling refuses, as `numeric-literal` (§12 step 6).
- There is no address-family field, and `deny_ranges = "::/0"` is not one:
  INV-4 refuses the whole answer set, so it refuses every name that publishes
  an AAAA record, not only IPv6 targets.
- `max_redirects` is the only bound on a redirect cycle; `ssrfr` does not detect
  a URL it has already visited.

Ports MUST be an allowlist. Browser "bad port" denylists omit both Redis and
Memcached **[sourced]**, and the reference Ruby implementation has no port
restriction at all. CWE-918's own alternate name is *Cross Site Port Attack*.

`allow_ports` applies to every allowed scheme, so `http://h:443/` and
`https://h:80/` pass it. That is deliberate: the guard authorizes a socket
(address and port), and a scheme that mismatches its port reaches the same
socket the matching scheme does, where the handshake fails. Binding ports to
schemes would make the field a per-scheme map for no reachability gain. An
operator who adds a port for a TLS service also admits plaintext HTTP to it.
*Ratified 2026-09-25* (`SSRF-qttneqxp`).

The default of 20 is the WHATWG Fetch Standard's limit ("If request's redirect
count is 20, then return a network error"), which Chrome and Firefox implement;
RFC 9110 §15.4 sets no number. A redirect beyond the budget refuses as
`redirect-limit` (§6.5).

`max_redirects = 0` is required because four OWASP sources, ASVS 5.0 V15.3.2
among them, recommend disabling redirects outright. Following them with
per-hop revalidation is a deliberate, documented deviation, not the standard
position.

**A policy is validated when it is built.** A rule that silently
matches nothing is a fail-open for a deny list and a false refusal for an allow
list. Building a policy MUST raise an operational error for an entry that is
empty, carries leading or trailing whitespace, joins several values in one string
(`"com, ru"`), is not a valid hostname rule under §5.0's normalization, or is a
range `raddr` cannot parse. `linklint` shipped all three of the first failures
with exit status 0 before fixing them **[sourced]** (`linklint` commits `e632d78`,
`12f56ab`, `2ac85ff`).

A limit that is missing, `NA`, negative, non-finite or not a whole number is
also a construction error, and so is a `user_agent` that is not a valid RFC 9110
field value (CR, LF and NUL are refused, never stripped).

**Limits are finite and raisable.** Every limit has a finite default, and a caller
may raise any of them without a ceiling; there is no non-overridable hard cap and
no "unlimited" sentinel. `0` means zero, never unlimited: only `max_redirects`
accepts it, and it refuses any 3xx. `total_timeout` covers decoding: elapsed time
is re-checked after resolution and after decoding, because a transport timer does
not preempt synchronous decompression (§14). `max_response_size` counts decoded
bytes as they are delivered, and the transport sends an explicit
`Accept-Encoding` (`r-binding.md` §5). No surveyed library ships a
non-overridable ceiling, and "0 = unlimited" is a foot-gun several of them do
ship.

`max_response_size` is checked on each delivery from the
transport, so the transfer ends on the first delivery that passes the limit: at
most one delivery is held beyond it (libcurl delivers at most
`CURL_MAX_WRITE_SIZE`, 16 KiB, per write callback **[sourced]**), and the hop
fails as `response-too-large` (§6.6), so none of it is returned. There is no
limit on the number of resolved addresses: INV-4 forbids truncating the set, and
failover over it is bounded by `total_timeout`.

`max_url_length` defaults to 8000 octets per hop, RFC 9110 §4.1's
minimum-support recommendation; no standard sets a maximum. It counts the UTF-8
octets of the URL string `ssrf_prepare_hop()` receives, before either parser
runs. A longer URL refuses as `parse`, and operator detail names the limit. A
condition raised by `rurl` or `curl_parse_url()`
while parsing is a `parse` refusal, never an R error to the caller (INV-11):
`rurl` 3.0.1 raises one for non-ASCII inputs under the default **[verified]**
(`design/evidence/2026-09-24-content-fetches.R`), and libcurl refuses any URL
over 8,000,000 bytes.

---

## 6. Result and reason model

### 6.1 Codes are a compatibility surface **[ratified]**

Reason codes are API: `kebab-case`, documented, stable, and enumerable at
runtime. `robotstxtr` and `sitemapr` publish the inherited values in their
reference documentation, so renaming breaks them (S6).

**Versioning mechanism.** Each closed code domain (reason codes,
operational causes, misuse condition classes (§6.6), the provider-endpoint table
and the metadata hostname list)
carries a version stamp, and a
test pins the set of keys to the stamp in both directions: a code added without a
bump fails, and a bump that leaves the pinned set stale fails. The package version
is named alongside, because data stamps do not cover detector logic (`linklint`
`docs/guarantees.md` A3, A8).

### 6.2 Two outcome classes **[ratified]**

Callers MUST be able to branch on **refused by policy** versus **failed on the
wire** without string matching. The token for policy refusal MUST NOT be reused
for network failure.

A refusal carries a reason code (§6.5), the offending address or
host, and the hop index. An operational failure carries a cause from the closed list in §6.6.
The positive outcome is a binding (§2), which carries the validated address set
and the pin actually used.

### 6.3 Vocabulary alignment

**Closed 2026-09-24 by verification** (was **[open]**). The question was whether `raddr`'s own code vocabulary aligns or conflicts with
the published `ssrfr` values. **[verified]** against `raddr` 0.1.2:

- `raddr` publishes a versioned vocabulary, `addr_codes_registry()`: 24 codes,
  each with `since = "0.1.2"`. By `raddr`'s own decision these are **evidence,
  not refusal reasons** (`raddr` `R/codes.R`). Classify codes such as
  `nat64_wk_embedded_not_global` and `teredo_client_not_global` live in the
  `codes` field of `as.data.frame(addr_classify(x))`; `addr_codes()` accepts only
  a parse result. The descriptive vocabulary is `addr_category()`'s levels.
- The two do not collide: `raddr` is `snake_case` evidence, `ssrfr` is
  `kebab-case` policy. **A mapping layer is required**, and it is §6.5's mapping
  table. `raddr` supplies no metadata classification; `cloud-metadata` comes from
  gate 2 and gate 5.

The two inherited misnomers are corrected deliberately rather than propagated:
CGNAT `100.64.0.0/10` reported as `cloud-metadata`, and IPv6 unique-local space
reported as `cloud-metadata` while the space containing it went unblocked. The
consumers have since corrected the first themselves (CGNAT is now `shared`).

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
- The projection MUST also accept an operational failure (§6.6)
  and return for it the same value it returns for a refusal. Across an untrusted
  boundary the outcome class is an oracle too: `connect-failed` against
  `timeout` separates closed from filtered ports inside any range `allow_ranges`
  opened, and a refusal where `unresolvable` was the alternative tells the
  prober that an internal name exists and resolves to prohibited space. §6.2's
  branch stays available to the caller.
- Applying that projection at the boundary where an untrusted party receives the
  result is the **application's** obligation, and this specification says so
  explicitly rather than leaving it implied.

Assigning projection to the application boundary *without* shipping the projection
would guarantee that every consumer writes their own and some of them leak. That
is the difference between a requirement and a hope.

- **Shape: MUST.** Refusals and operational failures MUST NOT expose which
  predicate fired or which cause ended the hop, which address, or which hop to an
  untrusted caller. *Amended 2026-09-25* (was "Refusals"; `SSRF-nbcgyled`).
- **Timing: SHOULD, best-effort.** Timing uniformity is in direct conflict with
  the lifecycle's normative order. §12 requires scheme and port checks *before*
  resolution, so that a `file://` host never triggers a DNS query to an
  attacker-controlled zone. That ordering guarantees informative timing: a scheme
  refusal returns in microseconds, an address refusal after a DNS round-trip.
  Equalizing them requires artificial padding bounded by DNS timeouts `ssrfr` does
  not control. Operational failures widen the gap: a `timeout` takes
  `connect_timeout` seconds per attempt. The conflict MUST be documented as a
  known limitation rather than papered over.

This resolves the tension INV-12 used to record as open: it is not a tension
between diagnostics and secrecy, it is a question of *who* receives the facts. An
attacker probing an endpoint is not the audience the transparency principle was
written for.

### 6.5 Reason-code vocabulary

**Published — a compatibility obligation.** **[verified]** in consumer source,
`sitemapr` and `robotstxtr` `R/ssrf.R` (2026-09-24); whether their rendered
reference pages list the same set is unchecked.

| Code | Meaning |
|---|---|
| `loopback` | loopback address |
| `private` | private / internal address space |
| `link-local` | link-local address |
| `cloud-metadata` | a known provider endpoint, by address (gate 2) or hostname (gate 5) |
| `shared` | shared address space, RFC 6598 (CGNAT) |
| `unspecified` | the unspecified address |
| `this-network` | `0.0.0.0/8` other than the unspecified address |
| `ipv4-mapped` | IPv4-mapped IPv6, prohibited embedded value |
| `ipv4-translated` | IPv4-translated IPv6, prohibited embedded value |
| `ipv4-compatible` | deprecated IPv4-compatible IPv6, prohibited embedded value |
| `nat64` | NAT64-embedded, prohibited embedded value |
| `6to4` | 6to4 address (refused at tier 1, §5.1) |
| `teredo` | Teredo address (refused at tier 1, §5.1) |
| `isatap` | ISATAP, prohibited embedded value |
| `malformed-address` | address literal that could not be decoded (ADR 0001 §3), or an address `raddr` failed to classify (§8 item 32) |
| `numeric-literal` | ambiguous numeric host encoding |
| `scheme` | scheme not permitted |

**Additions, ratified 2026-09-24.**

| Code | Meaning | Source |
|---|---|---|
| `downgrade` | redirect from a secure to an insecure scheme | ADR 0001 §4. Under INV-8 an `https`→`http` hop is always cross-origin, so credentials are already dropped; the refusal protects response integrity, not credentials. |
| `userinfo` | embedded credentials in the URL | §12 step 4 |
| `port` | port not permitted | §12 step 5 |
| `host-denied` | matched a caller `deny_hosts` rule | gate 4 |
| `range-denied` | matched a caller `deny_ranges` rule | gate 3 |
| `parse` | syntax failure, or `rurl` and libcurl disagree on the host | INV-2, §4.1 |
| `multicast` | multicast address | gate 1a |
| `redirect-limit` | a 3xx arrived after the chain's redirect budget was spent, including any 3xx under `max_redirects = 0` | §2.5, §5.3 |
| `reserved` | reserved, documentation, benchmarking, IETF-protocol and other special-purpose space no code above names | ADR 0004, superseding ADR 0001 §2.2's `private` for this space |

`unresolvable` and `pin-mismatch` were listed here in the retired guard spec.
They are operational causes (§6.6), not policy refusals: a DNS failure and a
connection-integrity failure are not policy decisions, and listing them here
contradicted §6.2.

**Mapping from `raddr` facts.** When several facts apply, the most specific
wins: gate 2's `cloud-metadata`, then an embedding kind, then the category. The
code names the embedding kind (`nat64`) rather than the decoded category
(`link-local`) because the consumers already publish the embedding-kind codes;
the decoded category is carried in operator detail (§6.4).

| `raddr` fact | Code |
|---|---|
| embedding kind `ipv4_mapped`, `ipv4_translated`, `ipv4_compatible` | `ipv4-mapped`, `ipv4-translated`, `ipv4-compatible` |
| embedding kind `nat64_wk`, `nat64_local`, `nat64_nsp` | `nat64` |
| embedding kind `6to4`, `teredo`, `isatap` | `6to4`, `teredo`, `isatap` |
| category `loopback`, `private`, `link_local`, `unspecified`, `this_network`, `shared`, `multicast` | same name, `kebab-case` |
| any other non-global category (`broadcast`, `documentation`, `benchmarking`, `future_use`, `protocol`, `anycast`, `discard`, `dummy`, `discovery`, `special`, `unallocated`) | `reserved` (ADR 0004) |
| parse failure codes | `malformed-address` |
| a `raddr` call that errors, returns `NULL` or returns a wrong shape for an address it has already parsed (INV-11) | `malformed-address` |
| `rurl` `layer1_syntax_verdict` `"fail"`, or `rurl`/libcurl host disagreement | `parse` |
| `rurl` `layer2_policy_verdict` other than `"admitted"` (e.g. `"rejected-scheme"`) | `scheme` |
| `rurl` numeric-literal shape diagnostic on the input host | `numeric-literal` |

### 6.6 Operational causes **[ratified]**

A separate closed enum, `kebab-case`:

| Cause | Meaning |
|---|---|
| `unresolvable` | resolution failed, returned no address, or returned an answer `raddr` cannot parse as an address (INV-11: the hop does not proceed) |
| `pin-mismatch` | the observed peer is not the pinned address, **or peer evidence is absent or malformed** (INV-5; `r-binding.md` §6). Absence of evidence is never a match. |
| `connect-failed` | no validated address accepted a connection |
| `tls-failed` | certificate or hostname verification failed |
| `timeout` | a connect or total deadline elapsed, including work done after bytes arrived |
| `response-too-large` | a size or count limit was reached: decoded body bytes, header bytes or header fields (§5.3); operator detail names which |
| `protocol-error` | a malformed, truncated or undecodable response |

When several limits trip during one transfer, the first one reached ends it and
names the cause.

When failover (§2.5) exhausts the validated addresses, the cause is `timeout`
only if every attempt ended because `connect_timeout` elapsed, and
`connect-failed` otherwise. Operator detail lists each address tried and how its
attempt ended. `total_timeout` elapsing is `timeout` wherever it happens.

Misuse of the API — a spent binding, a `from` that is not a followed redirect, an
invalid request-plan header, a malformed policy — is an operational *error* raised
as an R condition, not a cause carried in a result.

Callers catch these conditions by class, so the class names are API, a closed
domain versioned like the codes (§6.1). Every misuse condition has the class
vector `c("ssrfr_error_<kind>", "ssrfr_error", "error", "condition")`, built
with base R's `errorCondition()`, and carries its kind as a data field for
logging. The kinds:

| Class | Raised when |
|---|---|
| `ssrfr_error_invalid_policy` | building a policy fails its construction checks (§5.3) |
| `ssrfr_error_invalid_request` | a request plan breaks §2.3's header or body rules |
| `ssrfr_error_invalid_from` | `from` is unspent, records a failed fetch, or is not a followed redirect (§2.3); or, on a redirect hop, `url` is not the `Location` `from` recorded, byte for byte (§2.6). *Amended 2026-09-27* (`url` clause added; `SSRF-fvtqbanc`) |
| `ssrfr_error_spent_binding` | `ssrf_fetch()` receives a binding whose fetchability is spent (§2.5) |
| `ssrfr_error_budget_change` | a redirect-hop policy states a different `max_redirects` or `total_timeout` (§2.5) |
| `ssrfr_error_invalid_argument` | any other argument of the wrong type or shape, including `request` and `from` passed together, or neither |

The most specific kind applies: `ssrfr_error_invalid_argument` covers only what
no other row names. A condition's message follows §2.3's redaction rule.
*Ratified 2026-09-25* (§8 item 27, `SSRF-cnljaaek`).

### 6.7 Conventions

Reason codes and causes are `kebab-case`. For reason codes this diverges from
the sibling TypeScript project's `snake_case` (its causes are already
`kebab-case`) and from `raddr`'s `snake_case` evidence codes; the divergence is
**deliberate**, to preserve the published values above. *Corrected 2026-09-25*
(`SSRF-qttneqxp`).

---

## 7. Conformance **[ratified]**

Conformance is declared by publishing results against the corpus, not by code
sharing. Coverage is not the metric: the reference Ruby implementation advertised
100% coverage and had two bypasses reported by outsiders. **[sourced]**

Corpus components:

1. **Verdict vectors** — inputs, expected outcome, expected reason code, and the
   layer that must catch each; an implementation MUST pass each at
   that layer or earlier. Grouped by bypass class. Includes the inherited IPv6 spelling tables,
   which already encode two production bugs, ported verbatim.
2. **Parse vectors** — inputs where parsers disagree, with a ground-truth column
   measured from this stack (`rurl`, `curl_parse_url()`, and the address libcurl
   actually dials), and scheme, userinfo and port columns from both parsers
   (§12). This table makes INV-1 checkable and maps to
   **ASVS 5.0 V1.5.3** (parser consistency). Regenerating it on every dependency update turns
   an upstream parser change into a visible diff instead of a silent bypass.
3. **Requirement coverage** — external requirement IDs (OWASP cheat sheet items,
   ASVS requirement IDs, CWE mitigations) mapped to demonstrating tests, each
   marked enforced-by-library, enforced-by-application, or out of scope.
4. **Dependency pinning** — §4.3. Published results name the
   `raddr` version and its `addr_registry_version()`,
   `addr_address_space_version()` and `addr_registry_snapshot()` values, and
   the versions of `rurl`, the `curl` package, libcurl and libcurl's TLS
   backend, because every transport finding is version-specific. *Ratified 2026-09-25* (`SSRF-qttneqxp`).

Components 1–3 are committed in
[`tests/testthat/fixtures/`](../../tests/testthat/fixtures/), whose README
gives the file format: `verdict-vectors.tsv`, `parse-vectors.tsv` (its measured
columns generated by
[`2026-09-25-parse-vectors.R`](../evidence/2026-09-25-parse-vectors.R)) and
`requirements.tsv`, with the row counts and checksums of §7.2 in
`corpus-manifest.tsv`. *Linked 2026-09-25* (`SSRF-rsxokejd`).

### 7.1 The evidence base MUST be committed

Every `[verified]` and `[sourced]` claim dated before 2026-09-24 cited local
research notes that are git-ignored by policy. For a security library whose
central claim is that its properties are tested rather than asserted, the
citation chain MUST live in the repository: reproducible probe scripts, distilled
test fixtures, and source citations. Until then those claims are unfalsifiable by
anyone but their author.

`design/evidence/` holds the probe scripts, including the July probes re-run on
2026-09-24 (`r-binding.md` §9), and `design/references.md` the pinned source
citations (`SSRF-ssldkvmd`).

### 7.2 What counts as a pass

A conformance run MUST count a skipped test, and a test that makes no
assertion, as not passed. Skipping is legitimate where others check the
package, such as CRAN's farm (`r-binding.md` §7); it is never legitimate in the
run that declares conformance. A platform on which a security test skips has
not shown conformance there (§8 item 6).

Each corpus file MUST be committed with its row count and a content checksum,
and the test that loads it MUST assert both before it evaluates any row.
Regenerating a corpus (component 2) changes both in the same commit, so the
change shows in review.

Corpus rows are never deleted. A row whose expectation no longer holds is marked
superseded, with the reason, and stays in the file. *Ratified 2026-09-25* (`SSRF-qttneqxp`).

---

## 8. Open decisions

| # | Decision | Status |
|---|---|---|
| 1 | The refusal rule (§5) | **closed — ratified** 2026-09-24: positive predicate, refuse by default, and one bad address refuses the whole answer set — `SSRF-aqrgqdhi` |
| 2 | `raddr` ↔ published reason-code alignment (§6.3) | **closed — resolved by verification**: a mapping layer is required; the mapping (§6.5) was ratified 2026-09-24 with a new `reserved` code (ADR 0004) |
| 2a | The request plan as an input to `prepare` (§2.3) | **closed — ratified**, with transport-derived redirect status, mandatory plan inheritance, and constrained carryable-header nomination |
| 2b | Allow/deny precedence (§5.0) | **closed — ratified** as a four-tier, dimension-local matrix; `allow_ranges` overrides determinate multicast classification |
| 2c | The gate set itself (§5, table), including the provider-endpoint table and the §4 "no tables" amendment | **closed — ratified**; only an exact-endpoint `allow_ranges` entry overrides a provider endpoint (§5.0, ADR 0004) — `SSRF-aqrgqdhi` |
| 3 | Limits: defaults, floors, decoding, per-hop header limits | **closed — ratified** (§5.3): finite and raisable, with no ceiling and no "unlimited" sentinel; `total_timeout` is chain-scoped and covers decoding. `curl::nslookup()` has no timeout of its own **[assumption]**, a documented residual — `SSRF-pffrmkdr` |
| 4 | Search-domain resolution | **closed — ratified** (§5.0): names resolve as absolute, with no opt-out in v1 — `SSRF-ighscodn` |
| 5 | Default User-Agent | **closed — ratified** (§5.3) — `SSRF-uitcvnif` |
| 6 | Cross-platform re-verification of every transport finding (macOS only; the INV-6 pin fail-open is libcurl-internal and MUST NOT be assumed portable) | **closed — verified** 2026-09-30 on macOS, Linux and Windows (below). **Linux re-run 2026-09-25** beside macOS (libcurl 8.14.1): Ubuntu 22.04 (7.81.0), Ubuntu 24.04 (8.5.0) and Rocky 9 (7.76.1, `libcurl-minimal` and full), in Docker (`design/evidence/2026-09-25-linux-transport-results.txt`; `r-binding.md` §4–§6 carry the platform tags). Reproduced on every build: the `"HOST::IP:"` pin, the port-key fail-open, the empty-field and empty-`HOST` forms, failover, the reuse and DNS-cache leaks of a `resolve` pin, the `debugfunction` seam, the refused first-hop and redirect schemes under `protocols_str` or, on 7.76.1 and 7.81.0 where `protocols_str` is not settable, the `protocols` bitmask. Differs by build: the trace text, `maxfilesize` on a chunked body, and host-key matching. A key taken verbatim from `curl_parse_url()` engaged on every build for an ASCII host; for a U-label URL it **failed open** on Ubuntu 22.04 and 24.04 (IDN builds, UTF-8 locale), where libcurl matches the A-label (`r-binding.md` §4.2) — a decision of its own (item 34). Not run: the §4.1 disagreement refusal on numeric hosts (needs `ssrfr` code). HTTP/2 coalescing no longer applies: the transport speaks HTTP/1.1 only (`r-binding.md` §5; *amended 2026-09-26*, `SSRF-rgcijatt`). **Windows re-run 2026-09-29** through R-hub (Windows Server build 26100, R-devel, the CRAN `curl` 8.0.0 binary, libcurl 8.14.1 with IDN through WinIDN), under Schannel, the default, and again under `CURL_SSL_BACKEND=openssl`, with the same rows under both (`design/evidence/2026-09-29-windows-transport-results.txt`). Reproduced under both backends: everything reproduced on every Linux build above, with 26 compiled-in schemes refused on the first hop under `protocols_str` and under the bitmask. Differs: for a U-label URL the `curl_parse_url()` key **failed open**, as on the Ubuntu IDN builds (item 34); a dial to a closed loopback port traces `Connection timed out` within the 2-second connect timeout, where macOS and Linux trace `Connection refused` (`r-binding.md` §6); and the first progress call and the first `Trying` fall in one libcurl round, as on 8.5.0, not a round apart as on macOS's 8.14.1, so a progress callback that fails on its first call ends as `callback-error` there, not as `pin-mismatch` with check `absent` (`r-binding.md` §7). `CURLSSLOPT_NO_REVOKE` under Schannel verified by behaviour; the `NATIVE_CA` default under OpenSSL was not exercised, because `CURL_CA_BUNDLE` was set (`r-binding.md` §5). The same run found 28 failures in `ssrfr`'s own test suite on Windows (`design/evidence/2026-09-29-windows-testthat-output.txt`), none of them in `ssrfr`: R-hub's git checkout gave the corpus files CRLF endings; the Rtools libcurl ignores `cainfo` under Schannel, so the fixture CA cannot be trusted there, though a caller's https fetch, which sets no CA file, is unaffected (`r-binding.md` §5); Windows libcurl parses `file://HOST/` as a UNC path, so V0453 refuses as `scheme`, not `parse`, still at L0 (`r-binding.md` §2.3; superseded by V0538); and, under R-devel, a broken `gzcon()` trailer and a 10 ms timer (`r-binding.md` §7). Item 34's check is implemented (2026-09-29, `SSRF-afpkreyj`). **Suite on Windows 2026-09-30**: no failure, `R CMD check` status OK, under OpenSSL with only the two `SIGINT` tests skipped, and under Schannel with the fixture-CA tests skipped as well (`design/evidence/2026-09-30-windows-suite-results.txt`) — `SSRF-fjgfnaaq`; `SSRF-rcwugkqo`; `SSRF-nfizdzxt` |
| 7 | IPv6 pinning with a bracketed literal; the connection-reuse interaction in INV-7's corollary | **closed — verified** 2026-09-25 on macOS (8.14.1), Ubuntu 22.04 (7.81.0), Ubuntu 24.04 (8.5.0) and Rocky 9 (7.76.1), and 2026-09-29 on Windows (8.14.1, Schannel and OpenSSL): `"HOST::[::1]:"` dials `::1` and reaches an `httpuv` server there with `Host` intact; a `resolve` pin is bypassed by a pooled connection on the same or a fresh handle, a changed `connect_to` pin is not, and `forbid_reuse` closes the gap (`r-binding.md` §4.1, §4.4; `design/evidence/2026-09-25-linux-transport-results.txt`, `design/evidence/2026-09-29-windows-transport-results.txt`) — `SSRF-rcwugkqo`; `SSRF-fjgfnaaq` |
| 8 | Chain-scoped redirect budget under per-hop policy (§2.5) | **closed — ratified**, and extended to `total_timeout` — `SSRF-pipbsrtr` |
| 9 | Hostname rule normalization and suffix syntax (§5.0) | **closed — ratified** — `SSRF-pipbsrtr` |
| 10 | The parse boundary after `rurl` 3.0 (§4.1, §4.2) | **closed — replacement ratified** — `SSRF-foggmyfe` |
| 11 | Embedding evaluation (§5.2) | **closed — replacement ratified**; 6to4 and Teredo stay tier-1 refusals, and operator NAT64 prefixes are a documented residual (§5) — `SSRF-foggmyfe` |
| 12 | Ownership items `raddr` assigns to `ssrfr`: `X-Forwarded-For` extraction and a "most restrictive reading wins" convenience (`raddr` `docs/architecture.md`) | **closed — declined**: `X-Forwarded-For` is inbound request security (S5), and INV-1 fixes a single reading — `SSRF-dppgkbac` |
| 13 | Policy validation at construction; versioning mechanism for code domains (§5.3, §6.1) | **closed — ratified** — `SSRF-aqrgqdhi` |
| 14 | Ratify the inherited text: §5.3 and Part II (§11–§15), plus sentences tagged *[inherited]* in Part I | **closed — ratified**, with §11 widened to match S1, INV-10 without a proxy opt-in, and §15 narrowed — `SSRF-iuqixghb` |
| 15 | Items outside the 2026-09-24 brief: operational causes (§6.6); gate 2 on embedded addresses (§5); minimum `rurl` and `raddr` versions (§4) | **closed — ratified** 2026-09-24, after a second opinion; adds the `redirect-limit` refusal code, and the redirect default becomes 20 (ADR 0005) |
| 16 | Minimum libcurl (`r-binding.md` §5) | **closed — ratified, conditionally**: libcurl ≥ 7.73, the `curl` package's own floor, with the `protocols` bitmask below 7.85. If the Ubuntu 22.04 and Rocky 9 probes (item 6) show the protocol restriction or the pin failing there, the floor becomes 7.85 — `SSRF-arbcwamd` |
| 17 | v1 transport scope | **closed — ratified**: the `curl` package only; `httr2`, `httr` and `crul` adapters come after v1 — `SSRF-arbcwamd` |
| 18 | The host's own public addresses: a connection to an address assigned to the host is delivered locally (a Mattermost `IsOwnIP`-style check) | **closed — ratified** 2026-09-25: no detection in v1. The operator lists the host's public addresses in `deny_ranges`, and §9 records the residual. Interface enumeration needs a dependency §4 does not have; it is deferred to the "Ideas beyond v1" brainstorm (`iqupwehm`) — `SSRF-nbcgyled` |
| 19 | CNAME targets are never checked by hostname rules | **closed — ratified** 2026-09-25: no check in v1, documented in §5.0. `curl::nslookup()` returns addresses only, and `getaddrinfo()` exposes at most the final canonical name, never the chain; the address gates classify every answer whatever name produced it — `SSRF-nbcgyled` |
| 20 | Freshness of `raddr`'s IANA registry snapshot | **closed — ratified** 2026-09-25: no runtime age check (§4.3). `raddr`'s stamp is IANA's editorial date, so `addr_registry_outdated()` measures how long IANA has been quiet (upstream `RADD-poetjkbw`). Conformance results record the snapshot (§7), and a new IANA entry reaches `ssrfr` by raising the minimum `raddr` version (§4) — `SSRF-nbcgyled` |
| 21 | Retry lifecycle and response ownership (§2.2, §2.5) | **closed — ratified** 2026-09-25: `ssrf_fetch()` sends the request at most once; its only re-attempt is failover after a connection that never opened, and the cause when failover is exhausted is fixed in §6.6. A caller retry is a new `ssrf_prepare_hop()`. The response is read and decoded in full inside `ssrf_fetch()` and returned as a plain R value that owns no handle, connection or file. Streaming is beyond v1 — `SSRF-nbcgyled` |
| 22 | Maximum URL length | **closed — ratified** 2026-09-25: `max_url_length`, default 8000 octets (RFC 9110 §4.1), checked on the URL string `ssrf_prepare_hop()` receives before any parse; a longer URL refuses as `parse`, with no new code. Independently, an error raised by either parser is a `parse` refusal (INV-11) (§5.3; upstream `RURL-tlmoybsl`) — `SSRF-nbcgyled` |
| 23 | The local research-note findings brought in on 2026-09-24: the proposed passages in §2.2, §2.3, §2.5, §4.3, §5, §5.0, §5.3, §6.4, §7, §7.2, §9, S5, §13 (INV-10) and §14–§15 | **closed — ratified** 2026-09-25, with four amendments: INV-10's rule and rationale corrected (ADR 0006); INV-12 and §6.4's Shape bullet widened to operational failures; the failover cause fixed in §6.6; revocation placed outside INV-9. The §5.0 A-label rule waits on `rurl` (`RURL-vicyvlvh`) — `SSRF-nbcgyled` |
| 24 | The 2026-09-25 alignment audit of the local research notes against this document | **closed — ratified** 2026-09-25: corrections to §4.1, §6.7, INV-11 and INV-13; additions to S5, §2.3, §2.5, §5 (four gate 2 rows), §5.3, §6.1, §6.6, §7, §7.2 and §9, and the §4.1 disagreement check made a named test (`r-binding.md` §7). Contested items, ruled by a three-model vote (unanimous unless noted): gate 2 reads only destination embeddings, with the ISATAP residual documented (§5; split vote, maintainer's ruling); metadata request headers need vendor documentation naming a gate 2 endpoint, and three are added (§2.3); steps 3–5 read libcurl's parse, with corpus columns for drift (§12, §7); no method field (§9); `path_as_is = 1L` (`r-binding.md` §5); `allow_ports` stays scheme-independent (§5.3) — `SSRF-qttneqxp` |
| 25 | A loop helper that owns the redirect chain on top of `ssrf_prepare_hop()` and `ssrf_fetch()`, or a record that it comes after v1 | **closed — ratified** 2026-09-25 by a unanimous four-model vote: v1 ships `ssrf_fetch_chain()`, built only on the two primitives (§2.2) — `SSRF-cnljaaek` |
| 26 | Where INV-14's single off switch lives: an argument of §2.2's primitives, or the consumer-side toggle of ADR 0002 as the only one | **closed — ratified** 2026-09-25 by a unanimous four-model vote: the consumer's toggle is the only one; no `ssrfr` function disables the guard (INV-14, ADR 0007) — `SSRF-cnljaaek` |
| 27 | The class names of misuse conditions (§6.6); callers `tryCatch` on them, so they are API like the reason codes (§6.1) | **closed — ratified** 2026-09-25 by a unanimous four-model vote: a parent `ssrfr_error` and six `ssrfr_error_<kind>` subclasses, a versioned closed domain (§6.6) — `SSRF-cnljaaek` |
| 28 | Whether the response's `print` and `format` methods show the body (§2.2) | **closed — ratified** 2026-09-25 by a unanimous four-model vote: no; status, media type and body size only (§2.2) — `SSRF-cnljaaek` |
| 29 | A test helper for consumers, or only the documented `allow_ranges = "127.0.0.0/8"` recipe | **closed — ratified** 2026-09-25 by a unanimous four-model vote: the recipe only (§9) — `SSRF-cnljaaek` |
| 30 | A runtime refusal or warning on an untested major version of `curl`, `rurl` or `raddr`, or the corpus (§7) as the only check | **closed — ratified** 2026-09-25 by a unanimous four-model vote: no runtime check; the corpus and published results (§4.3) — `SSRF-cnljaaek` |
| 31 | How `robotstxtr` and `sitemapr` migrate: an L0 compatibility adapter first, or straight to the guarded fetch (S6, §6.5) | **closed — ratified** 2026-09-25 by a unanimous four-model vote: straight to the guarded fetch, with no L0 adapter (S6, ADR 0007) — `SSRF-cnljaaek` |
| 32 | The reason code when a `raddr` call fails on an address it has already parsed: INV-11 requires refusal, and §6.6's `unresolvable` covers only an answer `raddr` cannot parse | **closed — ratified** 2026-09-25 by the maintainer: `malformed-address`, the existing code for an address that could not be interpreted; no new code (§6.5). Raised by a GPT-6 Sol review of the implementation tickets — `SSRF-ifldwmnc` |
| 33 | A 3xx without `Location` once the redirect budget is spent: §2.3 calls it a final response, while §5.3 and §6.5 refuse any 3xx | **closed — ratified** 2026-09-25 by the maintainer: every 3xx refuses as `redirect-limit` once the budget is spent, including under `max_redirects = 0` (§2.3). Raised by the same review — `SSRF-fvtqbanc` |
| 34 | Whether the string handed to libcurl MUST be printable ASCII, enforced as a `parse` refusal, or whether A-label hosts stay a property of construction only (§4.1, INV-6) | **closed — ratified** 2026-09-29 by the maintainer, with one amendment: the host `curl_parse_url()` returns, the `connect_to` key, MUST be printable ASCII too, since libcurl percent-decodes the host (raised by a research agent, confirmed by a GPT-6 Sol review). The maintainer chose an enforced rule on the whole string over a check of its host component, which would need a third parser, and over a check at the `connect_to` key in L2. The `connect_to` key stays `curl_parse_url()`'s host, verbatim, in `"HOST::IP:"` form. Raised by the Linux transport re-run (item 6) — `SSRF-ljqshjmj` |

**Closed by this document:** component-wise versus whole-URL API (§3.1,
`SSRF-tnxmqvou`); whether the L2 result is a boolean (§2.1); the dependency
posture (§4); whether to build a C core (no — a shared parser would undermine
INV-1, and the only prize is a pre-connect veto, which is better pursued as an
upstream enhancement to R's `curl` package exposing `opensocketfunction`, the
pre-connect veto `safeurl-python` uses, and `prereqfunction`, which also sees
reused connections; `r-binding.md` §6).

---

## 9. Non-goals

- A general-purpose URL parser or validator.
- A replacement for firewalls, egress proxies, or IMDSv2-style hardening. Those
  are complementary and stronger; this library is defense in depth for
  applications that fetch caller-supplied URLs.
- Protection for callers who bypass the guarded path. Two-thirds of the CVEs
  surveyed were "some code path did not use the guarded client" or "the guard was
  detached." `ssrfr` SHOULD make the guarded path the path of least resistance
  and SHOULD document the unguarded R primitives that remain dangerous (S5).
- Protection against a compromised system resolver.
- Refusing the host's own public addresses. A connection to an
  address assigned to one of the host's interfaces is delivered locally (Linux
  `ip-route(8)`, `local` routes) and can reach services that a host firewall
  shields from outside; Mattermost refuses such addresses for this reason
  **[sourced]**. Gate 1 sees only a globally reachable address. `ssrfr` v1 does
  not enumerate interfaces; an operator whose host holds a public address lists
  it in `deny_ranges`.
- Keeping attacker-chosen names out of DNS. Resolution is how a
  hop is validated (§12 step 7), so every hostname that passes steps 1–6 is
  queried through the system resolver, and whoever runs that zone sees the
  query and whatever its labels encode. §11.1's blind-SSRF goal covers error
  shape and timing (INV-12), not the fact that a lookup happened. A
  `deny_hosts` match stops the query, because step 6 precedes step 7.
- Requests that response content causes other code to make.
  `ssrfr` follows 3xx responses only (§2.3). An HTML `<meta
  http-equiv="refresh">`, a `Refresh` header and script navigation are content
  to it. An application that follows one starts a new chain with `from = NULL`:
  the target is fully validated, but the chain's budgets and INV-8's
  cross-origin stripping do not carry over, and whatever request plan the
  application passes is its own. Parsers that fetch are outside the guarded path
  too: `xml2` loads external DTDs and entities over `http(s)` and `file` when
  `DTDLOAD` or `NOENT` is set, and requests nothing with its default options
  **[verified]** (`design/evidence/2026-09-24-content-fetches.R`). Parse fetched
  XML with `xml2`'s defaults.
- Anything below the socket. `ssrfr` validates the address it connects to. A
  public host that relays to internal targets, a transparent proxy, or NAT that
  rewrites the destination is invisible to it, and INV-5's peer check sees only
  the pinned address. Egress control belongs to the network (§11.2).
- Lookalike hostnames. §11.3 capability 4 is answered by matching hostname rules
  on the normalized A-label (§5.0) and by classifying whatever a name resolves
  to; `ssrfr` does not detect confusables or homographs (UTS #39).
- A report-only mode that fetches and logs what it would have refused. Declined:
  it is fail-open by construction (INV-11, S4's "fail-closed governs the gate").
  L0 and L1 already report without deciding.
- Caller-supplied predicates. Declined: the policy is the closed set of fields
  in §5.3, validated at construction, and a callback would be an unaudited gate
  outside §5.0's precedence.
- Concurrency limits. How many fetches run at once, and against which hosts, is
  the application's decision; §5.3's limits bound each hop and chain.
- A method allowlist. The application chooses the request method in its request
  plan; v1 has no policy field for it, and a redirect hop uses only the plan's
  method or §2.3's 301/302/303 transformation. An application that lets an
  untrusted party choose the method, such as an agent's HTTP tool, constrains
  it itself. *Ratified 2026-09-25* (`SSRF-qttneqxp`).
- A test helper for consumers. A consumer test that reaches a loopback server
  through the guard builds its policy with `allow_ranges = "127.0.0.0/8"`, the
  recipe `r-binding.md` §7 documents. An exported helper that loosens the
  policy would be one more function that can leak into production code.
  *Ratified 2026-09-25* (§8 item 29, `SSRF-cnljaaek`).
- Compliance claims beyond those permitted in §15.

---

## 10. Amendment log and section map

On 2026-09-24 the retired `ssrf-guard-spec.md` was merged into this document
(ADR 0003). The amendments this section used to list as outstanding were applied
in the merge: the L1 guarantee reads *classified* (§1); the L0 naming rationale
is §1.1's; classification delegation names `raddr` (§5); the result model is the
binding model (§2, §6.2); INV-12's tension is resolved by §6.4; the guard spec's
open decision 1 is closed (§3.1). The two `r-binding.md` amendments — the
dependency reversal in its §1, and `resolve_url()` with the finding that `curl`
cannot resolve references in its §2 — were applied to that file.

Where other documents or sibling repositories cite the retired guard spec, this
is where the text now lives:

| Retired `ssrf-guard-spec.md` | Here |
|---|---|
| §1 Threat model | §11 |
| §2 Layer model, §2.1, §2.2 | §1, §1.1, §1.3 |
| §3 Request lifecycle | §12 |
| §4 Invariants INV-1 … INV-14 | §13 (same numbers) |
| §5.1 Reason-code requirements | §6.1, §6.2 |
| §5.2 Vocabulary, including the misnomer note `sitemapr` cites | §6.5, §6.3 |
| §5.3 Conventions | §6.7 |
| §6 Classification requirements | §5 |
| §7 Transport hardening | §14 |
| §8 Configuration model | §5.3 (fields), §5.0 (precedence) |
| §9 Result model | §2, §6.2 |
| §10 Conformance | §7 |
| §11 Compliance claims | §15 |
| §12 Open decisions | §8 |
| §13 Non-goals | §9 |
| §14 References | §16 |

---

# Part II — the security contract **[ratified]**

Language-neutral: libcurl detail belongs in `r-binding.md`.

## 11. Threat model

### 11.1 In scope

An attacker controls, wholly or partly, any input that influences an outbound
request the host application makes server-side (S1): the URL itself, host or port
components assembled from separate inputs, links in fetched content that the
application follows, and the responses of the servers it reaches, redirects
included. The attacker's goals are to reach a network position the
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

### 11.2 Out of scope

- **Inbound** request security (CSRF, headers, CORS). Different problem.
- **Network-level egress control.** A guard in a library is defense in depth, not
  a replacement for a firewall or a separate VPC. `ssrfr` MUST NOT claim
  otherwise.
- **Application-layer authorization** of the fetched resource.
- **Content** safety of the response body (malware, XSS in rendered output).
- **DNS integrity.** A compromised resolver defeats any client-side guard.

### 11.3 The adversary's assumed capabilities

The attacker can:

1. Supply any byte string as the URL, or as any component the application
   assembles into one, including forms that are legal to one parser and illegal
   to another.
2. Control DNS for a domain they own — including **multiple A/AAAA records**,
   **very low TTLs**, and **changing the answer between two lookups** (rebinding).
3. Control an HTTP server that issues **redirects** to any target.
4. Register hostnames that resemble allowlisted ones.
5. Observe the timing and error output the host application returns.

Capability 2 is the one most implementations get wrong.

---

## 12. Request lifecycle

Per hop, in this order. Order is normative — several published vulnerabilities
are ordering errors.

```
 1. PARSE          with the parser whose result the transport will act on (INV-1, §4)
 2. PARSE STATUS    syntax failure or parser disagreement is a block      (INV-2)
 3. SCHEME          allowlist; http/https only by default; on a redirect hop,
                    https → http refuses as `downgrade` (ADR 0001 §4)
 4. USERINFO        reject embedded credentials unless explicitly allowed
 5. PORT            allowlist (default 80, 443)
 6. HOST POLICY     a non-canonical numeric host spelling refuses as
                    `numeric-literal` (ADR 0001 §2.4); then the hostname
                    dimension of §5.0                                    (INV-14)
 7. RESOLVE         exactly once; keep every address the call returns    (INV-4, INV-5)
 8. CLASSIFY        every address and each of its embeddings (§5);
                    refuse wholesale on any failure                      (INV-4)
 9. PIN             connect only to a validated address, unambiguously    (INV-6)
10. CONNECT         with transport hardening per §14
11. VERIFY          the peer is an address that was validated             (INV-5)
12. RESPONSE        enforce size and time budgets
13. ON 3xx          record status; if the redirect budget is spent, refuse as
                    `redirect-limit`; else strip/transform the guarded plan
                    (INV-8), then goto 1 for the new URL (INV-7)
```

*Added 2026-09-24:* the `downgrade` and `numeric-literal` checks in steps 3 and
6 were decided in ADR 0001 §4 and §2.4 but had no lifecycle step.

Steps 3–5 read the scheme, userinfo and effective port from `curl_parse_url()`
of the wire string (§4.1), because those are the values libcurl acts on; an
omitted port is the scheme's default. Only the host is compared across the two
parsers (step 2); the parse vectors carry scheme, userinfo and port columns, so
a divergence there shows as drift (§7) rather than as a runtime refusal.
*Ratified 2026-09-25* (`SSRF-qttneqxp`).

- **Scheme before resolve.** Resolving a `file://` host is wasted work and can
  itself leak (a DNS query to an attacker-controlled zone confirms reachability).
- **Port before resolve**, same reason.
- **Classification after resolution, never instead of it.** L0 host-string
  classification does not replace step 8.
- **Step 11 is not optional but is also not sufficient.** It is a detector; the
  pin at step 9 is the control. See INV-5.
- **Past the redirect budget, step 13 is decided at the status line.** Once the
  budget is spent, a 3xx refuses as `redirect-limit` as soon as its final status
  line has arrived, and the transfer stops there. Nothing after that line
  changes the outcome: not its header fields, a second `Location`, a body over
  step 12's limits, nor one that stalls past `total_timeout`. A step 12 limit
  reached before the line was complete, by interim `1xx` blocks or by the status
  line itself, was reached first and wins (§6.6). The status is
  transport-observed (§2.3): when the transport reports a status other than that
  line's, step 13 decided nothing, and the fetch ends as any transfer whose two
  statuses disagree: `protocol-error`, unless a step 12 limit or a transport
  error came first. *Amended 2026-09-27* (`SSRF-fvtqbanc`).

---

## 13. Load-bearing invariants

These are the safety properties. Each MUST be encoded as a test from the first
commit. Every one of them is a property a well-meaning contributor would
plausibly "simplify" later, and most have a published CVE behind them.

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

**Corollary — the parser is not portable.** Each implementation MUST bind to its
own stack's parser and MUST NOT import a foreign one for "consistency." In `ssrfr`
how this is met is §4.1–§4.2.

**Evidence.** Spring `CVE-2024-22243`/`-22259`/`-22262`; Claroty Team82's
16-library study; Tsai, Black Hat USA 2017. **[sourced]**

**Test.** The parse-vector corpus (§7), asserting guard host == transport host
by value for every vector.

### INV-2 — Parse ambiguity is a block, not a warning

If the parse yields anything other than unambiguous success, the request MUST be
refused.

**Rationale.** Hosts like `foo.09`, `0x1.2.3.4.5`, `1.2.3.08` are rejected by a
strict parser *because they are ambiguous*. That rejection **is** the security
signal. A lenient mode that returns a usable host plus a warning converts the
signal into a bypass.

With §4.2, ambiguity means a syntax failure or a disagreement
between parsers. An annotation
that does not bear on which host is dialed — a Public Suffix List note that a TLD
is unknown — is not ambiguity (§4.2).

**Test.** Corpus group: ambiguous authorities, all expecting refusal.

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

### INV-4 — Validate every resolved address; refuse wholesale on any failure

Every address the resolver call returned MUST be classified. If **any** is
prohibited, the request MUST be refused. An implementation MUST NOT filter the
answer set down to the permitted subset and proceed.

The property is that the connector only ever receives members of the validated
set, not that the set is every record the zone publishes: the system resolver
shapes it (hosts file, name-service configuration, address-selection filtering).

**Rationale.** Validating only the first record is the classic bug — `january`
`GHSA-4mcc` checked the first answer while the client tried all of them.
**[sourced]** Filtering to the "good" subset is subtler and also wrong: an
attacker who can add a private record to a legitimate hostname's answer set
should get a refusal, not a coin flip. Wholesale refusal also removes any timing
signal about which record was objectionable.

**Test.** Mocked multi-record resolutions: public+private, A public + AAAA `::1`,
all-private, all-public.

### INV-5 — Resolve exactly once per hop, and connect only to a validated address

The guard MUST perform exactly one resolution per hop, and the connection MUST
target an address from that validated set. The hostname MUST NOT be handed back
to the transport for re-resolution.

**Rationale.** This is the TOCTOU/DNS-rebinding defense and the single most
important property in this document. Handing the hostname back re-opens the
window between check and connect.

**Verification requirement.** Where the platform permits observing the connected
peer, the implementation MUST compare it against the validated set and fail if it
does not match; absent or malformed evidence counts as a mismatch
(§6.6). This is
a **detector, not the control** — it observes after `connect()` and cannot veto.
It MUST NOT be presented as the gate.

There MUST be no public resolver argument: an attacker-supplied resolver would
defeat the guard, and tests reach the resolver through an internal seam
(`r-binding.md` §3, §7).

**Evidence.** WordPress `wp_http_validate_url()` carried this bug for 5+ years;
LangChain `CVE-2026-41488`. **[sourced]**

**Test.** A counting resolver mock asserting exactly one call per hop; plus a
pin-effectiveness test using an unresolvable-by-design hostname (`.invalid`,
RFC 2606) so a passing result proves the pin was load-bearing.

### INV-6 — The pin MUST be unambiguous, and MUST NOT fail open

The mechanism binding a hostname to a validated address MUST NOT silently
disengage. Where the platform's pinning primitive is keyed (e.g. by host and
port), the implementation MUST construct the key such that a mismatch is
impossible, or MUST verify the pin engaged. With §4.2, the host in the key MUST
be the transport's own parse of the requested URL. That URL and its parsed host
meet §4.1's printable-ASCII rule (§8 item 34).

**Rationale.** **[verified]** in the R stack: both available primitives discard
the pin and perform a *real, unvalidated* resolution when the key's port does not
match the request's port — silently, with no error. A fail-open in the primary
safety mechanism.

**Test.** For each supported scheme and for explicit/default/non-default ports,
assert the connection went to the pinned address.

### INV-7 — Every dimension is revalidated on every hop

On redirect, the full §12 lifecycle MUST re-run against the new URL. It is not
sufficient to revalidate the address alone.

**Rationale.** A mature Go implementation revalidates address, port, and family
per hop but checks scheme, host rules, and credentials only once — so all three
are bypassable via redirect. **[sourced]** Three CVEs are exactly this bug,
validation followed by an unvalidated redirect: Grafana `CVE-2022-29170` and
Gitea `CVE-2026-58418` and `-57894`.

**Corollary.** The guard MUST own the redirect loop or be invoked per hop by a
caller that does (§1.3). Automatic transport-level redirect following MUST be
disabled. A guard attached to a transport *object* can be detached from it —
`CVE-2023-28155` deleted the agent on protocol switch, and the agent was the
guard. **[sourced]**

**Test.** Redirect chains ending at a prohibited target, one per dimension:
address, scheme, port, host rule, credentials.

### INV-8 — Credentials MUST NOT cross an origin boundary

On a cross-origin redirect the implementation MUST drop credential-bearing
material: `Authorization`, `Cookie`, and any caller-supplied header or body
carrying a secret. The request plan enters the guarded operation, a redirect hop
inherits it, and the redirect status is the one the transport observed. The
complete rules — carry allowlist, non-carryable and transport-owned fields,
refused field syntax, and the 301/302/303/307/308 transformation — are §2.3 and
are not restated here. `Authorization`, `Proxy-Authorization` and `Cookie` MUST
NOT be nominated as carryable.

**Rationale.** A working token-replay PoC was filed against the reference Ruby
implementation. Its fix, in 1.5.0 (April 2026), strips `authorization` and
`cookie` cross-origin, but 1.6.0 still replays `body`, `params`, and custom
headers verbatim. **[sourced]** The transport's
own "don't send credentials to other hosts" flag typically covers only
credentials the *transport* manages, not ones the caller set.

### INV-9 — Certificate verification MUST NOT be weakened

An implementation MUST NOT disable or relax TLS certificate or hostname
verification, and MUST NOT expose an option to do so. Verification here means
the certificate chain to a trusted root and the hostname. Revocation checking
(CRL, OCSP) is outside it: `ssrfr` checks revocation on no platform, so its
behaviour is the same on each (`r-binding.md` §5). *Clarified 2026-09-25*
(`SSRF-nbcgyled`).

**Rationale.** Pinning does **not** require it. **[verified]** by three
independent methods: a correct pin changes only the TCP peer, leaving SNI, the
`Host` header, and certificate validation bound to the hostname. What breaks TLS
is rewriting the URL's host to an IP literal — and the usual "fix" for that is
disabling verification, converting an SSRF mitigation into a MITM vulnerability.
The PHP library SafeCurl ships exactly that trade-off: its DNS-pinning mode puts
the IP in the URL, sends a `Host` header and turns off peer verification.
**[sourced]**

**Corollary.** The implementation MUST NOT rewrite the URL host to an IP literal.

### INV-10 — Ambient transport configuration MUST be neutralized

The implementation MUST disable proxy use, and MUST neutralize every ambient
configuration channel its transport reads: proxy environment variables, config
files, and any cache that can redirect a later request. v1 offers no proxy
opt-in: a caller-enabled proxy becomes the TCP peer and reaches the destination
from its own network, where `ssrfr` never classified the address, so the result
would read as a guarded fetch while guarding nothing. A trusted-proxy mode, in
which the proxy enforces destination policy and `ssrfr`'s claim narrows to
match, is deferred beyond v1. *Amended 2026-09-24* (was "unless the caller
explicitly opts in"). *Amended 2026-09-25* (was "resolves the hostname after
`ssrfr` validated it"; ADR 0006).

**Rationale.** A proxy moves the connection off the pinned path. The TCP peer
becomes the proxy, which reaches the destination from its own network, where
the address was never classified, and INV-5's peer check can no longer confirm
the pin. A proxy given the hostname also resolves it itself and discards the pin
entirely. **[sourced]** **[verified]**

*Replaced 2026-09-25* (was **[suspended]**; ADR 0006). The ratified rationale
said a proxy "resolves the hostname *itself*, discarding the pin entirely — a
total bypass." That holds for a proxy given the hostname, which is how the
reference Ruby implementation lost its pin. Under a `connect_to` pin, libcurl
8.14.1 gives the proxy the pinned address instead: an HTTP proxy receives
`CONNECT <pinned IP>:<port>`, even for `http://`, and a SOCKS5 or `socks5h`
proxy the IPv4 literal **[verified]**
(`design/evidence/2026-09-24-proxy-probes.R`). The pin's address survives; the
TCP peer does not.

The reference Ruby implementation followed ambient
proxies from its first release in 2017 until 1.6.0 (September 2026); MLflow's
webhook client is another surveyed project that ignores them. **[sourced]**
Beware channels that are not obviously proxies: an `Alt-Svc` cache remaps an
origin to a different protocol, host, and port for *later* requests and emits no
redirect, so a manual redirect loop cannot see it. **[sourced]**

**Test.** Set each ambient variable to a sentinel and assert the connection still
went to the pinned address; and serve an `Alt-Svc` header and assert it causes no
resolution, connection, or request (`r-binding.md` §7).

### INV-11 — Fail closed

Any error in parsing, resolution, or classification MUST result in refusal. There
is no path from "we could not determine this" to "proceed". (A failed
resolution is reported as the operational cause `unresolvable` (§6.6) rather
than a policy reason; either way no connection is made.)

**Rationale.** A literal that the address decoder cannot interpret MUST NOT fall
through to a default allow. The inherited implementation had exactly this hole
and was safe only because the parse layer rejected such inputs first — the
property was enforced by a different layer than the one that documented it.

**Test.** Malformed literals and truncated/refused resolutions, all expecting
refusal.

### INV-12 — Do not be an oracle

Refusals and operational failures exposed to an untrusted party MUST NOT reveal
which predicate fired or which cause ended the hop, which address, or which hop;
they SHOULD be indistinguishable in timing. *Amended 2026-09-25* (was
"Refusals"; §6.4). The
detailed record goes to the operator, the minimized projection to the untrusted
party, and the timing limit is documented (§6.4).

**Rationale.** Blind SSRF turns any differential — a distinct error, a faster
failure — into a port scanner. This is essentially unimplemented across the
surveyed field and is a genuine differentiator.

**Test.** The projection returns one identical value for every reason code and
every operational cause; `print`, `format` and every condition `ssrfr` raises
omit userinfo, request-plan header values and bodies, and neutralized proxy
values (§2.3); and the caller's full record still names the predicate, address
and hop. *Ratified 2026-09-25* (`SSRF-qttneqxp`).

### INV-13 — Denylists are never complete; gate on a positive predicate

Classification MUST be expressed as a positive routability predicate applied to
the resolved address, not as an enumerated list of prohibited ranges.

**Rationale.** `pydantic-ai` shipped **three CVEs in about four months**
(`CVE-2026-25580` → `-46678` → `-48782`). The first was a fetch with no address
check at all; its fix added a blocklist, and the next two were each an
IPv6-transition wrapper of the metadata address that the blocklist missed, the
last unfixable *in principle* because NAT64 prefixes are operator-chosen.
**[sourced]** *Corrected 2026-09-25* (was "three CVEs against one blocklist …
each an IPv6-transition wrapper"; `SSRF-qttneqxp`).

**Corollary — embedded addresses.** Any address form that carries another
address MUST have the carried value extracted and classified independently. The
carried value is not always the destination: IPv4-mapped and NAT64 forms carry
the address the connection reaches, while the 6to4 `V4ADDR`, Teredo's server and
client fields and the ISATAP locator are tunnel underlay (§5.1). The refusal is
the same either way, and its code names the embedding kind (§6.5). A
registry-driven "globally reachable" flag does **not** cover this: IANA correctly
marks the NAT64 well-known prefix as globally reachable, because it maps onto
global IPv4 — so the wrapper is reachable while what it *wraps* may not be.
In `ssrfr`, `raddr` extracts and `ssrfr` evaluates both (§5.2).

**Corollary — hostname rules are still required.** Some provider endpoints are
reached by a name that no address rule sees before resolution, and some must be
reached by name over HTTPS (IBM Cloud **[sourced]**). A hostname denylist is
therefore a first-class control, not a convenience (§5, gate 5).

### INV-14 — Deny wins

When both a caller allow rule and a caller deny rule match, the request MUST be
refused. Built-in refusals are not deny rules for this purpose: §5.0 defines how a
caller allow rule interacts with them, and which of them no allow rule can
override.

**Rationale.** The alternative — allow overrides deny, as one Go implementation
does, where configuring any allowlist silently flips the whole policy to
default-deny — makes the effective policy hard to predict from the configuration.
**[sourced]** A conjunctive model is auditable.

**Corollary.** The consumer SHOULD provide one explicit, unmistakably-named way
to disable the guard entirely. It is a single top-level argument of the
consumer's own API, never the default, and documented as disabling the guard
(ADR 0001 §5), like `ssrf_guard = FALSE` in `robotstxtr` and `sitemapr`. `ssrfr`
itself has none: no `ssrfr` function takes an argument that disables the guard,
because a binding produced without validation would be a detached guard (§9). A
deliberately authorized internal target is reached with `allow_ranges` or
`allow_hosts` (§5.0). *Amended 2026-09-25* (was "An implementation SHOULD
provide"; §8 item 26, `SSRF-cnljaaek`, ADR 0007).

---

## 14. Transport hardening

`r-binding.md` §5 names the concrete options. The implementation MUST achieve
these effects:

| Requirement | Attack prevented |
|---|---|
| Scheme allowlist enforced at the transport, not only by the guard | scheme smuggling if a code path bypasses the guard |
| Automatic redirect following disabled | unvalidated hop (INV-7) |
| Connection reuse must not outlive a pin | a pooled connection bypassing this request's validation |
| Resolution caching must not serve an unvalidated later request | stale-answer bypass |
| Proxy and ambient config neutralized | a connection off the pinned path: the proxy becomes the TCP peer and reaches an address `ssrfr` never classified, and a proxy given the hostname resolves it again (INV-10) |
| Origin-remapping caches disabled | invisible later redirect (INV-10) |
| Local-socket transports disabled | container control-plane access |
| Connect timeout and total timeout both set | port scanning by timing; resource exhaustion |
| Response size bounded by counting delivered bytes | decompression bombs; header-declared size is advisory only |
| Transport-managed credentials and cookie state disabled (netrc, the cookie engine, cookie files) | credentials the request plan did not carry: a `401` answered from an ambient netrc; a replayed `Set-Cookie` (INV-8, INV-10) |
| The transport handle is built by `ssrfr` for each fetch; no public argument, policy field or request plan accepts a `curl` handle, `curl` options or a callback | a caller option silently undoing a row above: `unix_socket_path` skips resolution and the pin entirely; `proxy`, `connect_to`, `resolve` or `followlocation` replace the pin or the loop |

**Note.** A declared-size limit is not a size limit: older transports ignore it
when the server omits a length header, and it is measured on wire bytes so a
compressed bomb passes. Count bytes as they are delivered. **[sourced]** A timer
alone does not preempt synchronous decoding either: `linklint` races its total
deadline, an event-loop timer, against a synchronous decompression call, and the
timer cannot fire until the decode returns **[sourced]**. The total deadline
therefore covers decoding, and header bytes and field counts have limits of their
own (§5.3).

---

## 15. Compliance claims

Permitted, with citation: OWASP SSRF Prevention Cheat Sheet items; ASVS 5.0
V1.3.6, V15.3.2, V1.5.3; CWE-918; CAPEC-664; WSTG SSRF tests; refusal of IPv6
zone-ID literals (§4.2; RFC 9844).

ASVS 5.0 V13.2.4 only in qualified form: `ssrfr` *supports* an application's
destination allowlist, which the requirement allows at any layer. Its allow
fields are exceptions over a default-allow-public posture, not a destination
allowlist, so V13.2.4 is enforced by the application (§7, requirement coverage).

Explicitly **not** permitted:

- A year-less "OWASP Top 10 A10 = SSRF". In the 2025 edition SSRF is folded into
  A01:2025 Broken Access Control; A10:2025 is a different category. Cite an
  edition.
- "ASVS V50" — no such chapter exists in 5.0.
- "Zero bypasses", "zero false positives", or any safety rate
  derived from the project's own corpus. A published result names the corpus
  version and its per-group counts (§7); passing it shows those vectors are
  handled, not that no bypass exists.
- ASVS 5.0 V13.2.5. It requires the web or application server itself to be
  configured with an allowlist, which a library cannot satisfy.
- PCI DSS or CIS benchmark compliance. Neither has citable SSRF text.
- Any claim that the library replaces network-level egress control (§11.2).
- Any claim that L0 provides SSRF protection (§1.1).

---

## 16. References

Full citations with pinned URLs are in [`../references.md`](../references.md)
(non-normative; §7.1).
Primary sources:

- OWASP SSRF Prevention Cheat Sheet; OWASP ASVS 5.0; OWASP WSTG; OWASP API
  Security Top 10 (API7:2023).
- CWE-918; CAPEC-664.
- RFC 3986; WHATWG URL Standard; RFC 9110 §15.4; RFC 9844 (obsoletes RFC 6874); RFC 2606; UTS-46;
  RFC 6052; RFC 3056; RFC 4380; RFC 5214; RFC 6598.
- Tsai, *A New Era of SSRF — Exploiting URL Parsers*, Black Hat USA 2017.
- Claroty Team82, *Exploiting URL Parsing Confusion*, 2022.
- ONsec/Wallarm, *SSRF Bible*.
- Implementation prior art: `ssrf_filter` (Ruby), `safeurl` (Go/Python),
  `advocate` (Python), Sentry, MLflow, smokescreen (Stripe), Gitea `hostmatcher`,
  and the sibling `linklint` (TypeScript), whose provider-endpoint table, peer
  fail-closed rule and policy-input hygiene fixes this document adopts as
  proposals.
- Vendor metadata documentation as cited in `linklint`
  `packages/core/src/data/cloud-metadata.ts` (IBM Cloud VPC metadata API; Azure
  WireServer; Equinix Metal sunset notice).
