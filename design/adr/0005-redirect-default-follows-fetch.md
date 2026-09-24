---
status: accepted
date: 2026-09-24
tracking: SSRF-pffrmkdr
---

# ADR 0005: The redirect default follows the Fetch Standard

## Context

ADR 0004 §4 set the default `max_redirects` to 10, the value most surveyed SSRF
libraries use (Go's `net/http`, aiohttp, `ssrf_filter`, `linklint`). The number
was ours to defend, because nothing normative named it.

Something does. The WHATWG Fetch Standard, which browsers implement, stops a
redirect chain at 20: *"If request's redirect count is 20, then return a network
error."* Chrome chose its limit of 20 to match Firefox. RFC 9110 §15.4 sets no
number; it asks clients to detect cycles and notes that an earlier version
recommended five. Among HTTP clients, libcurl (since 8.3.0) and Python's
`requests` default to 30, Go to 10.

## Decision

The default `max_redirects` is **20**, citing the Fetch Standard. Everything
else in ADR 0004 §4 stands: the limit is finite and raisable, `0` means "refuse
any 3xx", and the budget covers the whole chain.

A 3xx that arrives after the budget is spent refuses with a new policy reason
code, `redirect-limit`. The Fetch Standard calls it a network error, but in
`ssrfr` the budget is a caller-set policy field, so exceeding it is a refusal,
not a wire failure.

`ssrfr-v1.md` §5.3 states the default, and §6.5 the code.

## Consequences

- The default is a cited standard rather than a survey median.
- A chain can take twice as many hops as under ADR 0004. Each hop is fully
  revalidated and the 30 s chain deadline still bounds the total, so the extra
  exposure is time, not reach.
- Consumers with tighter needs keep their own value: `sitemapr` defaults to 5,
  and RFC 9309 asks robots.txt crawlers to follow at least five.
