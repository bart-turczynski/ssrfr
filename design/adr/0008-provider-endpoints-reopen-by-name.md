---
status: accepted
date: 2026-11-16
tracking: SSRF-ntxhdswq
---

# ADR 0008: provider endpoints reopen only by name, never by a range

## Context

ADR 0004 item 1 let an `allow_ranges` entry that names a provider endpoint
exactly (a /32 or /128 equal to a row of `ssrfr-v1.md` §5 gate 2's table)
reopen that endpoint, and §2.3 tied the metadata-service request markers to
the same entry. A broader range left the endpoints inside it refused.

Some table rows sit in address space callers also use for ordinary hosts:
`100.100.100.200` in the shared address space `100.64.0.0/10`, `fd00:ec2::254`
and `fd20:ce::254` in unique local space. A caller who lists an internal host
by its exact address can therefore reopen a cloud-metadata service without
meaning to, and unlock the markers with it. `robotstxtr` promises its users
that its allow ranges never reopen a provider endpoint (its ADR 0001 §6) and
had to enforce that itself, a guard rule living in a consumer.

## Decision

1. **Only a dedicated field reopens a provider endpoint.**
   `ssrf_policy(allow_provider_endpoints = )` names the endpoints to reopen,
   each an address of the table. `allow_ranges` never reopens one. A caller
   deny range still wins, and tier 1 (an endpoint inside another address)
   still refuses unconditionally.
2. **An `allow_ranges` entry equal to a provider endpoint is a construction
   error.** It could reopen nothing, and a policy entry that silently does
   nothing is an error throughout `ssrf_policy()`. The message names the
   address as on the provider-endpoint list and points to the new field; it
   does not claim a metadata service is there.
3. **The markers follow the field.** A request plan may carry them when
   `allow_provider_endpoints` names any endpoint. A check per hop, admitting a
   marker only toward a reopened endpoint, was considered and declined: R
   rarely runs server-side, the default stays closed, and the simpler rule is
   enough.

Item 1 of ADR 0004 is superseded. Its premise, that a broad private-network
opt-in must not reopen metadata, is kept and extended to exact entries.

## Consequences

`ssrfr` 1.1.0 changes behavior for a policy with an exact entry for an
endpoint, which now errors. 1.0.0, still in CRAN's incoming queue, carries
the old rule; no user depends on it yet.
`robotstxtr` and `sitemapr` can pass their allow ranges through unchanged once
they require this release. The gate set and the reason codes are unchanged.

Decided by the maintainer on 2026-11-16, after a second opinion from Codex
(GPT-6.1-Sol), which recommended this option and the per-hop marker check the
maintainer declined.
