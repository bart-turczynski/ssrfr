# ADR-002: v1 dependency and policy model

- Status: Accepted
- Date: 2026-07-31
- Deciders: Bart Turczyński
- Amends: `ADR-001-network-safety-policy.md` §5 and §7
- Related: `docs/spec/ssrfr-v1.md` §4 and §5.0

## Context

ADR-001 was written before the v1 specification resolved two structural
questions. First, it kept a vendored, zero-dependency classifier so `ssrfr` would
not block on `raddr`. Subsequent review established that vendoring the inherited
matcher preserves the denylist architecture that ADR-001 itself rejects; `raddr`
already owns the registry-driven positive classification model.

Second, ADR-001 said caller allow rules could not override built-in refusals and
provided one global off switch. That left `allow_hosts` and `allow_ranges`
operationally inert. Operators with legitimate internal or metadata-service
targets would have to disable the whole guard rather than grant a narrow
exception.

## Decision

### 1. `curl`, `rurl`, and `raddr` are hard dependencies

`rurl` owns URL parsing, normalization, reference resolution, and IDNA. `raddr`
owns address parsing, registry snapshots, reachability facts, and embedding
classification. `ssrfr` consumes those facts and owns policy, refusal semantics,
DNS answer-set validation, pinning, guarded transport, and conformance evidence.

`ssrfr` owns no parser, classification tables, or second embedding decoder
inventory. The vendored `ssrf_in_cidr()` seam described by ADR-001 §7 is removed
from the design. Release ordering is a submission-time scheduling concern, not a
reason to duplicate security-sensitive logic.

### 2. Precedence is four-tier and dimension-local

Each of the address and hostname dimensions is evaluated independently:

1. indeterminate address classification, and a non-global verdict derived from
   an embedded address, refuse and cannot be overridden;
2. a matching caller deny rule refuses;
3. a matching caller allow rule overrides only a built-in refusal in the same
   dimension;
4. otherwise the built-in rule applies.

The address built-ins are determinate non-global reachability and multicast. The
hostname built-in is the metadata hostname list established by ADR-001 §2.4.
`allow_ranges` overrides determinate built-in address refusals, including
multicast. `allow_hosts` overrides the built-in metadata hostname refusal. Caller
deny rules always win, and neither allow rule affects the other dimension.

Allow fields are narrowly scoped exception lists, not default-deny allowlists. A
name allowed in the hostname dimension still has every resolved address checked;
an address exception does not excuse a caller-denied or built-in-denied hostname.

The consumer-facing global off switch remains available for applications that
intend to bypass `ssrfr` entirely, but it is no longer the only way to reach a
deliberately authorized internal target.

## Consequences

- The classification model has one owner and one registry update path.
- Fine-grained exceptions preserve all unrelated SSRF controls and are safer than
  forcing operators toward the global off switch.
- `allow_hosts` has one concrete purpose: overriding a built-in-denied metadata
  hostname. It does not authorize arbitrary DNS answers.
- `allow_ranges` can authorize private, link-local, or multicast destinations
  without weakening hostname policy or allowing indeterminate classifications.
- `allow_ranges` cannot authorize a destination reached through an address
  embedding (NAT64, 6to4, and the other forms `raddr` decodes). An allow range can
  only match the outer wrapper, so an override would admit every internal target
  wrapped in an allowed prefix. Callers reach such targets by their direct
  address (`ssrfr-v1.md` §5.0).
- ADR-001 §5's statement that built-ins are overridable only in the deny direction
  and §7's vendored-classifier dependency posture are superseded.
