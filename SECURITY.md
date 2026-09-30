# Security Policy

## Supported versions

Security fixes are made against the latest released version of `ssrfr` and the
development version on `main`; please upgrade to the most recent release before
reporting.

| Version                        | Supported          |
| ------------------------------ | ------------------ |
| Latest release                 | :white_check_mark: |
| Development version (`main`)   | :white_check_mark: |
| Older releases                 | :x:                |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues.**

Preferred channel — **email the maintainer at bartek@turczynski.pl.**

Alternatively, open a **confidential issue** on the GitLab project:

1. Go to [Issues](https://gitlab.com/bart-turczynski/ssrfr/-/work_items) and click
   **New issue**.
2. Tick **This issue is confidential** before submitting.

A confidential issue is visible only to project members.

Email is listed first deliberately: it works whether or not you have a GitLab
account, and it is the channel the maintainer monitors.

Do not include secrets, credentials, tokens, or private customer data in a
report, an issue, a merge request or a log. A reproduction against a server
you control, or a loopback server under a test policy, is enough.

## What to expect

- We aim to acknowledge a report within **7 days**.
- We will investigate, work on a fix, and coordinate disclosure with you.
- We are happy to credit reporters in the release notes unless you prefer to
  remain anonymous.

## Scope

`ssrfr` is an SSRF guard: it decides whether a URL may be fetched under a
policy, and fetches it through a connection pinned to an address it validated.

### What is in scope

- A URL, redirect chain or resolver answer that makes `ssrf_fetch()` or
  `ssrf_fetch_chain()` connect to a destination the policy refuses.
- A connection to an address the binding did not validate, a second name
  resolution during a fetch, or a pin that silently fails open.
- A URL that `ssrfr` checks as one host while libcurl connects to another.
- A credential or request header crossing an origin boundary it should not
  cross on a redirect.
- Weakened certificate verification, or a proxy or other ambient transport
  setting that takes effect despite the guard.
- A response limit that can be exceeded, or a crash, hang or unbounded memory
  use on any input.
- Userinfo, request header values, bodies or proxy values appearing in a
  printed or formatted result or a condition message, or a projection from
  `ssrf_public_reason()` that tells an untrusted party more than it should.

### What is out of scope

- Requests made without a binding: base R's `download.file()` and `url()`,
  direct `curl`, `httr` or `httr2` calls, and the packages that read URLs
  through them. `ssrfr` cannot guard those.
- `ssrf_inspect_url()` finding nothing wrong with a name that later resolves
  somewhere else. Inspection is a pre-filter, not a defense; only the guarded
  fetch is.
- Destinations a policy explicitly allows, such as a range opened with
  `allow_ranges`.
- The residuals the
  [v1 specification](https://gitlab.com/bart-turczynski/ssrfr/-/blob/main/design/specs/ssrfr-v1.md)
  documents as outside v1, such as the host's own public addresses when they
  are not listed in `deny_ranges`.
- Egress control. A firewall or a separate network is the stronger boundary;
  `ssrfr` is defense in depth beside it.
