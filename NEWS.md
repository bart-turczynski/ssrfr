# ssrfr 0.0.0.9000

First release: an SSRF guard for R code that fetches URLs an attacker can influence.

## Requirements

* `ssrfr` requires R >= 4.1.0 (was R >= 4.0.0). `rurl`, which it imports, needs `pslr`, which requires R 4.1, and `rurl` and `raddr` both declare R 4.1 on their development branches. The weekly `deep-check` pipeline checks the package on R 4.1.3 (`SEOR-rcpzfhgx`).

## Guarded fetch

* `ssrf_prepare_hop()` decides one hop. It parses the URL, checks it against the policy, resolves the name once with a trailing root dot (so that no DNS search domain applies) and classifies every address, then returns a refusal with a reason code, an operational failure, or a binding pinned to the validated addresses. One refused address refuses the whole answer (SSRF-rgcijatt, SSRF-ifldwmnc).
* The request plan (method, header fields, body, and the fields nominated to cross origins in `carry`) is validated when the hop is prepared. A plan that sets a field the transport owns (`Host`, `Expect` and the like) raises `ssrfr_error_invalid_request`, as does a metadata-service request marker such as `Metadata-Flavor` unless the policy's `allow_ranges` names a provider endpoint exactly (SSRF-rgcijatt).
* `ssrf_fetch()` fetches through a binding and connects only to a validated address, through a `connect_to` pin that keeps the `Host` header, SNI and certificate verification bound to the hostname. It never resolves the name again, confirms from libcurl's trace that the connection reached the pinned address (failing as `"pin-mismatch"` otherwise), and fails over in resolver order only when a connection never opened (SSRF-rgcijatt).
* `ssrf_fetch()` never weakens certificate verification, ignores proxy variables, allows only `http` and `https`, speaks HTTP/1.1 only, reuses no connection, and sends a request at most once: it sends neither `Expect: 100-continue` nor a default `Accept` the plan did not ask for (SSRF-rgcijatt).
* A binding is single-use: `ssrf_fetch()` spends it on entry, and a second fetch raises `ssrfr_error_spent_binding`. The response is read in full within the policy's limits and owns no handle, and a transfer whose status libcurl reports differently from the status line it received fails as `"protocol-error"`; its `print()` shows the status, media type and body size, never the body (SSRF-rgcijatt, SSRF-fvtqbanc).
* Response limits count what arrives: `max_response_size` counts decoded bytes, so a compression bomb stops at the limit without libcurl decoding the rest, and `max_header_bytes` and `max_header_fields` include interim `1xx` responses and a chunked body's trailer fields (SSRF-rgcijatt, SSRF-itqfcyrw, SSRF-fvtqbanc).
* `ssrf_prepare_hop(from = binding)` prepares a redirect hop from the previous hop's `Location`, resolved against its URL and checked from the start. The request plan is inherited, not restated: `301` and `302` turn `POST` into `GET`, `303` turns everything but `HEAD` into `GET`, `307` and `308` keep the method and body, and a redirect to another origin drops the body, the fields that describe it (`Content-Range`, `Content-Disposition` and `Repr-Digest` included) and every field not nominated in `carry`. `Authorization`, `Proxy-Authorization` and `Cookie` never cross an origin. The binding's `redirect` field records what was dropped, and a redirect hop's refusal or failure records the URL its `Location` resolved to (SSRF-fvtqbanc).
* An `https` to `http` redirect refuses as `"downgrade"`. Once a chain has followed `max_redirects` redirects, any further `3xx` refuses as `"redirect-limit"`. `max_redirects` and `total_timeout` belong to the whole chain, and a redirect hop's policy that restates either differently raises `ssrfr_error_budget_change` (SSRF-fvtqbanc).
* A redirect hop's `from` must be a fetched binding that holds a followed redirect, and its `url` must be that binding's `Location` byte for byte, or `ssrf_prepare_hop()` raises `ssrfr_error_invalid_from` (SSRF-fvtqbanc).
* `ssrf_fetch_chain()` follows a redirect chain for a caller without a loop of its own. Built only on `ssrf_prepare_hop()` and `ssrf_fetch()`, it returns the last outcome: the final response, or the refusal or failure that ended the chain. A caller that must log every hop runs the per-hop loop instead (SSRF-bvuwvcnh).

## Inspection

* `ssrf_inspect_url()` reports what a URL is under a policy with no network I/O: the parse `rurl` and libcurl agree on, the scheme, host and port, the classification of an address-literal host, and the reason code of the first check that applies. It is a pre-filter and a configuration-linting aid, not a defense (SSRF-uxmxqufj).
* A URL refuses as `"parse"` unless the string handed to libcurl, and the host libcurl reads from it, are printable ASCII, so a U-label host reaches libcurl only as its A-label. A string that is not valid UTF-8 refuses the same way rather than raising an error (SSRF-afpkreyj).
* A host with an `xn--` label that is not a genuine A-label, such as `xn--a.example`, now refuses as `"parse"`, on `rurl`'s `domain-invalid-ace-label` diagnostic; `ssrfr` now requires `rurl` >= 3.1.0 (SSRF-imtdxdym).
* `ssrf_inspect_url(layer = "L1")` also resolves the name once and classifies every address it resolves to, with each address's own facts in `addresses`. A resolver error, an empty answer or an answer that is not an address is the operational cause `"unresolvable"` (SSRF-ifldwmnc).

## Policy

* `ssrf_policy()` builds a guard policy: allowed schemes and ports, denied and allowed hosts and address ranges, whether URLs may carry credentials, and the redirect, time, size and URL-length limits. By default it allows only `http` and `https`, on ports 80 and 443, to public addresses. A malformed entry, range, limit or `user_agent` raises `ssrfr_error_invalid_policy` instead of becoming a rule that silently matches nothing (SSRF-upyqnwmv).

## Results and vocabularies

* Refusals, operational failures and responses are values, not errors. A misuse of the API is an `ssrfr_error` condition with a subclass per kind (SSRF-upyqnwmv, SSRF-rgcijatt).
* `ssrf_public_reason()` projects a refusal or failure to the one value an untrusted party may see (SSRF-upyqnwmv).
* Refusals, failures and conditions print and format without userinfo, request header values, bodies or proxy values. A failure's `detail` lists the addresses a fetch tried and how each attempt ended and, when one of its own callbacks ended the fetch, every callback that failed (SSRF-upyqnwmv, SSRF-rgcijatt, SSRF-dmmcitul).
* `ssrf_vocabulary()` lists the closed, versioned vocabularies: reason codes, operational causes, condition classes, and the policy data refused by default (provider metadata endpoints by address, metadata hostnames by name, and metadata-service request headers), each data row citing the vendor documentation that names it (SSRF-upyqnwmv, SSRF-uxmxqufj, SSRF-rgcijatt).

## Documentation

* ssrfr has a logo, the fleet's black hex, in `man/figures/logo.svg` and `logo.png`. r-universe shows it on the package card and the documentation site in its header, and the `README.md` heading carries it with the alt text "hex logo, white on black" (`SEOR-wxjuxbtu`, `SEOR-wfleahtg`).

* The logo files carry full metadata: every project link (GitLab, GitHub, CRAN, r-universe, the documentation site), a screen-reader description and the standard image metadata fields, written by `scripts/logo-metadata.py` from the fleet's `seor` repository (`SEOR-eyfiidrv`). Their keywords are the `X-schema.org-keywords` tags of `DESCRIPTION`, after `R`, `rstats` and `R package`, so the logo and r-universe list the same tags (`SEOR-qoqmestu`).

* `README.md` now shows how to install `ssrfr` from r-universe, before the GitLab development install, and its development notes moved to `CONTRIBUTING.md` and `ARCHITECTURE.md`. `DESCRIPTION` declares `X-schema.org-keywords`, which r-universe search reads (`SEOR-kqmqosji`, `SEOR-nplcfbib`).
