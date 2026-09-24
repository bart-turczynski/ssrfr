# References

Non-normative. Source citations for the `[sourced]` claims, compliance claims and
reference list in [`specs/ssrfr-v1.md`](specs/ssrfr-v1.md), plus the external
sources [`specs/r-binding.md`](specs/r-binding.md) leans on. The spec states each
claim; this file only says where it comes from. `[verified]` claims are backed by
the probe scripts in [`evidence/`](evidence/), not by this file.

Distilled on 2026-09-24 from the July research notes (2026-07-25 and
2026-07-31), which stay local and uncommitted.

## Conventions

- **Pinned** means the link cannot change under the citation: a commit SHA, a
  release tag, a versioned document, an RFC (immutable by RFC Editor policy), a
  WHATWG commit snapshot, or a Wayback Machine snapshot whose timestamp is in
  the URL.
- **Accessed** is the date the pinned link was resolved and checked to exist.
  For Wayback links the snapshot date is in the URL; it can postdate the July
  research.
- A source with no pinned form is listed under [Not yet pinned](#not-yet-pinned)
  with its canonical URL, for the maintainer to archive or replace.
- A claim without an entry here has no committed citation yet (fp
  `SSRF-ssldkvmd`).

Pinned revisions used throughout:

| Source | Revision |
|---|---|
| `arkadiyt/ssrf_filter` | tag 1.6.0, `847abaf76841cdc630752c13c0cd3528f7fdc102` |
| `curl/curl` | tag `curl-8_14_1` (the libcurl bundled with R's `curl` 8.0.0) |
| `jeroen/curl` (R package) | `4092c366c27c8b64528b493be5e09fb6484a1172` (the 7.1.0 snapshot read on 2026-07-31) |
| OWASP ASVS | tag `v5.0.0_release` (the 5.0.0 release; the repository has no plain `v5.0.0` tag) |
| OWASP Cheat Sheet Series | `c04039adbe6f727a2198b3a3ea634fec98ac068a` |
| OWASP Top 10 | `3a31f35346c3f4e90f350395124382fa53af2afe` |
| OWASP WSTG | `ea174034f91439a17a1595e57d51e5b461820273` |
| OWASP API Security | `33cea37b2ffde3e2e62f6b5d79a029a22a846633` |
| `linklint` | `8830901a6c9e95a69b110b06db01bd97fa2aabb9` |
| `rurl` | tag v3.0.1, `0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35` |

---

## ssrfr-v1.md

### §1 Layer contracts

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| Collapsing the layers is the defect in `CVE-2026-41488`; the advisory names "validate-then-fetch with separate DNS resolution" | LangChain advisory GHSA-r7w7-9xr2-qq2r | <http://web.archive.org/web/20260424232417/https://github.com/langchain-ai/langchain/security/advisories/GHSA-r7w7-9xr2-qq2r> | 2026-09-24 |
| §1.1: a mature implementation refuses an L0-equivalent — "the checking and fetching have to happen in a single step" | `ssrf_filter` maintainer, issue #78 | not yet pinned (below) | — |

### §4 Dependency contract

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| `rurl` 3.0 parses `http`/`https` in-tree (r-binding.md §2.1) | `rurl` `R/parse-web.R` | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/parse-web.R> | 2026-09-24 |
| `raddr::addr_curl()` regressed 7 of 18 hosts (r-binding.md §2.6) | `rurl` ADR 0018 | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/design/adr/0018-ip-literals-belong-to-raddr.md> | 2026-09-24 |

### §5 The refusal rule

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| Gate 2 starting point: the ten-row provider-endpoint table, with a vendor citation per row (AWS, Azure WireServer `168.63.129.16`, Oracle, Alibaba, GCP, IBM, Tencent, Exoscale) | `linklint` `packages/core/src/data/cloud-metadata.ts` | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/core/src/data/cloud-metadata.ts> | 2026-09-24 |
| Gate 5: IBM Cloud's metadata API is reachable at `169.254.169.254` or `api.metadata.cloud.ibm.com`, and over HTTPS must be the hostname | IBM Cloud VPC metadata API docs | not yet pinned (below); quoted in the `linklint` file above | — |
| Equinix Metal was sunset on 2026-06-30; its metadata page is scheduled for removal | Equinix Metal metadata docs; recorded in the `linklint` file above | not yet pinned (below) | — |
| Two independent implementations missed Oracle's `192.0.0.192` | `[verified]`, not sourced: [`evidence/2026-09-24-oracle-metadata-miss.R`](evidence/2026-09-24-oracle-metadata-miss.R) | — | — |
| §5.0: case folding must be ASCII-only; `stringi`'s `"root"` locale does not override the ambient one | `linklint` `docs/locale-case-mapping.md` | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/docs/locale-case-mapping.md> | 2026-09-24 |
| §5.3: the browser "bad port" list omits Redis (6379) and Memcached (11211) | WHATWG Fetch, "bad port" | <https://fetch.spec.whatwg.org/commit-snapshots/357bd98924d94b81fbe8608192a2ee1f123b82f4/#bad-port> | 2026-09-24 |
| §5.3: the reference Ruby implementation has no port restriction | `ssrf_filter` source | <https://github.com/arkadiyt/ssrf_filter/blob/847abaf76841cdc630752c13c0cd3528f7fdc102/lib/ssrf_filter/ssrf_filter.rb> | 2026-09-24 |
| §5.3: CWE-918's alternate term is *Cross Site Port Attack* (XSPA) | CWE-918 | <http://web.archive.org/web/20260724102025/https://cwe.mitre.org/data/definitions/918.html> | 2026-09-24 |
| §5.3: four OWASP sources recommend disabling redirects: the SSRF Prevention Cheat Sheet (twice), Top 10 A10:2021, API7:2023, and ASVS 5.0 V15.3.2 | see the four rows below | | |
| | OWASP SSRF Prevention Cheat Sheet | <https://github.com/OWASP/CheatSheetSeries/blob/c04039adbe6f727a2198b3a3ea634fec98ac068a/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md> | 2026-09-24 |
| | OWASP Top 10 A10:2021 | <https://github.com/OWASP/Top10/blob/3a31f35346c3f4e90f350395124382fa53af2afe/2021/docs/en/A10_2021-Server-Side_Request_Forgery_(SSRF).md> | 2026-09-24 |
| | OWASP API Security Top 10, API7:2023 | <https://github.com/OWASP/API-Security/blob/33cea37b2ffde3e2e62f6b5d79a029a22a846633/editions/2023/en/0xa7-server-side-request-forgery.md> | 2026-09-24 |
| | ASVS 5.0.0 V15.3.2 | <https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md> | 2026-09-24 |
| §5.3: `linklint` shipped empty, untrimmed and comma-joined policy entries with exit status 0 | `linklint` commits `e632d78`, `12f56ab`, `2ac85ff` | <https://gitlab.com/bart-turczynski/linklint/-/commit/e632d78a877ebef8c5a83c599ac061145816d390>, <https://gitlab.com/bart-turczynski/linklint/-/commit/12f56ab872c438be812d8b4ce843f7f366f24761>, <https://gitlab.com/bart-turczynski/linklint/-/commit/2ac85ffddc935d4f13a223a0e038b405c6fed833> | 2026-09-24 |

### §7 Conformance

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| The reference Ruby implementation advertises 100% coverage | `ssrf_filter` README | <https://github.com/arkadiyt/ssrf_filter/blob/847abaf76841cdc630752c13c0cd3528f7fdc102/README.md> | 2026-09-24 |
| …and had two bypasses reported by outsiders | HackerOne reports #3634400 and #3642600; fixes in the changelog | <https://github.com/arkadiyt/ssrf_filter/blob/847abaf76841cdc630752c13c0cd3528f7fdc102/CHANGELOG.md>; reports not yet pinned (below) | 2026-09-24 |
| Parse vectors map to ASVS 5.0 V1.5.3 (parser consistency) | ASVS 5.0.0 V1 | <https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x10-V1-Encoding-and-Sanitization.md> | 2026-09-24 |

### §13 Load-bearing invariants

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| INV-1: Spring `CVE-2024-22243` | Spring security advisory | <http://web.archive.org/web/20260730215833/https://spring.io/security/cve-2024-22243/> | 2026-09-24 |
| INV-1: Spring `CVE-2024-22259` | Spring security advisory | not yet pinned (below) | — |
| INV-1: Spring `CVE-2024-22262` | Spring security advisory | <http://web.archive.org/web/20260730215521/https://spring.io/security/cve-2024-22262/> | 2026-09-24 |
| INV-1: Claroty Team82's 16-library study | Claroty Team82, *Exploiting URL Parsing Confusion*, 2022 | <http://web.archive.org/web/20260801132538/https://claroty.com/team82/research/exploiting-url-parsing-confusion> | 2026-09-24 |
| INV-1: Tsai, Black Hat USA 2017 | Orange Tsai, *A New Era of SSRF — Exploiting URL Parser in Trending Programming Languages!* | <http://web.archive.org/web/20260723005656/https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf> | 2026-09-24 |
| INV-4: `january` checked only the first resolved address | stoatchat/january GHSA-4mcc-p83c-r77q | not yet pinned (below) | — |
| INV-5: WordPress `wp_http_validate_url()` validated, then the transport re-resolved | Sonar, *WordPress Core — Unauthenticated Blind SSRF* | not yet pinned (below) | — |
| INV-5: WordPress's opt-in fix (the validated address returned by reference) | `wp-includes/http.php` at 6.8.0 | <https://github.com/WordPress/wordpress-develop/blob/a33a49e2e7f7e47656bc835996c692593edeba00/src/wp-includes/http.php> | 2026-09-24 |
| INV-5: LangChain `CVE-2026-41488` | as §1 | as §1 | 2026-09-24 |
| INV-7: Gitea `CVE-2026-58418` (migration validates, then follows the redirect unvalidated) and `CVE-2026-57894` (migration follows git HTTP redirects after validation) | GitLab advisory database | not yet pinned (below) | — |
| INV-7: Grafana `CVE-2022-29170`, datasource restrictions bypassed via redirects | Grafana GHSA-9rrr-6fq2-4f99 | <http://web.archive.org/web/20250422121301/https://github.com/grafana/grafana/security/advisories/GHSA-9rrr-6fq2-4f99> | 2026-09-24 |
| INV-7: `CVE-2023-28155`, the agent deleted on protocol switch (`request`) | GHSA-p8p7-x288-28g6 | not yet pinned (below) | — |
| INV-8: a token-replay PoC was filed against the reference Ruby implementation | HackerOne #3642600 | not yet pinned (below) | — |
| INV-8: cross-origin stripping of `authorization` and `cookie` since 1.5.0; 1.6.0 still passes the same method, body and params to every hop | `ssrf_filter` changelog and source at 1.6.0 | <https://github.com/arkadiyt/ssrf_filter/blob/847abaf76841cdc630752c13c0cd3528f7fdc102/CHANGELOG.md>, <https://github.com/arkadiyt/ssrf_filter/blob/847abaf76841cdc630752c13c0cd3528f7fdc102/lib/ssrf_filter/ssrf_filter.rb> | 2026-09-24 |
| INV-8: the transport's own flag covers only transport-managed credentials | libcurl `CURLOPT_UNRESTRICTED_AUTH` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_UNRESTRICTED_AUTH.md> | 2026-09-24 |
| INV-9: SafeCurl's DNS-pinning mode puts the resolved IP in the URL, sends a `Host` header and sets `CURLOPT_SSL_VERIFYPEER` to false | `j0k3r/safecurl` 3.0.1 (the maintained fork) `src/Url.php`, `src/SafeCurl.php`; the original `fin1te/safecurl` does the same | <https://github.com/j0k3r/safecurl/blob/da8215615c92b6550c2db51dba80ba6b0c92070c/src/Url.php#L58-L62>, <https://github.com/j0k3r/safecurl/blob/da8215615c92b6550c2db51dba80ba6b0c92070c/src/SafeCurl.php#L109-L116>, <https://github.com/fin1te/safecurl/blob/a7c3d703c06e827b33f1dcdbdcbe0796beb5a86d/src/fin1te/SafeCurl/SafeCurl.php> | 2026-09-24 |
| INV-9: a pin changes only the TCP peer; SNI and verification stay on the URL host | libcurl `CURLOPT_CONNECT_TO` (the `[verified]` part is [`evidence/2026-09-24-tls-pin-probes.R`](evidence/2026-09-24-tls-pin-probes.R)) | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CONNECT_TO.md> | 2026-09-24 |
| INV-10: `ssrf_filter` routed through ambient proxies until "Ignore proxies" (PR #89), first released in 1.6.0 on 2026-09-08 | `ssrf_filter` commit `d401e93`; changelog at 1.6.0 | <https://github.com/arkadiyt/ssrf_filter/commit/d401e9353a5f053c6a7252d53696cdc30ce837f2> | 2026-09-24 |
| INV-10: MLflow's webhook client ignores ambient proxies (`trust_env = False`) | MLflow `mlflow/webhooks/delivery.py` | <https://github.com/mlflow/mlflow/blob/21a620e1f52713d30e274ca5b303332a8ca8643e/mlflow/webhooks/delivery.py> | 2026-09-24 |
| INV-10: libcurl reads proxy environment variables by default | libcurl `CURLOPT_PROXY` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_PROXY.md> | 2026-09-24 |
| INV-10: an `Alt-Svc` cache remaps an origin for later requests | RFC 7838; libcurl `CURLOPT_ALTSVC` | <https://www.rfc-editor.org/rfc/rfc7838.html>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_ALTSVC.md> | 2026-09-24 |
| INV-13: `pydantic-ai` `CVE-2026-25580` | GHSA-2jrp-274c-jhv3 | <http://web.archive.org/web/20260701122622/https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-2jrp-274c-jhv3> | 2026-09-24 |
| INV-13: `pydantic-ai` `CVE-2026-46678` | GHSA-cqp8-fcvh-x7r3 | <http://web.archive.org/web/20260729214844/https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cqp8-fcvh-x7r3> | 2026-09-24 |
| INV-13: `pydantic-ai` `CVE-2026-48782` | GHSA-cg7w-rg45-pc59 | not yet pinned (below) | — |
| INV-13: the blocklist those advisories patched | `pydantic_ai/_ssrf.py` | <https://github.com/pydantic/pydantic-ai/blob/f8a5fe56ff6978ee33aaac32e23b88fb93258d4a/pydantic_ai_slim/pydantic_ai/_ssrf.py> | 2026-09-24 |
| INV-13: IBM Cloud metadata must be reached by name over HTTPS | as §5 gate 5 | not yet pinned (below) | — |
| INV-14: one Go implementation lets an allow match win, and any allowlist flips it to default-deny | `doyensec/safeurl` `client.go` | <https://github.com/doyensec/safeurl/blob/bfe6b43562f4f4787b124a821eeb4b2bd138f9d8/client.go> | 2026-09-24 |
| INV-14: the conjunctive alternative (deny always wins) | Gitea `modules/hostmatcher` | <https://github.com/go-gitea/gitea/blob/05f049e8bb1eabb8f9b2b967062524839f7e36aa/modules/hostmatcher/hostmatcher.go> | 2026-09-24 |

### §14 Transport hardening

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| A declared-size limit has no effect without a length header before libcurl 8.4.0, and counts wire bytes | libcurl `CURLOPT_MAXFILESIZE_LARGE` ("Since 8.4.0, this option also stops ongoing transfers"; measured in [`evidence/2026-09-24-hermetic-test-probes.R`](evidence/2026-09-24-hermetic-test-probes.R), EXP4-EXP5) | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_MAXFILESIZE_LARGE.md> | 2026-09-24 |
| `linklint` races its total deadline (a `setTimeout` sleep) against work that decompresses synchronously | `linklint` `safe-transport.ts` (the race, and the decode call) and `decompression.ts` (`gunzipSync`, `inflateSync`, `brotliDecompressSync`) | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/src/transport/safe-transport.ts#L128-137>, <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/src/transport/safe-transport.ts#L278>, <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/src/transport/decompression.ts#L60-64> | 2026-09-24 |
| A timer callback cannot run while synchronous work holds the event loop | Node.js timers, "Scheduling timers" | not yet pinned (below) | — |

### §15 Compliance claims

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| OWASP SSRF Prevention Cheat Sheet items | Cheat Sheet Series | <https://github.com/OWASP/CheatSheetSeries/blob/c04039adbe6f727a2198b3a3ea634fec98ac068a/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md> | 2026-09-24 |
| ASVS 5.0 V1.3.6 (SSRF), V1.5.3 (parser consistency) | ASVS 5.0.0 V1 | <https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x10-V1-Encoding-and-Sanitization.md> | 2026-09-24 |
| ASVS 5.0 V13.2.4, V13.2.5 (outbound allowlists) | ASVS 5.0.0 V13 | <https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x22-V13-Configuration.md> | 2026-09-24 |
| ASVS 5.0 V15.3.2 (do not follow redirects) | ASVS 5.0.0 V15 | <https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md> | 2026-09-24 |
| "ASVS V50" does not exist in 5.0 | ASVS 5.0.0 chapter list (V1-V17) | <https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en> | 2026-09-24 |
| CWE-918 | MITRE CWE | <http://web.archive.org/web/20260724102025/https://cwe.mitre.org/data/definitions/918.html> | 2026-09-24 |
| CAPEC-664 | MITRE CAPEC | <http://web.archive.org/web/20251209150722/https://capec.mitre.org/data/definitions/664.html> | 2026-09-24 |
| WSTG SSRF tests (WSTG-INJT-19; formerly WSTG-INPV-19) | OWASP WSTG | <https://github.com/OWASP/wstg/blob/ea174034f91439a17a1595e57d51e5b461820273/document/4-Web_Application_Security_Testing/07-Injection/19-Server-Side_Request_Forgery.md> | 2026-09-24 |
| Refusal of IPv6 zone-ID literals: RFC 9844 obsoletes RFC 6874 and with it the URI syntax for a zone ID | RFC 9844 | <https://www.rfc-editor.org/rfc/rfc9844.html> | 2026-09-24 |
| In the 2025 Top 10, SSRF is folded into A01:2025 Broken Access Control | OWASP Top 10 2025, A01 | <https://github.com/OWASP/Top10/blob/3a31f35346c3f4e90f350395124382fa53af2afe/2025/docs/en/A01_2025-Broken_Access_Control.md> | 2026-09-24 |
| A10:2025 is a different category | OWASP Top 10 2025, A10 | <https://github.com/OWASP/Top10/blob/3a31f35346c3f4e90f350395124382fa53af2afe/2025/docs/en/A10_2025-Mishandling_of_Exceptional_Conditions.md> | 2026-09-24 |

### §16 References

| Source | Pinned URL | Accessed |
|---|---|---|
| OWASP SSRF Prevention Cheat Sheet; ASVS 5.0; WSTG; API7:2023 | §15 and §5.3 rows above | 2026-09-24 |
| CWE-918; CAPEC-664 | §15 rows above | 2026-09-24 |
| RFC 3986 | <https://www.rfc-editor.org/rfc/rfc3986.html> | 2026-09-24 |
| WHATWG URL Standard | <https://url.spec.whatwg.org/commit-snapshots/8e14777cfa145b08a9fb735fe580ec0c366564c3/> | 2026-09-24 |
| RFC 9110 §15.4 | <https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4> | 2026-09-24 |
| RFC 9844 | <https://www.rfc-editor.org/rfc/rfc9844.html> | 2026-09-24 |
| RFC 6874 (obsoleted by RFC 9844) | <https://www.rfc-editor.org/rfc/rfc6874.html> | 2026-09-24 |
| RFC 2606 | <https://www.rfc-editor.org/rfc/rfc2606.html> | 2026-09-24 |
| UTS #46, revision 36 | <https://www.unicode.org/reports/tr46/tr46-36.html> | 2026-09-24 |
| RFC 6052 | <https://www.rfc-editor.org/rfc/rfc6052.html> | 2026-09-24 |
| RFC 3056 | <https://www.rfc-editor.org/rfc/rfc3056.html> | 2026-09-24 |
| RFC 4380 | <https://www.rfc-editor.org/rfc/rfc4380.html> | 2026-09-24 |
| RFC 5214 | <https://www.rfc-editor.org/rfc/rfc5214.html> | 2026-09-24 |
| RFC 6598 | <https://www.rfc-editor.org/rfc/rfc6598.html> | 2026-09-24 |
| Tsai, Black Hat USA 2017 | §13 INV-1 row above | 2026-09-24 |
| Claroty Team82, 2022 | §13 INV-1 row above | 2026-09-24 |
| ONsec/Wallarm, *SSRF Bible* (the copy the Cheat Sheet hosts) | <https://github.com/OWASP/CheatSheetSeries/blob/c04039adbe6f727a2198b3a3ea634fec98ac068a/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf> | 2026-09-24 |
| `ssrf_filter` (Ruby) | <https://github.com/arkadiyt/ssrf_filter/tree/847abaf76841cdc630752c13c0cd3528f7fdc102> | 2026-09-24 |
| `safeurl` (Go) | <https://github.com/doyensec/safeurl/tree/bfe6b43562f4f4787b124a821eeb4b2bd138f9d8> | 2026-09-24 |
| `safeurl-python` | <https://github.com/IncludeSecurity/safeurl-python/tree/1656c92e7580423e961ce13a348cc2a640ab62ac> | 2026-09-24 |
| `advocate` (Python) | <https://github.com/JordanMilne/Advocate/tree/f65cbf925cacafded20bbb878776a543b6f2d21b> | 2026-09-24 |
| Sentry `src/sentry/net/socket.py` | <https://github.com/getsentry/sentry/blob/d2336d661bc66b7a5f5be0996e2f30b27619c2dd/src/sentry/net/socket.py> | 2026-09-24 |
| MLflow `mlflow/webhooks/ssrf.py` | <https://github.com/mlflow/mlflow/blob/21a620e1f52713d30e274ca5b303332a8ca8643e/mlflow/webhooks/ssrf.py> | 2026-09-24 |
| smokescreen (Stripe) | <https://github.com/stripe/smokescreen/tree/39ea747ce38fa90b959bae943706381199f4ad0d> | 2026-09-24 |
| Gitea `modules/hostmatcher` | <https://github.com/go-gitea/gitea/tree/05f049e8bb1eabb8f9b2b967062524839f7e36aa/modules/hostmatcher> | 2026-09-24 |
| `linklint` (TypeScript) | <https://gitlab.com/bart-turczynski/linklint/-/tree/8830901a6c9e95a69b110b06db01bd97fa2aabb9> | 2026-09-24 |
| Vendor metadata documentation as cited in `linklint` | §5 gate 2 row above | 2026-09-24 |

---

## r-binding.md

| Section | Claim | Source | Pinned URL | Accessed |
|---|---|---|---|---|
| §4.1 | libcurl's reuse check is hostname-based and runs before DNS; only `CONNECT_TO` takes part in it (reproduced in [`evidence/2026-09-24-transport-probes.R`](evidence/2026-09-24-transport-probes.R), block 12) | libcurl `lib/url.c` (`url_match_destination`) | <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c> | 2026-09-24 |
| §4.1 | The reuse check happens before resolution | *Everything curl*, "Connection reuse" | <http://web.archive.org/web/20260609152108/https://everything.curl.dev/transfers/conn/reuse.html> | 2026-09-24 |
| §4.2 | `CONNECT_TO` syntax and empty fields | libcurl `CURLOPT_CONNECT_TO` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CONNECT_TO.md> | 2026-09-24 |
| §4.2 | `RESOLVE` syntax, multiple addresses | libcurl `CURLOPT_RESOLVE` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_RESOLVE.md> | 2026-09-24 |
| §5 | `noproxy = ""` proxies everything | libcurl `CURLOPT_NOPROXY` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_NOPROXY.md> | 2026-09-24 |
| §5 | Redirect protocol default | libcurl `CURLOPT_REDIR_PROTOCOLS_STR` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_REDIR_PROTOCOLS_STR.md> | 2026-09-24 |
| §5 | `fresh_connect` does not cover redirect follow-ups; use `forbid_reuse` | libcurl `CURLOPT_FRESH_CONNECT`; `lib/url.c` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_FRESH_CONNECT.md> | 2026-09-24 |
| §6 | R's `curl` marshals only xferinfo/progress, read, debug, SSL-context and seek callbacks (checked in [`evidence/2026-09-24-curl-callback-options.R`](evidence/2026-09-24-curl-callback-options.R)) | `jeroen/curl` `src/handle.c` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/handle.c> | 2026-09-24 |
| §4.3 | Through 1.5.0 `ssrf_filter` pinned one random address; a user measured ~60% failures on dual-stack hosts from an IPv4-only host | `ssrf_filter` issue #92 | not yet pinned (below) | — |
| §4.3 | 1.6.0 retries the other validated addresses | `ssrf_filter` PR #93, commit `c9a0784` | <https://github.com/arkadiyt/ssrf_filter/commit/c9a078481984356ce41cf0af247caa819c74b676> | 2026-09-24 |
| §5 | `maxfilesize` stops ongoing transfers only since libcurl 8.4.0 | as `ssrfr-v1.md` §14 | as §14 | 2026-09-24 |
| §6 | `safeurl-python` validates in `CURLOPT_OPENSOCKETFUNCTION` | `safeurl-python` `safeurl/safeurl.py` | <https://github.com/IncludeSecurity/safeurl-python/blob/1656c92e7580423e961ce13a348cc2a640ab62ac/safeurl/safeurl.py> | 2026-09-24 |
| §6 | The hook other ecosystems validate in runs after connect or reuse, before the request | libcurl `CURLOPT_PREREQFUNCTION` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_PREREQFUNCTION.md> | 2026-09-24 |
| §7 | `.invalid` never resolves | RFC 2606 §2 | <https://www.rfc-editor.org/rfc/rfc2606.html#section-2> | 2026-09-24 |
| §7 | `local_mocked_bindings()` and its `.package` guidance | `testthat` 3.3.2 `R/mock2.R` | <https://github.com/r-lib/testthat/blob/ace29c526f93b6ae1a402d93e6b1ccaf65de1e61/R/mock2.R> | 2026-09-24 |
| §7 | `webfakes` 1.5.0 | `r-lib/webfakes` tag v1.5.0 | <https://github.com/r-lib/webfakes/tree/7c72eb621e81f4297bc3f97a291424c73fc7f870> | 2026-09-24 |
| §7 | `linklint` splits its live transport tests the same way | `packages/online/test/node-transport-live.test.ts` | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/test/node-transport-live.test.ts> | 2026-09-24 |
| §7 | Proxy-isolation pattern | `packages/online/test/proxy-isolation-harness.ts` | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/test/proxy-isolation-harness.ts> | 2026-09-24 |
| §8 | `mcptools` ships a self-described "literal-only block, not a DNS-rebinding defense" | `posit-dev/mcptools` `R/utils.R` | <https://github.com/posit-dev/mcptools/blob/8a07faae095755afd7160432a12a85cce3cb8cde/R/utils.R> | 2026-09-24 |

---

## Not yet pinned

No commit, version or archived snapshot was found for these on 2026-09-24.
Archive them (for example with the Wayback Machine's "Save Page Now") and move
the snapshot URL into the table above, or replace the source.

| Cited at | Source | Canonical URL |
|---|---|---|
| §1.1 | `ssrf_filter` issue #78 | <https://github.com/arkadiyt/ssrf_filter/issues/78> |
| §5 gate 5, INV-13 | IBM Cloud VPC metadata API | <https://cloud.ibm.com/apidocs/vpc-metadata> |
| §5 gate 5 | Equinix Metal metadata (scheduled for removal 2026-09-30) | <https://docs.equinix.com/metal/server-metadata/metadata/> |
| §5 gate 2 | Azure WireServer `168.63.129.16` | <https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16> |
| §5 gate 2 | Oracle Cloud instance metadata | <https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm> |
| §5 gate 2 | Alibaba Cloud instance metadata | <https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/> |
| §7, INV-8 | HackerOne #3634400 (`ssrf_filter`) | <https://hackerone.com/reports/3634400> |
| §7, INV-8 | HackerOne #3642600 (`ssrf_filter`) | <https://hackerone.com/reports/3642600> |
| INV-1 | Spring `CVE-2024-22259` | <https://spring.io/security/cve-2024-22259/> |
| INV-4 | `january` GHSA-4mcc-p83c-r77q | no working URL found; the repository-level advisory did not resolve under `stoatchat/january` or `revoltchat/january` |
| INV-5 | Sonar, WordPress blind SSRF | <https://www.sonarsource.com/blog/wordpress-core-unauthenticated-blind-ssrf/> |
| INV-7 | Gitea `CVE-2026-57894` | <https://advisories.gitlab.com/golang/code.gitea.io/gitea/CVE-2026-57894/> |
| INV-7 | Gitea `CVE-2026-58418` | <https://advisories.gitlab.com/golang/code.gitea.io/gitea/CVE-2026-58418/> |
| INV-7 | `request` `CVE-2023-28155` | <https://github.com/advisories/GHSA-p8p7-x288-28g6> |
| §4.3 (r-binding) | `ssrf_filter` issue #92 | <https://github.com/arkadiyt/ssrf_filter/issues/92> |
| §14 | Node.js timers, "Scheduling timers" | <https://nodejs.org/api/timers.html#scheduling-timers> |
| INV-13 | `pydantic-ai` `CVE-2026-48782` | <https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59> |
