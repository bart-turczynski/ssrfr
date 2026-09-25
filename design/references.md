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

### §2 The decision primitive

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| §2.3: a redirect status is 301, 302, 303, 307 or 308 | WHATWG Fetch, "redirect status" | <https://fetch.spec.whatwg.org/commit-snapshots/357bd98924d94b81fbe8608192a2ee1f123b82f4/#redirect-status> | 2026-09-24 |
| §2.3: a redirect without `Location` is returned as the response | WHATWG Fetch, "HTTP-redirect fetch" | <https://fetch.spec.whatwg.org/commit-snapshots/357bd98924d94b81fbe8608192a2ee1f123b82f4/#http-redirect-fetch> | 2026-09-24 |
| §2.3: more than one value for a single-value header is a failure | WHATWG Fetch, "extract header list values" | <https://fetch.spec.whatwg.org/commit-snapshots/357bd98924d94b81fbe8608192a2ee1f123b82f4/#extract-header-list-values> | 2026-09-24 |
| §2.3: `Location` is one URI-reference; duplicated field lines are not interoperably recoverable; fragment inheritance | RFC 9110 §10.2.2 | <https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2> | 2026-09-24 |
| §2.3: the target URI excludes the fragment | RFC 9110 §7.1; RFC 9112 §3.2.1 (origin-form); RFC 3986 §5.1 (base URI) | <https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1>, <https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.1>, <https://www.rfc-editor.org/rfc/rfc3986.html#section-5.1> | 2026-09-24 |
| §2.3: IMDSv2 tokens come from a `PUT` with `X-aws-ec2-metadata-token-ttl-seconds` and are required under IMDSv2 | AWS EC2 User Guide, "How IMDSv2 works" | <http://web.archive.org/web/20240613072848/https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html> | 2026-09-24 |
| §2.3: GCP denies a request without `Metadata-Flavor: Google`; legacy `X-Google-Metadata-Request` | GCP, "Query VM metadata" (November 2025 snapshot; the live page now calls the legacy header deprecated) | <http://web.archive.org/web/20251117162032/https://cloud.google.com/compute/docs/metadata/querying-metadata> | 2026-09-24 |
| §2.3: Azure IMDS requires `Metadata: true` | Microsoft Learn, Azure IMDS | <http://web.archive.org/web/20260910090308/https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service> | 2026-09-24 |
| §2.3: OCI IMDSv2 requires `Authorization: Bearer Oracle`; Alibaba's token header | Oracle and Alibaba metadata docs | not yet pinned (below) | — |
| §2.3: Linode's metadata requests carry `Metadata-Token` and `Metadata-Token-Expiry-Seconds` to `169.254.169.254`. Quotes: `curl -X PUT -H "Metadata-Token-Expiry-Seconds: 3600" http://169.254.169.254/v1/token`; `curl -H "Metadata-Token: $TOKEN" http://169.254.169.254/v1/instance` | Akamai TechDocs, *Metadata service API* | <http://web.archive.org/web/20260925003924/https://techdocs.akamai.com/cloud-computing/docs/metadata-service-api> | 2026-09-25 |
| §2.3: Vultr sends `METADATA-TOKEN` to `169.254.169.254`. Quote: "When making requests, you must pass `METADATA-TOKEN: vultr` in the request header." | Vultr Docs, *Vultr Marketplace* | <http://web.archive.org/web/20260615015103/https://docs.vultr.com/vultr-marketplace> | 2026-09-25 |
| §2.3: Huawei Cloud's metadata token request carries `X-Metadata-Token-Ttl-Seconds`. Quote: `curl -X PUT http://169.254.169.254/meta-data/latest/api/token -H "X-Metadata-Token-Ttl-Seconds:21600"` | Huawei Cloud ECS user guide, *Obtaining Metadata and Configuring Custom Data* (`ecs_03_0166`) | <https://web.archive.org/web/20260925094506/https://support.huaweicloud.com/intl/en-us/usermanual-ecs/ecs_03_0166.html> | 2026-09-25 |
| §2.5: `ssrf_filter` 1.6.0 fails over only on a fixed list of connection errors | `ssrf_filter` `lib/ssrf_filter/ssrf_filter.rb` | <https://github.com/arkadiyt/ssrf_filter/blob/847abaf76841cdc630752c13c0cd3528f7fdc102/lib/ssrf_filter/ssrf_filter.rb#L223-L233> | 2026-09-24 |
| §2.5: MLflow's peer-check error is never retried | MLflow `mlflow/webhooks/ssrf.py` | <https://github.com/mlflow/mlflow/blob/21a620e1f52713d30e274ca5b303332a8ca8643e/mlflow/webhooks/ssrf.py#L33-L38> | 2026-09-24 |
| §2.3: `net/http` client errors carry the URL with the password removed | Go `src/net/http/client.go`, go1.25.0 | <https://github.com/golang/go/blob/6e676ab2b809d46623acb5988248d95d1eb7939c/src/net/http/client.go#L617-L633> | 2026-09-24 |
| §2.3: `plumber` logs every error and returns its message to the client in debug mode | `plumber` v1.3.0 `R/default-handlers.R` | <https://github.com/rstudio/plumber/blob/49cb0164a6456dbb127109531a23e68bfbcec5e6/R/default-handlers.R#L7-L29> | 2026-09-24 |

### §4 Dependency contract

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| `rurl` 3.0 parses `http`/`https` in-tree (r-binding.md §2.1) | `rurl` `R/parse-web.R` | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/parse-web.R> | 2026-09-24 |
| `raddr::addr_curl()` regressed 7 of 18 hosts (r-binding.md §2.6) | `rurl` ADR 0018 | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/design/adr/0018-ip-literals-belong-to-raddr.md> | 2026-09-24 |
| §4.3: `raddr`'s stamp is IANA's page-level "Last Updated" date; `addr_registry_outdated()` compares `Sys.Date()` with it | `raddr` 0.1.2 `R/registry.R` | <https://gitlab.com/bart-turczynski/raddr/-/blob/e1ed138b6c8ac6a319597d025dc4dc64500155c9/R/registry.R#L255-L281> | 2026-09-24 |
| §4.3: IANA's special-purpose registries were last updated 2025-10-09; `3fff::/20` and `5f00::/16` are not globally reachable | IANA IPv6 and IPv4 Special-Purpose Address Space | <http://web.archive.org/web/20260803153040/https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>, <http://web.archive.org/web/20260805170549/https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml> | 2026-09-24 |

### §5 The refusal rule

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| Gate 2 starting point: the ten-row provider-endpoint table, with a vendor citation per row (AWS, Azure WireServer `168.63.129.16`, Oracle, Alibaba, GCP, IBM, Tencent, Exoscale) | `linklint` `packages/core/src/data/cloud-metadata.ts` | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/core/src/data/cloud-metadata.ts> | 2026-09-24 |
| Gate 5: IBM Cloud's metadata API is reachable at `169.254.169.254` or `api.metadata.cloud.ibm.com`, and over HTTPS must be the hostname. Quote: "When the `metadata_service.protocol` property is `http`, the endpoint URL may contain either the service's IP address `http://169.254.169.254` or the service's hostname `http://api.metadata.cloud.ibm.com`. When the `metadata_service.protocol` property is `https`, the endpoint URL must contain the service's hostname `https://api.metadata.cloud.ibm.com`." | IBM Cloud VPC metadata API docs (JS-rendered; the snapshot carries the sentence in its embedded page data) | <http://web.archive.org/web/20251206195733/https://cloud.ibm.com/apidocs/vpc-metadata> | 2026-09-25 |
| Equinix Metal was sunset on 2026-06-30; its metadata page is scheduled for removal. Quote: "Equinix Metal was sunset on June 30, 2026. The user documentation will be removed on September 30, 2026." The page names the endpoint `https://metadata.platformequinix.com/metadata` | Equinix Metal metadata docs | <http://web.archive.org/web/20260925003909/https://docs.equinix.com/metal/server-metadata/metadata/> | 2026-09-25 |
| Gate 2: Scaleway `169.254.42.42`. Quote: "The endpoint for the Scaleway Metadata API is `169.254.42.42/32`" | Scaleway, *Manual configuration of private IPs* | <http://web.archive.org/web/20260925003934/https://www.scaleway.com/en/docs/instances/reference-content/manual-configuration-private-ips/> | 2026-09-25 |
| Gate 2: Scaleway `fd00:42::42`. Quote (line 22): `metadataAPIv6 = "http://[fd00:42::42]"`. Scaleway's documentation names no IPv6 endpoint; its own SDK is the vendor source | `scaleway/scaleway-sdk-go` `api/instance/v1/instance_metadata_sdk.go` | <https://github.com/scaleway/scaleway-sdk-go/blob/25895fc5ce562db9b94242f507ffbb553347a73f/api/instance/v1/instance_metadata_sdk.go#L22> | 2026-09-25 |
| Gate 2: Linode `fd00:a9fe:a9fe::1` and `fe80::a9fe:a9fe`. Quote: "the Metadata API is accessible via link-local addresses, specifically: **IPv4**: `169.254.169.254` **IPv6**: `fd00:a9fe:a9fe::1`, `fe80::a9fe:a9fe`" | Akamai TechDocs, *Metadata service API* | <http://web.archive.org/web/20260925003924/https://techdocs.akamai.com/cloud-computing/docs/metadata-service-api> | 2026-09-25 |
| Two independent implementations missed Oracle's `192.0.0.192` | `[verified]`, not sourced: [`evidence/2026-09-24-oracle-metadata-miss.R`](evidence/2026-09-24-oracle-metadata-miss.R) | — | — |
| §5.0: the host parser returns failure when domain-to-ASCII fails | WHATWG URL, host parsing | <https://url.spec.whatwg.org/commit-snapshots/8e14777cfa145b08a9fb735fe580ec0c366564c3/#concept-host-parser> | 2026-09-24 |
| §5.0: under `whatwg`, `rurl` keeps the pre-encode host when domain-to-ASCII fails, and its layer-1 verdict does not depend on it | `rurl` 3.0.1 `R/parse-phases.R`, `R/verdicts.R` | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/parse-phases.R#L2126-2146>, <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/verdicts.R#L149-161> | 2026-09-24 |
| §5.0: `curl::nslookup()` calls `getaddrinfo()` without `AI_CANONNAME` and returns address strings only | R `curl` 8.0.0 `src/nslookup.c` (CRAN mirror; `jeroen/curl` has no 8.x tag) | <https://github.com/cran/curl/blob/60797e1d9330605cb5ab185ceb192c196d62da5b/src/nslookup.c> | 2026-09-24 |
| §5.0: `AI_CANONNAME` yields one canonical name, not the alias chain | POSIX.1-2024, `getaddrinfo()` | <https://pubs.opengroup.org/onlinepubs/9799919799/functions/getaddrinfo.html> | 2026-09-24 |
| §5.3: RFC 9110 recommends supporting URIs of at least 8000 octets | RFC 9110 §4.1 | <https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1> | 2026-09-24 |
| §5.3: libcurl refuses a URL part longer than `CURL_MAX_INPUT_LENGTH` (8,000,000) | libcurl `lib/urldata.h`, `lib/urlapi.c` | <https://github.com/curl/curl/blob/curl-8_14_1/lib/urldata.h>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/urlapi.c> | 2026-09-24 |
| §5.3: `rurl`'s parse cache looks keys up with `mget()`, which R limits to 10,000-byte names | `rurl` 3.0.1 `R/zzz.R` | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/zzz.R#L233-L246> | 2026-09-24 |
| §5.3: libcurl passes at most `CURL_MAX_WRITE_SIZE` (16384) body bytes per write callback | libcurl `CURLOPT_WRITEFUNCTION`; `include/curl/curl.h` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_WRITEFUNCTION.md>, <https://github.com/curl/curl/blob/curl-8_14_1/include/curl/curl.h> | 2026-09-24 |
| §5.3: R `curl`'s `multi_add(data = )` passes each delivery straight to the R function | R `curl` 8.0.0 `src/multi.c`, `src/utils.c` | <https://github.com/cran/curl/blob/60797e1d9330605cb5ab185ceb192c196d62da5b/src/multi.c#L89-L93>, <https://github.com/cran/curl/blob/60797e1d9330605cb5ab185ceb192c196d62da5b/src/utils.c#L169-L180> | 2026-09-24 |

### §6 Result and reason model

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| §6.4: response timing through the fetching endpoint tells an attacker whether a port is open | OWASP API Security Top 10, API7:2023, Scenario #1 | <https://github.com/OWASP/API-Security/blob/33cea37b2ffde3e2e62f6b5d79a029a22a846633/editions/2023/en/0xa7-server-side-request-forgery.md> | 2026-09-24 |
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
| §7.2: a skipped test hid a broken capability probe for years; the linklint IdnaTestV2 corpus is pinned by checksum and row count | as the r-binding §7 rows for Advocate and `linklint` below | as below | 2026-09-24 |

### §9 Non-goals

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| A destination assigned to the host is a `local` route, looped back and delivered locally | iproute2 `man/man8/ip-route.8.in`, tag v6.16.0 | <https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/man/man8/ip-route.8.in?h=v6.16.0> | 2026-09-24 |
| Mattermost refuses self-assigned addresses because they bypass host-based firewalls | Mattermost `httpservice/client.go` (`IsOwnIP`), `httpservice.go` (`checkInternalIP`) | <https://github.com/mattermost/mattermost/blob/4cd9cbfc6c3852c5cdc5b0a4c8e938533afbcd76/server/public/shared/httpservice/client.go#L44-L73>, <https://github.com/mattermost/mattermost/blob/4cd9cbfc6c3852c5cdc5b0a4c8e938533afbcd76/server/public/shared/httpservice/httpservice.go#L80-L107> | 2026-09-24 |
| Meta refresh and the `Refresh` header both run the shared declarative refresh steps | WHATWG HTML, commit snapshot | <https://html.spec.whatwg.org/commit-snapshots/1a249c2a40bd341f7c2c0c9954a9a264b1983b93/#shared-declarative-refresh-steps> | 2026-09-24 |
| S5: `read_xml()` on a URL opens `curl::curl()` or `url()`; `xml2`'s entity loader fetches `http(s)` with `download.file()` | `xml2` 1.6.0 `R/paths.R`, `src/xml2_init.c` (CRAN mirror) | <https://github.com/cran/xml2/blob/5162db172775660781709d1eebb05f78837cfafe/R/paths.R#L1-L12>, <https://github.com/cran/xml2/blob/5162db172775660781709d1eebb05f78837cfafe/src/xml2_init.c#L55-L106> | 2026-09-24 |

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
| INV-10 correction: a connect-to host switches an HTTP proxy to tunnel mode, and the tunnel target is the connect-to host (measured in [`evidence/2026-09-24-proxy-probes.R`](evidence/2026-09-24-proxy-probes.R)) | libcurl `CURLOPT_CONNECT_TO`; `lib/url.c`; `lib/http_proxy.c` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CONNECT_TO.md?plain=1#L70-L73>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c#L3611-L3618>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/http_proxy.c#L194-L211> | 2026-09-24 |
| INV-10: an `Alt-Svc` cache remaps an origin for later requests | RFC 7838; libcurl `CURLOPT_ALTSVC` | <https://www.rfc-editor.org/rfc/rfc7838.html>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_ALTSVC.md> | 2026-09-24 |
| INV-13: `pydantic-ai` `CVE-2026-25580` | GHSA-2jrp-274c-jhv3 | <http://web.archive.org/web/20260701122622/https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-2jrp-274c-jhv3> | 2026-09-24 |
| INV-13: `pydantic-ai` `CVE-2026-46678` | GHSA-cqp8-fcvh-x7r3 | <http://web.archive.org/web/20260729214844/https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cqp8-fcvh-x7r3> | 2026-09-24 |
| INV-13: `pydantic-ai` `CVE-2026-48782` | GHSA-cg7w-rg45-pc59 | not yet pinned (below) | — |
| INV-13: the blocklist those advisories patched | `pydantic_ai/_ssrf.py` | <https://github.com/pydantic/pydantic-ai/blob/f8a5fe56ff6978ee33aaac32e23b88fb93258d4a/pydantic_ai_slim/pydantic_ai/_ssrf.py> | 2026-09-24 |
| INV-13: IBM Cloud metadata must be reached by name over HTTPS | as §5 gate 5 | <http://web.archive.org/web/20251206195733/https://cloud.ibm.com/apidocs/vpc-metadata> | 2026-09-25 |
| INV-14: one Go implementation lets an allow match win, and any allowlist flips it to default-deny | `doyensec/safeurl` `client.go` | <https://github.com/doyensec/safeurl/blob/bfe6b43562f4f4787b124a821eeb4b2bd138f9d8/client.go> | 2026-09-24 |
| INV-14: the conjunctive alternative (deny always wins) | Gitea `modules/hostmatcher` | <https://github.com/go-gitea/gitea/blob/05f049e8bb1eabb8f9b2b967062524839f7e36aa/modules/hostmatcher/hostmatcher.go> | 2026-09-24 |

### §14 Transport hardening

| Claim | Source | Pinned URL | Accessed |
|---|---|---|---|
| A declared-size limit has no effect without a length header before libcurl 8.4.0, and counts wire bytes | libcurl `CURLOPT_MAXFILESIZE_LARGE` ("Since 8.4.0, this option also stops ongoing transfers"; measured in [`evidence/2026-09-24-hermetic-test-probes.R`](evidence/2026-09-24-hermetic-test-probes.R), EXP4-EXP5) | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_MAXFILESIZE_LARGE.md> | 2026-09-24 |
| `linklint` races its total deadline (a `setTimeout` sleep) against work that decompresses synchronously | `linklint` `safe-transport.ts` (the race, and the decode call) and `decompression.ts` (`gunzipSync`, `inflateSync`, `brotliDecompressSync`) | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/src/transport/safe-transport.ts#L128-137>, <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/src/transport/safe-transport.ts#L278>, <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/online/src/transport/decompression.ts#L60-64> | 2026-09-24 |
| A Unix socket path means "curl does not resolve the DNS hostname in the URL" | libcurl `CURLOPT_UNIX_SOCKET_PATH` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_UNIX_SOCKET_PATH.md> | 2026-09-24 |
| `safeurl` accepts a caller `http.Transport` and panics on custom dialers | `doyensec/safeurl` `client.go` | <https://github.com/doyensec/safeurl/blob/bfe6b43562f4f4787b124a821eeb4b2bd138f9d8/client.go#L17-L28> | 2026-09-24 |
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
| §2.1 | `url_standard` defaults to `NULL` on `safe_parse_url()`, `get_parse_verdicts()` and `resolve_url()`; `resolve_url()` defaults to `output = "clean"`; `serialize_url()` takes `standard` | `rurl` 3.0.1 `R/parse.R`, `R/verdicts.R`, `R/resolve.R`, `R/serialize.R` | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/parse.R#L502-541>, <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/verdicts.R#L315-324>, <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/resolve.R#L745-746>, <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/R/serialize.R#L450> | 2026-09-24 |
| §2.1 | `url_standard = NULL` is the legacy parse; only the companion helpers require it | `rurl` ADR 0007, ADR 0015 | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/design/adr/0007-url-standard-selector.md>, <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/design/adr/0015-require-url-standard-on-companion-helpers.md> | 2026-09-24 |
| §2.1 | `clean_url` is a lossy policy projection | `rurl` ADR 0017 | <https://gitlab.com/bart-turczynski/rurl/-/blob/0ca8f0966e1fd9e03cb145fd0c3bb20fcdd44f35/design/adr/0017-clean-url-is-a-lossy-policy-projection.md> | 2026-09-24 |
| §4.1 | libcurl's reuse check is hostname-based and runs before DNS; only `CONNECT_TO` takes part in it (reproduced in [`evidence/2026-09-24-transport-probes.R`](evidence/2026-09-24-transport-probes.R), block 12) | libcurl `lib/url.c` (`url_match_destination`) | <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c> | 2026-09-24 |
| §4.1 | The reuse check happens before resolution | *Everything curl*, "Connection reuse" | <http://web.archive.org/web/20260609152108/https://everything.curl.dev/transfers/conn/reuse.html> | 2026-09-24 |
| §4.2 | `CONNECT_TO` syntax and empty fields | libcurl `CURLOPT_CONNECT_TO` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CONNECT_TO.md> | 2026-09-24 |
| §4.2 | `RESOLVE` syntax, multiple addresses | libcurl `CURLOPT_RESOLVE` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_RESOLVE.md> | 2026-09-24 |
| §4.1 | Synchronous fetches share one process-wide multi handle | `jeroen/curl` `R/fetch.R`, `src/interrupt.c`, `src/init.c` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/R/fetch.R#L75-L76>, <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/interrupt.c#L23-L44>, <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/init.c#L96-L101> | 2026-09-24 |
| §4.1 | A multi handle shares its DNS cache and connection pool across easy handles | libcurl `curl_multi_add_handle` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/curl_multi_add_handle.md> | 2026-09-24 |
| §4.1 | `handle_reset()` is `curl_easy_reset()` plus the package defaults; reset keeps connections, DNS cache, cookies, alt-svc | `jeroen/curl` `src/handle.c`; libcurl `curl_easy_reset` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/handle.c#L223-L238>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/curl_easy_reset.md> | 2026-09-24 |
| §4.1 | "The safest way to perform multiple independent requests is by using a separate handle for each request" | `jeroen/curl` `R/handle.R` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/R/handle.R#L13-L17> | 2026-09-24 |
| §4.1 | `RESOLVE` populates the DNS cache, and un-prefixed entries never expire; `CONNECT_TO` does not affect other easy handles on the same multi | libcurl `CURLOPT_RESOLVE`, `CURLOPT_CONNECT_TO` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_RESOLVE.md>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CONNECT_TO.md> | 2026-09-24 |
| §4.1, §5 | The reuse check compares connect-to host and port and never mixes pinned and unpinned connections | libcurl `lib/url.c` | <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c#L859-L867>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c#L1118-L1154> | 2026-09-24 |
| §4.2 | An empty `HOST` field always matches | libcurl `CURLOPT_CONNECT_TO`; `lib/url.c` | <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c#L3050-L3053> | 2026-09-24 |
| §5 | `noproxy = ""` proxies everything | libcurl `CURLOPT_NOPROXY` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_NOPROXY.md> | 2026-09-24 |
| §5 | Redirect protocol default | libcurl `CURLOPT_REDIR_PROTOCOLS_STR` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_REDIR_PROTOCOLS_STR.md> | 2026-09-24 |
| §5 | `fresh_connect` does not cover redirect follow-ups or authentication rounds; use `forbid_reuse` | libcurl `CURLOPT_FRESH_CONNECT`; `lib/url.c` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_FRESH_CONNECT.md>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c#L3689-L3697> | 2026-09-24 |
| §5 | `fresh_connect` is not acknowledged on follow-location or authentication rounds | libcurl `lib/url.c` | <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c#L3689-L3697> | 2026-09-24 |
| §5 | The package's handle defaults (encoding, followlocation, timeouts, low-speed, cookie engine, user agent, netrc, auth, pipewait), unchanged in 8.0.0 | `jeroen/curl` `src/handle.c` `set_handle_defaults()`; 8.0.0 at `be1eb9c4` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/handle.c#L118-L206>, <https://github.com/jeroen/curl/blob/be1eb9c4336e303d0edb8a2eefba5ad2e887bf0b/src/handle.c> | 2026-09-24 |
| §5 | `curl` 7.0.0 applies `options("netrc")` | `jeroen/curl` `NEWS`; commit `1639621` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/NEWS#L10-L16>, <https://github.com/jeroen/curl/commit/1639621f660523e00d8a2796279f245608ad7808> | 2026-09-24 |
| §5 | R 4.6.0 added `options("netrc")` for `download.file(method = "libcurl")` | R `doc/NEWS.Rd`, tag R-4-6-0 | <https://svn.r-project.org/R/tags/R-4-6-0/doc/NEWS.Rd> | 2026-09-24 |
| §5 | libcurl ignores netrc by default | libcurl `CURLOPT_NETRC` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_NETRC.md> | 2026-09-24 |
| §5 | netrc and redirect credential leaks: `CVE-2026-3783` (8.14.1 affected; bearer token and a followed redirect), `CVE-2024-11053` | curl security advisories | <http://web.archive.org/web/20260818170204/https://curl.se/docs/CVE-2026-3783.html>, <http://web.archive.org/web/20260818170220/https://curl.se/docs/CVE-2024-11053.html> | 2026-09-24 |
| §5 | `cookiefile = ""` starts the engine and `NULL` disables it; `cookiejar` writes at cleanup | libcurl `CURLOPT_COOKIEFILE`, `CURLOPT_COOKIEJAR` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_COOKIEFILE.md>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_COOKIEJAR.md> | 2026-09-24 |
| §5 | `""` asks for every built-in encoding; `NULL` disables decoding; decoders follow the response's `Content-Encoding` | libcurl `CURLOPT_ACCEPT_ENCODING`; `lib/http.c`; `lib/content_encoding.c` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_ACCEPT_ENCODING.md>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/http.c#L3065-L3075>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/content_encoding.c#L707-L729> | 2026-09-24 |
| §5 | HTTP version defaults; HTTP/3 only when asked | libcurl `CURLOPT_HTTP_VERSION` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_HTTP_VERSION.md> | 2026-09-24 |
| §5 | `ipresolve` does not override a numeric host; `RESOLVE` addresses of the other family are ignored | libcurl `CURLOPT_IPRESOLVE`, `CURLOPT_RESOLVE` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_IPRESOLVE.md> | 2026-09-24 |
| §5 | `maxage_conn` bounds only idle-connection reuse (default 118 s) | libcurl `CURLOPT_MAXAGE_CONN` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_MAXAGE_CONN.md> | 2026-09-24 |
| §5 | DoH lookups are separate requests with their own verification settings; a hostname `interface` is resolved without DoH; `share` shares caches and cookies | libcurl `CURLOPT_DOH_URL`, `CURLOPT_INTERFACE`, `CURLOPT_LOCALPORT`, `CURLOPT_SHARE` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_DOH_URL.md>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_INTERFACE.md>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_LOCALPORT.md>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_SHARE.md> | 2026-09-24 |
| §5 | On Windows every new handle sets `CURLSSLOPT_NO_REVOKE` (with `CURLSSLOPT_NATIVE_CA` under OpenSSL when `CURL_CA_BUNDLE` is unset); the flag affects Schannel only; libcurl checks neither OCSP stapling nor a CRL unless asked | `jeroen/curl` `src/handle.c`; libcurl `CURLOPT_SSL_OPTIONS`, `CURLOPT_SSL_VERIFYSTATUS`, `CURLOPT_CRLFILE` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/handle.c#L129-L141>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_SSL_OPTIONS.md>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_SSL_VERIFYSTATUS.md>, <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CRLFILE.md> | 2026-09-25 |
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
| §7 | `ssrf_filter` proves SNI with two virtual hosts on one port | `ssrf_filter` `spec/lib/ssrf_filter_spec.rb` at 1.6.0, "connects when using SNI" | <https://github.com/arkadiyt/ssrf_filter/blob/847abaf76841cdc630752c13c0cd3528f7fdc102/spec/lib/ssrf_filter_spec.rb#L371-L409> | 2026-09-24 |
| §7 | `s_server` serves a second certificate for one server name | OpenSSL `openssl-s_server` manual, `-cert2`, `-key2`, `-servername` | <https://github.com/openssl/openssl/blob/openssl-3.6.4/doc/man1/openssl-s_server.pod.in#L207-L209> | 2026-09-24 |
| §7 | No SNI for IP literals | RFC 6066 §3 | <https://www.rfc-editor.org/rfc/rfc6066.html#section-3> | 2026-09-24 |
| §7 | `webfakes` takes a single server certificate | `webfakes` `R/server.R` at v1.5.0 | <https://github.com/r-lib/webfakes/blob/7c72eb621e81f4297bc3f97a291424c73fc7f870/R/server.R#L80> | 2026-09-24 |
| §7 | A connect-to host does not change the name used for SNI and verification | libcurl `CURLOPT_CONNECT_TO` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CONNECT_TO.md?plain=1#L57-L59> | 2026-09-24 |
| §7 | Mocking works by modifying bindings in the package namespace | `testthat` 3.3.2 `R/mock2.R` | <https://github.com/r-lib/testthat/blob/ace29c526f93b6ae1a402d93e6b1ccaf65de1e61/R/mock2.R#L60-L64> | 2026-09-24 |
| §7 | Advocate's test suite raises on any `connect()` outside the validating path | Advocate `test/monkeypatching.py`, `CheckedSocket` | <https://github.com/JordanMilne/Advocate/blob/f65cbf925cacafded20bbb878776a543b6f2d21b/test/monkeypatching.py#L11-L40> | 2026-09-24 |
| §7 | `curl_version()$protocols` is libcurl's run-time list | `jeroen/curl` `src/version.c` (7.1.0 snapshot) | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/version.c#L17-L25> | 2026-09-24 |
| §7 | Advocate's hostname tests are skipped by a capability probe that compares a `str` to `b"example.com"` | Advocate `test/test_advocate.py` | <https://github.com/JordanMilne/Advocate/blob/f65cbf925cacafded20bbb878776a543b6f2d21b/test/test_advocate.py#L47-L55> | 2026-09-24 |
| §7 | `on_cran()` is `TRUE` when `NOT_CRAN` is unset and R is non-interactive | `testthat` 3.3.2 `R/skip.R` | <https://github.com/r-lib/testthat/blob/ace29c526f93b6ae1a402d93e6b1ccaf65de1e61/R/skip.R#L314-L321> | 2026-09-24 |
| §7 | Proxy variables libcurl reads; `http_proxy` lowercase only; case-insensitive systems honour `HTTP_PROXY`; `ALL_PROXY` | libcurl `libcurl-env` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/libcurl-env.md?plain=1#L25-L45> | 2026-09-24 |
| §7 | `proxy = ""` disables proxies even when a variable is set | libcurl `CURLOPT_PROXY` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_PROXY.md?plain=1#L90-L91> | 2026-09-24 |
| §7 | A connect-to host switches an HTTP proxy to tunnel mode | libcurl `CURLOPT_CONNECT_TO`; `lib/url.c` | <https://github.com/curl/curl/blob/curl-8_14_1/docs/libcurl/opts/CURLOPT_CONNECT_TO.md?plain=1#L70-L73>, <https://github.com/curl/curl/blob/curl-8_14_1/lib/url.c#L3611-L3618> | 2026-09-24 |
| §7 | The tunnel target is the connect-to host | libcurl `lib/http_proxy.c`, `Curl_http_proxy_get_destination` | <https://github.com/curl/curl/blob/curl-8_14_1/lib/http_proxy.c#L194-L211> | 2026-09-24 |
| §7 | R's `curl` provides the Windows proxy helpers without applying them in the handle | `jeroen/curl` `R/proxy.R`; `src/handle.c` (no proxy set at handle creation) | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/R/proxy.R#L16-L40>, <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/src/handle.c> | 2026-09-24 |
| §7 | On webR, `curl` sets `ALL_PROXY` at load | `jeroen/curl` `R/onload.R` | <https://github.com/jeroen/curl/blob/4092c366c27c8b64528b493be5e09fb6484a1172/R/onload.R#L20-L47> | 2026-09-24 |
| §7 | `_R_CHECK_SUGGESTS_ONLY_`, `_R_CHECK_DEPENDS_ONLY_`, `_R_CHECK_NO_RECOMMENDED_` semantics | R Internals, "Tools" (`R-ints.texi` at `tags/R-4-6-0`) | <https://github.com/wch/r-source/blob/71d21fd4e419c28bbb2a5fe160683ca6030a0536/doc/manual/R-ints.texi#L4573-L4605> | 2026-09-24 |
| §7 | `--as-cran` turns on `_R_CHECK_SUGGESTS_ONLY_` and `_R_CHECK_NO_RECOMMENDED_` | same | <https://github.com/wch/r-source/blob/71d21fd4e419c28bbb2a5fe160683ca6030a0536/doc/manual/R-ints.texi#L4614-L4623> | 2026-09-24 |
| §7 | `_R_CHECK_LIMIT_CORES_`: more than 2 children is an error; TRUE for submissions | same | <https://github.com/wch/r-source/blob/71d21fd4e419c28bbb2a5fe160683ca6030a0536/doc/manual/R-ints.texi#L4174-L4179> | 2026-09-24 |
| §7 | Check with each variable set and with neither; test-suite managers are used conditionally too | Writing R Extensions, "Suggested packages" (`R-exts.texi` at `tags/R-4-6-0`) | <https://github.com/wch/r-source/blob/71d21fd4e419c28bbb2a5fe160683ca6030a0536/doc/manual/R-exts.texi#L1101-L1122> | 2026-09-24 |
| §7 | At most two threads or cores; long tests may be made optional if the rest exercise every feature | CRAN Repository Policy source, svn r6942 | <https://svn.r-project.org/R-dev-web/trunk/CRAN/Policy/CRAN_policies.texi?p=6942> | 2026-09-24 |
| §7 | `skip_if_not_installed()`, `skip_if_offline()` (implies `skip_on_cran()`), `skip_on_cran()` | `testthat` 3.3.2 `R/skip.R` | <https://github.com/r-lib/testthat/blob/ace29c526f93b6ae1a402d93e6b1ccaf65de1e61/R/skip.R#L103-L182> | 2026-09-24 |
| §7 | `webfakes`' server certificate: `CN=localhost`, SANs `IP:127.0.0.1`, `DNS:localhost`, `DNS:localhost.localdomain`, valid to 2124; CA key shipped | `webfakes` `inst/cert/localhost/` at v1.5.0 | <https://github.com/r-lib/webfakes/tree/7c72eb621e81f4297bc3f97a291424c73fc7f870/inst/cert/localhost> | 2026-09-24 |
| §7 | civetweb is built without `USE_IPV6` | `webfakes` `src/Makevars.in` at v1.5.0 | <https://github.com/r-lib/webfakes/blob/7c72eb621e81f4297bc3f97a291424c73fc7f870/src/Makevars.in#L3-L4> | 2026-09-24 |
| §7 | `httpuv` added IPv6 support in 1.4.0 | `httpuv` `NEWS.md` at v1.6.17 | <https://github.com/rstudio/httpuv/blob/5e3d6827c284210b6a7cba7009cf73beb2e03525/NEWS.md#L248-L252> | 2026-09-24 |
| §7 | `serverSocket()` binds `INADDR_ANY` on an `AF_INET` socket | R `src/modules/internet/sock.c`, `Sock_open` (`tags/R-4-6-0`) | <https://github.com/wch/r-source/blob/71d21fd4e419c28bbb2a5fe160683ca6030a0536/src/modules/internet/sock.c#L224-L258> | 2026-09-24 |
| §7 | `linklint` asserts a SHA-256 and a 6,391-row count on its IdnaTestV2 corpus | `linklint` `packages/core/test/idna-conformance.test.ts` | <https://gitlab.com/bart-turczynski/linklint/-/blob/8830901a6c9e95a69b110b06db01bd97fa2aabb9/packages/core/test/idna-conformance.test.ts#L61-63> | 2026-09-24 |
| §7 | `tools::sha256sum()` is new in R 4.5.0 | R `doc/NEWS.Rd` (`tags/R-4-6-0`) | <https://github.com/wch/r-source/blob/71d21fd4e419c28bbb2a5fe160683ca6030a0536/doc/NEWS.Rd#L1166-L1168> | 2026-09-24 |
| §8 | `mcptools` ships a self-described "literal-only block, not a DNS-rebinding defense" | `posit-dev/mcptools` `R/utils.R` | <https://github.com/posit-dev/mcptools/blob/8a07faae095755afd7160432a12a85cce3cb8cde/R/utils.R> | 2026-09-24 |

---

## Not yet pinned

No commit, version or archived snapshot was found for these on 2026-09-24.
Archive them (for example with the Wayback Machine's "Save Page Now") and move
the snapshot URL into the table above, or replace the source.

| Cited at | Source | Canonical URL |
|---|---|---|
| §1.1 | `ssrf_filter` issue #78 | <https://github.com/arkadiyt/ssrf_filter/issues/78> |
| §5 gate 2 | Azure WireServer `168.63.129.16` | <https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16> |
| §5 gate 2, §2.3 | Oracle Cloud instance metadata | <https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm> |
| §5 gate 2, §2.3 | Alibaba Cloud instance metadata | <https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/> |
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
| r-binding §7 | Advocate issue #26 | <https://github.com/JordanMilne/Advocate/issues/26> |
| INV-13 | `pydantic-ai` `CVE-2026-48782` | <https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59> |
