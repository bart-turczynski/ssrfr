# ssrfr 0.0.0.9000

* Initial scaffold.
* New `ssrf_policy()` builds a guard policy with every field and default of the v1 specification, and refuses a malformed entry, range, limit or `user_agent` with an `ssrfr_error_invalid_policy` condition (SSRF-upyqnwmv).
* New `ssrf_vocabulary()` lists the closed, versioned vocabularies: reason codes, operational causes and misuse condition classes (SSRF-upyqnwmv).
* New `ssrf_public_reason()` projects any refusal or operational failure to one value an untrusted party can see (SSRF-upyqnwmv).
* Refusals, operational failures and misuse conditions print and format without userinfo, request header values, bodies or proxy values (SSRF-upyqnwmv).
* The placeholder `scaffold_ready()` is removed (SSRF-upyqnwmv).
* New `ssrf_inspect_url()` reports what a URL is under a policy with no network I/O: the parse `rurl` and libcurl agree on, the scheme, host and port libcurl reads, the `raddr` classification of an address-literal host, and the reason code the first applicable check reports. It is a pre-filter and configuration-linting aid, not a defense (SSRF-uxmxqufj).
* `ssrf_vocabulary()` lists two new closed, versioned vocabularies of policy data: the provider endpoints refused by address (`"provider_endpoints"`) and the metadata hostnames refused by name (`"metadata_hostnames"`), each row citing and quoting the vendor documentation that names it (SSRF-uxmxqufj).
