# ssrfr 0.0.0.9000

* Initial scaffold.
* New `ssrf_policy()` builds a guard policy with every field and default of the v1 specification, and refuses a malformed entry, range, limit or `user_agent` with an `ssrfr_error_invalid_policy` condition (SSRF-upyqnwmv).
* New `ssrf_vocabulary()` lists the closed, versioned vocabularies: reason codes, operational causes and misuse condition classes (SSRF-upyqnwmv).
* New `ssrf_public_reason()` projects any refusal or operational failure to one value an untrusted party can see (SSRF-upyqnwmv).
* Refusals, operational failures and misuse conditions print and format without userinfo, request header values, bodies or proxy values (SSRF-upyqnwmv).
* The placeholder `scaffold_ready()` is removed (SSRF-upyqnwmv).
