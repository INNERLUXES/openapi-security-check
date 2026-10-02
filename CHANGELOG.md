# Changes

## 1.0.0

First release.

- Reads one OpenAPI 3.0 or 3.1 description (JSON, or the YAML subset of docs/inputs.md) and reports what the description itself shows, grouped by the risk of the OWASP API Security Top 10 (2023 edition) it relates to, with the IDs API1:2023 to API10:2023 and the names as the OWASP project writes them. Never calls the API and never fetches anything.
- API1: an object identifier in a path whose security has no scopes, or the same scopes as the list operation, as a review item that says it cannot prove the risk (`object-id-review`).
- API2: operations without a security requirement, an empty security array that is not marked `x-public: true`, an optional security requirement, and an API key in the query string (`security-missing`, `security-disabled`, `security-optional`, `apikey-in-query`).
- API3: request body objects that accept unlisted properties, and `readOnly` properties in a request body (`mass-assignment-open`, `readonly-in-request`).
- API4: lists without a paging parameter, arrays and strings that a client sends without `maxItems` or `maxLength`, and operations that document no 429 response (`list-without-paging`, `unbounded-array`, `unbounded-string`, `no-rate-limit-response`).
- API5: administrative-looking paths or `x-admin` operations with the same scopes as ordinary operations (`admin-same-scopes`).
- API7: parameters and body fields that take a URL (`url-input`).
- API8: server addresses over plain http and HTTP basic authentication over them (`http-server`, `basic-over-http`).
- API9: more than one major version, a non-production server next to others, and deprecated operations (`multiple-versions`, `non-production-server`, `deprecated-operation`).
- API6 and API10 are reported as `not checked`: a description of the interface cannot show them.
- Local `$ref` is followed, with a limit on the chain and on the depth and a check for cycles. A `$ref` to another file or an address is refused with a finding and never opened (`ref-remote`, `ref-unresolved`, `ref-cycle`, `limit-reached`).
- Every finding has an id, a severity (error, warning, info), the risk, the JSON pointer and the line, the operation, a message, a fix and the address of the OWASP page. No example, default, enum value or server address is printed.
- The risk names, the field names and the keywords come from official pages, which are saved in `research/sources`; a test compares `src/data.js` and the findings with the saved text.
- Reports as text, Markdown, JSON and CSV; `--fail-on` for a pipeline gate; info never fails the run; exit code `2` for a usage or input error.
- Safe input: one file is read, files over 10 MB are refused, JSON nested more than 64 deep is refused, the YAML reader accepts a documented subset only, patterns are bounded, and control characters are removed from every text shown.
- Release packages come with a CycloneDX SBOM, SHA-256 checksums and a build provenance attestation.
