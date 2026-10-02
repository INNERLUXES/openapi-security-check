# openapi-security-check

Maps an OpenAPI 3.0 or 3.1 description to the risks of the OWASP API Security Top 10 (2023 edition), and reports what the description itself shows. You give it the file. It reads the operations, the security requirements, the servers and the schemas of requests, and groups what it finds under the risk it relates to, with the ID and the name exactly as the OWASP project writes them: API1:2023 Broken Object Level Authorization, API2:2023 Broken Authentication, and so on to API10:2023 Unsafe Consumption of APIs. Every finding names the JSON pointer and the line of the place, the severity, the risk, and a sentence on how to fix it.

A description is read by more people than the API is built by: partners, security reviewers, client generators and gateways. It is also the cheapest place to see a number of weaknesses early. An operation that nobody protected, an API key that travels in the query string, a server that is listed with `http://`, a request body that accepts any property, a list that has no paging, a field that takes a URL, two versions that are both still in the file: none of these breaks a build, and all of them are visible in the description. This tool reads them in a second, so the check can run on every pull request that changes the description.

- Every finding has an id, a severity (error, warning or info), the OWASP risk, the JSON pointer and the line, a plain message, a fix and the address of the OWASP page of the risk.
- What a description cannot show is said, not guessed. An object identifier in a path is a **review item** that says it cannot prove broken object level authorization. API6:2023 and API10:2023 are reported as `not checked` in every report, never as passed.
- Local `$ref` is followed, with limits and a check for cycles. A `$ref` to another file or an address is **never fetched**: it is an error finding, so a description that was only partly read does not pass the gate.
- It reads one file and nothing else. It never calls the API, opens no network connection and runs no program.
- Nothing from the description is copied into a report except structure: no example, no default, no enum value, no description text and no server address (which may hold a user name and a password).
- The risk IDs and names, the field names and the schema keywords are the ones of the official pages. The pages are saved in [research/sources](research/sources), and a test compares every name in [src/data.js](src/data.js) and the sentences that the documents quote with the saved text.
- Reports as text, Markdown, JSON and CSV, with an exit code for a pipeline gate. Info findings never fail the run.
- Plain JavaScript, no dependencies; the same file always gives the same report.

```
npm test
```

```
ℹ tests 104
ℹ pass 103
ℹ fail 0
ℹ skipped 1
```

The skipped test makes a symbolic link, which Windows does not allow without a privilege; on Linux and macOS all 104 run.

## Quick start

Requires Node 22 or newer. There is nothing to install.

```
git clone https://github.com/INNERLUXES/openapi-security-check.git
cd openapi-security-check
node bin/openapi-security-check.js examples/parcel-tracking.json
```

Or without a clone, in the folder of your description:

```
npx --yes github:INNERLUXES/openapi-security-check openapi.yaml
```

`examples/` holds a made-up API. `examples/parcel-tracking.json` is a parcel tracking API, wrong on purpose: no security on a status operation, an API key in the query string, HTTP basic authentication next to a server at `http://`, a staging server listed next to the production one, a request body that is also the response schema, a list with no paging, a field that takes a URL, an administrative export with the same scopes as everything else, a second version and a deprecated operation. `examples/parcel-tracking-fixed.json` is the same API with all of it corrected, and `examples/parcel-tracking-fixed.yaml` is the fixed one in YAML. `examples/output` holds the reports of the first file in every format; `npm run example` writes them again and fails if the README no longer shows what a real run prints.

## Usage

```
node bin/openapi-security-check.js examples/parcel-tracking.json
```

```
openapi-security-check: examples/parcel-tracking.json
OpenAPI 3.0.3, json, "Parcel Tracking API": 9 operations, 2 servers, 3 security schemes
edition: OWASP API Security Top 10 2023
risks:
  API1:2023   Broken Object Level Authorization                 warn         object-id-review x4
  API2:2023   Broken Authentication                             fail         apikey-in-query x1, security-disabled x1
  API3:2023   Broken Object Property Level Authorization        warn         mass-assignment-open x1, readonly-in-request x2
  API4:2023   Unrestricted Resource Consumption                 warn         list-without-paging x1, unbounded-array x1, no-rate-limit-response x5, unbounded-string x2
  API5:2023   Broken Function Level Authorization               warn         admin-same-scopes x1
  API6:2023   Unrestricted Access to Sensitive Business Flows   not checked  the description cannot show it
  API7:2023   Server Side Request Forgery                       warn         url-input x2
  API8:2023   Security Misconfiguration                         fail         http-server x1, basic-over-http x1
  API9:2023   Improper Inventory Management                     warn         multiple-versions x1, non-production-server x1, deprecated-operation x1
  API10:2023  Unsafe Consumption of APIs                        not checked  the description cannot show it
findings: 3 error, 20 warning, 3 info

API1:2023 Broken Object Level Authorization (4 findings)
  https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

  WARNING  object-id-review  #/paths/~1parcels~1{parcelId}/delete  line 54
           operation: DELETE /parcels/{parcelId}
           DELETE /parcels/{parcelId} takes the object identifier {parcelId} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable
           fix: Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier

  WARNING  object-id-review  #/paths/~1parcels~1{parcelId}/get  line 44
           operation: GET /parcels/{parcelId}
           GET /parcels/{parcelId} takes the object identifier {parcelId} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable
           fix: Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier

  WARNING  object-id-review  #/paths/~1track~1{code}/get  line 90
           operation: GET /track/{code}
           GET /track/{code} takes the object identifier {code} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable
           fix: Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier

  WARNING  object-id-review  #/paths/~1v2~1parcels~1{parcelId}~1events/get  line 61
           operation: GET /v2/parcels/{parcelId}/events
           GET /v2/parcels/{parcelId}/events takes the object identifier {parcelId} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable
           fix: Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier

API2:2023 Broken Authentication (2 findings)
  https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/

  ERROR    apikey-in-query  #/components/securitySchemes/LegacyKey/in  line 126
           The security scheme LegacyKey sends an API key in the query string (1 operation uses it). A key in a URL ends up in logs, browser history and referrer headers. OWASP lists "Sends sensitive authentication details, such as auth tokens and passwords in the URL" as a sign of a broken authentication
           fix: Send the key in a header (in: header) instead

  WARNING  security-disabled  #/paths/~1status/get/security  line 109
           operation: GET /status
           GET /status sets an empty security array, so anyone can call it. If that is meant, mark the operation with x-public: true; the tool then reads it as public on purpose
           fix: Give the operation a security requirement, or add x-public: true next to the empty array

API3:2023 Broken Object Property Level Authorization (3 findings)
  https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/

  WARNING  mass-assignment-open  #/components/schemas/Parcel  line 130
           operation: POST /parcels
           An object that a client sends (first reached from POST /parcels) accepts properties that it does not list: additionalProperties is not set. If the server binds the whole body to an object, a client can set properties it was never meant to set
           fix: Set additionalProperties: false, and list only the properties a client may write

  WARNING  readonly-in-request  #/components/schemas/Parcel/properties/id  line 134
           operation: POST /parcels
           The property id is marked readOnly but is part of a schema that a client sends (first reached from POST /parcels). The specification says a readOnly property SHOULD NOT be sent in a request, and a server that binds the body to an object may still accept it
           fix: Use one schema for the request without the property, and one for the response, or make sure the server ignores it

  WARNING  readonly-in-request  #/components/schemas/Parcel/properties/status  line 135
           operation: POST /parcels
           The property status is marked readOnly but is part of a schema that a client sends (first reached from POST /parcels). The specification says a readOnly property SHOULD NOT be sent in a request, and a server that binds the body to an object may still accept it
           fix: Use one schema for the request without the property, and one for the response, or make sure the server ignores it

API4:2023 Unrestricted Resource Consumption (9 findings)
  https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/

  WARNING  list-without-paging  #/paths/~1parcels/get  line 15
           operation: GET /parcels
           GET /parcels returns a list and has no paging parameter, so one request can return every record. OWASP lists "Number of records per page to return in a single request-response" among the limits an API needs
           fix: Add a limit and an offset, or a cursor, with a maximum value

  WARNING  unbounded-array  #/components/schemas/Parcel/properties/labels  line 137
           operation: POST /parcels
           An array that a client sends (first reached from POST /parcels) has no maxItems. OWASP asks for "maximum number of elements in arrays" on all incoming payloads
           fix: Set maxItems

  WARNING  no-rate-limit-response  #/paths/~1admin~1parcels~1export/get/responses  line 81
           operation: GET /admin/parcels/export
           GET /admin/parcels/export documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429)
           fix: Add a 429 response, with the header that tells the client when to retry

  WARNING  no-rate-limit-response  #/paths/~1parcels/get/responses  line 18
           operation: GET /parcels
           GET /parcels documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429)
           fix: Add a 429 response, with the header that tells the client when to retry

  WARNING  no-rate-limit-response  #/paths/~1parcels/post/responses  line 32
           operation: POST /parcels
           POST /parcels documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429)
           fix: Add a 429 response, with the header that tells the client when to retry

  WARNING  no-rate-limit-response  #/paths/~1parcels~1{parcelId}/delete/responses  line 57
           operation: DELETE /parcels/{parcelId}
           DELETE /parcels/{parcelId} documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429)
           fix: Add a 429 response, with the header that tells the client when to retry

  WARNING  no-rate-limit-response  #/paths/~1parcels~1{parcelId}/get/responses  line 47
           operation: GET /parcels/{parcelId}
           GET /parcels/{parcelId} documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429)
           fix: Add a 429 response, with the header that tells the client when to retry

  INFO     unbounded-string  #/components/schemas/Parcel/properties/recipientName  line 136
           operation: POST /parcels
           A string that a client sends (first reached from POST /parcels) has no maxLength, no enum and no fixed format. OWASP asks for "maximum length for strings" on all incoming parameters
           fix: Set maxLength

  INFO     unbounded-string  #/paths/~1parcels~1{parcelId}/parameters/0/schema  line 42
           operation: GET /parcels/{parcelId}
           A string that a client sends (first reached from GET /parcels/{parcelId}) has no maxLength, no enum and no fixed format. OWASP asks for "maximum length for strings" on all incoming parameters
           fix: Set maxLength

API5:2023 Broken Function Level Authorization (1 finding)
  https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/

  WARNING  admin-same-scopes  #/paths/~1admin~1parcels~1export/get  line 78
           operation: GET /admin/parcels/export
           GET /admin/parcels/export looks administrative (its path names admin, internal or manage) but asks for the same security as ordinary operations. OWASP also says not to assume that an endpoint is regular or administrative from its path, so the names are only a hint
           fix: Give administrative operations their own scope or role in the security requirement, and check it in the server code

API7:2023 Server Side Request Forgery (2 findings)
  https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/

  WARNING  url-input  #/components/schemas/Parcel/properties/callbackUrl  line 138
           operation: POST /parcels
           The format uri of callbackUrl says that a client sends a URL (first reached from POST /parcels). If the server fetches it, an attacker can point the server at an address inside the network. OWASP lists webhooks, file fetching from URLs and URL previews as the usual places. The description cannot show whether the server validates the address
           fix: Accept only addresses from an allow list of origins and schemes, and say so in the description of the field

  WARNING  url-input  #/paths/~1track~1{code}/get/parameters/1  line 97
           operation: GET /track/{code}
           The name of returnUrl says that a client sends a URL (first reached from GET /track/{code}). If the server fetches it, an attacker can point the server at an address inside the network. OWASP lists webhooks, file fetching from URLs and URL previews as the usual places. The description cannot show whether the server validates the address
           fix: Accept only addresses from an allow list of origins and schemes, and say so in the description of the field

API8:2023 Security Misconfiguration (2 findings)
  https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/

  ERROR    http-server  #/servers/1/url  line 10
           The server at #/servers/1 uses plain http, so everything sent to it can be read and changed on the way. OWASP lists "Transport Layer Security (TLS) is missing" as a sign of a security misconfiguration
           fix: Use an https:// address, and keep http only for localhost

  ERROR    basic-over-http  #/components/securitySchemes/BasicAuth  line 127
           operation: GET /track/{code}
           The security scheme BasicAuth is HTTP basic authentication, and 1 operation that uses it is served from a plain http address (first: GET /track/{code}). Basic authentication sends the user name and password with every request, readable by anyone on the way
           fix: Serve these operations over https only, or use a scheme that does not send the password with each request

API9:2023 Improper Inventory Management (3 findings)
  https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/

  WARNING  multiple-versions  #/paths/~1v2~1parcels~1{parcelId}~1events/get  line 61
           The description names major version v1 and also v2. Running several versions of an API expands the attack surface, and OWASP asks for a retirement plan for each version
           fix: Document which versions are in use and when the old one is retired, or split the description by version

  WARNING  non-production-server  #/servers/1/url  line 10
           The server at #/servers/1 is named as a staging, test or development environment, and the description also lists a server that is not. OWASP asks to document the environment of each API host and not to expose non-production deployments
           fix: Publish a separate description for the non-production environment, or remove the server from this one

  INFO     deprecated-operation  #/paths/~1track~1{code}/get/deprecated  line 93
           operation: GET /track/{code}
           GET /track/{code} is deprecated but still in the description. An old operation that is still served keeps its attack surface until it is retired
           fix: Remove the operation when its retirement date has passed, and document the date

note: 1 operation marked public on purpose (an empty security array with the x-public marker) was not reported as unprotected

GATE: FAIL - 3 errors
```

The exit code is `1`: an API key in the query string, a server at plain http and HTTP basic authentication over it are errors, and errors fail the run by default. The twenty warnings do not, unless you run with `--fail-on warning`. The four `object-id-review` findings say in their text that the description cannot show an object level check; the `no-rate-limit-response` findings are one per operation. The status operation with an empty security array and no marker is reported, and the health probe, which has the marker `x-public: true`, is counted in a note and not reported. The risks API6:2023 and API10:2023 say `not checked` because no description can show them.

The fixed API passes, also with `--fail-on warning`:

```
node bin/openapi-security-check.js examples/parcel-tracking-fixed.json --fail-on warning
```

```
openapi-security-check: examples/parcel-tracking-fixed.json
OpenAPI 3.0.3, json, "Parcel Tracking API": 7 operations, 1 server, 1 security scheme
edition: OWASP API Security Top 10 2023
risks:
  API1:2023   Broken Object Level Authorization                 pass         no finding
  API2:2023   Broken Authentication                             pass         no finding
  API3:2023   Broken Object Property Level Authorization        pass         no finding
  API4:2023   Unrestricted Resource Consumption                 pass         no finding
  API5:2023   Broken Function Level Authorization               pass         no finding
  API6:2023   Unrestricted Access to Sensitive Business Flows   not checked  the description cannot show it
  API7:2023   Server Side Request Forgery                       pass         no finding
  API8:2023   Security Misconfiguration                         pass         no finding
  API9:2023   Improper Inventory Management                     pass         no finding
  API10:2023  Unsafe Consumption of APIs                        not checked  the description cannot show it
findings: 0 error, 0 warning, 0 info

no findings

note: 1 operation marked public on purpose (an empty security array with the x-public marker) was not reported as unprotected

GATE: PASS (--fail-on warning)
```

Passing means that none of the checks found anything in the file. It does not mean that the API is safe; [docs/limits.md](docs/limits.md) lists what a description cannot show.

```
openapi-security-check <openapi-file> [options]
```

```
--format <name>     text, markdown, json or csv (default: text)
--fail-on <level>   exit with 1 when a finding is at this level or above: error or warning
                    (default: error); info never fails the run
--help              show the usage
--version           show the version
```

Paths in the report are relative to the folder you run the command in, with forward slashes on every system; a file outside it is shown with its absolute path.

## The ten risks

| Risk | What the tool checks from the description | Checks |
| --- | --- | --- |
| [API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | an object identifier in the path, with no scopes or the scopes of the list operation, as a review item | `object-id-review` |
| [API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) | operations with no security, an empty security array without the marker, optional security, an API key in the query string | `security-missing`, `security-disabled`, `security-optional`, `apikey-in-query` |
| [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) | request objects that accept unlisted properties, `readOnly` properties in a request | `mass-assignment-open`, `readonly-in-request` |
| [API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) | lists without paging, arrays and strings without a maximum, no 429 response | `list-without-paging`, `unbounded-array`, `unbounded-string`, `no-rate-limit-response` |
| [API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) | administrative-looking operations with the scopes of ordinary ones | `admin-same-scopes` |
| [API6:2023 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) | nothing: a description cannot show it | `not checked` |
| [API7:2023 Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/) | parameters and fields that take a URL | `url-input` |
| [API8:2023 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/) | servers at plain http, basic authentication over them | `http-server`, `basic-over-http` |
| [API9:2023 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) | more than one major version, a non-production server, deprecated operations | `multiple-versions`, `non-production-server`, `deprecated-operation` |
| [API10:2023 Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/) | nothing: a description cannot show it | `not checked` |

| Id | Severity | What it reports |
| --- | --- | --- |
| `security-missing` | warning | An operation has no security requirement, at the top level or on the operation |
| `security-disabled` | warning | An operation sets `security: []` without `x-public: true` |
| `security-optional` | warning | An empty requirement `{}` among the alternatives makes security optional |
| `apikey-in-query` | error | An `apiKey` scheme sends the key in the query string |
| `object-id-review` | warning | An object identifier in the path and a security with no scopes, or the same scopes as the list operation (a review item) |
| `admin-same-scopes` | warning | An administrative-looking path or an `x-admin` operation with the security of ordinary operations |
| `mass-assignment-open` | warning | A request object with `additionalProperties` true or not set |
| `readonly-in-request` | warning | A `readOnly` property in a request body schema |
| `list-without-paging` | warning | A list operation with no paging parameter |
| `unbounded-array` | warning | An array that a client sends has no `maxItems` |
| `unbounded-string` | info | A string that a client sends has no `maxLength`, `enum` or fixed format |
| `no-rate-limit-response` | warning | An operation documents no 429 response |
| `url-input` | warning | A parameter or a field with a uri format, or a name such as `callbackUrl`, `webhookUrl` or `redirect` |
| `http-server` | error | A server address that starts with `http://` and is not local |
| `basic-over-http` | error | HTTP basic authentication used on an operation served from plain http |
| `multiple-versions` | warning | More than one major version in the servers and the paths |
| `non-production-server` | warning | A staging, test or dev server listed next to another server |
| `deprecated-operation` | info | A deprecated operation is still in the description |
| `ref-remote` | error | A `$ref` to another file or an address, which is not followed |
| `ref-unresolved` | error | A local `$ref` that points to nothing |
| `limit-reached` | error | The schemas are deeper or more numerous than the limits, so the rest was not checked |
| `ref-cycle` | info | A `$ref` that leads back to itself; it was followed once |

[docs/method.md](docs/method.md) gives each check, its exact rule, what it can see and what it cannot. [docs/rules-and-sources.md](docs/rules-and-sources.md) lists every name with the saved page it comes from.

## Public on purpose

An operation that is open to everyone by design (a login, a health probe) has an empty security array. The specification allows it, and the tool does not guess whether it was a choice or an oversight, so the operation is reported unless it is marked:

```yaml
/health:
  get:
    security: []
    x-public: true
```

`x-public: true` is the tool's own extension: the specification only says that an extension starts with `x-`. It counts only next to the explicit empty array. A marked operation is not reported, and a note in the report counts them. `x-admin: true` on an operation or a path item marks it as administrative for `admin-same-scopes`, whatever its path.

## Where the facts come from

| Fact | Source |
| --- | --- |
| The ten risks, their IDs and names | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ and the page of each risk |
| `securitySchemes`, `in: query`, `servers`, `deprecated`, the empty security array and the empty requirement | https://spec.openapis.org/oas/v3.1.0 |
| `readOnly` and `additionalProperties` in OpenAPI 3.0 | https://spec.openapis.org/oas/v3.0.3 |
| `readOnly`, `maxItems`, `maxLength`, `format` (`uri`, `iri`) | JSON Schema Validation (research/sources/json-schema-validation.txt) |
| `additionalProperties`, `unevaluatedProperties`, `properties`, `items`, `allOf` | JSON Schema Core (research/sources/json-schema-core.txt) |

## Formats

- `text`: for a terminal: the document, the ten risks with their result, then the findings grouped by risk with the page of each risk, each with its rule id, pointer, line, operation, message and fix.
- `markdown`: the same for a pull request comment or the job summary, with the risk list linked to the OWASP pages. Pipes, line breaks and angle brackets from the input are escaped, so a value from the file cannot break a table.
- `json`: the whole report: the document, the ten risks, every finding with id, severity, risk, pointer, line, operation, subject, message, fix and source, the notes and the gate.
- `csv`: one row per finding with the risk ID and name, quoted as RFC 4180 says. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet does not run it as a formula.

To put the report in the job summary of a GitHub Actions run:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
    with:
      node-version: 22
  - name: OpenAPI security report
    run: npx --yes github:INNERLUXES/openapi-security-check openapi.yaml --format markdown >> "$GITHUB_STEP_SUMMARY"
  - name: OpenAPI security gate
    run: npx --yes github:INNERLUXES/openapi-security-check openapi.yaml --fail-on warning
```

It needs no secrets, no running service and no build; a Linux runner is enough. Start with the default gate (errors only), and move to `--fail-on warning` when the first report is clean.

## Exit codes

`0` no finding at the `--fail-on` level, `1` at least one such finding (by default: an error), `2` a usage or input error (a missing file, a file that is not JSON or the YAML subset, a version other than OpenAPI 3.0 or 3.1, a file over the size limit, an unknown option).

A `$ref` to another file is not exit code `2`: it is a finding (`ref-remote`), so the run still checks everything else and the gate fails.

## Limits

The tool reads what the description says, not what the API does. A check in the server code, a limit at a gateway, a role that the description does not name and a flow that is abused by automation are not seen. A finding is a review item, and a `pass` is not a safe API. Names are heuristics: the words that make a path administrative, a parameter a paging parameter, a field a URL and a server non-production are listed in [docs/method.md](docs/method.md). [docs/limits.md](docs/limits.md) lists these, with the size limits and the YAML that is read.

## Related

The tool covers the OWASP view of a description. It does not repeat its neighbours in the same organization: `api-product-check` reviews a product's description for what its customers depend on (tenant identifiers, operation ids, error responses), and `api-break-check` compares two versions of a description for breaking changes. Where this tool mentions authentication, paging or a 429 response, it does so as the OWASP risk the gap belongs to, with the pointer and the OWASP page, and not as a product review.

## Background

- How APIs are designed, secured, versioned and documented, with checks like this one in the pipeline: [API development services](https://innerluxes.dev/software-development/api-development).

## License

MIT
