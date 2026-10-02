# Rules and sources

Every name and every quoted sentence in `src/data.js` and in the messages comes from an official page, which is saved as text in [research/sources](../research/sources) with its address on the first line. `test/data.test.js` compares them: the risk IDs and names with the OWASP index page and with the heading of each risk page, the field names with the OpenAPI text, the keywords with the JSON Schema text, and the quoted sentences with the pages. To change a name, save the new page text first, change `src/data.js`, and change this document.

## The OWASP API Security Top 10, 2023 edition

| ID | Name | Page |
| --- | --- | --- |
| API1:2023 | Broken Object Level Authorization | https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ |
| API2:2023 | Broken Authentication | https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ |
| API3:2023 | Broken Object Property Level Authorization | https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/ |
| API4:2023 | Unrestricted Resource Consumption | https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/ |
| API5:2023 | Broken Function Level Authorization | https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/ |
| API7:2023 | Server Side Request Forgery | https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/ |
| API8:2023 | Security Misconfiguration | https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/ |
| API9:2023 | Improper Inventory Management | https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ |
| API10:2023 | Unsafe Consumption of APIs | https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/ |

The list is on https://owasp.org/API-Security/editions/2023/en/0x11-t10/ (saved as `owasp-top-10.txt`).

## What each rule rests on

| Rule | Fact | Source |
| --- | --- | --- |
| `apikey-in-query` | an API key can be sent in `query`, `header` or `cookie` (the `in` field of a Security Scheme Object); OWASP lists "Sends sensitive authentication details, such as auth tokens and passwords in the URL" as a sign of broken authentication | https://spec.openapis.org/oas/v3.1.0, API2 page |
| `security-missing`, `security-disabled`, `security-optional` | a top-level `security` applies to all operations; an operation's `security` overrides it; "To remove a top-level security declaration, an empty array can be used"; "To make security optional, an empty security requirement ({}) can be included in the array"; an extension field starts with `x-` | https://spec.openapis.org/oas/v3.1.0 |
| `http-server` | the `servers` array, a Server Object's `url` and `variables` (`default`, `enum`); servers can be set on a path item and an operation; OWASP lists "Transport Layer Security (TLS) is missing" | https://spec.openapis.org/oas/v3.1.0, API8 page |
| `basic-over-http` | an `http` Security Scheme Object with `scheme` set to `basic` (the Basic Authentication sample) | https://spec.openapis.org/oas/v3.1.0 |
| `object-id-review` | "Every API endpoint that receives an ID of an object ... should implement object-level authorization checks"; a path template names a parameter in the path | API1 page, https://spec.openapis.org/oas/v3.1.0 |
| `admin-same-scopes` | "Don't assume that an API endpoint is regular or administrative only based on the URL path"; "Can a regular user access administrative endpoints?" | API5 page |
| `mass-assignment-open` | "Omitting this keyword has the same assertion behavior as an empty schema" (`additionalProperties`); OpenAPI 3.0.3: "additionalProperties defaults to true"; `unevaluatedProperties` | JSON Schema Core (research/sources/json-schema-core.txt), https://spec.openapis.org/oas/v3.0.3 |
| `readonly-in-request` | `readOnly`: "it MAY be sent as part of a response but SHOULD NOT be sent as part of the request" | https://spec.openapis.org/oas/v3.0.3, JSON Schema Validation (research/sources/json-schema-validation.txt) |
| `list-without-paging` | OWASP: "Number of records per page to return in a single request-response" | API4 page |
| `unbounded-array`, `unbounded-string` | `maxItems` and `maxLength`; OWASP: "maximum length for strings, maximum number of elements in arrays" | JSON Schema Validation (research/sources/json-schema-validation.txt), API4 page |
| `no-rate-limit-response` | the `responses` codes of an operation (an explicit code, or a range such as 4XX); OWASP: "Implement a limit on how often a client can interact with the API" | https://spec.openapis.org/oas/v3.1.0, API4 page |
| `url-input` | the `format` values `uri`, `uri-reference`, `iri`, `iri-reference` of JSON Schema (resource identifiers); OWASP names webhooks, file fetching from URLs and URL previews | JSON Schema Validation (research/sources/json-schema-validation.txt), API7 page |
| `multiple-versions` | OWASP: "Running multiple versions of an API requires additional management resources from the API provider and expands the attack surface"; "There is no retirement plan for each API version" | API9 page |
| `non-production-server` | OWASP: "Which environment is the API running in (e.g. production, staging, test, development)?" | API9 page |
| `deprecated-operation` | the `deprecated` field of an Operation Object: "Consumers SHOULD refrain from usage of the declared operation" | https://spec.openapis.org/oas/v3.1.0 |
| `ref-remote`, `ref-unresolved`, `ref-cycle` | the Reference Object: a `$ref` holds a reference identifier; the tool follows `#/` references only | https://spec.openapis.org/oas/v3.1.0 |

## What is the tool's own choice

The specifications and OWASP say what the fields mean and what to look for. They do not say which thresholds a tool should use, so the following are the tool's own and are described in [method.md](method.md): the severity of each finding; the extension names `x-public` and `x-admin`; the words that make a path administrative (admin, internal, manage); the paging parameter names; the words that make a name hold a URL; the words that make a server non-production; reading `url` as a format name; the formats that count as having a fixed length; which first segment is not an object identifier; and the limits in [limits.md](limits.md).

## Which version of the OpenAPI text

OpenAPI 3.1.0 is the text the field names are taken from. OpenAPI 3.0.3 is saved too, because the tool reads 3.0 descriptions, and its Schema Object defines `readOnly` and `additionalProperties` itself, where 3.1 takes them from JSON Schema. Both are in `research/sources`.
