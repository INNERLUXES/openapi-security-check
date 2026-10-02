## openapi-security-check: 3 error, 20 warning, 3 info

Document: `examples/parcel-tracking.json`. OpenAPI 3.0.3, json, "Parcel Tracking API": 9 operations, 2 servers, 3 security schemes. Edition: OWASP API Security Top 10 2023.

| Risk | Result | Detail |
| --- | --- | --- |
| [API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) Broken Object Level Authorization | warn | object-id-review x4 |
| [API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) Broken Authentication | **fail** | apikey-in-query x1, security-disabled x1 |
| [API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) Broken Object Property Level Authorization | warn | mass-assignment-open x1, readonly-in-request x2 |
| [API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) Unrestricted Resource Consumption | warn | list-without-paging x1, unbounded-array x1, no-rate-limit-response x5, unbounded-string x2 |
| [API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) Broken Function Level Authorization | warn | admin-same-scopes x1 |
| [API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) Unrestricted Access to Sensitive Business Flows | not checked | whether a flow such as buying a ticket or posting a comment can be abused when it is automated is a question about the business, which a description of the interface does not answer |
| [API7:2023](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/) Server Side Request Forgery | warn | url-input x2 |
| [API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/) Security Misconfiguration | **fail** | http-server x1, basic-over-http x1 |
| [API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) Improper Inventory Management | warn | multiple-versions x1, non-production-server x1, deprecated-operation x1 |
| [API10:2023](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/) Unsafe Consumption of APIs | not checked | how the API treats the data it receives from third-party services happens inside the server, and a description lists only the operations the API offers |

### API1:2023 Broken Object Level Authorization

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| warning | object-id-review | #/paths/~1parcels~1{parcelId}/delete (line 54), DELETE /parcels/{parcelId} | DELETE /parcels/{parcelId} takes the object identifier {parcelId} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable | Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier |
| warning | object-id-review | #/paths/~1parcels~1{parcelId}/get (line 44), GET /parcels/{parcelId} | GET /parcels/{parcelId} takes the object identifier {parcelId} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable | Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier |
| warning | object-id-review | #/paths/~1track~1{code}/get (line 90), GET /track/{code} | GET /track/{code} takes the object identifier {code} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable | Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier |
| warning | object-id-review | #/paths/~1v2~1parcels~1{parcelId}~1events/get (line 61), GET /v2/parcels/{parcelId}/events | GET /v2/parcels/{parcelId}/events takes the object identifier {parcelId} in its path, and its security names no scopes. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable | Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller's identifier |

### API2:2023 Broken Authentication

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| error | apikey-in-query | #/components/securitySchemes/LegacyKey/in (line 126) | The security scheme LegacyKey sends an API key in the query string (1 operation uses it). A key in a URL ends up in logs, browser history and referrer headers. OWASP lists "Sends sensitive authentication details, such as auth tokens and passwords in the URL" as a sign of a broken authentication | Send the key in a header (in: header) instead |
| warning | security-disabled | #/paths/~1status/get/security (line 109), GET /status | GET /status sets an empty security array, so anyone can call it. If that is meant, mark the operation with x-public: true; the tool then reads it as public on purpose | Give the operation a security requirement, or add x-public: true next to the empty array |

### API3:2023 Broken Object Property Level Authorization

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| warning | mass-assignment-open | #/components/schemas/Parcel (line 130), POST /parcels | An object that a client sends (first reached from POST /parcels) accepts properties that it does not list: additionalProperties is not set. If the server binds the whole body to an object, a client can set properties it was never meant to set | Set additionalProperties: false, and list only the properties a client may write |
| warning | readonly-in-request | #/components/schemas/Parcel/properties/id (line 134), POST /parcels | The property id is marked readOnly but is part of a schema that a client sends (first reached from POST /parcels). The specification says a readOnly property SHOULD NOT be sent in a request, and a server that binds the body to an object may still accept it | Use one schema for the request without the property, and one for the response, or make sure the server ignores it |
| warning | readonly-in-request | #/components/schemas/Parcel/properties/status (line 135), POST /parcels | The property status is marked readOnly but is part of a schema that a client sends (first reached from POST /parcels). The specification says a readOnly property SHOULD NOT be sent in a request, and a server that binds the body to an object may still accept it | Use one schema for the request without the property, and one for the response, or make sure the server ignores it |

### API4:2023 Unrestricted Resource Consumption

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| warning | list-without-paging | #/paths/~1parcels/get (line 15), GET /parcels | GET /parcels returns a list and has no paging parameter, so one request can return every record. OWASP lists "Number of records per page to return in a single request-response" among the limits an API needs | Add a limit and an offset, or a cursor, with a maximum value |
| warning | unbounded-array | #/components/schemas/Parcel/properties/labels (line 137), POST /parcels | An array that a client sends (first reached from POST /parcels) has no maxItems. OWASP asks for "maximum number of elements in arrays" on all incoming payloads | Set maxItems |
| warning | no-rate-limit-response | #/paths/~1admin~1parcels~1export/get/responses (line 81), GET /admin/parcels/export | GET /admin/parcels/export documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429) | Add a 429 response, with the header that tells the client when to retry |
| warning | no-rate-limit-response | #/paths/~1parcels/get/responses (line 18), GET /parcels | GET /parcels documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429) | Add a 429 response, with the header that tells the client when to retry |
| warning | no-rate-limit-response | #/paths/~1parcels/post/responses (line 32), POST /parcels | POST /parcels documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429) | Add a 429 response, with the header that tells the client when to retry |
| warning | no-rate-limit-response | #/paths/~1parcels~1{parcelId}/delete/responses (line 57), DELETE /parcels/{parcelId} | DELETE /parcels/{parcelId} documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429) | Add a 429 response, with the header that tells the client when to retry |
| warning | no-rate-limit-response | #/paths/~1parcels~1{parcelId}/get/responses (line 47), GET /parcels/{parcelId} | GET /parcels/{parcelId} documents no 429 response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit 429) | Add a 429 response, with the header that tells the client when to retry |
| info | unbounded-string | #/components/schemas/Parcel/properties/recipientName (line 136), POST /parcels | A string that a client sends (first reached from POST /parcels) has no maxLength, no enum and no fixed format. OWASP asks for "maximum length for strings" on all incoming parameters | Set maxLength |
| info | unbounded-string | #/paths/~1parcels~1{parcelId}/parameters/0/schema (line 42), GET /parcels/{parcelId} | A string that a client sends (first reached from GET /parcels/{parcelId}) has no maxLength, no enum and no fixed format. OWASP asks for "maximum length for strings" on all incoming parameters | Set maxLength |

### API5:2023 Broken Function Level Authorization

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| warning | admin-same-scopes | #/paths/~1admin~1parcels~1export/get (line 78), GET /admin/parcels/export | GET /admin/parcels/export looks administrative (its path names admin, internal or manage) but asks for the same security as ordinary operations. OWASP also says not to assume that an endpoint is regular or administrative from its path, so the names are only a hint | Give administrative operations their own scope or role in the security requirement, and check it in the server code |

### API7:2023 Server Side Request Forgery

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| warning | url-input | #/components/schemas/Parcel/properties/callbackUrl (line 138), POST /parcels | The format uri of callbackUrl says that a client sends a URL (first reached from POST /parcels). If the server fetches it, an attacker can point the server at an address inside the network. OWASP lists webhooks, file fetching from URLs and URL previews as the usual places. The description cannot show whether the server validates the address | Accept only addresses from an allow list of origins and schemes, and say so in the description of the field |
| warning | url-input | #/paths/~1track~1{code}/get/parameters/1 (line 97), GET /track/{code} | The name of returnUrl says that a client sends a URL (first reached from GET /track/{code}). If the server fetches it, an attacker can point the server at an address inside the network. OWASP lists webhooks, file fetching from URLs and URL previews as the usual places. The description cannot show whether the server validates the address | Accept only addresses from an allow list of origins and schemes, and say so in the description of the field |

### API8:2023 Security Misconfiguration

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| error | http-server | #/servers/1/url (line 10) | The server at #/servers/1 uses plain http, so everything sent to it can be read and changed on the way. OWASP lists "Transport Layer Security (TLS) is missing" as a sign of a security misconfiguration | Use an https:// address, and keep http only for localhost |
| error | basic-over-http | #/components/securitySchemes/BasicAuth (line 127), GET /track/{code} | The security scheme BasicAuth is HTTP basic authentication, and 1 operation that uses it is served from a plain http address (first: GET /track/{code}). Basic authentication sends the user name and password with every request, readable by anyone on the way | Serve these operations over https only, or use a scheme that does not send the password with each request |

### API9:2023 Improper Inventory Management

| Severity | Check | Where | Message | Fix |
| --- | --- | --- | --- | --- |
| warning | multiple-versions | #/paths/~1v2~1parcels~1{parcelId}~1events/get (line 61) | The description names major version v1 and also v2. Running several versions of an API expands the attack surface, and OWASP asks for a retirement plan for each version | Document which versions are in use and when the old one is retired, or split the description by version |
| warning | non-production-server | #/servers/1/url (line 10) | The server at #/servers/1 is named as a staging, test or development environment, and the description also lists a server that is not. OWASP asks to document the environment of each API host and not to expose non-production deployments | Publish a separate description for the non-production environment, or remove the server from this one |
| info | deprecated-operation | #/paths/~1track~1{code}/get/deprecated (line 93), GET /track/{code} | GET /track/{code} is deprecated but still in the description. An old operation that is still served keeps its attack surface until it is retired | Remove the operation when its retirement date has passed, and document the date |

- 1 operation marked public on purpose (an empty security array with the x-public marker) was not reported as unprotected

**Gate failed:** 3 errors.
