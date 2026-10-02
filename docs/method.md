# Method

The tool answers one question: what does this OpenAPI description show about the risks of the OWASP API Security Top 10 (2023 edition)? It reads the description as data, never calls the API, and turns each thing it finds into a finding with a severity, the JSON pointer and the line of the place, the risk it relates to, and a sentence on how to fix it. The risk IDs and names (API1:2023 to API10:2023), the OpenAPI field names and the schema keywords all come from official pages that are saved under [research/sources](../research/sources) and listed in [rules-and-sources.md](rules-and-sources.md). A test compares them with the saved text, so the tool and its sources cannot drift apart without a failing test.

A description is a promise about the interface, not a record of what the server does. Every check below therefore says what it can see and what it cannot. Where the description cannot show whether a risk is real (object level authorization is the clearest case), the finding says that it is something to review.

## Severities

- **error**: the description says something that the OWASP project names as a sign of a weakness, in plain words: an API key sent in the query string, a server at a plain http address, basic authentication over http, or a part of the description that the tool could not read.
- **warning**: a review item or a gap that a well-formed description closes: an operation without security, an object identifier with weak scopes, a request body that accepts unlisted properties, a list without paging, no documented 429 response, a field that takes a URL, two versions, a non-production server.
- **info**: something worth a look that is not a gap by itself: a string without a maximum length, a deprecated operation, a `$ref` that leads back to itself.

By default only errors fail the run. `--fail-on warning` fails on warnings too. Info never fails the run.

## The ten risks

| Risk | What the tool checks | Result in the report |
| --- | --- | --- |
| API1:2023 Broken Object Level Authorization | `object-id-review` | a result from the findings |
| API2:2023 Broken Authentication | `security-missing`, `security-disabled`, `security-optional`, `apikey-in-query` | a result from the findings |
| API3:2023 Broken Object Property Level Authorization | `mass-assignment-open`, `readonly-in-request` | a result from the findings |
| API4:2023 Unrestricted Resource Consumption | `list-without-paging`, `unbounded-array`, `unbounded-string`, `no-rate-limit-response` | a result from the findings |
| API5:2023 Broken Function Level Authorization | `admin-same-scopes` | a result from the findings |
| API6:2023 Unrestricted Access to Sensitive Business Flows | nothing | `not checked` |
| API7:2023 Server Side Request Forgery | `url-input` | a result from the findings |
| API8:2023 Security Misconfiguration | `http-server`, `basic-over-http` | a result from the findings |
| API9:2023 Improper Inventory Management | `multiple-versions`, `non-production-server`, `deprecated-operation` | a result from the findings |
| API10:2023 Unsafe Consumption of APIs | nothing | `not checked` |

A result of `pass` means that none of the checks listed for the risk found anything. It does not mean that the API is free of the risk: the tool checks what a description can show, and the other rows of this document say what it cannot.

API6 is about whether a business flow can be abused when it is automated, which is a question about the business. API10 is about how the server treats the data it gets from other services, which happens inside the server. A description of the interface shows neither, so the report says `not checked` for both and never `pass`.

## Security requirements (API2)

In OpenAPI the `security` list at the top level applies to every operation, and an operation's own `security` replaces it. Only one of the alternatives in the list has to be satisfied. The specification gives two ways to open an operation to everyone: an empty array on the operation ("To remove a top-level security declaration, an empty array can be used") and an empty requirement `{}` among the alternatives ("To make security optional, an empty security requirement ({}) can be included in the array").

**`security-missing`** (warning). The operation has no `security` of its own and the top level has none, or the top level is an empty array. *Can see:* that the description lists no credentials for the operation. *Cannot see:* a gateway or a framework that protects the operation without the description saying so. An operation that is public on purpose (a login, a health probe) is better written with the marker below.

**`security-disabled`** (warning). The operation sets `security: []`. This is the specification's way to say "no authentication", and the tool treats it as a choice that has to be made visible: an operation with an empty `security` array and the extension `x-public: true` is read as **public on purpose** and is not reported; it is counted in a note. The marker is the tool's own convention. The specification only says that an extension starts with `x-`, and OWASP defines no such name. The marker counts only on an operation that has the explicit empty array, with the value `true` (a string `"true"` is not `true`). A marker on an operation without the empty array changes nothing, and the message of `security-missing` says so.

**`security-optional`** (warning). One of the alternatives is `{}`, so a client can call the operation without credentials. This is sometimes written to mean that a token may or may not be present, which is the case to document in the description of the operation. There is no marker for this form.

**`apikey-in-query`** (error). A security scheme of type `apiKey` with `in: query`. OWASP lists "Sends sensitive authentication details, such as auth tokens and passwords in the URL" among the signs of broken authentication; a URL is kept in server logs, browser history and referrer headers. A scheme that the description defines but no operation uses is still reported, because the description says how the key is to be sent. *Cannot see:* how the server stores the key, rotates it or checks it.

## Object identifiers (API1)

**`object-id-review`** (warning). A path that has a template which is a whole segment and not the first one (`/parcels/{parcelId}`, `/users/{id}/orders`) names an object. The operation is reported when its security names no scopes, or when its scopes are the same as the scopes of the list operation, which is the GET of the same path without the last template (`GET /parcels` for `/parcels/{parcelId}`). The test for "the same" compares the schemes and the scopes, ignoring their order.

*What this means:* nothing more than that this operation takes an identifier and the description gives it no scope that is different from the one that lists everything. Object level authorization is a check in the server code, on every request, that the caller may act on the object. OWASP is clear that "Comparing the user ID of the current session (e.g. by extracting it from the JWT token) with the vulnerable ID parameter isn't a sufficient solution", and the description cannot show any of it. The finding says so in its message, and the check **cannot prove broken object level authorization**. The first segment of a path is not read as an identifier (`/{tenant}/things`) because it is more often a version, a tenant or a language. A path whose identifier is written in a way that is not a whole segment (`/files/name-{id}`) is not read.

## Administrative operations (API5)

**`admin-same-scopes`** (warning). An operation looks administrative when a segment of its path has the word admin, internal or manage in it (`/admin/users`, `/internal-reports`, `/user-management`, `/adminPanel`; the words are found after splitting at punctuation and between a lower case and an upper case letter, so `administration` and `managers` are not), or when the operation or its path item has the extension `x-admin: true`. It is reported when its security (the schemes with their scopes) is the same as that of at least one operation that does not look administrative, including the case where both have none.

OWASP warns: "Don't assume that an API endpoint is regular or administrative only based on the URL path". The path words are a hint for a review, and an administrative operation under a plain path is not found unless it carries `x-admin`. *Cannot see:* the roles or the groups that the server checks, which are not in the description.

## Properties of objects (API3)

**`mass-assignment-open`** (warning). A schema that a client sends as a request body, of type `object` or with `properties`, has `additionalProperties` set to `true` or not set. The JSON Schema page says that omitting the keyword "has the same assertion behavior as an empty schema", so an unlisted property is accepted, and OpenAPI 3.0 says "additionalProperties defaults to true". A schema is closed by `additionalProperties: false` or `unevaluatedProperties: false`; a schema that gives `additionalProperties` as a schema (a typed map) is not reported. *Cannot see:* whether the server binds the whole body to an object (the thing that makes extra properties dangerous) or copies only the properties it knows. The pointer is the schema at its definition, once, even when several operations use it; the message names the first operation that reaches it.

**`readonly-in-request`** (warning). A property marked `readOnly: true` is part of a schema that a client sends. OpenAPI 3.0 says that such a property "MAY be sent as part of a response but SHOULD NOT be sent as part of the request"; the JSON Schema page says that attempts by an application to modify such a value "are expected to be ignored or rejected by that owning authority". A property in a request schema that is read only is the sign of one schema shared by the request and the response, and a server that binds the body to an object may accept it. *Cannot see:* what the server does with the property.

Only the schemas of request bodies are read for both. The response side of API3 (excessive data exposure) needs to know which properties are sensitive, which a description does not say, so it is not checked.

## Resource consumption (API4)

OWASP's list of limits includes "Number of records per page to return in a single request-response", and its prevention advice asks to "Define and enforce a maximum size of data on all incoming parameters and payloads, such as maximum length for strings, maximum number of elements in arrays" and to limit how often a client can call the API.

**`list-without-paging`** (warning). A `GET` is a list when its first success response (a 2xx code or a range such as 2XX) has a schema of type `array`, or an object with an array in a property named items, data, results, records, entries, list, content or values (only when the path does not end in a template). It has paging when a query or header parameter is named limit, page, pagesize, perpage, size, offset, cursor, after, before, pagetoken, nexttoken, top, skip, take, maxresults, pagenumber, startingafter, endingbefore, pagecursor or count (letter case, `_`, `-` and `$` ignored). *Cannot see:* paging done in some other way (a header the server reads without the description saying so), or a list whose size is naturally small.

**`unbounded-array`** (warning). A schema of type `array` that a client sends, in a parameter or a request body, has no `maxItems`.

**`unbounded-string`** (info). A schema of type `string` that a client sends has no `maxLength`, no `enum` or `const` and no format of a fixed shape (date, date-time, time, duration, uuid, ipv4, ipv6, binary). The severity is info because it is the commonest finding by far and a limit may be set in front of the server.

**`no-rate-limit-response`** (warning). The operation does not document a `429` response. Only an explicit `429` counts, and a range such as `4XX` does not, because a client needs to know what the limit looks like. *Cannot see:* a limit that exists but is not documented, or one that the gateway enforces and answers with a code the description does not list.

## URLs that a client sends (API7)

**`url-input`** (warning). A parameter or a property of a request body whose schema is a string with a format of `uri`, `uri-reference`, `iri` or `iri-reference` (the resource identifier formats of JSON Schema), or `url` (not a JSON Schema format, but the name tools use, so it is read as a convention), or whose name is `url`, `uri`, `href`, `link`, `callback` or `webhook`, ends in `url` or `uri`, or has `redirect` in it. A field with an `enum` or a `const` is not reported, and neither is a field that is not a string. OWASP says that SSRF flaws "occur when an API is fetching a remote resource without validating the user-supplied URL" and names webhooks, file fetching from URLs and URL previews. *Cannot see:* whether the server fetches the URL, and whether it validates it. A redirect that the browser follows is not SSRF; the name is a hint to review.

## Servers and transport (API8)

**`http-server`** (error). A server (at the top level, on a path item or on an operation) whose address starts with `http://`, unless the host is local: `localhost`, a name that ends in `.localhost`, `127.x.x.x` or `[::1]`. A server address that starts with a variable (`{scheme}://host`) is read from the variable's `default` and `enum`: it is reported when either is `http`. A relative address is not reported. OWASP lists "Transport Layer Security (TLS) is missing". *Cannot see:* a proxy that terminates TLS in front of an address that is written as http, or an address that is written as https and served as http.

**`basic-over-http`** (error). A security scheme of type `http` with the scheme `basic`, used by an operation whose applicable servers include a non-local http address (its own servers, else those of its path item, else the top level). Basic authentication sends the user name and password with every request. It is reported once for the scheme, and it comes on top of `http-server`.

## Inventory (API9)

OWASP asks for an inventory of the hosts that documents "the API environment (e.g. production, staging, test, development)" and the version, and it lists "There is no retirement plan for each API version" among the signs of a documentation blindspot.

**`multiple-versions`** (warning). More than one major version is named in the paths of the servers and in the path templates: a segment such as `v1`, `v2`, `V3.1`. The first version found is the baseline; each other major version is reported once at the first place where it appears. A segment such as `v2fa` is not a version. *Cannot see:* whether the old version is still served, and its retirement date.

**`non-production-server`** (warning). A server whose host or description has the word staging, stage, test, testing, dev, development, qa or uat is reported when the description also lists a server that is not of that kind and is not local. The last label of the host (the top-level domain) is not read as a word. A description with only non-production servers is not reported, because the tool cannot tell whether it is meant for production. A heuristic by name: `contest` is not `test`.

**`deprecated-operation`** (info). An operation with `deprecated: true` is still in the description.

## Reading the description

These findings are not about a risk of the API. They say what the tool could not read, and they are in a group of their own in the report.

- **`ref-remote`** (error). A `$ref` that does not start with `#/` points to another file or an address. The tool never fetches or opens it, so what is behind it was not checked, and the gate fails until the description is bundled into one file. The address is not printed.
- **`ref-unresolved`** (error). A `$ref` that starts with `#/` points to a place that does not exist.
- **`ref-cycle`** (info). A `$ref` that leads back to itself, or a schema that contains itself. The tool follows it once and says so; a recursive schema is usual and nothing to fix.
- **`limit-reached`** (error). The schemas are nested deeper, or are more numerous, than the limits in [limits.md](limits.md), so the rest was not walked.

## What every finding says

A finding has an id, a severity, the risk (ID and name) or none, the JSON pointer and the line of the place, the operation (`GET /parcels`) when it belongs to one, a subject, a message, a fix and the address of the official OWASP page of the risk. The pointer is a URI fragment with `~0` and `~1` escapes. Where a finding is about a shared schema, the pointer is the definition in `components`, because that is the place to fix it.

No value from the description is copied into a finding: not an example, a default, an enum value or a description text, and not a server address. A finding names parameters, properties, schemes and paths, which are the structure of the interface.
