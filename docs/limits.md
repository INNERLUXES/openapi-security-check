# Limits

## What the tool can know

- **It sees what the description says, not what the API does.** A description is written by people, often generated from code, and often out of date. An operation that the server serves but the description leaves out is not seen. A check that the server makes and the description does not mention (authorization of an object, a rate limit at a gateway, paging that the server applies without a parameter) is not seen, and a description that promises more than the server does passes. The tool reports what the file shows and nothing about the running service.
- **A finding is a review item, not proof.** `object-id-review` is the clearest case: broken object level authorization is a check in the server code, and no description can show that it is missing or present. The same holds, in a lesser degree, for `admin-same-scopes` (the roles are not in the description), `mass-assignment-open` (the binding is in the code), `url-input` (the fetching is in the code) and `no-rate-limit-response`. The messages say so.
- **A pass is not a safe API.** A result of `pass` for a risk means that none of the checks for that risk found anything in the file. API6 (Unrestricted Access to Sensitive Business Flows) and API10 (Unsafe Consumption of APIs) are reported as `not checked`, because a description of the interface cannot show them.
- **Names are heuristics.** The admin words (admin, internal, manage), the paging names, the names that hold a URL, the words of a non-production server (staging, test, dev) and the version segments (`v1`) are read from names. A name that does not follow the usual words is not found, and a name that does is sometimes not what it looks like. OWASP itself says not to assume that an endpoint is administrative from its path.
- **Scopes are compared as written.** Two operations have the same scopes when they name the same schemes with the same scopes. The tool does not know what a scope allows. `parcels:read` for a list and for one parcel is "the same", and the review finding asks for a decision, which may be that it is fine.
- **Only the operations under `paths` are read.** `webhooks` and `callbacks` (OpenAPI 3.1 and 3.0) are not read; the report says how many there are. A path item written as a `$ref` to another place in the same file is followed.
- **Only the schemas of requests are walked** for the checks on what a client sends. The schemas of responses are read only to decide whether an operation is a list. `allOf`, `anyOf` and `oneOf` members are walked as their own schemas, and `additionalProperties` is looked at on each schema by itself: a schema that is closed by `unevaluatedProperties` in a composition elsewhere is not combined with its members. A discriminator is not read.
- **Security requirements are read as lists.** The tool does not check that a scheme named in `security` is defined, that an OAuth 2 scope is declared, or that the flows are sound.
- **`$ref` is followed inside the file only.** A description split over files has to be bundled first; a remote `$ref` is an error finding, so the gate does not pass a description that was only partly read.
- **The YAML reader is a subset.** [inputs.md](inputs.md) lists what it accepts. A description with block scalars (`|` or `>`), anchors or tags is refused with its line, so the file has to be written in the subset or converted to JSON.
- **Only OpenAPI 3.0 and 3.1.** Swagger 2.0 is refused, and so is any other version. A 3.1 description is read with the current JSON Schema keywords for the keywords it uses; nothing in a 3.1 only feature (`type` as an array, `webhooks`, `pathItems`) is needed beyond `type` as an array, which is read.
- **OWASP has more guidance than a description can show.** The tool checks the items of the OWASP pages that a description can show, and lists them in [method.md](method.md). Logging, patching, CORS, error messages, hardening and the other items of the pages are out of reach.

## What the tool does not check

- Whether the API is vulnerable. It does not call the API, scan a host, fuzz an operation or read the source.
- The correctness of the OpenAPI document itself. It is not a validator; a document with a wrong structure is read as far as it goes. Use a validator for that.
- Sensitive properties in responses (the excessive data exposure half of API3), the strength of an authentication flow, tokens, passwords, and the contents of any scheme's flows.
- The contents of the other siblings' territory: tenant identifiers, operation ids and error responses (see api-product-check), and changes between two versions of a description (see api-break-check).

## Size and depth

- A file over 10 MB is refused, from the size of the open file.
- JSON nested deeper than 64 levels, or with more than 200,000 values, is refused. YAML nested deeper than 64 levels, with more than 100,000 lines or a line over 4,000 characters, is refused.
- More than 5,000 operations is refused.
- A chain of `$ref` longer than 32 is a cycle. Schemas nested deeper than 48 levels, or more than 300,000 schema visits, end the walk with `limit-reached`.
- Text from the description shown in a report is cut to a fixed length: 400 characters for a pointer, 200 for a subject or an operation, 700 for a message and 500 for a fix.

Every limit is reported, as a finding or as a refusal with exit code 2, so a cut is never silent.
