# 1. Read the description, not the running API

## Context

The tool needs to say what an API shows about the risks of the OWASP API Security Top 10 before the API is used. There are richer ways to know whether an API is vulnerable: call it with another user's identifiers, send it oversized bodies, point its URL fields at an internal address, read its source. Each of them needs a running service, credentials, test data and permission to attack it, and the answer comes when the cost of a change is already high. The people who need the answer most often need it earlier: when the description changes in a pull request, in a pipeline with no access to the service, before a partner is given the document, or in a review of an API that comes from an agency or a vendor.

A description does not say everything. A gateway can enforce a rate limit that the description does not mention, a server can check the owner of every object that the description gives no scope for, and a field that looks like a URL can be one that the server never fetches. A check that treated the absence of a gap in the description as proof of a safe API would be wrong in the way that matters most. And the reverse is true: a gap in the description is not proof of a vulnerable API.

## Decision

The tool reads one OpenAPI description as data. It reads the risk names, the field names and the keywords from official pages that are saved with their addresses, and a test compares the code with the saved text. It never calls the API, never fetches a referenced file, and never runs a program.

Every check says what it can and cannot see. A finding that the description cannot settle (an object identifier, an administrative path, a field that takes a URL) is worded as a review item and says that it does not prove the risk. The two risks that a description cannot show, unrestricted access to sensitive business flows and unsafe consumption of APIs, are reported as not checked and never as passed. A part of the description that the tool could not read (a reference to another file, a reference that points to nothing, a walk that hit a limit) is an error, so the gate does not pass a description that was only partly read. Findings carry the JSON pointer and the line, and never a value from the description.

An operation that is public on purpose is made visible by an extension that the tool documents (`x-public: true` with an empty security array), so that a deliberate choice and an oversight look different in the report.

## Consequences

The check runs in a second, on Linux, macOS or Windows, with only Node, no account and no network access, and no input can make it run code or reach out to a host. The same file gives the same report, so it can run on every pull request and gate a release. The cost is that it sees what the file says, not what the API does: many review items are reported that turn out to be fine, and a vulnerable server behind a clean description is not found. The tool says what it left out, lists its limits in docs/limits.md, and leaves the final answer to the people who know the service. It does not repeat the work of the neighbouring tools that review a product description for its customers (tenants, operation ids, error responses) or compare two versions of a description for breaking changes.
