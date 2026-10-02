# Security

## Reporting a problem

Write to info@innerluxes.dev with the subject line "openapi-security-check security", or use private vulnerability reporting on this repository. Please do not open a public issue for a vulnerability.

Include a small made-up OpenAPI description that shows the problem, what you expected and what happened. Use made-up API names, and no real keys, tokens, internal addresses or customer data.

## Scope

In scope:

- an input that makes the tool open a network connection, open a file other than the one it was given, or run a program
- an input that makes the tool print a value of the description that it is documented not to print: an example, a default, an enum value, a description text or a server address
- a description that makes a reader accept something its documented format does not allow
- an input that makes the tool hang, take very long, or use unbounded memory or stack, such as deep nesting, very many values, a very long string or path, a schema that contains itself, a very long chain of references, or a path that is not a regular file
- text from a path, a name, a title or a pointer that breaks a Markdown table, injects a formula into a CSV report, or rewrites the terminal through control or direction characters
- a key such as `__proto__` that changes how objects behave inside the tool
- a finding that docs/method.md says is reported, for an input the tool accepts, that the report leaves out, or a risk reported as passed that docs/method.md says is `not checked`

Out of scope: whether the API that a description describes is vulnerable (docs/limits.md lists what a description cannot show), the OWASP pages and the specifications the tool follows, and how your pipeline stores the reports.

Read [docs/threat-model.md](docs/threat-model.md) for the rest.
