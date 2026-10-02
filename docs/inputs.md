# Inputs

The tool takes one argument: the path of one OpenAPI description. It reads that file and nothing else. It follows no `$ref` that leaves the file and opens nothing that a file names. A symbolic link given as the argument is followed, because the person who runs the tool named it; the file it leads to must be a regular file.

## The file

- OpenAPI 3.0 or 3.1: the `openapi` field must be a string that starts with `3.0` or `3.1`. A Swagger 2.0 file (`swagger: "2.0"`) is refused with a message that says to convert it first. Any other version is refused.
- JSON or YAML. The format is chosen from the file name (`.json`, `.yaml`, `.yml`); for any other name the tool reads a file that starts with `{` or `[` as JSON and anything else as YAML.
- A file over 10 MB is refused from the size of the open file, before it is read. A folder, a pipe or a device is refused.
- A description in several files has to be bundled into one first. A `$ref` that does not start with `#/` is reported (`ref-remote`) and never opened.

## What is read from the description

| Field | Used for |
| --- | --- |
| `openapi` | the version check |
| `info.title` | shown in the report (cleaned and cut) |
| `servers`, on the top level, a path item and an operation: `url`, `description`, `variables` with `default` and `enum` | `http-server`, `basic-over-http`, `multiple-versions`, `non-production-server` |
| `security` on the top level and on an operation | `security-missing`, `security-disabled`, `security-optional`, `object-id-review`, `admin-same-scopes` |
| `components.securitySchemes`: `type`, `in`, `scheme` | `apikey-in-query`, `basic-over-http` |
| `paths`, each path item and its `get`, `put`, `post`, `delete`, `options`, `head`, `patch`, `trace`; `parameters` of a path item and of an operation | every check on operations |
| an operation's `parameters` (`name`, `in`, `schema`, `content`), `requestBody` (`content` and its `schema`), `responses` (the codes and the first 2xx response's `content`), `deprecated` | API3, API4, API7, API9 |
| schemas: `type`, `properties`, `items`, `allOf`, `anyOf`, `oneOf`, `additionalProperties`, `unevaluatedProperties`, `enum`, `const`, `format`, `readOnly`, `maxItems`, `maxLength` | API3, API4, API7 |
| the extensions `x-public` and `x-admin` | see below |

Not read: `webhooks` and `callbacks` (they are counted and named in a note), `examples`, `example`, `default` values, `description` texts, `externalDocs`, `tags`, `links`, `discriminator`, `xml`, `encoding`, and the `exclusiveMinimum` family. The 3.0 keyword `nullable` is not needed for any check.

## The two extensions

The specification says that an extension field starts with `x-` and that the names that start with `x-oai-` and `x-oas-` are reserved. Neither name below is defined by OWASP or by the OpenAPI Initiative; they are the tool's own.

- `x-public: true` on an operation that also has `security: []` marks the operation as **public on purpose**. It is not reported, and a note counts it. The value must be the boolean `true`. On an operation without the empty array it has no effect.
- `x-admin: true` on an operation or on its path item marks it as administrative for `admin-same-scopes`, whatever its path is.

## `$ref`

Only a `$ref` that starts with `#/` is followed, through objects and arrays, with `~1` and `~0` and `%XX` decoded. A chain of `$ref` longer than 32 is treated as a cycle. A schema that is reached again while it is being walked is checked once (`ref-cycle`). A `$ref` inside an `example`, `default`, `const`, `enum` or `value` is data and is not a reference; a property that happens to be called `default` is still read as a property.

## JSON

The JSON reader accepts the JSON of RFC 8259 and nothing more: no comments, no trailing commas, no single quotes, no duplicate keys in one object. A byte order mark at the start is skipped. Nesting deeper than 64 levels, or more than 200,000 values, is refused. A key such as `__proto__` is only a name.

## The YAML subset

The YAML reader accepts what most descriptions are written with, and refuses everything else with the line, never guessing.

Accepted:

- block mappings and block sequences, indented with spaces
- plain, single-quoted and double-quoted scalars (a double-quoted string may use `\"`, `\\`, `\/`, `\n`, `\t`, `\r`, `\0`, `\b` and `\f`)
- comments that start with `#` after a space or at the start of a line
- flow sequences of scalars on one line (`[a, b]`, `[]`) and the empty flow mapping `{}`
- one document, with or without a leading `---`
- keys with `/`, `{`, `}` and `:` inside, such as `/parcels/{parcelId}:` and `"parcels:read":`

Refused, with the line:

- anchors, aliases, tags (`&`, `*`, `!`), directives, merge keys (`<<`)
- block scalars (`|` and `>`): a multi-line `description` has to be written as one quoted line, or the file converted to JSON
- flow mappings with content (`{a: 1}`), and a flow sequence that is split over lines or nested
- tabs in the indentation, more than one document, a key given twice in one mapping
- more than 100,000 lines, a line over 4,000 characters, nesting deeper than 64 levels

A scalar that looks like a number is a number (`200`, `1.5`), `true`, `false`, `null` and `~` are what they say, and a version such as `3.0.3` is a string. Response codes are best quoted (`"200"`), as the specification asks, but an unquoted `200:` key is read as the key `200`.
