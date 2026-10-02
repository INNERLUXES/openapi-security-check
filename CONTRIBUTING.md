# Contributing

Every change goes through a pull request and is reviewed before it is merged. The pipeline runs the tests on Linux, Windows and macOS, the repository checks, CodeQL, and a secure development check of the repository itself.

Commit messages in this repository follow Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, with `!` for a breaking change.

## Changing a check

1. Describe the change in docs/method.md first: what the check reports, its severity, what it can see and what it cannot, and the OWASP page or the specification text it follows. Where the tool makes its own choice (a threshold, a list of names, a severity), say so and say why.
2. Add a test with the description written inline, small enough that the result can be worked out by hand, and a near miss that must not match. Use made-up API names.
3. Text from the input goes through `safeText` before it reaches a finding or a note, so control characters are removed. No value of the description (an example, a default, an enum value, a description text, a server address) goes into a finding.
4. A finding id, once released, keeps its meaning: pipelines and other tools read it from the JSON and CSV reports.
5. A thing the tool cannot see is reported, never passed. A finding that the description cannot settle says that it is a review item.

## Changing the risk names, the field names or the keywords

The names in `src/data.js` come from the pages saved in `research/sources`: the OWASP API Security Top 10 pages, the OpenAPI Specification and the JSON Schema pages. When a page changes, save the new text in `research/sources` (the address on the first line), change `src/data.js` to match, and update docs/rules-and-sources.md. `test/data.test.js` compares the IDs, the names, the field names and the quoted sentences with the saved text, so changing one without the other fails. The code in `src` writes no field name of its own; it takes them from `src/data.js`.

Never add a risk name, a field name or a rule from memory or from a blog post. A new rule needs the official page, opened and saved, and the words of the page that give the name or the sentence.

## Changing the readers

1. For the JSON, YAML and `$ref` readers, add a test for every form you add and one that must be refused. Keep refusing YAML outside the subset of docs/inputs.md and JSON that is not JSON.
2. Keep the size, depth and visit limits, and keep a limit on the length of a string before a pattern runs on it. A pattern must be anchored, with bounded repeats and no nested repetition; add a test with a long near miss.
3. Paths are opened with `path.resolve`, never `path.join`, so an absolute path works on every system. Paths shown in a report are relative, with forward slashes. Do not assume that a backslash is a separator on Linux or macOS.

## Rules for the code

- No runtime dependencies. Node 22 or newer and nothing else.
- The tool reads the file it is given and writes only to the screen. It opens no network connection, runs no program, and never follows a URL or a `$ref` that leaves the file.
- Source files stay ASCII; write any other character in a pattern as a Unicode escape.
- Never commit a real secret, even as a fixture. `npm run check` fails on anything that looks like a credential.
- The README and the documents carry no dates or years. The one exception is the edition year in the name of the OWASP edition and in the risk IDs (API1:2023 to API10:2023); `tools/check.mjs` allows it in those forms only.

## Before you open the pull request

```
npm test
npm run check
npm run example
```
