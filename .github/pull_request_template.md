## What changes

<!-- One or two sentences. -->

## Checks

- [ ] `npm test`, `npm run check` and `npm run example` pass, and the files under `examples/output` are the ones `npm run example` wrote
- [ ] A change to a check or a reader is described in docs/method.md, says what the check can and cannot see, and has a test with the description written inline and a near miss that must not match
- [ ] A change to a risk name, a field name or a keyword follows the official pages: the new page text is saved in research/sources, `src/data.js` and docs/rules-and-sources.md match it, and nothing was added from memory
- [ ] Text from the input goes through `safeText`, and no example value, default, enum value or server address is copied into a finding
- [ ] The tool still fetches nothing, opens no connection, runs no program, and follows no `$ref` that leaves the file
- [ ] A thing the tool cannot see is reported as not checked or as a review item, never as passed or as proven
- [ ] Paths are opened with `path.resolve`, shown relative with forward slashes, and file names are compared exactly, so the result is the same on Linux, macOS and Windows
- [ ] No real secret in fixtures or examples
- [ ] The commit messages of this pull request follow Conventional Commits
