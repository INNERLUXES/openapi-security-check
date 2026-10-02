import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CATEGORIES, LIMITS, USAGE, VERSION, checkText, csvCell, main, mdCell, parseArgs, toCsv, toJson, toMarkdown, toText } from '../src/index.js';
import { base, check, cli, json, op, run, withPaths } from './helpers.js';

const root = resolve(fileURLToPath(import.meta.url), '..', '..');
const BAD = withPaths({ '/things': { get: op({ security: [] }) }, '/things/{id}': { delete: { security: [{ ApiAuth: [] }], responses: { 204: { description: 'gone' } } } } }, { servers: [{ url: 'http://api.example.test' }] });

test('the report has the ten risks in order, with the 2023 IDs, and "not checked" for the two that a description cannot show', () => {
  const r = check(withPaths({ '/things': { get: op() } }));
  assert.deepEqual(r.categories.map((c) => c.id), CATEGORIES.map((c) => c.id));
  assert.deepEqual(r.categories.map((c) => c.name), CATEGORIES.map((c) => c.name));
  assert.equal(r.categories[5].result, 'not checked');
  assert.equal(r.categories[9].result, 'not checked');
  assert.equal(r.categories[0].result, 'pass');
  assert.equal(r.edition, 'OWASP API Security Top 10 2023');
});

test('the result of a risk is the worst of its findings: fail for an error, warn for a warning, info for info', () => {
  const r = check(BAD);
  const by = Object.fromEntries(r.categories.map((c) => [c.id, c.result]));
  assert.equal(by['API8:2023'], 'fail');
  assert.equal(by['API2:2023'], 'warn');
  assert.equal(by['API1:2023'], 'warn');
  const info = check(withPaths({ '/old': { get: op({ deprecated: true }) } }));
  assert.equal(info.categories[8].result, 'info');
});

test('findings are ordered: errors first, then by risk number, then by rule, then by pointer', () => {
  const r = check(BAD);
  const rank = { error: 0, warning: 1, info: 2 };
  for (let i = 1; i < r.findings.length; i += 1) {
    const a = r.findings[i - 1];
    const b = r.findings[i];
    assert.ok(rank[a.severity] <= rank[b.severity], `${a.id} before ${b.id}`);
    if (a.severity === b.severity) assert.ok(a.check <= b.check, `${a.id} before ${b.id}`);
  }
  assert.equal(r.findings[0].severity, 'error');
});

test('text: findings are grouped under the risk they relate to, with the page of the risk', () => {
  const text = toText(check(BAD));
  assert.match(text, /^openapi-security-check: description.json\n/);
  assert.match(text, /\nAPI8:2023 Security Misconfiguration \(1 finding\)\n {2}https:\/\/owasp\.org\/API-Security\/editions\/2023\/en\/0xa8-security-misconfiguration\/\n/);
  assert.match(text, /\nAPI2:2023 Broken Authentication \(\d+ findings?\)\n/);
  assert.match(text, /\n {2}ERROR {4}http-server {2}#\/servers\/0\/url {2}line \d+\n/);
  assert.match(text, /\nGATE: FAIL - 1 error\n$/);
  assert.ok(text.indexOf('API1:2023 Broken Object') < text.indexOf('API8:2023 Security Misconfiguration ('));
});

test('text: a finding that is not about a risk is grouped apart, and nothing is printed for a clean description', () => {
  const remote = toText(check(withPaths({ '/things': { $ref: 'other.yaml#/x' } })));
  assert.match(remote, /\nReading the description \(not an OWASP risk\) \(1 finding\)\n/);
  const clean = toText(check(withPaths({ '/things': { get: op() } })));
  assert.match(clean, /\nno findings\n/);
  assert.match(clean, /GATE: PASS \(--fail-on error\)\n$/);
});

test('markdown: a table per risk, with the risk list linked to the OWASP pages, and input text escaped', () => {
  const md = toMarkdown(check(withPaths({ '/a|b<c>': { get: op({ security: [] }) } })));
  assert.match(md, /^## openapi-security-check: 0 error, 1 warning, 0 info\n/);
  assert.match(md, /\| \[API2:2023\]\(https:\/\/owasp\.org\/API-Security\/editions\/2023\/en\/0xa2-broken-authentication\/\) Broken Authentication \|/);
  assert.match(md, /\n### API2:2023 Broken Authentication\n/);
  assert.ok(md.includes('a\\|b&lt;c&gt;'));
  assert.ok(!md.includes('<c>'));
  assert.match(md, /\*\*Gate passed\*\* \(--fail-on error\)\.\n$/);
  assert.equal(mdCell('a|b\\c\nd&e'), 'a\\|b\\\\c d&amp;e');
});

test('json: the whole report with the risk, the pointer, the severity and the fix of every finding', () => {
  const r = JSON.parse(toJson(check(BAD, { version: '9.9.9' })));
  assert.equal(r.tool, 'openapi-security-check');
  assert.equal(r.version, '9.9.9');
  assert.equal(r.categories.length, 10);
  const f = r.findings.find((x) => x.id === 'http-server');
  assert.deepEqual(Object.keys(f).sort(), ['category', 'check', 'fix', 'id', 'line', 'message', 'operation', 'pointer', 'severity', 'source', 'subject']);
  assert.deepEqual(f.category, { id: 'API8:2023', name: 'Security Misconfiguration' });
  assert.equal(r.gate.pass, false);
  assert.equal(r.document.operations, 2);
});

test('csv: one row per finding, RFC 4180 quoting with CRLF, and a leading quote on a cell that a spreadsheet would run', () => {
  const csv = toCsv(check(BAD));
  const lines = csv.split('\r\n');
  assert.equal(lines[0], 'severity,category_id,category_name,id,pointer,line,operation,subject,message,fix');
  assert.ok(lines.length > 3 && lines.at(-1) === '');
  assert.ok(csv.includes('error,API8:2023,Security Misconfiguration,http-server,#/servers/0/url,'));
  assert.equal(csvCell('=SUM(A1)'), "'=SUM(A1)");
  assert.equal(csvCell('+1'), "'+1");
  assert.equal(csvCell('say "hi", ok'), '"say ""hi"", ok"');
  const remote = toCsv(check(withPaths({ '/things': { $ref: 'other.yaml#/x' } })));
  assert.ok(remote.split('\r\n')[1].startsWith('error,,,ref-remote,'));
});

test('--fail-on: errors fail by default, warnings fail with --fail-on warning, info never fails', () => {
  const warn = withPaths({ '/things': { get: op({ security: [] }) } });
  assert.equal(check(warn).gate.pass, true);
  assert.equal(check(warn, { failOn: 'warning' }).gate.pass, false);
  assert.match(check(warn, { failOn: 'warning' }).gate.reason, /1 warning/);
  const info = withPaths({ '/old': { get: op({ deprecated: true }) } });
  assert.equal(check(info, { failOn: 'warning' }).gate.pass, true);
});

test('cli: exit code 0 for a clean description, 1 for a finding at the level, 2 for a usage or input error', async () => {
  const clean = await run({ 'a.json': withPaths({ '/things': { get: op() } }) }, ['a.json']);
  assert.equal(clean.code, 0);
  assert.match(clean.out, /GATE: PASS/);
  const bad = await run({ 'a.json': BAD }, ['a.json']);
  assert.equal(bad.code, 1);
  const warnOnly = await run({ 'a.json': withPaths({ '/things': { get: op({ security: [] }) } }) }, ['a.json']);
  assert.equal(warnOnly.code, 0);
  assert.equal((await run({ 'a.json': withPaths({ '/things': { get: op({ security: [] }) } }) }, ['a.json', '--fail-on', 'warning'])).code, 1);
  const missing = await run({}, ['nope.json']);
  assert.equal(missing.code, 2);
  assert.match(missing.err, /nope\.json: no such file/);
});

test('cli: usage errors give exit code 2 and the usage text', async () => {
  for (const args of [[], ['--format', 'xml', 'a.json'], ['a.json', '--fail-on', 'info'], ['a.json', '--bogus'], ['a.json', 'b.json'], ['-'], ['https://example.test/a.json'], ['a.json', '--format'], ['a.json', '--fail-on', '--format']]) {
    const r = await cli(args);
    assert.equal(r.code, 2, args.join(' '));
    assert.match(r.err, /Usage: openapi-security-check/);
  }
  assert.match((await cli(['-'])).err, /standard input is not supported/);
  assert.match((await cli(['https://example.test/a.json'])).err, /never fetches a URL/);
  assert.match((await cli(['a.json', '--fail-on', 'info'])).err, /takes error or warning, not info/);
});

test('cli: --help and --version', async () => {
  const help = await cli(['--help']);
  assert.equal(help.code, 0);
  assert.equal(help.out, USAGE);
  assert.match(USAGE, /x-public: true/);
  assert.match(USAGE, /Exit codes: 0 no finding/);
  const version = await cli(['--version']);
  assert.equal(version.out, `${VERSION}\n`);
  assert.equal(JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')).version, VERSION);
  assert.equal(parseArgs(['a.json', '--format', 'csv']).format, 'csv');
});

test('cli: a file that is not usable gives exit code 2 with the reason and a path relative to the folder', async () => {
  const notJson = await run({ 'a.json': '{"openapi": ' }, ['a.json']);
  assert.equal(notJson.code, 2);
  assert.match(notJson.err, /^openapi-security-check: a\.json: the JSON: line 1:/);
  const yaml = await run({ 'sub/a.yaml': 'openapi: "3.0.3"\ninfo:\n  description: >\n    x\n' }, ['sub/a.yaml']);
  assert.equal(yaml.code, 2);
  assert.match(yaml.err, /sub\/a\.yaml: the YAML: line 3:/);
  const folder = await run({ 'sub/a.json': '{}' }, ['sub']);
  assert.equal(folder.code, 2);
  assert.match(folder.err, /sub: a folder, not a file/);
  const big = await run({ 'a.json': json(base()) }, ['a.json'], { ...LIMITS, maxFileBytes: 20 });
  assert.equal(big.code, 2);
  assert.match(big.err, /bytes is over the 20 byte limit/);
  const swagger = await run({ 'a.json': { swagger: '2.0' } }, ['a.json']);
  assert.equal(swagger.code, 2);
  assert.match(swagger.err, /Swagger 2.0 is not supported/);
});

test('cli: every output format works from the command line and the paths shown use forward slashes', async () => {
  for (const format of ['text', 'markdown', 'json', 'csv']) {
    const r = await run({ 'dir/a.json': BAD }, ['dir/a.json', '--format', format]);
    assert.equal(r.code, 1, format);
    assert.ok(r.out.includes('dir/a.json') || format === 'csv', format);
    assert.ok(!r.out.includes('dir\\a.json'), format);
  }
});

test('the same description as JSON and as YAML gives the same findings', () => {
  const doc = withPaths({ '/things': { get: op({ security: [] }) } });
  const asYaml = `openapi: "3.0.3"
info:
  title: Demo
  version: "1.0.0"
servers:
  - url: "https://api.example.test/v1"
security:
  - ApiAuth:
      - read
paths:
  /things:
    get:
      security: []
      responses:
        "200":
          description: ok
        "429":
          description: slow down
components:
  securitySchemes:
    ApiAuth:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: "https://auth.example.test/token"
          scopes:
            read: Read
`;
  const a = checkText(JSON.stringify(doc), 'a.json');
  const b = checkText(asYaml, 'a.yaml');
  assert.deepEqual(a.findings.map((f) => [f.id, f.pointer]), b.findings.map((f) => [f.id, f.pointer]));
  assert.equal(b.findings.length, 1);
});

test('examples: the failing example has the errors the README names, and the fixed one passes with --fail-on warning', async () => {
  let out = '';
  const failing = await main([resolve(root, 'examples/parcel-tracking.json')], { out: (t) => { out += t; }, err: () => {} }, LIMITS, root);
  assert.equal(failing, 1);
  assert.match(out, /findings: 3 error, 20 warning, 3 info/);
  for (const file of ['parcel-tracking-fixed.json', 'parcel-tracking-fixed.yaml']) {
    let fixedOut = '';
    const code = await main([resolve(root, 'examples', file), '--fail-on', 'warning'], { out: (t) => { fixedOut += t; }, err: () => {} }, LIMITS, root);
    assert.equal(code, 0, file);
    assert.match(fixedOut, /findings: 0 error, 0 warning, 0 info/);
  }
});

test('examples: the files in examples/output are what the tool prints now', async () => {
  for (const [format, name] of [['text', 'parcel-tracking.txt'], ['markdown', 'parcel-tracking.md'], ['json', 'parcel-tracking.json'], ['csv', 'parcel-tracking.csv']]) {
    let out = '';
    await main([resolve(root, 'examples/parcel-tracking.json'), '--format', format], { out: (t) => { out += t; }, err: () => {} }, LIMITS, root);
    const saved = await readFile(resolve(root, 'examples/output', name), 'utf8');
    assert.equal(saved, out, name);
  }
});
