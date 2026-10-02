// Runs the README examples, checks that they report what the README shows, and writes the reports of the failing
// example description to examples/output. CI runs it and then fails if those files changed, so the example output
// in the repository is always the real output.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, LIMITS } from '../src/index.js';

const root = resolve(fileURLToPath(import.meta.url), '..', '..');

// Runs the tool on files of the repository; paths in the report are relative to the repository.
async function run(argv) {
  let out = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => process.stderr.write(t) }, LIMITS, root);
  return { code, out };
}

const problems = [];
function expect(name, result, code, expected, unwanted) {
  const missing = expected.filter((e) => !result.out.includes(e));
  const wrong = unwanted.filter((e) => result.out.includes(e));
  if (result.code !== code || missing.length || wrong.length) {
    problems.push(`${name}: unexpected report (exit code ${result.code}, expected ${code}; missing: ${missing.join(' / ') || 'none'}; should not appear: ${wrong.join(' / ') || 'none'})`);
  }
}

const failing = await run([resolve(root, 'examples/parcel-tracking.json')]);
process.stdout.write(failing.out);
expect('failing description', failing, 1, [
  'openapi-security-check: examples/parcel-tracking.json',
  'findings: 3 error, 20 warning, 3 info',
  'ERROR    apikey-in-query  #/components/securitySchemes/LegacyKey/in  line 126',
  'ERROR    http-server  #/servers/1/url  line 10',
  'ERROR    basic-over-http  #/components/securitySchemes/BasicAuth  line 127',
  'WARNING  security-disabled  #/paths/~1status/get/security  line 109',
  'WARNING  admin-same-scopes  #/paths/~1admin~1parcels~1export/get  line 78',
  'WARNING  readonly-in-request  #/components/schemas/Parcel/properties/id  line 134',
  'WARNING  list-without-paging  #/paths/~1parcels/get  line 15',
  'WARNING  url-input  #/components/schemas/Parcel/properties/callbackUrl  line 138',
  'WARNING  multiple-versions',
  'WARNING  non-production-server  #/servers/1/url  line 10',
  'INFO     deprecated-operation',
  'API6:2023   Unrestricted Access to Sensitive Business Flows   not checked',
  'GATE: FAIL - 3 errors'
], ['GATE: PASS', 'Sample Recipient']);

process.stdout.write('\n');
const fixed = await run([resolve(root, 'examples/parcel-tracking-fixed.json'), '--fail-on', 'warning']);
process.stdout.write(fixed.out);
expect('fixed description with --fail-on warning', fixed, 0, [
  'openapi-security-check: examples/parcel-tracking-fixed.json',
  'findings: 0 error, 0 warning, 0 info',
  'no findings',
  'GATE: PASS (--fail-on warning)'
], ['ERROR', 'WARNING']);

// The same description written as YAML gives the same report, apart from the file name and the format.
const yaml = await run([resolve(root, 'examples/parcel-tracking-fixed.yaml'), '--fail-on', 'warning']);
const same = (t) => t.replace('parcel-tracking-fixed.json', 'parcel-tracking-fixed.yaml').replace('3.0.3, json,', '3.0.3, yaml,');
if (yaml.code !== 0 || yaml.out !== same(fixed.out)) problems.push('the YAML version of the fixed description does not give the same report as the JSON version');

// The README shows the runs as they are printed.
const readme = (await readFile(resolve(root, 'README.md'), 'utf8')).split('\r\n').join('\n');
if (!readme.includes(failing.out)) problems.push('README: the sample output of the failing description differs from a real run');
if (!readme.includes(fixed.out)) problems.push('README: the sample output of the fixed description differs from a real run');

// The same description in the other formats, kept as examples of what each one looks like.
await mkdir(resolve(root, 'examples/output'), { recursive: true });
await writeFile(resolve(root, 'examples/output/parcel-tracking.txt'), failing.out);
for (const [format, name] of [['markdown', 'parcel-tracking.md'], ['json', 'parcel-tracking.json'], ['csv', 'parcel-tracking.csv']]) {
  const r = await run([resolve(root, 'examples/parcel-tracking.json'), '--format', format]);
  if (r.code !== 1) problems.push(`${format}: exit code ${r.code}, expected 1`);
  await writeFile(resolve(root, 'examples/output', name), r.out);
}

if (problems.length) {
  for (const p of problems) console.error(`example: ${p}`);
  process.exit(1);
}
