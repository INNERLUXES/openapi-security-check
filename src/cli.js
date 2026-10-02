// Command line: openapi-security-check <openapi-file> [options]

import { readFileSync } from 'node:fs';
import { FINDINGS, LIMITS, checkFile } from './check.js';
import { EXTENSIONS, OWASP_INDEX_URL } from './data.js';
import { toText, toMarkdown, toJson, toCsv } from './report.js';

export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const FORMATS = { text: toText, markdown: toMarkdown, json: toJson, csv: toCsv };
const THRESHOLDS = ['error', 'warning'];

export const USAGE = `Usage: openapi-security-check <openapi-file> [options]

Reads one OpenAPI 3.0 or 3.1 description (JSON, or the YAML subset of docs/inputs.md) and reports what the
description itself shows, grouped by the risk of the OWASP API Security Top 10 (2023 edition) it relates to
(${OWASP_INDEX_URL}). A local $ref is followed; a $ref to another
file or an address is never fetched and is reported. It never prints an example value or a server address, opens
no network connection and runs no program.

Options:
  --format <name>     text, markdown, json or csv (default: text)
  --fail-on <level>   exit with 1 when a finding is at this level or above: error or warning
                      (default: error); info never fails the run
  --help              show this text
  --version           show the version

An operation that is public on purpose has an empty security array and ${EXTENSIONS.public}: true.

Checks: ${FINDINGS.map((f) => f.id).join(', ')}

Exit codes: 0 no finding at the --fail-on level, 1 such a finding, 2 usage or input error.
`;

export function parseArgs(argv) {
  const o = { file: null, format: 'text', failOn: 'error', help: false, version: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`${a} needs a value`);
      i += 1;
      return v;
    };
    if (a === '--help' || a === '-h') o.help = true;
    else if (a === '--version' || a === '-v') o.version = true;
    else if (a === '--format') o.format = next();
    else if (a === '--fail-on') o.failOn = next();
    else if (a === '-') throw new Error('reading from standard input is not supported; give the path of the file');
    else if (a.startsWith('-')) throw new Error(`unknown argument ${a}`);
    else if (o.file !== null) throw new Error(`give one file, not ${a} as well`);
    else o.file = a;
  }
  if (!o.help && !o.version) {
    if (o.file === null) throw new Error('give the path of the OpenAPI file');
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(o.file)) throw new Error('give a local path; the tool never fetches a URL');
    if (!Object.hasOwn(FORMATS, o.format)) throw new Error(`unknown format ${o.format} (text, markdown, json or csv)`);
    if (!THRESHOLDS.includes(o.failOn)) throw new Error(`--fail-on takes error or warning, not ${o.failOn}`);
  }
  return o;
}

function clean(text) {
  return String(text).replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' ');
}

// Exit code: 0 no finding at the --fail-on level, 1 such a finding, 2 usage or input error.
export async function main(argv, io = { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t) }, limits = LIMITS, base = process.cwd()) {
  let o;
  try {
    o = parseArgs(argv);
  } catch (error) {
    io.err(`openapi-security-check: ${clean(error.message)}\n\n${USAGE}`);
    return 2;
  }
  if (o.help) {
    io.out(USAGE);
    return 0;
  }
  if (o.version) {
    io.out(`${VERSION}\n`);
    return 0;
  }
  let report;
  try {
    report = await checkFile(o.file, { failOn: o.failOn, version: VERSION, limits, base });
  } catch (error) {
    io.err(`openapi-security-check: ${clean(error.message)}\n`);
    return 2;
  }
  io.out(FORMATS[o.format](report));
  return report.gate.pass ? 0 : 1;
}
