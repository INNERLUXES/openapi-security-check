// Shared test helpers: descriptions built inline, and files written into a temporary folder that is removed after
// the test.

import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { checkText, main } from '../src/index.js';

export async function withFiles(files, fn) {
  const dir = await mkdtemp(resolve(tmpdir(), 'openapi-security-check-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(dirname(resolve(dir, rel)), { recursive: true });
      await writeFile(resolve(dir, rel), content);
    }
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export const json = (value) => `${JSON.stringify(value, null, 2)}\n`;

// A description that has no finding: one https server, an OAuth 2 scheme with the scope "read" at the top level,
// and operations that document a 429 response. Tests change one thing at a time.
export const base = (extra = {}) => ({
  openapi: '3.0.3',
  info: { title: 'Demo', version: '1.0.0' },
  servers: [{ url: 'https://api.example.test/v1' }],
  security: [{ ApiAuth: ['read'] }],
  paths: {},
  components: {
    securitySchemes: {
      ApiAuth: { type: 'oauth2', flows: { clientCredentials: { tokenUrl: 'https://auth.example.test/token', scopes: { read: 'Read', write: 'Write', admin: 'Admin' } } } }
    }
  },
  ...extra
});

// An operation with a 200 and a 429 response.
export const op = (extra = {}) => ({ responses: { 200: { description: 'ok' }, 429: { description: 'slow down' } }, ...extra });

// A description with these paths.
export const withPaths = (paths, extra = {}) => base({ paths, ...extra });

// A request body with this schema.
export const body = (schema) => ({ required: true, content: { 'application/json': { schema } } });

// Checks a description given as an object (written as JSON) or as text.
export function check(doc, options = {}) {
  const text = typeof doc === 'string' ? doc : JSON.stringify(doc);
  return checkText(text, options.name ?? 'description.json', { ...options });
}

export const ids = (report) => report.findings.map((f) => f.id);
export const find = (report, id) => report.findings.filter((f) => f.id === id);

// Writes the files (objects are written as JSON, strings as they are) and runs the command line with these
// arguments (paths relative to the folder).
export async function run(files, args = [], limits) {
  const written = {};
  for (const [name, content] of Object.entries(files)) written[name] = typeof content === 'string' ? content : json(content);
  return withFiles(written, async (dir) => {
    let out = '';
    let err = '';
    const code = await main(args, { out: (t) => { out += t; }, err: (t) => { err += t; } }, limits, dir);
    return { code, out, err };
  });
}

// Runs the command line with exactly these arguments.
export async function cli(argv) {
  let out = '';
  let err = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => { err += t; } });
  return { code, out, err };
}
