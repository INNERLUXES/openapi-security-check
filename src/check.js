// Reads one OpenAPI description, runs the checks of src/rules.js and returns one report: the ten OWASP API Security
// risks of the 2023 edition with their result, the findings grouped by risk, notes and the gate.
// docs/method.md gives the reason behind every finding. The tool reads the one file it is given and opens no
// connection.

import { resolve } from 'node:path';
import { CATEGORIES, FIELDS } from './data.js';
import { DOC_LIMITS, isObj, parseDocument } from './doc.js';
import { FILE_LIMITS, displayPath, readBounded } from './files.js';
import { FINDINGS, ORDER, RANK, SEVERITIES, meetsThreshold, runRules, safeText } from './rules.js';

export const LIMITS = { ...DOC_LIMITS, ...FILE_LIMITS };
export { FINDINGS, RANK, SEVERITIES, meetsThreshold, safeText };

function compare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function plural(count, one, many = `${one}s`) {
  return `${count.toLocaleString('en-US')} ${count === 1 ? one : many}`;
}

// Builds the report for the text of one description. name is the file name shown and used to choose JSON or YAML.
export function checkText(text, name, { failOn = 'error', version = '0.0.0', limits = LIMITS, path = name } = {}) {
  const parsed = parseDocument(text, name, limits);
  const { findings: all, facts } = runRules(parsed, limits);
  all.sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.check - b.check || ORDER[a.id] - ORDER[b.id] || compare(a.pointer, b.pointer) || compare(a.subject, b.subject));

  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of all) counts[f.severity] += 1;

  const categories = CATEGORIES.map((c) => {
    const own = all.filter((f) => f.check === c.n);
    const worst = own.length ? own.reduce((w, f) => (RANK[f.severity] < RANK[w] ? f.severity : w), 'info') : null;
    let result = !c.checkable ? 'not checked' : worst === 'error' ? 'fail' : worst === 'warning' ? 'warn' : worst === 'info' ? 'info' : 'pass';
    let detail;
    if (!c.checkable) detail = c.reason;
    else if (own.length) detail = [...new Set(own.map((f) => f.id))].map((id) => `${id} x${own.filter((f) => f.id === id).length}`).join(', ');
    else detail = 'no finding';
    return { n: c.n, id: c.id, name: c.name, source: c.source, result, detail: safeText(detail, 400), findings: own.length };
  });

  const notes = [];
  if (facts.operations === 0) notes.push('No operation was found under paths, so there was nothing to check');
  if (facts.publicOnPurpose.length) notes.push(`${plural(facts.publicOnPurpose.length, 'operation')} marked public on purpose (an empty security array with the x-public marker) ${facts.publicOnPurpose.length === 1 ? 'was' : 'were'} not reported as unprotected`);
  if (facts.webhooks || facts.callbacks) notes.push(`${plural(facts.webhooks, 'webhook')} and ${plural(facts.callbacks, 'callback')} were not read: only the operations under paths are checked`);
  const info = isObj(parsed.data[FIELDS.info]) ? parsed.data[FIELDS.info] : {};

  const failing = all.filter((f) => meetsThreshold(f.severity, failOn));
  const eCount = failing.filter((f) => f.severity === 'error').length;
  const wCount = failing.filter((f) => f.severity === 'warning').length;
  const reason = [eCount ? plural(eCount, 'error') : null, wCount ? plural(wCount, 'warning') : null].filter(Boolean).join(', ');

  return {
    tool: 'openapi-security-check',
    version,
    edition: 'OWASP API Security Top 10 2023',
    document: {
      path: safeText(path, 400),
      openapi: safeText(parsed.openapi, 40),
      format: parsed.format,
      title: typeof info[FIELDS.title] === 'string' ? safeText(info[FIELDS.title], 120) : '',
      operations: facts.operations,
      servers: facts.servers,
      securitySchemes: facts.securitySchemes
    },
    publicOnPurpose: facts.publicOnPurpose,
    categories,
    findings: all,
    notes,
    counts,
    gate: { failOn, pass: failing.length === 0, reason }
  };
}

// Reads the file and builds the report. The path in the report is relative to base, with forward slashes.
export async function checkFile(file, { failOn = 'error', version = '0.0.0', limits = LIMITS, base = process.cwd() } = {}) {
  const full = resolve(base, file);
  let text;
  try {
    text = (await readBounded(full, limits.maxFileBytes)).toString('utf8');
  } catch (error) {
    throw new Error(`${displayPath(full, base)}: ${error.reason ?? error.message}`);
  }
  try {
    return checkText(text, full, { failOn, version, limits, path: displayPath(full, base) });
  } catch (error) {
    throw new Error(`${displayPath(full, base)}: ${error.message}`);
  }
}
