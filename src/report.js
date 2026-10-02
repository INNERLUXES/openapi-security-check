// Report formats: text for a terminal, Markdown for a pull request or job summary, JSON for other tools, CSV
// for a spreadsheet. Findings are grouped by the OWASP API Security Top 10 (2023) risk they relate to.

import { CATEGORIES } from './data.js';

function plural(count, one, many = `${one}s`) {
  return `${count.toLocaleString('en-US')} ${count === 1 ? one : many}`;
}

function countsLine(c) {
  return `${c.error} error, ${c.warning} warning, ${c.info} info`;
}

function gateLine(r) {
  return r.gate.pass ? `GATE: PASS (--fail-on ${r.gate.failOn})` : `GATE: FAIL - ${r.gate.reason}`;
}

const NOT_A_RISK = 'Reading the description (not an OWASP risk)';

// The findings of one risk, or the findings that are not about a risk when category is null.
function groups(r) {
  const out = [];
  const tool = r.findings.filter((f) => f.category === null);
  if (tool.length) out.push({ title: NOT_A_RISK, source: null, findings: tool });
  for (const c of CATEGORIES) {
    const own = r.findings.filter((f) => f.category && f.category.id === c.id);
    if (own.length) out.push({ title: `${c.id} ${c.name}`, source: c.source, findings: own });
  }
  return out;
}

function documentLine(r) {
  const d = r.document;
  return `OpenAPI ${d.openapi}, ${d.format}${d.title ? `, "${d.title}"` : ''}: ${plural(d.operations, 'operation')}, ${plural(d.servers, 'server')}, ${plural(d.securitySchemes, 'security scheme')}`;
}

export function toText(r) {
  const lines = [`openapi-security-check: ${r.document.path}`, documentLine(r), `edition: ${r.edition}`, 'risks:'];
  for (const c of r.categories) lines.push(`  ${c.id.padEnd(10)}  ${c.name.padEnd(48)}  ${c.result.padEnd(11)}  ${c.result === 'not checked' ? 'the description cannot show it' : c.detail}`);
  lines.push(`findings: ${countsLine(r.counts)}`);
  if (!r.findings.length) lines.push('', 'no findings');
  for (const g of groups(r)) {
    lines.push('', `${g.title} (${plural(g.findings.length, 'finding')})`);
    if (g.source) lines.push(`  ${g.source}`);
    for (const f of g.findings) {
      lines.push('', `  ${f.severity.toUpperCase().padEnd(7)}  ${f.id}  ${f.pointer}  line ${f.line}`);
      if (f.operation) lines.push(`           operation: ${f.operation}`);
      lines.push(`           ${f.message}`, `           fix: ${f.fix}`);
    }
  }
  if (r.notes.length) lines.push('');
  for (const note of r.notes) lines.push(`note: ${note}`);
  lines.push('', gateLine(r));
  return lines.join('\n') + '\n';
}

// A Markdown table cell: backslashes and pipes escaped, line breaks flattened, and <, > and & written as
// entities, so text from the input file cannot break the table or be read as HTML.
export function mdCell(t) {
  return String(t)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n|\r/g, ' ');
}

export function toMarkdown(r) {
  const lines = [`## openapi-security-check: ${countsLine(r.counts)}`, '', `Document: \`${mdCell(r.document.path).replace(/`/g, "'")}\`. ${mdCell(documentLine(r))}. Edition: ${mdCell(r.edition)}.`];
  lines.push('', '| Risk | Result | Detail |', '| --- | --- | --- |');
  for (const c of r.categories) lines.push(`| [${mdCell(c.id)}](${c.source}) ${mdCell(c.name)} | ${c.result === 'fail' ? '**fail**' : mdCell(c.result)} | ${mdCell(c.detail)} |`);
  if (!r.findings.length) lines.push('', 'No findings.');
  for (const g of groups(r)) {
    lines.push('', `### ${mdCell(g.title)}`, '', '| Severity | Check | Where | Message | Fix |', '| --- | --- | --- | --- | --- |');
    for (const f of g.findings) lines.push(`| ${f.severity} | ${mdCell(f.id)} | ${mdCell(`${f.pointer} (line ${f.line})${f.operation ? `, ${f.operation}` : ''}`)} | ${mdCell(f.message)} | ${mdCell(f.fix)} |`);
  }
  if (r.notes.length) lines.push('');
  for (const note of r.notes) lines.push(`- ${mdCell(note)}`);
  lines.push('', r.gate.pass ? `**Gate passed** (--fail-on ${r.gate.failOn}).` : `**Gate failed:** ${mdCell(r.gate.reason)}.`);
  return lines.join('\n') + '\n';
}

export function toJson(r) {
  return JSON.stringify(r, null, 2) + '\n';
}

// RFC 4180 quoting, and a leading quote on cells a spreadsheet would read as a formula.
export function csvCell(value) {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// One row per finding. The category columns are empty for a finding that is not about a risk.
export function toCsv(r) {
  const rows = [['severity', 'category_id', 'category_name', 'id', 'pointer', 'line', 'operation', 'subject', 'message', 'fix']];
  for (const f of r.findings) rows.push([f.severity, f.category ? f.category.id : '', f.category ? f.category.name : '', f.id, f.pointer, String(f.line), f.operation ?? '', f.subject, f.message, f.fix]);
  return rows.map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
