// The checks. Each one reads the description as data and reports what the description itself shows, grouped by the
// OWASP API Security Top 10 (2023) risk it relates to. docs/method.md gives the reason behind every finding and
// says what each check can and cannot see. Nothing here opens a connection or runs a program, and no value of an
// example, a default or an enum of the description, and no server address, is copied into a finding.

import {
  API_KEY_IN, BASIC_SCHEME, CATEGORIES, EXTENSIONS, FIELDS, FIXED_FORMATS, METHODS, PARAM_IN, SCHEMA, SCHEME_TYPES, SOURCES, TOO_MANY_REQUESTS,
  URL_FORMAT_CONVENTION, URL_FORMATS
} from './data.js';
import { DOC_LIMITS, createResolver, escapeToken, findRefs, isObj, lineOf } from './doc.js';

export const SEVERITIES = ['error', 'warning', 'info'];
export const RANK = { error: 0, warning: 1, info: 2 };

const OAS = SOURCES.find((s) => s.id === 'openapi-3.1.0').url;
const CAT = Object.fromEntries(CATEGORIES.map((c) => [c.n, c]));

// Every finding, in report order within a severity. category is the number of the OWASP risk (0: not a risk of the
// API but a limit of what the tool could read).
export const FINDINGS = [
  { id: 'ref-remote', category: 0, severity: 'error', what: 'A $ref that points to another file or an address: it is not followed, so what is behind it was not checked', source: OAS },
  { id: 'ref-unresolved', category: 0, severity: 'error', what: 'A local $ref that points to nothing', source: OAS },
  { id: 'limit-reached', category: 0, severity: 'error', what: 'The schemas are nested or numerous beyond the limits of the tool, so the rest of them was not checked', source: OAS },
  { id: 'ref-cycle', category: 0, severity: 'info', what: 'A $ref that leads back to itself: the schemas below it were checked once, and the cycle was not followed again', source: OAS },
  { id: 'security-missing', category: 2, severity: 'warning', what: 'An operation has no security requirement, at the top level or on the operation', source: CAT[2].source },
  { id: 'security-disabled', category: 2, severity: 'warning', what: 'An operation sets an empty security array without the x-public marker', source: CAT[2].source },
  { id: 'security-optional', category: 2, severity: 'warning', what: 'The security requirements of an operation include an empty requirement, which makes security optional', source: CAT[2].source },
  { id: 'apikey-in-query', category: 2, severity: 'error', what: 'An apiKey security scheme sends the key in the query string', source: CAT[2].source },
  { id: 'http-server', category: 8, severity: 'error', what: 'A server address starts with http:// and is not a local address', source: CAT[8].source },
  { id: 'basic-over-http', category: 8, severity: 'error', what: 'HTTP basic authentication is used on an operation whose server address is plain http', source: CAT[8].source },
  { id: 'object-id-review', category: 1, severity: 'warning', what: 'An operation takes an object identifier in its path and its security has no scopes, or the same scopes as the list operation (a review item: the description cannot show the object-level check)', source: CAT[1].source },
  { id: 'admin-same-scopes', category: 5, severity: 'warning', what: 'An operation that looks administrative has the same security scopes as ordinary operations', source: CAT[5].source },
  { id: 'mass-assignment-open', category: 3, severity: 'warning', what: 'A request body object accepts properties that it does not list: additionalProperties is true or not set', source: CAT[3].source },
  { id: 'readonly-in-request', category: 3, severity: 'warning', what: 'A property marked readOnly is part of a request body schema', source: CAT[3].source },
  { id: 'list-without-paging', category: 4, severity: 'warning', what: 'A list operation has no paging parameter', source: CAT[4].source },
  { id: 'unbounded-array', category: 4, severity: 'warning', what: 'An array that a client sends has no maxItems', source: CAT[4].source },
  { id: 'no-rate-limit-response', category: 4, severity: 'warning', what: 'An operation documents no 429 response', source: CAT[4].source },
  { id: 'unbounded-string', category: 4, severity: 'info', what: 'A string that a client sends has no maxLength, no enum and no fixed format', source: CAT[4].source },
  { id: 'url-input', category: 7, severity: 'warning', what: 'A parameter or a body field takes a URL (a uri format, or a name such as callbackUrl, webhookUrl or redirect)', source: CAT[7].source },
  { id: 'multiple-versions', category: 9, severity: 'warning', what: 'More than one major version appears in the server addresses and the paths', source: CAT[9].source },
  { id: 'non-production-server', category: 9, severity: 'warning', what: 'A staging, test or development server is listed next to a server that is not one', source: CAT[9].source },
  { id: 'deprecated-operation', category: 9, severity: 'info', what: 'A deprecated operation is still in the description', source: CAT[9].source }
];

const BY_ID = Object.fromEntries(FINDINGS.map((f) => [f.id, f]));
export const ORDER = Object.fromEntries(FINDINGS.map((f, i) => [f.id, i]));

// Text from the input: control, line separator and direction characters replaced by a space, length capped.
export function safeText(value, max = 300) {
  const s = String(value).replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' ');
  return s.length > max ? `${s.slice(0, max - 3)}...` : s;
}

export function meetsThreshold(severity, failOn) {
  return RANK[severity] <= RANK[failOn];
}

const entries = (v) => (isObj(v) ? Object.entries(v) : []);
const str = (v, max = 2000) => (typeof v === 'string' ? v.slice(0, max) : '');
const typesOf = (node) => (Array.isArray(node[SCHEMA.type]) ? node[SCHEMA.type].filter((t) => typeof t === 'string') : typeof node[SCHEMA.type] === 'string' ? [node[SCHEMA.type]] : []);
const label = (op) => `${op.method.toUpperCase()} ${op.path}`;
const sub = (pointer, ...tokens) => `${pointer}${tokens.map((t) => `/${escapeToken(t)}`).join('')}`;

// ---- security requirements ---------------------------------------------------------------------------------------

// The state of a list of security requirements: none (not written, or not a list), empty (an empty list), optional
// (an empty requirement among the alternatives), or set; and the alternatives with their schemes and scopes.
export function readRequirements(raw) {
  if (!Array.isArray(raw)) return { state: 'none', alternatives: [] };
  if (raw.length === 0) return { state: 'empty', alternatives: [] };
  const alternatives = [];
  let optional = false;
  for (const item of raw) {
    if (!isObj(item)) continue;
    const schemes = entries(item).map(([name, scopes]) => ({ name, scopes: Array.isArray(scopes) ? scopes.filter((s) => typeof s === 'string') : [] }));
    if (schemes.length === 0) optional = true;
    else alternatives.push({ schemes });
  }
  return { state: optional ? 'optional' : alternatives.length ? 'set' : 'none', alternatives };
}

// A text that is the same for two operations that ask for the same schemes with the same scopes.
export function signature(req) {
  if (req.state === 'none' || req.state === 'empty') return '(none)';
  const alts = req.alternatives.map((a) => a.schemes.map((s) => `${s.name}[${[...s.scopes].sort().join(',')}]`).sort().join('+')).sort();
  return req.state === 'optional' ? [...alts, '{}'].join('|') : alts.join('|');
}

export function hasScopes(req) {
  return req.alternatives.some((a) => a.schemes.some((s) => s.scopes.length > 0));
}

// ---- servers -------------------------------------------------------------------------------------------------------

const NON_PRODUCTION = new Set(['staging', 'stage', 'test', 'testing', 'dev', 'development', 'qa', 'uat']);

// The scheme of a server address (lower case), or null for a relative address. An address that starts with a server
// variable ("{scheme}://host") is read from the default and the enum of that variable.
export function serverScheme(server) {
  const url = str(server[FIELDS.url]).trim();
  const m = /^([A-Za-z][A-Za-z0-9+.-]{0,15}):\/\//.exec(url);
  if (m) return m[1].toLowerCase();
  const v = /^\{([^{}]{1,100})\}:\/\//.exec(url);
  if (!v) return null;
  const def = isObj(server[FIELDS.variables]) && isObj(server[FIELDS.variables][v[1]]) ? server[FIELDS.variables][v[1]] : null;
  if (!def) return null;
  const values = [def[FIELDS.default], ...(Array.isArray(def[FIELDS.enum]) ? def[FIELDS.enum] : [])].filter((x) => typeof x === 'string').map((x) => x.toLowerCase());
  return values.includes('http') ? 'http' : values[0] ?? null;
}

export function serverHost(server) {
  const url = str(server[FIELDS.url]).trim();
  const m = /^[A-Za-z{][A-Za-z0-9+.{}-]{0,40}:\/\/(?:[^/?#@]{0,300}@)?(\[[^\]]{1,64}\]|[^/?#:]{1,255})/.exec(url);
  return m ? m[1].toLowerCase() : '';
}

export function isLocalHost(host) {
  return host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(host);
}

export function isNonProductionServer(server) {
  // The last label of the host is the top-level domain (.test is one), so it is not read as a word.
  const labels = serverHost(server).split('.');
  const host = (labels.length > 1 ? labels.slice(0, -1) : labels).join('.');
  const text = `${host} ${str(server[FIELDS.description], 300)}`.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
  return text.split(/[^a-z0-9]+/).some((t) => NON_PRODUCTION.has(t));
}

// The major version a text names as a segment such as v2, or null.
export function majorOfSegment(segment) {
  const m = /^[vV](\d{1,4})(?:\.\d{1,4}){0,2}$/.exec(segment);
  return m ? Number(m[1]) : null;
}

function serverPathSegments(server) {
  const url = str(server[FIELDS.url]).trim().replace(/^[A-Za-z{][A-Za-z0-9+.{}-]{0,40}:\/\/[^/?#]{0,300}/, '');
  return url.split('?')[0].split('#')[0].split('/').filter(Boolean);
}

// ---- names -------------------------------------------------------------------------------------------------------

const PAGING = new Set(['limit', 'page', 'pagesize', 'perpage', 'size', 'offset', 'cursor', 'after', 'before', 'pagetoken', 'nexttoken', 'top', 'skip', 'take', 'maxresults', 'pagenumber', 'startingafter', 'endingbefore', 'pagecursor', 'count']);
const ENVELOPE = new Set(['items', 'data', 'results', 'records', 'entries', 'list', 'content', 'values']);

export function isPagingName(name) {
  return PAGING.has(String(name).slice(0, 100).toLowerCase().replace(/[^a-z0-9]/g, ''));
}

// A name that holds a URL: ends in url or uri, is url, uri, href, link, callback or webhook, or names a redirect.
export function isUrlName(name) {
  const n = String(name).slice(0, 100).toLowerCase().replace(/[^a-z0-9]/g, '');
  return n === 'url' || n === 'uri' || n === 'href' || n === 'link' || n === 'callback' || n === 'webhook' || n.endsWith('url') || n.endsWith('uri') || n.includes('redirect');
}

export function adminTokens(segment) {
  return String(segment).slice(0, 200).replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

const ADMIN_WORDS = new Set(['admin', 'admins', 'administrator', 'internal', 'manage', 'management']);

export function isAdminPath(path) {
  return path.split('/').some((seg) => !seg.startsWith('{') && adminTokens(seg).some((t) => ADMIN_WORDS.has(t)));
}

// The names of the object identifiers of a path: a template that is a whole segment and not the first one.
export function pathIdentifiers(path) {
  const segments = path.split('/').filter(Boolean);
  const out = [];
  segments.forEach((seg, i) => {
    const m = /^\{([^{}/]{1,100})\}$/.exec(seg);
    if (m && i > 0) out.push(m[1]);
  });
  return out;
}

// ---- the run -------------------------------------------------------------------------------------------------------

export function runRules(parsed, limits = DOC_LIMITS) {
  const { data, lines } = parsed;
  const resolver = createResolver(data, limits);
  const found = new Map();
  const seenSchemas = new Set();
  let visits = 0;
  let limitHit = false;

  function add(id, pointer, op, subject, message, fix) {
    const key = `${id}\u0000${pointer}\u0000${subject}`;
    if (found.has(key)) return;
    const spec = BY_ID[id];
    const cat = spec.category === 0 ? null : CAT[spec.category];
    found.set(key, {
      id,
      severity: spec.severity,
      check: spec.category,
      category: cat ? { id: cat.id, name: cat.name } : null,
      pointer: safeText(pointer, 400),
      line: lineOf(lines, pointer),
      operation: op ? safeText(label(op), 200) : null,
      subject: safeText(subject, 200),
      message: safeText(message, 700),
      fix: safeText(fix, 500),
      source: spec.source
    });
  }

  // Follows a $ref and reports a chain that leads back to itself.
  function res(node, pointer) {
    const r = resolver.resolve(node, pointer);
    if (r.status === 'cycle') add('ref-cycle', pointer, null, 'reference', `The $ref at ${pointer} leads back to itself, so it points to no value. The cycle was not followed`, 'Break the cycle if it is not meant, or ignore this note for a schema that contains itself');
    return r;
  }

  // ---- references: remote and unresolved ----
  const refs = findRefs(data);
  for (const r of refs.remote) add('ref-remote', r.at, null, 'reference', `A $ref at ${r.at} points to another file or an address. The tool never fetches or opens it, so what is behind it was not checked`, 'Bundle the description into one file, so that every $ref starts with #/');
  for (const r of refs.local) {
    const probe = resolver.resolve({ [FIELDS.$ref]: r.ref }, r.at);
    if (probe.status === 'broken') add('ref-unresolved', r.at, null, 'reference', `The $ref at ${r.at} points to a place that does not exist in the file`, 'Fix the reference, or add the object it names');
  }

  // ---- operations ----
  const paths = isObj(data[FIELDS.paths]) ? data[FIELDS.paths] : {};
  const ops = [];
  for (const [path, rawItem] of entries(paths)) {
    if (!path.startsWith('/')) continue;
    const r = res(rawItem, sub('#', FIELDS.paths, path));
    if (r.status !== 'ok' || !isObj(r.node)) continue;
    for (const method of METHODS) {
      if (isObj(r.node[method])) ops.push({ method, path, pointer: sub(r.pointer, method), node: r.node[method], item: r.node, itemPointer: r.pointer });
    }
  }
  if (ops.length > limits.maxOperations) throw new Error(`${ops.length.toLocaleString('en-US')} operations is over the limit of ${limits.maxOperations.toLocaleString('en-US')}`);

  const rootReq = readRequirements(data[FIELDS.security]);
  for (const op of ops) {
    const own = Object.hasOwn(op.node, FIELDS.security);
    op.ownSecurity = own;
    op.req = own ? readRequirements(op.node[FIELDS.security]) : rootReq;
    op.sig = signature(op.req);
    op.admin = isAdminPath(op.path) || op.node[EXTENSIONS.admin] === true || op.item[EXTENSIONS.admin] === true;
    op.publicOnPurpose = own && op.req.state === 'empty' && op.node[EXTENSIONS.public] === true;
  }

  // ---- API2: security requirements ----
  for (const op of ops) {
    const where = op.ownSecurity ? sub(op.pointer, FIELDS.security) : op.pointer;
    if (op.publicOnPurpose) continue;
    if (op.ownSecurity && op.req.state === 'empty') {
      add('security-disabled', where, op, label(op), `${label(op)} sets an empty ${FIELDS.security} array, so anyone can call it. If that is meant, mark the operation with ${EXTENSIONS.public}: true; the tool then reads it as public on purpose`, `Give the operation a security requirement, or add ${EXTENSIONS.public}: true next to the empty array`);
    } else if (op.req.state === 'none' || op.req.state === 'empty') {
      const why = op.ownSecurity ? 'its security requirement lists nothing' : rootReq.state === 'empty' ? 'the top-level security is an empty array and the operation has none' : 'there is no top-level security and the operation has none';
      add('security-missing', op.pointer, op, label(op), `${label(op)} has no security requirement: ${why}. A client can call it without credentials. ${EXTENSIONS.public}: true counts only next to an explicit empty ${FIELDS.security} array`, `Add a ${FIELDS.security} requirement at the top level or on the operation`);
    } else if (op.req.state === 'optional') {
      add('security-optional', where, op, label(op), `The ${FIELDS.security} requirements of ${label(op)} include an empty requirement ({}), which the specification says makes security optional: a client can call it without credentials`, 'Remove the empty requirement, or say in the description of the operation why it is public');
    }
  }

  const schemes = isObj(data[FIELDS.components]) && isObj(data[FIELDS.components][FIELDS.securitySchemes]) ? data[FIELDS.components][FIELDS.securitySchemes] : {};
  const usedBy = new Map();
  for (const op of ops) {
    for (const alt of op.req.alternatives) for (const s of alt.schemes) usedBy.set(s.name, (usedBy.get(s.name) ?? 0) + 1);
  }
  const schemeList = [];
  for (const [name, raw] of entries(schemes)) {
    const base = sub('#', FIELDS.components, FIELDS.securitySchemes, name);
    const r = res(raw, base);
    if (r.status === 'ok' && isObj(r.node)) schemeList.push({ name, node: r.node, pointer: r.pointer });
  }
  for (const s of schemeList) {
    if (s.node[FIELDS.type] === SCHEME_TYPES.apiKey && s.node[FIELDS.in] === API_KEY_IN.query) {
      const used = usedBy.get(s.name) ?? 0;
      add('apikey-in-query', sub(s.pointer, FIELDS.in), null, s.name, `The security scheme ${safeText(s.name, 80)} sends an API key in the query string (${used} ${used === 1 ? 'operation uses' : 'operations use'} it). A key in a URL ends up in logs, browser history and referrer headers. OWASP lists "Sends sensitive authentication details, such as auth tokens and passwords in the URL" as a sign of a broken authentication`, `Send the key in a header (${FIELDS.in}: ${API_KEY_IN.header}) instead`);
    }
  }

  // ---- API8: servers ----
  const serverEntries = [];
  const serversAt = (list, pointer, op) => {
    if (!Array.isArray(list)) return;
    list.forEach((s, i) => {
      if (isObj(s)) serverEntries.push({ node: s, pointer: sub(pointer, FIELDS.servers, String(i)), op });
    });
  };
  serversAt(data[FIELDS.servers], '#', null);
  const seenItems = new Set();
  for (const op of ops) {
    if (!seenItems.has(op.itemPointer)) {
      seenItems.add(op.itemPointer);
      serversAt(op.item[FIELDS.servers], op.itemPointer, null);
    }
    serversAt(op.node[FIELDS.servers], op.pointer, op);
  }
  const httpServer = (s) => serverScheme(s.node) === 'http' && !isLocalHost(serverHost(s.node));
  for (const s of serverEntries) {
    if (httpServer(s)) add('http-server', sub(s.pointer, FIELDS.url), s.op, 'server', `The server at ${s.pointer} uses plain http, so everything sent to it can be read and changed on the way. OWASP lists "Transport Layer Security (TLS) is missing" as a sign of a security misconfiguration`, 'Use an https:// address, and keep http only for localhost');
  }
  // The servers that apply to an operation: its own, else its path item's, else the top level.
  const applicable = (op) => {
    for (const list of [op.node[FIELDS.servers], op.item[FIELDS.servers], data[FIELDS.servers]]) if (Array.isArray(list) && list.length) return list.filter(isObj);
    return [];
  };
  for (const s of schemeList) {
    if (s.node[FIELDS.type] !== SCHEME_TYPES.http || typeof s.node[FIELDS.scheme] !== 'string' || s.node[FIELDS.scheme].toLowerCase() !== BASIC_SCHEME) continue;
    const users = ops.filter((op) => op.req.alternatives.some((a) => a.schemes.some((x) => x.name === s.name)) && applicable(op).some((srv) => serverScheme(srv) === 'http' && !isLocalHost(serverHost(srv))));
    if (users.length) add('basic-over-http', s.pointer, users[0], s.name, `The security scheme ${safeText(s.name, 80)} is HTTP basic authentication, and ${users.length} ${users.length === 1 ? 'operation that uses it is' : 'operations that use it are'} served from a plain http address (first: ${label(users[0])}). Basic authentication sends the user name and password with every request, readable by anyone on the way`, 'Serve these operations over https only, or use a scheme that does not send the password with each request');
  }

  // ---- API9: inventory ----
  {
    const seen = [];
    for (const s of serverEntries) for (const seg of serverPathSegments(s.node)) {
      const major = majorOfSegment(seg);
      if (major !== null) seen.push({ major, pointer: sub(s.pointer, FIELDS.url) });
    }
    for (const op of ops) {
      for (const seg of op.path.split('/')) {
        const major = majorOfSegment(seg);
        if (major !== null) seen.push({ major, pointer: op.pointer });
      }
    }
    if (seen.length) {
      const base = seen[0].major;
      const done = new Set([base]);
      for (const s of seen) {
        if (done.has(s.major)) continue;
        done.add(s.major);
        add('multiple-versions', s.pointer, null, `v${s.major}`, `The description names major version v${base} and also v${s.major}. Running several versions of an API expands the attack surface, and OWASP asks for a retirement plan for each version`, 'Document which versions are in use and when the old one is retired, or split the description by version');
      }
    }
    const kinds = serverEntries.map((s) => ({ s, dev: isNonProductionServer(s.node), local: isLocalHost(serverHost(s.node)) }));
    if (kinds.some((k) => !k.dev && !k.local)) {
      for (const k of kinds) if (k.dev) add('non-production-server', sub(k.s.pointer, FIELDS.url), k.s.op, 'server', `The server at ${k.s.pointer} is named as a staging, test or development environment, and the description also lists a server that is not. OWASP asks to document the environment of each API host and not to expose non-production deployments`, 'Publish a separate description for the non-production environment, or remove the server from this one');
    }
    for (const op of ops) {
      if (op.node[FIELDS.deprecated] === true) add('deprecated-operation', sub(op.pointer, FIELDS.deprecated), op, label(op), `${label(op)} is deprecated but still in the description. An old operation that is still served keeps its attack surface until it is retired`, 'Remove the operation when its retirement date has passed, and document the date');
    }
  }

  // ---- parameters and request bodies of every operation ----
  const inputsOf = (op) => {
    const params = [];
    const seenParams = new Set();
    for (const [list, base] of [[op.node[FIELDS.parameters], sub(op.pointer, FIELDS.parameters)], [op.item[FIELDS.parameters], sub(op.itemPointer, FIELDS.parameters)]]) {
      if (!Array.isArray(list)) continue;
      list.forEach((raw, i) => {
        const r = res(raw, sub(base, String(i)));
        if (r.status !== 'ok' || !isObj(r.node)) return;
        const key = `${r.node[FIELDS.in]}\u0000${r.node[FIELDS.name]}`;
        if (seenParams.has(key)) return;
        seenParams.add(key);
        params.push({ node: r.node, pointer: r.pointer });
      });
    }
    let body = [];
    if (op.node[FIELDS.requestBody] !== undefined) {
      const r = res(op.node[FIELDS.requestBody], sub(op.pointer, FIELDS.requestBody));
      if (r.status === 'ok' && isObj(r.node) && isObj(r.node[FIELDS.content])) {
        body = entries(r.node[FIELDS.content]).filter(([, mt]) => isObj(mt) && mt[FIELDS.schema] !== undefined).map(([name, mt]) => ({ name, schema: mt[FIELDS.schema], pointer: sub(r.pointer, FIELDS.content, name, FIELDS.schema) }));
      }
    }
    return { params, body };
  };

  // ---- schemas that a client sends ----
  function walk(node, pointer, role, op, depth, active) {
    const r = res(node, pointer);
    if (r.status !== 'ok' || !isObj(r.node)) return;
    const ptr = r.pointer;
    const s = r.node;
    if (active.has(ptr)) {
      add('ref-cycle', ptr, op, 'schema', `The schema at ${ptr} contains itself. It was checked once and the cycle was not followed again`, 'Nothing to fix if the schema is meant to be recursive');
      return;
    }
    const key = `${role}\u0000${ptr}`;
    if (seenSchemas.has(key)) return;
    seenSchemas.add(key);
    visits += 1;
    if (depth > limits.maxSchemaDepth || visits > limits.maxSchemaVisits) {
      if (!limitHit) {
        limitHit = true;
        add('limit-reached', ptr, op, 'schemas', `The schemas are nested deeper than ${limits.maxSchemaDepth} levels, or there are more than ${limits.maxSchemaVisits.toLocaleString('en-US')} of them, so the schemas below ${ptr} were not checked`, 'Flatten the schemas, or check a smaller description');
      }
      return;
    }
    active.add(ptr);
    const types = typesOf(s);
    const isObject = types.includes('object') || isObj(s[SCHEMA.properties]);
    const hasEnum = Array.isArray(s[SCHEMA.enum]) || s[SCHEMA.const] !== undefined;
    const format = str(s[SCHEMA.format], 40);

    if (role === 'body' && isObject) {
      const extra = s[SCHEMA.additionalProperties];
      const closed = extra === false || s[SCHEMA.unevaluatedProperties] === false || isObj(extra);
      if (!closed) {
        add('mass-assignment-open', sub(ptr, ...(extra === true ? [SCHEMA.additionalProperties] : [])), op, 'object', `An object that a client sends${op ? ` (first reached from ${label(op)})` : ''} accepts properties that it does not list: ${SCHEMA.additionalProperties} is ${extra === true ? 'true' : 'not set'}. If the server binds the whole body to an object, a client can set properties it was never meant to set`, `Set ${SCHEMA.additionalProperties}: false, and list only the properties a client may write`);
      }
    }
    if (types.includes('array') || s[SCHEMA.items] !== undefined) {
      if (s[SCHEMA.maxItems] === undefined) add('unbounded-array', ptr, op, 'array', `An array that a client sends${op ? ` (first reached from ${label(op)})` : ''} has no ${SCHEMA.maxItems}. OWASP asks for "maximum number of elements in arrays" on all incoming payloads`, `Set ${SCHEMA.maxItems}`);
    }
    if (types.includes('string') && s[SCHEMA.maxLength] === undefined && !hasEnum && !FIXED_FORMATS.includes(format)) {
      add('unbounded-string', ptr, op, 'string', `A string that a client sends${op ? ` (first reached from ${label(op)})` : ''} has no ${SCHEMA.maxLength}, no ${SCHEMA.enum} and no fixed ${SCHEMA.format}. OWASP asks for "maximum length for strings" on all incoming parameters`, `Set ${SCHEMA.maxLength}`);
    }
    if (isObj(s[SCHEMA.properties])) {
      for (const [name, rawProp] of entries(s[SCHEMA.properties])) {
        const site = sub(ptr, SCHEMA.properties, name);
        const p = res(rawProp, site);
        if (p.status === 'ok' && isObj(p.node)) {
          if (role === 'body' && p.node[SCHEMA.readOnly] === true) {
            add('readonly-in-request', site, op, name, `The property ${safeText(name, 80)} is marked ${SCHEMA.readOnly} but is part of a schema that a client sends${op ? ` (first reached from ${label(op)})` : ''}. The specification says a ${SCHEMA.readOnly} property SHOULD NOT be sent in a request, and a server that binds the body to an object may still accept it`, 'Use one schema for the request without the property, and one for the response, or make sure the server ignores it');
          }
          checkUrlField(name, p.node, site, op);
        }
        walk(rawProp, site, role, op, depth + 1, active);
      }
    }
    if (s[SCHEMA.items] !== undefined) walk(s[SCHEMA.items], sub(ptr, SCHEMA.items), role, op, depth + 1, active);
    for (const kw of [SCHEMA.allOf, SCHEMA.anyOf, SCHEMA.oneOf]) {
      if (Array.isArray(s[kw])) s[kw].forEach((m, i) => walk(m, sub(ptr, kw, String(i)), role, op, depth + 1, active));
    }
    if (isObj(s[SCHEMA.additionalProperties])) walk(s[SCHEMA.additionalProperties], sub(ptr, SCHEMA.additionalProperties), role, op, depth + 1, active);
    active.delete(ptr);
  }

  function checkUrlField(name, schema, pointer, op) {
    const types = typesOf(schema);
    const format = str(schema[SCHEMA.format], 40).toLowerCase();
    const urlFormat = URL_FORMATS.includes(format) || format === URL_FORMAT_CONVENTION;
    const stringy = types.includes('string') || (types.length === 0 && urlFormat);
    if (!stringy || Array.isArray(schema[SCHEMA.enum]) || schema[SCHEMA.const] !== undefined) return;
    if (urlFormat || isUrlName(name)) {
      add('url-input', pointer, op, name, `The ${urlFormat ? `${SCHEMA.format} ${format}` : 'name'} of ${safeText(name, 80)} says that a client sends a URL${op ? ` (first reached from ${label(op)})` : ''}. If the server fetches it, an attacker can point the server at an address inside the network. OWASP lists webhooks, file fetching from URLs and URL previews as the usual places. The description cannot show whether the server validates the address`, 'Accept only addresses from an allow list of origins and schemes, and say so in the description of the field');
    }
  }

  for (const op of ops) {
    const { params, body } = inputsOf(op);
    for (const p of params) {
      const name = str(p.node[FIELDS.name], 100);
      const rawSchema = p.node[FIELDS.schema] !== undefined ? [p.node[FIELDS.schema], sub(p.pointer, FIELDS.schema)] : null;
      if (rawSchema) {
        const sr = res(rawSchema[0], rawSchema[1]);
        if (sr.status === 'ok' && isObj(sr.node)) checkUrlField(name, sr.node, p.pointer, op);
        walk(rawSchema[0], rawSchema[1], 'param', op, 0, new Set());
      } else if (isObj(p.node[FIELDS.content])) {
        for (const [mt, v] of entries(p.node[FIELDS.content])) if (isObj(v) && v[FIELDS.schema] !== undefined) walk(v[FIELDS.schema], sub(p.pointer, FIELDS.content, mt, FIELDS.schema), 'param', op, 0, new Set());
      }
    }
    for (const b of body) walk(b.schema, b.pointer, 'body', op, 0, new Set());
    op.params = params;
  }

  // ---- API4: paging and the 429 response ----
  const successSchema = (op) => {
    const responses = op.node[FIELDS.responses];
    if (!isObj(responses)) return null;
    const code = Object.keys(responses).filter((k) => /^2(?:\d\d|XX)$/i.test(k)).sort()[0];
    if (code === undefined) return null;
    const r = res(responses[code], sub(op.pointer, FIELDS.responses, code));
    if (r.status !== 'ok' || !isObj(r.node) || !isObj(r.node[FIELDS.content])) return null;
    for (const [mt, v] of entries(r.node[FIELDS.content])) {
      if (!isObj(v) || v[FIELDS.schema] === undefined) continue;
      const s = res(v[FIELDS.schema], sub(r.pointer, FIELDS.content, mt, FIELDS.schema));
      if (s.status === 'ok' && isObj(s.node)) return s;
    }
    return null;
  };
  const isList = (op) => {
    if (op.method !== 'get') return false;
    const s = successSchema(op);
    if (!s) return false;
    if (typesOf(s.node).includes('array')) return true;
    const lastIsTemplate = /\{[^{}/]{1,100}\}$/.test(op.path);
    if (lastIsTemplate || !isObj(s.node[SCHEMA.properties])) return false;
    return entries(s.node[SCHEMA.properties]).some(([k, v]) => {
      if (!ENVELOPE.has(k.toLowerCase())) return false;
      const p = res(v, sub(s.pointer, SCHEMA.properties, k));
      return p.status === 'ok' && isObj(p.node) && typesOf(p.node).includes('array');
    });
  };
  for (const op of ops) {
    op.list = isList(op);
    if (op.list && !op.params.some((p) => (p.node[FIELDS.in] === PARAM_IN.query || p.node[FIELDS.in] === PARAM_IN.header) && isPagingName(str(p.node[FIELDS.name], 100)))) {
      add('list-without-paging', op.pointer, op, label(op), `${label(op)} returns a list and has no paging parameter, so one request can return every record. OWASP lists "Number of records per page to return in a single request-response" among the limits an API needs`, 'Add a limit and an offset, or a cursor, with a maximum value');
    }
    const responses = op.node[FIELDS.responses];
    if (!isObj(responses) || !Object.hasOwn(responses, TOO_MANY_REQUESTS)) {
      add('no-rate-limit-response', isObj(responses) ? sub(op.pointer, FIELDS.responses) : op.pointer, op, label(op), `${label(op)} documents no ${TOO_MANY_REQUESTS} response. OWASP asks for a limit on how often a client can call the API, and a client needs to know what the limit looks like (the tool counts only an explicit ${TOO_MANY_REQUESTS})`, `Add a ${TOO_MANY_REQUESTS} response, with the header that tells the client when to retry`);
    }
  }

  // ---- API1: object identifiers ----
  const byPathGet = new Map();
  for (const op of ops) if (op.method === 'get') byPathGet.set(op.path, op);
  for (const op of ops) {
    const ids = pathIdentifiers(op.path);
    if (ids.length === 0) continue;
    const collection = /\/\{[^{}/]{1,100}\}$/.test(op.path) ? op.path.replace(/\/\{[^{}/]{1,100}\}$/, '') : null;
    const listOp = collection ? byPathGet.get(collection) : null;
    let reason = null;
    if (!hasScopes(op.req)) reason = 'its security names no scopes';
    else if (listOp && listOp !== op && listOp.sig === op.sig) reason = `its security has the same scopes as the list operation ${label(listOp)}`;
    if (reason) {
      add('object-id-review', op.pointer, op, ids[ids.length - 1], `${label(op)} takes the object identifier {${safeText(ids[ids.length - 1], 80)}} in its path, and ${reason}. Every endpoint that receives an ID of an object needs a check that the caller may act on that object. The description cannot show that check, so this is something to review, not a finding that the API is vulnerable`, 'Check in the server code that the caller may act on this object; use random identifiers; add a test that calls the operation with another caller\'s identifier');
    }
  }

  // ---- API5: administrative operations ----
  {
    const ordinary = new Set(ops.filter((o) => !o.admin).map((o) => o.sig));
    for (const op of ops) {
      if (!op.admin || !ordinary.has(op.sig)) continue;
      add('admin-same-scopes', op.pointer, op, label(op), `${label(op)} looks administrative (${isAdminPath(op.path) ? 'its path names admin, internal or manage' : `it is marked ${EXTENSIONS.admin}`}) but asks for the same security as ordinary operations. OWASP also says not to assume that an endpoint is regular or administrative from its path, so the names are only a hint`, 'Give administrative operations their own scope or role in the security requirement, and check it in the server code');
    }
  }

  // ---- the result ----
  const list = [...found.values()];
  const webhooks = isObj(data[FIELDS.webhooks]) ? Object.keys(data[FIELDS.webhooks]).length : 0;
  let callbacks = 0;
  for (const op of ops) if (isObj(op.node[FIELDS.callbacks])) callbacks += Object.keys(op.node[FIELDS.callbacks]).length;
  return {
    findings: list,
    facts: {
      operations: ops.length,
      publicOnPurpose: ops.filter((o) => o.publicOnPurpose).map((o) => ({ operation: safeText(label(o), 200), pointer: safeText(o.pointer, 400) })),
      servers: serverEntries.length,
      securitySchemes: schemeList.length,
      webhooks,
      callbacks
    }
  };
}
