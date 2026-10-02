// Reading one OpenAPI 3.0 or 3.1 description from JSON or from the YAML subset of docs/inputs.md, and following its
// local $ref. Only references inside the file (#/...) are followed. A reference to another file or an address is
// never fetched or opened: it is listed, with the place where it was found, and the checks do not see through it.

import { extname } from 'node:path';
import { DATA_FIELDS, FIELDS, MAP_FIELDS } from './data.js';
import { parseJson } from './json.js';
import { parseYaml } from './yaml.js';

export const DOC_LIMITS = {
  maxNesting: 64,
  maxNodes: 200_000,
  maxYamlLines: 100_000,
  maxOperations: 5000,
  maxRefChain: 32,
  maxSchemaDepth: 48,
  maxSchemaVisits: 300_000
};

export const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// A JSON pointer token written for a URI fragment: "~" becomes "~0" and "/" becomes "~1".
export function escapeToken(t) {
  return String(t).replace(/~/g, '~0').replace(/\//g, '~1');
}

export function pointerOf(tokens) {
  return tokens.length === 0 ? '#' : `#/${tokens.map(escapeToken).join('/')}`;
}

export function isLocalRef(ref) {
  return typeof ref === 'string' && (ref === '#' || ref.startsWith('#/'));
}

// "#/components/schemas/Parcel" -> ["components", "schemas", "Parcel"], with %XX, ~1 and ~0 decoded.
export function decodePointer(ref) {
  if (!isLocalRef(ref)) throw new Error('not a local reference');
  if (ref === '#') return [];
  return ref.slice(2).split('/').map((part) => {
    let p = part;
    try {
      p = decodeURIComponent(part);
    } catch {
      // a lone % stays as it is
    }
    return p.replace(/~1/g, '/').replace(/~0/g, '~');
  });
}

// Follows own properties only, so a pointer cannot reach anything outside the parsed document.
export function getPointer(data, tokens) {
  let cur = data;
  for (const token of tokens) {
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9][0-9]{0,8})$/.test(token) || Number(token) >= cur.length) return undefined;
      cur = cur[Number(token)];
    } else if (isObj(cur) && Object.hasOwn(cur, token)) cur = cur[token];
    else return undefined;
  }
  return cur;
}

// The reader's nodes as plain data (objects without a prototype, so a key such as __proto__ is only a name), and a
// map from the pointer of every value to its line. The depth of the nodes is already limited by the readers.
function toData(node, pointer, lines) {
  lines.set(pointer, node.line);
  if (node.t === 'object') {
    const out = Object.create(null);
    for (const p of node.props) {
      const child = `${pointer === '#' ? '#/' : `${pointer}/`}${escapeToken(p.key)}`;
      out[p.key] = toData(p.value, child, lines);
      lines.set(child, p.line);
    }
    return out;
  }
  if (node.t === 'array') return node.items.map((item, i) => toData(item, `${pointer === '#' ? '#/' : `${pointer}/`}${i}`, lines));
  return node.value;
}

function looksLikeJson(text) {
  return /^\ufeff?\s*[{[]/.test(text);
}

// Parses the text of one description. name is the file name, used to choose JSON or YAML.
export function parseDocument(text, name = '', limits = DOC_LIMITS) {
  const ext = extname(name).toLowerCase();
  const yaml = ext === '.yaml' || ext === '.yml' || (ext !== '.json' && !looksLikeJson(text));
  const readerLimits = { maxDepth: limits.maxNesting, maxNodes: limits.maxNodes };
  let node;
  if (yaml) node = parseYaml(text, 'the YAML', { limits: { maxDepth: limits.maxNesting, maxLines: limits.maxYamlLines, maxLineLength: 4000 } });
  else node = parseJson(text, 'the JSON', { limits: readerLimits });
  if (node.t !== 'object') throw new Error('not an OpenAPI description: the file does not hold an object');
  const lines = new Map();
  const data = toData(node, '#', lines);
  if (typeof data.swagger === 'string') throw new Error(`Swagger ${data.swagger.slice(0, 20)} is not supported: convert it to OpenAPI 3 first`);
  const version = data[FIELDS.openapi];
  if (typeof version !== 'string') throw new Error(`not an OpenAPI description: no "${FIELDS.openapi}" version field (a string)`);
  if (!/^3\.[01](?:\.\d{1,3})?(?:-[A-Za-z0-9.]{1,20})?$/.test(version)) throw new Error(`OpenAPI ${version.slice(0, 20).replace(/[^ -~]/g, '?')} is not supported (3.0 and 3.1 are)`);
  if (data[FIELDS.paths] !== undefined && !isObj(data[FIELDS.paths])) throw new Error(`"${FIELDS.paths}" is not an object`);
  return { data, lines, openapi: version, format: yaml ? 'yaml' : 'json' };
}

// The line of a pointer, or of its nearest ancestor that has one.
export function lineOf(lines, pointer) {
  let p = pointer;
  for (;;) {
    const line = lines.get(p);
    if (line !== undefined) return line;
    const cut = p.lastIndexOf('/');
    if (cut <= 1) return lines.get('#') ?? 1;
    p = p.slice(0, cut);
  }
}

const DATA_KEYS = new Set(DATA_FIELDS);
const NAME_MAPS = new Set(MAP_FIELDS);

// Every $ref of the document with the pointer of the place where it is written. Iterative, so that a deep file
// cannot overflow the stack. A reference is local when it starts with "#/" (or is "#"); everything else is remote.
export function findRefs(data) {
  const local = [];
  const remote = [];
  const stack = [[data, []]];
  while (stack.length) {
    const [node, tokens] = stack.pop();
    if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i -= 1) stack.push([node[i], [...tokens, String(i)]]);
    } else if (isObj(node)) {
      const keys = Object.keys(node);
      if (typeof node[FIELDS.$ref] === 'string') {
        (isLocalRef(node[FIELDS.$ref]) ? local : remote).push({ ref: node[FIELDS.$ref], at: pointerOf(tokens) });
      }
      for (let i = keys.length - 1; i >= 0; i -= 1) {
        if (keys[i] === FIELDS.$ref && typeof node[keys[i]] === 'string') continue;
        // The value of an example, a default, a const or an enum is data, not a place for a reference; the name of a
        // property called "default" is not data.
        if (DATA_KEYS.has(keys[i]) && !NAME_MAPS.has(tokens[tokens.length - 1])) continue;
        stack.push([node[keys[i]], [...tokens, keys[i]]]);
      }
    }
  }
  return { local, remote };
}

// resolver.resolve(node) follows a chain of $ref until it reaches a value. It returns the value, the pointer of the
// value ("#/components/schemas/Parcel" for a reference, the given pointer otherwise) and a status: ok, cycle (a
// chain that comes back to itself, or is longer than maxRefChain), remote or broken.
export function createResolver(data, limits = DOC_LIMITS) {
  return {
    resolve(node, pointer) {
      let cur = node;
      let at = pointer;
      const seen = [];
      while (isObj(cur) && typeof cur[FIELDS.$ref] === 'string') {
        const ref = cur[FIELDS.$ref];
        if (!isLocalRef(ref)) return { node: undefined, pointer: at, status: 'remote' };
        const tokens = decodePointer(ref);
        const target = pointerOf(tokens);
        if (seen.includes(target) || seen.length >= limits.maxRefChain) return { node: undefined, pointer: target, status: 'cycle' };
        seen.push(target);
        cur = getPointer(data, tokens);
        at = target;
        if (cur === undefined) return { node: undefined, pointer: target, status: 'broken' };
      }
      return { node: cur, pointer: at, status: 'ok' };
    }
  };
}
