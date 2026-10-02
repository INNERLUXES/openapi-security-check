import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { API_KEY_IN, BASIC_SCHEME, CATEGORIES, DATA_FIELDS, EXTENSIONS, FIELDS, FINDINGS, MAP_FIELDS, METHODS, OWASP_INDEX_URL, SCHEMA, SCHEME_TYPES, SOURCES, TOO_MANY_REQUESTS, URL_FORMATS } from '../src/index.js';

const source = async (id) => readFile(new URL(`../research/sources/${SOURCES.find((s) => s.id === id).file}`, import.meta.url), 'utf8');
const quotes = (t) => t.split(String.fromCharCode(0x2019)).join("'").split(String.fromCharCode(0x2018)).join("'").split(String.fromCharCode(0x201c)).join('"').split(String.fromCharCode(0x201d)).join('"');
// Text compared without line breaks, runs of white space, backticks or the typographic quotes.
const flat = (t) => quotes(t).replace(/`/g, '').replace(/\s+/g, ' ').toLowerCase();
const has = (text, needle) => flat(text).includes(flat(needle));
const word = (text, name) => new RegExp(`(?:^|[^A-Za-z0-9_$])${name.replace(/[$]/g, '\\$')}(?:$|[^A-Za-z0-9_])`).test(text);

test('sources: every saved page has its address on the first line, as listed in src/data.js', async () => {
  for (const s of SOURCES) {
    const text = await source(s.id);
    assert.equal(text.split('\n')[0], `Source: ${s.url}`, s.file);
    assert.ok(text.length > 1000, `${s.file} holds the page text`);
  }
  assert.equal(SOURCES.length, new Set(SOURCES.map((s) => s.url)).size);
  assert.equal(SOURCES.length, new Set(SOURCES.map((s) => s.file)).size);
});

test('sources: every file in research/sources is listed in src/data.js, and the other way round', async () => {
  const files = (await readdir(new URL('../research/sources/', import.meta.url))).sort();
  assert.deepEqual(files, SOURCES.map((s) => s.file).sort());
});

test('sources: the pages come from the official sites', () => {
  for (const s of SOURCES) assert.match(s.url, /^https:\/\/(?:owasp\.org\/API-Security\/editions\/2023\/en\/|spec\.openapis\.org\/oas\/v3\.[01]\.[0-3]$|json-schema\.org\/draft\/2020-12\/)/, s.url);
});

test('categories: the OWASP page lists the ten risks with these IDs and names', async () => {
  const page = await source('owasp-top-10');
  assert.equal(CATEGORIES.length, 10);
  assert.equal(OWASP_INDEX_URL, 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/');
  for (const c of CATEGORIES) assert.ok(page.includes(`\n${c.id} - ${c.name} |\n`), `${c.id} - ${c.name}`);
  const listed = [...page.matchAll(/^(API\d{1,2}:2023) - /gm)].map((m) => m[1]);
  assert.deepEqual(listed, CATEGORIES.map((c) => c.id));
  assert.deepEqual(CATEGORIES.map((c) => c.id), Array.from({ length: 10 }, (_, i) => `API${i + 1}:2023`));
});

test('categories: the page of each risk has the same ID and name as its heading', async () => {
  for (const c of CATEGORIES) {
    const entry = SOURCES.find((s) => s.id === `owasp-api${c.n}`);
    assert.equal(entry.url, c.source);
    const page = await source(entry.id);
    assert.ok(page.includes(`\n# ${c.id} ${c.name}\n`), c.id);
  }
});

test('categories: the address of each risk page is the address the index links to (number and name)', () => {
  for (const c of CATEGORIES) {
    const slug = c.name.toLowerCase().replace(/ /g, '-');
    assert.equal(c.source, `https://owasp.org/API-Security/editions/2023/en/0xa${c.n.toString(16)}-${slug}/`);
  }
});

test('categories: the two risks that a description cannot show say why', () => {
  assert.deepEqual(CATEGORIES.filter((c) => !c.checkable).map((c) => c.id), ['API6:2023', 'API10:2023']);
  for (const c of CATEGORIES.filter((x) => !x.checkable)) assert.ok(c.reason.length > 40);
});

test('fields: every OpenAPI field name that src uses is in the OpenAPI 3.1.0 text', async () => {
  const page = await source('openapi-3.1.0');
  for (const [key, name] of Object.entries(FIELDS)) assert.ok(word(page, name), `${key}: ${name}`);
  for (const name of Object.values(SCHEME_TYPES)) assert.ok(page.includes(`"${name}"`), name);
  for (const name of Object.values(API_KEY_IN)) assert.ok(page.includes(`"${name}"`), name);
  for (const m of METHODS) assert.ok(page.includes(`\n${m} |\nOperation Object |\nA definition of a ${m.toUpperCase()} operation on this path.`), m);
});

test('fields: the keywords of the Schema Object are in the JSON Schema 2020-12 text, and readOnly in OpenAPI 3.0.3', async () => {
  const validation = await source('json-schema-validation');
  const core = await source('json-schema-core');
  const oas30 = await source('openapi-3.0.3');
  for (const k of [SCHEMA.type, SCHEMA.enum, SCHEMA.const, SCHEMA.format, SCHEMA.readOnly, SCHEMA.maxItems, SCHEMA.maxLength]) assert.ok(word(validation, k), k);
  for (const k of [SCHEMA.properties, SCHEMA.items, SCHEMA.allOf, SCHEMA.anyOf, SCHEMA.oneOf, SCHEMA.additionalProperties, SCHEMA.unevaluatedProperties]) assert.ok(word(core, k), k);
  for (const k of [SCHEMA.readOnly, SCHEMA.additionalProperties, SCHEMA.maxItems, SCHEMA.maxLength, SCHEMA.format]) assert.ok(word(oas30, k), `3.0.3 ${k}`);
});

test('fields: the names that the reference scan treats as data or as maps of names are in the specifications', async () => {
  const text = `${await source('openapi-3.1.0')}
${await source('json-schema-core')}
${await source('json-schema-validation')}`;
  for (const k of [...DATA_FIELDS, ...MAP_FIELDS]) assert.ok(word(text, k), k);
});

test('fields: readOnly means a property that a request should not send', async () => {
  const oas30 = await source('openapi-3.0.3');
  assert.ok(has(oas30, 'it MAY be sent as part of a response but SHOULD NOT be sent as part of the request'));
  const validation = await source('json-schema-validation');
  assert.ok(has(validation, 'attempts by an application to modify the value of this property are expected to be ignored or rejected by that owning authority'));
});

test('fields: additionalProperties that is not written accepts any property, from the specifications', async () => {
  const core = await source('json-schema-core');
  assert.ok(has(core, 'Omitting this keyword has the same assertion behavior as an empty schema'));
  const oas30 = await source('openapi-3.0.3');
  assert.ok(has(oas30, 'additionalProperties defaults to true'));
});

test('fields: the security requirement rules the checks rely on are in the OpenAPI 3.1.0 text', async () => {
  const page = await source('openapi-3.1.0');
  assert.ok(has(page, 'To make security optional, an empty security requirement ({}) can be included in the array'));
  assert.ok(has(page, 'To remove a top-level security declaration, an empty array can be used'));
  assert.ok(has(page, 'This definition overrides any declared top-level security'));
  assert.ok(has(page, 'The location of the API key. Valid values are "query", "header" or "cookie".'));
  assert.ok(has(page, 'Supported schemes are HTTP authentication, an API key (either as a header, a cookie parameter or as a query parameter)'));
  assert.equal(BASIC_SCHEME, 'basic');
  assert.ok(page.includes('"type": "http",\n  "scheme": "basic"'));
});

test('fields: the response codes, the deprecated field and the server fields are in the text', async () => {
  const page = await source('openapi-3.1.0');
  assert.equal(TOO_MANY_REQUESTS, '429');
  assert.ok(has(page, 'Any HTTP status code can be used as the property name'));
  assert.ok(has(page, 'Declares this operation to be deprecated'));
  assert.ok(has(page, 'An array of Server Objects, which provide connectivity information to a target server'));
  assert.ok(has(page, 'An alternative server array to service this operation'));
  assert.ok(has(page, 'If the servers property is not provided, or is an empty array, the default value would be a Server Object with a url value of /'));
});

test('fields: the URL formats are the resource identifier formats of JSON Schema, and url is not one', async () => {
  const page = await source('json-schema-validation');
  assert.deepEqual(URL_FORMATS, ['uri', 'uri-reference', 'iri', 'iri-reference']);
  for (const f of URL_FORMATS) assert.ok(new RegExp(`^\\s*${f}:`, 'm').test(page), f);
  assert.ok(!/^\s*url:/m.test(page));
});

test('fields: the extensions the tool reads start with x- and are not reserved by the OpenAPI Initiative', async () => {
  const page = await source('openapi-3.1.0');
  assert.ok(has(page, 'The field name MUST begin with x-'));
  assert.ok(has(page, 'Field names beginning x-oai- and x-oas- are reserved'));
  for (const name of Object.values(EXTENSIONS)) {
    assert.match(name, /^x-/);
    assert.doesNotMatch(name, /^x-oa[is]-/);
  }
  assert.deepEqual(EXTENSIONS, { public: 'x-public', admin: 'x-admin' });
});

test('fields: the sentences of the OWASP pages that a message quotes are on the saved pages', async () => {
  const code = await readFile(new URL('../src/rules.js', import.meta.url), 'utf8');
  const quoted = [
    ['owasp-api2', 'Sends sensitive authentication details, such as auth tokens and passwords in the URL'],
    ['owasp-api8', 'Transport Layer Security (TLS) is missing'],
    ['owasp-api4', 'Number of records per page to return in a single request-response'],
    ['owasp-api4', 'maximum number of elements in arrays'],
    ['owasp-api4', 'maximum length for strings'],
    ['owasp-api5', "Don't assume that an API endpoint is regular or administrative only based on the URL path"]
  ];
  for (const [id, text] of quoted) assert.ok(has(await source(id), text), text);
  for (const [, text] of quoted.slice(0, 5)) assert.ok(code.includes(text), `src/rules.js quotes: ${text}`);
});

test('fields: src names no field of the specifications outside src/data.js', async () => {
  const names = ['readOnly', 'additionalProperties', 'unevaluatedProperties', 'securitySchemes', 'maxItems', 'maxLength', 'requestBody', 'deprecated', 'apiKey', 'servers', 'components', 'parameters', 'responses', 'webhooks', 'callbacks', 'openapi', 'x-public', 'x-admin', 'basic', '429'];
  for (const file of ['rules.js', 'check.js', 'doc.js', 'report.js', 'cli.js']) {
    const lines = (await readFile(new URL(`../src/${file}`, import.meta.url), 'utf8')).split(String.fromCharCode(10));
    const text = lines.filter((l) => !l.trim().startsWith('//')).join(String.fromCharCode(10));
    for (const n of names) assert.ok(!text.includes(`'${n}'`) && !text.includes(`"${n}"`), `${file} writes '${n}' itself`);
  }
});

test('findings: every finding has a saved source page, a valid severity and a risk of the list', () => {
  const urls = new Set(SOURCES.map((s) => s.url));
  assert.equal(new Set(FINDINGS.map((f) => f.id)).size, FINDINGS.length);
  for (const f of FINDINGS) {
    assert.ok(urls.has(f.source), f.id);
    assert.ok(['error', 'warning', 'info'].includes(f.severity), f.id);
    assert.ok(f.category >= 0 && f.category <= 10, f.id);
    if (f.category > 0) assert.equal(f.source, CATEGORIES[f.category - 1].source, f.id);
  }
  for (const id of ['security-missing', 'apikey-in-query', 'http-server', 'object-id-review', 'admin-same-scopes', 'mass-assignment-open', 'list-without-paging', 'url-input', 'multiple-versions']) assert.ok(FINDINGS.some((f) => f.id === id), id);
});

test('docs: every sentence that the documents quote from an OWASP, OpenAPI or JSON Schema page is on a saved page', async () => {
  const pages = (await Promise.all(SOURCES.map((s) => source(s.id)))).map(flat).join(' ');
  let checked = 0;
  for (const file of ['docs/method.md', 'docs/rules-and-sources.md']) {
    const text = quotes(await readFile(new URL(`../${file}`, import.meta.url), 'utf8'));
    for (const m of text.matchAll(/"([^"\n]{30,300})"/g)) {
      if (m[1].includes('...')) continue;
      assert.ok(pages.includes(flat(m[1])), `${file}: ${m[1]}`);
      checked += 1;
    }
  }
  assert.ok(checked >= 12, `${checked} quotes checked`);
});
