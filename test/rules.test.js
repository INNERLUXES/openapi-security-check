import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DOC_LIMITS, LIMITS, adminTokens, hasScopes, isAdminPath, isLocalHost, isNonProductionServer, isPagingName, isUrlName, majorOfSegment, pathIdentifiers, readRequirements, serverHost, serverScheme, signature } from '../src/index.js';
import { base, body, check, find, ids, op, withPaths } from './helpers.js';

const scheme = (name, def) => ({ components: { securitySchemes: { ApiAuth: base().components.securitySchemes.ApiAuth, [name]: def } } });
const useScopes = (...scopes) => ({ security: [{ ApiAuth: scopes }] });

test('a description with nothing to report has no finding, and the gate passes with --fail-on warning', () => {
  const r = check(withPaths({ '/things': { get: op() } }), { failOn: 'warning' });
  assert.deepEqual(r.findings, []);
  assert.equal(r.gate.pass, true);
  assert.deepEqual(r.counts, { error: 0, warning: 0, info: 0 });
});

test('security-missing (API2): no security at the top level or on the operation is a warning with the pointer, the line and the risk', () => {
  const r = check(withPaths({ '/things': { get: op() } }, { security: undefined }));
  const [f] = find(r, 'security-missing');
  assert.equal(f.severity, 'warning');
  assert.equal(f.pointer, '#/paths/~1things/get');
  assert.equal(f.operation, 'GET /things');
  assert.deepEqual(f.category, { id: 'API2:2023', name: 'Broken Authentication' });
  assert.ok(f.line > 0 && f.fix.length > 10 && f.source.startsWith('https://owasp.org/'));
  assert.equal(r.gate.pass, true);
});

test('security-missing: a top-level requirement covers an operation, and an operation requirement covers it without a top-level one', () => {
  assert.deepEqual(ids(check(withPaths({ '/things': { get: op() } }))), []);
  assert.deepEqual(ids(check(withPaths({ '/things': { get: op({ security: [{ ApiAuth: ['read'] }] }) } }, { security: undefined }))), []);
});

test('security-missing: an empty top-level array protects nothing, and the message says where it comes from', () => {
  const r = check(withPaths({ '/things': { get: op() } }, { security: [] }));
  assert.match(find(r, 'security-missing')[0].message, /top-level security is an empty array/);
});

test('security-disabled (API2): an empty array on an operation is a warning unless it carries x-public: true', () => {
  const plain = check(withPaths({ '/ping': { get: op({ security: [] }) } }));
  const [f] = find(plain, 'security-disabled');
  assert.equal(f.pointer, '#/paths/~1ping/get/security');
  assert.equal(plain.publicOnPurpose.length, 0);
  const marked = check(withPaths({ '/ping': { get: op({ security: [], 'x-public': true }) } }));
  assert.deepEqual(marked.findings, []);
  assert.deepEqual(marked.publicOnPurpose.map((p) => p.operation), ['GET /ping']);
  assert.ok(marked.notes.some((n) => /1 operation marked public on purpose/.test(n)));
  const falseMarker = check(withPaths({ '/ping': { get: op({ security: [], 'x-public': false }) } }));
  assert.deepEqual(ids(falseMarker), ['security-disabled']);
  const stringMarker = check(withPaths({ '/ping': { get: op({ security: [], 'x-public': 'true' }) } }));
  assert.deepEqual(ids(stringMarker), ['security-disabled']);
});

test('security-missing: x-public counts only next to an explicit empty security array', () => {
  const r = check(withPaths({ '/ping': { get: op({ 'x-public': true }) } }, { security: undefined }));
  assert.deepEqual(ids(r), ['security-missing']);
  assert.match(r.findings[0].message, /explicit empty security array/);
  assert.deepEqual(ids(check(withPaths({ '/ping': { get: op({ 'x-public': true, ...useScopes('read') }) } }))), []);
});

test('security-optional (API2): an empty requirement among the alternatives makes security optional', () => {
  const onOp = check(withPaths({ '/things': { get: op({ security: [{ ApiAuth: ['read'] }, {}] }) } }));
  assert.deepEqual(ids(onOp), ['security-optional']);
  assert.equal(onOp.findings[0].pointer, '#/paths/~1things/get/security');
  const global = check(withPaths({ '/things': { get: op() } }, { security: [{}] }));
  assert.deepEqual(ids(global), ['security-optional']);
});

test('apikey-in-query (API2): an apiKey in the query string is an error; in a header or a cookie it is not', () => {
  const q = check(withPaths({ '/things': { get: op({ security: [{ K: [] }] }) } }, scheme('K', { type: 'apiKey', in: 'query', name: 'key' })));
  const [f] = find(q, 'apikey-in-query');
  assert.equal(f.severity, 'error');
  assert.equal(f.pointer, '#/components/securitySchemes/K/in');
  assert.equal(q.gate.pass, false);
  for (const where of ['header', 'cookie']) {
    assert.deepEqual(ids(check(withPaths({ '/things': { get: op({ security: [{ K: [] }] }) } }, scheme('K', { type: 'apiKey', in: where, name: 'key' })))), []);
  }
});

test('http-server (API8): a server that starts with http:// is an error, except for a local address and a relative one', () => {
  const at = (url) => ids(check(withPaths({ '/things': { get: op() } }, { servers: [{ url }] })));
  assert.deepEqual(at('http://api.example.test/v1'), ['http-server']);
  assert.deepEqual(at('HTTP://api.example.test/v1'), ['http-server']);
  assert.deepEqual(at('https://api.example.test/v1'), []);
  assert.deepEqual(at('http://localhost:8080'), []);
  assert.deepEqual(at('http://127.0.0.1:8080/v1'), []);
  assert.deepEqual(at('http://[::1]:8080'), []);
  assert.deepEqual(at('http://dev.localhost'), []);
  assert.deepEqual(at('/v1'), []);
  assert.deepEqual(at('http://localhost.example.test'), ['http-server']);
  assert.equal(check(withPaths({ '/things': { get: op() } }, { servers: [{ url: 'http://api.example.test' }] })).findings[0].pointer, '#/servers/0/url');
});

test('http-server: servers on a path item and on an operation count, and a variable that stands for the scheme is read', () => {
  const pathLevel = check(withPaths({ '/things': { servers: [{ url: 'http://x.example.test' }], get: op() } }));
  assert.equal(find(pathLevel, 'http-server')[0].pointer, '#/paths/~1things/servers/0/url');
  const opLevel = check(withPaths({ '/things': { get: op({ servers: [{ url: 'http://x.example.test' }] }) } }));
  assert.equal(find(opLevel, 'http-server')[0].pointer, '#/paths/~1things/get/servers/0/url');
  const variable = (def, values) => ids(check(withPaths({ '/things': { get: op() } }, { servers: [{ url: '{scheme}://api.example.test', variables: { scheme: { default: def, enum: values } } }] })));
  assert.deepEqual(variable('https', ['https', 'http']), ['http-server']);
  assert.deepEqual(variable('https', ['https']), []);
  assert.deepEqual(variable('http', ['http']), ['http-server']);
});

test('http-server: the address, and a user name or password inside it, never reach a report', () => {
  const secret = ['pw', 'zz-not-a-real-secret'].join('-');
  const r = check(withPaths({ '/things': { get: op() } }, { servers: [{ url: `http://svc:${secret}@api.example.test/v1` }] }));
  assert.deepEqual(ids(r), ['http-server']);
  assert.ok(!JSON.stringify(r).includes(secret));
  assert.ok(!JSON.stringify(r).includes('api.example.test'));
});

test('basic-over-http (API8): HTTP basic on an operation served from plain http is an error; over https it is not', () => {
  const basic = scheme('B', { type: 'http', scheme: 'basic' });
  const paths = { '/things': { get: op({ security: [{ B: [] }] }) } };
  const bad = check(withPaths(paths, { ...basic, servers: [{ url: 'http://api.example.test' }] }));
  assert.deepEqual(ids(bad).sort(), ['basic-over-http', 'http-server']);
  assert.equal(find(bad, 'basic-over-http')[0].pointer, '#/components/securitySchemes/B');
  assert.deepEqual(ids(check(withPaths(paths, basic))), []);
  const unused = check(withPaths({ '/things': { get: op() } }, { ...basic, servers: [{ url: 'http://api.example.test' }] }));
  assert.deepEqual(ids(unused), ['http-server']);
  const bearer = scheme('B', { type: 'http', scheme: 'bearer' });
  assert.deepEqual(ids(check(withPaths(paths, { ...bearer, servers: [{ url: 'http://api.example.test' }] }))), ['http-server']);
});

test('object-id-review (API1): an object identifier in the path and a security with no scopes is a review warning', () => {
  const r = check(withPaths({ '/things/{id}': { get: op({ security: [{ ApiAuth: [] }] }) } }));
  const [f] = find(r, 'object-id-review');
  assert.equal(f.severity, 'warning');
  assert.equal(f.pointer, '#/paths/~1things~1{id}/get');
  assert.equal(f.subject, 'id');
  assert.match(f.message, /cannot show that check/);
  assert.match(f.message, /not a finding that the API is vulnerable/);
  assert.deepEqual(f.category, { id: 'API1:2023', name: 'Broken Object Level Authorization' });
});

test('object-id-review: the same scopes as the list operation is reported, other scopes and a first-segment template are not', () => {
  const list = { get: op(useScopes('read')) };
  const same = check(withPaths({ '/things': list, '/things/{id}': { get: op(useScopes('read')) } }));
  assert.deepEqual(ids(same), ['object-id-review']);
  assert.match(same.findings[0].message, /same scopes as the list operation GET \/things/);
  assert.deepEqual(ids(check(withPaths({ '/things': list, '/things/{id}': { get: op(useScopes('write')) } }))), []);
  assert.deepEqual(ids(check(withPaths({ '/{tenant}/things': { get: op(useScopes()) } }))), []);
  assert.deepEqual(ids(check(withPaths({ '/things/{id}': { get: op(useScopes('read')) } }))), []);
  assert.deepEqual(ids(check(withPaths({ '/things/{id}/parts': { get: op(useScopes()) } }))), ['object-id-review']);
});

test('admin-same-scopes (API5): an admin-looking path with the scopes of ordinary operations is a warning', () => {
  const ordinary = { '/things': { get: op() } };
  const r = check(withPaths({ ...ordinary, '/admin/things': { get: op() } }));
  const [f] = find(r, 'admin-same-scopes');
  assert.equal(f.pointer, '#/paths/~1admin~1things/get');
  assert.deepEqual(f.category, { id: 'API5:2023', name: 'Broken Function Level Authorization' });
  assert.match(f.message, /names are only a hint/);
  assert.deepEqual(ids(check(withPaths({ ...ordinary, '/admin/things': { get: op(useScopes('admin')) } }))), []);
});

test('admin-same-scopes: a path word, a camelCase word and x-admin are read; a longer word and a template are not', () => {
  const at = (path, extra = {}) => ids(check(withPaths({ '/things': { get: op() }, [path]: { get: op(extra) } })));
  assert.deepEqual(at('/user-management'), ['admin-same-scopes']);
  assert.deepEqual(at('/internal/reports'), ['admin-same-scopes']);
  assert.deepEqual(at('/adminPanel'), ['admin-same-scopes']);
  assert.deepEqual(at('/reports', { 'x-admin': true }), ['admin-same-scopes']);
  assert.deepEqual(at('/managers'), []);
  assert.deepEqual(at('/administration'), []);
  assert.deepEqual(at('/{admin}/reports'), []);
  assert.deepEqual(at('/reports', { 'x-admin': 'yes' }), []);
});

test('mass-assignment-open (API3): a request object without additionalProperties, or with true, is a warning; false is not', () => {
  const at = (schema) => check(withPaths({ '/things': { post: op({ requestBody: body(schema) }) } }));
  const open = at({ type: 'object', properties: { name: { type: 'string', maxLength: 10 } } });
  const [f] = find(open, 'mass-assignment-open');
  assert.equal(f.pointer, '#/paths/~1things/post/requestBody/content/application~1json/schema');
  assert.deepEqual(f.category, { id: 'API3:2023', name: 'Broken Object Property Level Authorization' });
  assert.equal(find(at({ type: 'object', additionalProperties: true, properties: {} }), 'mass-assignment-open')[0].pointer.endsWith('/schema/additionalProperties'), true);
  assert.deepEqual(ids(at({ type: 'object', additionalProperties: false, properties: { name: { type: 'string', maxLength: 10 } } })), []);
  assert.deepEqual(ids(at({ type: 'object', unevaluatedProperties: false, properties: {} })), []);
  assert.deepEqual(ids(at({ type: 'object', additionalProperties: { type: 'string', maxLength: 5 } })), []);
});

test('mass-assignment-open: a schema in components that two operations use is reported once, at its definition', () => {
  const doc = withPaths({ '/a': { post: op({ requestBody: body({ $ref: '#/components/schemas/Thing' }) }) }, '/b': { put: op({ requestBody: body({ $ref: '#/components/schemas/Thing' }) }) } });
  doc.components.schemas = { Thing: { type: 'object', properties: { n: { type: 'integer' } } } };
  const r = check(doc);
  assert.equal(find(r, 'mass-assignment-open').length, 1);
  assert.equal(find(r, 'mass-assignment-open')[0].pointer, '#/components/schemas/Thing');
  const responseOnly = withPaths({ '/a': { get: op({ responses: { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'object', properties: { x: { type: 'string' } } } } } }, 429: { description: 'slow' } } }) } });
  assert.deepEqual(ids(check(responseOnly)), []);
});

test('readonly-in-request (API3): a readOnly property in a request body schema is a warning; in a response only it is not', () => {
  const closed = (properties) => ({ type: 'object', additionalProperties: false, properties });
  const bad = check(withPaths({ '/things': { post: op({ requestBody: body(closed({ id: { type: 'string', maxLength: 36, readOnly: true }, name: { type: 'string', maxLength: 5 } })) }) } }));
  const [f] = find(bad, 'readonly-in-request');
  assert.equal(f.pointer, '#/paths/~1things/post/requestBody/content/application~1json/schema/properties/id');
  assert.equal(f.subject, 'id');
  const fine = check(withPaths({ '/things': { post: op({ requestBody: body(closed({ id: { type: 'string', maxLength: 36, readOnly: false } })) }) } }));
  assert.deepEqual(ids(fine), []);
  const nested = check(withPaths({ '/things': { post: op({ requestBody: body(closed({ parts: { type: 'array', maxItems: 3, items: { allOf: [closed({ n: { type: 'integer', readOnly: true } })] } } })) }) } }));
  assert.deepEqual(ids(nested), ['readonly-in-request']);
});

test('list-without-paging (API4): a list operation with no paging parameter is a warning', () => {
  const list = (parameters, schema = { type: 'array', items: { type: 'string', maxLength: 5 } }) => ({ '/things': { get: op({ parameters, responses: { 200: { description: 'ok', content: { 'application/json': { schema } } }, 429: { description: 'slow' } } }) } });
  const none = check(withPaths(list(undefined)));
  assert.deepEqual(ids(none), ['list-without-paging']);
  assert.equal(none.findings[0].pointer, '#/paths/~1things/get');
  for (const name of ['limit', 'page_size', 'pageSize', 'offset', 'cursor', '$top', 'per-page', 'next_token']) {
    assert.deepEqual(ids(check(withPaths(list([{ name, in: 'query', schema: { type: 'string', maxLength: 9 } }])))), [], name);
  }
  assert.deepEqual(ids(check(withPaths(list([{ name: 'filter', in: 'query', schema: { type: 'string', maxLength: 9 } }])))), ['list-without-paging']);
  assert.deepEqual(ids(check(withPaths(list([{ name: 'limit', in: 'path', schema: { type: 'string', maxLength: 9 } }])))), ['list-without-paging']);
  assert.deepEqual(ids(check(withPaths(list(undefined, { type: 'object', additionalProperties: false, properties: { items: { type: 'array', items: { type: 'string', maxLength: 5 } } } })))), ['list-without-paging']);
  assert.deepEqual(ids(check(withPaths(list(undefined, { type: 'object', additionalProperties: false, properties: { name: { type: 'string', maxLength: 5 } } })))), []);
});

test('list-without-paging: only a GET is a list, and a parameter that is a $ref is read', () => {
  const post = withPaths({ '/things': { post: op({ responses: { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'array', items: { type: 'integer' } } } } }, 429: { description: 'slow' } } }) } });
  assert.deepEqual(ids(check(post)), []);
  const viaRef = withPaths({ '/things': { get: op({ parameters: [{ $ref: '#/components/parameters/Limit' }], responses: { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'array', items: { type: 'integer' } } } } }, 429: { description: 'slow' } } }) } });
  viaRef.components.parameters = { Limit: { name: 'limit', in: 'query', schema: { type: 'integer', maximum: 50 } } };
  assert.deepEqual(ids(check(viaRef)), []);
});

test('unbounded-array and unbounded-string (API4): what a client sends needs maxItems and maxLength, with the right exceptions', () => {
  const at = (schema) => check(withPaths({ '/things': { post: op({ requestBody: body({ type: 'object', additionalProperties: false, properties: { v: schema } }) }) } }));
  const arr = at({ type: 'array', items: { type: 'integer' } });
  assert.deepEqual(ids(arr), ['unbounded-array']);
  assert.equal(arr.findings[0].severity, 'warning');
  assert.deepEqual(ids(at({ type: 'array', maxItems: 5, items: { type: 'integer' } })), []);
  const str = at({ type: 'string' });
  assert.deepEqual(ids(str), ['unbounded-string']);
  assert.equal(str.findings[0].severity, 'info');
  for (const ok of [{ type: 'string', maxLength: 10 }, { type: 'string', enum: ['a', 'b'] }, { type: 'string', format: 'uuid' }, { type: 'string', format: 'date-time' }, { type: 'string', format: 'binary' }, { type: 'integer' }]) assert.deepEqual(ids(at(ok)), [], JSON.stringify(ok));
  assert.deepEqual(ids(at({ type: ['string', 'null'] })), ['unbounded-string']);
  assert.equal(str.gate.pass, true);
});

test('unbounded-array: a parameter that is an array is checked too, and a response schema is not', () => {
  const param = check(withPaths({ '/things': { get: op({ parameters: [{ name: 'tags', in: 'query', schema: { type: 'array', items: { type: 'string', maxLength: 5 } } }, { name: 'limit', in: 'query', schema: { type: 'integer' } }] }) } }));
  assert.deepEqual(ids(param), ['unbounded-array']);
  assert.equal(param.findings[0].pointer, '#/paths/~1things/get/parameters/0/schema');
  const response = check(withPaths({ '/things': { get: op({ parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer' } }], responses: { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'object', additionalProperties: false, properties: { tags: { type: 'array', items: { type: 'string' } } } } } } }, 429: { description: 'slow' } } }) } }));
  assert.deepEqual(ids(response), []);
});

test('no-rate-limit-response (API4): an operation without a 429 response is a warning; a range such as 4XX does not count', () => {
  const no = check(withPaths({ '/things': { get: { responses: { 200: { description: 'ok' } } } } }));
  assert.deepEqual(ids(no), ['no-rate-limit-response']);
  assert.equal(no.findings[0].pointer, '#/paths/~1things/get/responses');
  assert.match(no.findings[0].message, /explicit 429/);
  assert.deepEqual(ids(check(withPaths({ '/things': { get: { responses: { 200: { description: 'ok' }, '4XX': { description: 'client error' } } } } }))), ['no-rate-limit-response']);
  assert.deepEqual(ids(check(withPaths({ '/things': { get: {} } }))), ['no-rate-limit-response']);
  assert.equal(check(withPaths({ '/things': { get: {} } })).findings[0].pointer, '#/paths/~1things/get');
});

test('url-input (API7): a field with a uri format, or a name such as callbackUrl, webhookUrl or redirect, is a warning to review', () => {
  const at = (name, schema) => check(withPaths({ '/things': { post: op({ requestBody: body({ type: 'object', additionalProperties: false, properties: { [name]: schema } }) }) } }));
  const byName = at('callbackUrl', { type: 'string', maxLength: 200 });
  assert.deepEqual(ids(byName), ['url-input']);
  assert.deepEqual(byName.findings[0].category, { id: 'API7:2023', name: 'Server Side Request Forgery' });
  assert.equal(byName.findings[0].pointer, '#/paths/~1things/post/requestBody/content/application~1json/schema/properties/callbackUrl');
  for (const name of ['webhook_url', 'redirect_uri', 'redirect', 'avatarUrl', 'link', 'callback']) assert.deepEqual(ids(at(name, { type: 'string', maxLength: 200 })), ['url-input'], name);
  assert.match(at('target', { type: 'string', format: 'uri', maxLength: 200 }).findings[0].message, /format uri/);
  assert.deepEqual(ids(at('target', { type: 'string', format: 'url', maxLength: 200 })), ['url-input']);
  for (const [name, schema] of [['redirect', { type: 'boolean' }], ['callbackUrl', { type: 'string', enum: ['a'] }], ['description', { type: 'string', maxLength: 5 }], ['curlers', { type: 'string', maxLength: 5 }], ['returnTo', { type: 'string', maxLength: 5 }]]) {
    assert.deepEqual(ids(at(name, schema)), [], name);
  }
});

test('url-input: a parameter is read by its name and by its format, and a response field is not', () => {
  const q = check(withPaths({ '/things': { get: op({ parameters: [{ name: 'returnUrl', in: 'query', schema: { type: 'string', maxLength: 99 } }, { name: 'src', in: 'query', schema: { type: 'string', format: 'uri-reference', maxLength: 99 } }] }) } }));
  assert.deepEqual(find(q, 'url-input').map((f) => f.pointer), ['#/paths/~1things/get/parameters/0', '#/paths/~1things/get/parameters/1']);
  const resp = check(withPaths({ '/things': { get: op({ responses: { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'object', additionalProperties: false, properties: { homepageUrl: { type: 'string', format: 'uri' } } } } } }, 429: { description: 'slow' } } }) } }));
  assert.deepEqual(ids(resp), []);
});

test('multiple-versions (API9): two major versions in the servers and the paths are a warning', () => {
  const r = check(withPaths({ '/things': { get: op() }, '/v2/things': { get: op() } }));
  const [f] = find(r, 'multiple-versions');
  assert.equal(f.subject, 'v2');
  assert.equal(f.pointer, '#/paths/~1v2~1things/get');
  assert.deepEqual(f.category, { id: 'API9:2023', name: 'Improper Inventory Management' });
  assert.deepEqual(ids(check(withPaths({ '/v1/things': { get: op() } }))), []);
  assert.deepEqual(ids(check(withPaths({ '/v1/things': { get: op() }, '/v1.1/other': { get: op() } }))), []);
  assert.deepEqual(ids(check(withPaths({ '/v10/things': { get: op() } }))).sort(), ['multiple-versions']);
  assert.deepEqual(ids(check(withPaths({ '/v2fa/things': { get: op() } }))), []);
  assert.equal(find(check(withPaths({ '/v3/x': { get: op() } }, { servers: [{ url: 'https://a.example.test/v2' }] })), 'multiple-versions')[0].subject, 'v3');
});

test('non-production-server (API9): a staging, test or dev server next to another server is a warning', () => {
  const servers = (...list) => ids(check(withPaths({ '/things': { get: op() } }, { servers: list })));
  assert.deepEqual(servers({ url: 'https://api.example.test/v1' }, { url: 'https://staging.example.test/v1' }), ['non-production-server']);
  assert.deepEqual(servers({ url: 'https://api.example.test/v1' }, { url: 'https://api-dev.example.test/v1' }), ['non-production-server']);
  assert.deepEqual(servers({ url: 'https://api.example.test/v1', description: 'Production' }, { url: 'https://x.example.test/v1', description: 'Test environment' }), ['non-production-server']);
  assert.deepEqual(servers({ url: 'https://staging.example.test/v1' }), []);
  assert.deepEqual(servers({ url: 'https://api.example.test/v1' }, { url: 'https://contest.example.test/v1' }), []);
  assert.deepEqual(servers({ url: 'https://api.example.test/v1' }, { url: 'http://localhost:3000/v1' }), []);
  assert.equal(find(check(withPaths({ '/things': { get: op() } }, { servers: [{ url: 'https://api.example.test/v1' }, { url: 'https://staging.example.test/v1' }] })), 'non-production-server')[0].pointer, '#/servers/1/url');
});

test('deprecated-operation (API9): a deprecated operation is info, and info never fails the gate', () => {
  const r = check(withPaths({ '/old': { get: op({ deprecated: true }) }, '/new': { get: op({ deprecated: false }) } }), { failOn: 'warning' });
  assert.deepEqual(ids(r), ['deprecated-operation']);
  assert.equal(r.findings[0].severity, 'info');
  assert.equal(r.findings[0].pointer, '#/paths/~1old/get/deprecated');
  assert.equal(r.gate.pass, true);
});

test('ref-remote: a $ref to another file or an address is an error, listed by place, and its address is never printed', () => {
  const r = check(withPaths({ '/things': { get: op({ responses: { 200: { $ref: 'https://schemas.example.test/zz-remote-name.json#/R' }, 429: { description: 'slow' } } }) } }));
  const [f] = find(r, 'ref-remote');
  assert.equal(f.severity, 'error');
  assert.equal(f.category, null);
  assert.equal(f.pointer, '#/paths/~1things/get/responses/200');
  assert.ok(!JSON.stringify(r).includes('zz-remote-name'));
  assert.ok(!JSON.stringify(r).includes('schemas.example.test'));
  assert.equal(check(withPaths({ '/things': { $ref: './other.yaml#/paths/x' } })).findings.filter((x) => x.id === 'ref-remote').length, 1);
});

test('ref-unresolved: a local $ref that points to nothing is an error; a valid one is followed', () => {
  const bad = check(withPaths({ '/things': { post: op({ requestBody: { $ref: '#/components/requestBodies/Missing' } }) } }));
  assert.deepEqual(find(bad, 'ref-unresolved').map((f) => f.pointer), ['#/paths/~1things/post/requestBody']);
  const good = withPaths({ '/things': { post: op({ requestBody: { $ref: '#/components/requestBodies/New' } }) } });
  good.components.requestBodies = { New: body({ type: 'object', properties: { n: { type: 'integer' } } }) };
  assert.deepEqual(find(check(good), 'mass-assignment-open').map((f) => f.pointer), ['#/components/requestBodies/New/content/application~1json/schema']);
});

test('ref-cycle: a schema that contains itself, and a loop of references, are checked once and reported as info', () => {
  const node = withPaths({ '/things': { post: op({ requestBody: body({ $ref: '#/components/schemas/Node' }) }) } });
  node.components.schemas = { Node: { type: 'object', additionalProperties: false, properties: { children: { type: 'array', maxItems: 5, items: { $ref: '#/components/schemas/Node' } } } } };
  const r = check(node);
  assert.deepEqual(ids(r), ['ref-cycle']);
  assert.equal(r.findings[0].severity, 'info');
  assert.equal(r.gate.pass, true);
  const loop = withPaths({ '/things': { post: op({ requestBody: body({ $ref: '#/components/schemas/A' }) }) } });
  loop.components.schemas = { A: { $ref: '#/components/schemas/B' }, B: { $ref: '#/components/schemas/A' } };
  assert.deepEqual(ids(check(loop)), ['ref-cycle']);
});

test('limit-reached: schemas nested deeper than the limit are an error, and the rest is not walked', () => {
  let schema = { type: 'integer' };
  for (let i = 0; i < 8; i += 1) schema = { type: 'object', additionalProperties: false, properties: { n: schema } };
  const doc = withPaths({ '/things': { post: op({ requestBody: body(schema) }) } });
  const r = check(doc, { limits: { ...LIMITS, maxSchemaDepth: 4 } });
  assert.deepEqual(ids(r), ['limit-reached']);
  assert.equal(r.findings[0].severity, 'error');
  assert.deepEqual(ids(check(doc)), []);
  assert.deepEqual(ids(check(doc, { limits: { ...LIMITS, maxSchemaVisits: 3 } })), ['limit-reached']);
});

test('too many operations are refused, and webhooks and callbacks are named as not read', () => {
  const many = withPaths({ '/a': { get: op() }, '/b': { get: op() }, '/c': { get: op() } });
  assert.throws(() => check(many, { limits: { ...DOC_LIMITS, maxOperations: 2 } }), /3 operations is over the limit of 2/);
  const hooks = withPaths({ '/a': { get: op({ callbacks: { done: {} } }) } }, { webhooks: { newThing: {} } });
  assert.ok(check(hooks).notes.some((n) => /1 webhook and 1 callback were not read/.test(n)));
  assert.ok(check(withPaths({})).notes.some((n) => /No operation was found/.test(n)));
});

test('what the description shows is not copied: example values, defaults and descriptions never reach a report', () => {
  const marks = ['zz-example-1', 'zz-default-2', 'zz-desc-3', 'zz-enum-4'];
  const doc = withPaths({
    '/things': {
      post: op({
        description: marks[2],
        security: [],
        requestBody: body({ type: 'object', example: { who: marks[0] }, properties: { a: { type: 'string', example: marks[0], default: marks[1], enum: [marks[3]] }, b: { type: 'string', example: marks[0], default: marks[1] } } })
      })
    }
  });
  const r = check(doc);
  assert.ok(r.findings.length > 0);
  for (const m of marks) assert.ok(!JSON.stringify(r).includes(m), m);
});

test('text from the description is cleaned: control and direction characters never reach a finding', () => {
  const esc = String.fromCharCode(27);
  const rlo = String.fromCharCode(0x202e);
  const doc = withPaths({ [`/th${esc}[31mings${rlo}`]: { get: op({ security: [] }) } });
  const r = check(doc);
  const text = JSON.stringify(r);
  assert.ok(!text.includes(esc) && !text.includes(rlo));
  assert.ok(!/[\u0000-\u001f]/.test(text.replace(/\\n/g, '')));
  assert.equal(find(r, 'security-disabled').length, 1);
});

test('hostile input: a very long server address, name or path, and brace runs, are read in bounded time', () => {
  const long = 'a'.repeat(300000);
  const braces = '{'.repeat(100000);
  const started = Date.now();
  const r = check(withPaths({ [`/${braces}/{${long}}`]: { get: op({ parameters: [{ name: long, in: 'query', schema: { type: 'string', maxLength: 5 } }] }) }, [`/${long}`]: { get: op() } }, { servers: [{ url: `http://${long}:${long}@${long}/v1`, description: long }, { url: `{${long}://x` }] }));
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
  assert.ok(r.findings.length >= 0);
  assert.ok(find(r, 'http-server').length === 1);
});

test('pure helpers: requirements, signatures, servers, names and paths', () => {
  assert.equal(readRequirements(undefined).state, 'none');
  assert.equal(readRequirements([]).state, 'empty');
  assert.equal(readRequirements([{}]).state, 'optional');
  assert.equal(readRequirements([{ A: ['x'] }]).state, 'set');
  assert.equal(signature(readRequirements([{ B: ['y', 'x'], A: [] }])), 'A[]+B[x,y]');
  assert.equal(signature(readRequirements([{ A: ['x'] }, {}])), 'A[x]|{}');
  assert.equal(signature(readRequirements([])), '(none)');
  assert.equal(hasScopes(readRequirements([{ A: [] }])), false);
  assert.equal(hasScopes(readRequirements([{ A: ['x'] }])), true);
  assert.equal(serverScheme({ url: 'HTTPS://x' }), 'https');
  assert.equal(serverScheme({ url: '/v1' }), null);
  assert.equal(serverHost({ url: 'https://user:pw@Host.Example.test:8443/v1' }), 'host.example.test');
  assert.equal(serverHost({ url: 'http://[::1]:80/x' }), '[::1]');
  assert.equal(isLocalHost('127.0.0.1'), true);
  assert.equal(isLocalHost('127.0.0.1.example.test'), false);
  assert.equal(isNonProductionServer({ url: 'https://stage.example.test' }), true);
  assert.equal(isNonProductionServer({ url: 'https://prod.example.test', description: 'Production' }), false);
  assert.equal(majorOfSegment('v12'), 12);
  assert.equal(majorOfSegment('V2.1'), 2);
  assert.equal(majorOfSegment('version2'), null);
  assert.equal(isPagingName('Page_Size'), true);
  assert.equal(isPagingName('filter'), false);
  assert.equal(isUrlName('Callback-URL'), true);
  assert.equal(isUrlName('name'), false);
  assert.deepEqual(adminTokens('adminPanel_v2'), ['admin', 'panel', 'v2']);
  assert.equal(isAdminPath('/a/internal/b'), true);
  assert.equal(isAdminPath('/a/{admin}/b'), false);
  assert.deepEqual(pathIdentifiers('/things/{id}/parts/{partId}'), ['id', 'partId']);
  assert.deepEqual(pathIdentifiers('/{tenant}/things'), []);
  assert.deepEqual(pathIdentifiers('/things/id-{id}'), []);
});
