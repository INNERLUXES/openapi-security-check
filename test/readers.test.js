import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, symlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { DOC_LIMITS, FILE_LIMITS, createResolver, decodePointer, displayPath, escapeToken, fileError, findRefs, getPointer, lineOf, parseDocument, parseJson, parseYaml, pointerOf, readBounded } from '../src/index.js';
import { base, json, withFiles } from './helpers.js';

const YAML_DOC = `openapi: "3.0.3"
info:
  title: Demo
  version: "1.0.0"
paths:
  /things/{id}:
    get:
      security: []
      parameters:
        - name: id
          in: path
          schema:
            type: string
      responses:
        "200":
          description: ok
        '429':
          description: slow
`;

test('parseDocument: JSON and the YAML subset give the same data and the same pointers', () => {
  const fromYaml = parseDocument(YAML_DOC, 'a.yaml');
  const asJson = JSON.stringify(fromYaml.data);
  const fromJson = parseDocument(asJson, 'a.json');
  assert.deepEqual(fromJson.data, fromYaml.data);
  assert.equal(fromYaml.format, 'yaml');
  assert.equal(fromJson.format, 'json');
  assert.ok(fromYaml.lines.has('#/paths/~1things~1{id}/get/security'));
  assert.equal(fromYaml.lines.get('#/paths/~1things~1{id}/get/security'), 8);
});

test('parseDocument: the format is read from the name, or from the first character when the name does not say', () => {
  assert.equal(parseDocument(json(base()), 'spec').format, 'json');
  assert.equal(parseDocument(YAML_DOC, 'spec').format, 'yaml');
  assert.equal(parseDocument(json(base()), 'spec.txt').format, 'json');
});

test('parseDocument: YAML outside the documented subset is refused with the line, never guessed', () => {
  const block = `openapi: "3.0.3"\ninfo:\n  title: Demo\n  description: |\n    text\n  version: "1"\npaths: {}\n`;
  assert.throws(() => parseDocument(block, 'a.yaml'), /line 4: .*block scalars/);
  assert.throws(() => parseDocument('openapi: "3.0.3"\nx: &a 1\n', 'a.yaml'), /line 2/);
  assert.throws(() => parseDocument('openapi: "3.0.3"\n\tx: 1\n', 'a.yaml'), /tab/);
  assert.throws(() => parseDocument('openapi: "3.0.3"\n---\nx: 1\n', 'a.yaml'), /more than one document/);
});

test('parseDocument: things that are not an OpenAPI 3.0 or 3.1 description are refused with a reason', () => {
  assert.throws(() => parseDocument('[1, 2]', 'a.json'), /does not hold an object/);
  assert.throws(() => parseDocument('{"swagger": "2.0"}', 'a.json'), /Swagger 2.0 is not supported/);
  assert.throws(() => parseDocument('{"info": {}}', 'a.json'), /no "openapi" version field/);
  assert.throws(() => parseDocument('{"openapi": "4.0.0"}', 'a.json'), /OpenAPI 4.0.0 is not supported/);
  assert.throws(() => parseDocument('{"openapi": 3.1}', 'a.json'), /no "openapi" version field/);
  assert.throws(() => parseDocument('{"openapi": "3.0.3", "paths": []}', 'a.json'), /"paths" is not an object/);
  assert.equal(parseDocument('{"openapi": "3.1.0"}', 'a.json').openapi, '3.1.0');
  assert.equal(parseDocument('{"openapi": "3.0.0"}', 'a.json').openapi, '3.0.0');
});

test('parseDocument: JSON that is not strict JSON, and a key given twice, are refused', () => {
  assert.throws(() => parseDocument('{"openapi": "3.0.3",}', 'a.json'), /line 1/);
  assert.throws(() => parseDocument("{'openapi': '3.0.3'}", 'a.json'), /key in quotes/);
  assert.throws(() => parseDocument('{"openapi": "3.0.3", "openapi": "3.1.0"}', 'a.json'), /appears twice/);
  assert.throws(() => parseDocument('{"openapi": "3.0.3"} x', 'a.json'), /text after the end/);
});

test('parseDocument: a key such as __proto__ is only a name and changes nothing', () => {
  const parsed = parseDocument('{"openapi": "3.0.3", "__proto__": {"polluted": true}, "paths": {}}', 'a.json');
  assert.equal(Object.getPrototypeOf(parsed.data), null);
  assert.equal(Object.hasOwn(parsed.data, '__proto__'), true);
  assert.equal({}.polluted, undefined);
});

test('parseDocument: nesting deeper than the limit and too many values are refused', () => {
  const deep = `{"openapi": "3.0.3", "x": ${'['.repeat(70)}${']'.repeat(70)}}`;
  assert.throws(() => parseDocument(deep, 'a.json'), /nested more than 64 deep/);
  const wide = `{"openapi": "3.0.3", "x": [${Array.from({ length: 50 }, () => '1').join(',')}]}`;
  assert.throws(() => parseDocument(wide, 'a.json', { ...DOC_LIMITS, maxNodes: 20 }), /more than 20 values/);
  assert.throws(() => parseDocument(`openapi: "3.0.3"\n${'a: 1\n'.repeat(30)}`, 'a.yaml', { ...DOC_LIMITS, maxYamlLines: 10 }), /more than 10 lines/);
});

test('parseJson and parseYaml: nodes keep the line of every value', () => {
  const node = parseJson('{\n  "a": 1,\n  "b": [\n    2\n  ]\n}', 'x');
  assert.equal(node.props[1].line, 3);
  assert.equal(node.props[1].value.items[0].line, 4);
  const y = parseYaml('a: 1\nb:\n  - 2\n', 'x');
  assert.equal(y.props[1].line, 2);
  assert.equal(y.props[1].value.items[0].line, 3);
});

test('pointers: tokens are escaped with ~0 and ~1, and decoded with %XX', () => {
  assert.equal(escapeToken('/a~b'), '~1a~0b');
  assert.equal(pointerOf([]), '#');
  assert.equal(pointerOf(['paths', '/a/{id}', 'get']), '#/paths/~1a~1{id}/get');
  assert.deepEqual(decodePointer('#/components/schemas/A%20B'), ['components', 'schemas', 'A B']);
  assert.deepEqual(decodePointer('#/paths/~1a~0b'), ['paths', '/a~b']);
  assert.deepEqual(decodePointer('#'), []);
  assert.deepEqual(decodePointer('#/a/%E0%A4%A'), ['a', '%E0%A4%A']);
  assert.throws(() => decodePointer('other.json#/a'), /not a local reference/);
});

test('pointers: getPointer follows own properties and array indexes only', () => {
  const data = parseDocument('{"openapi": "3.0.3", "a": {"b": [10, 20]}}', 'x.json').data;
  assert.equal(getPointer(data, ['a', 'b', '1']), 20);
  assert.equal(getPointer(data, ['a', 'b', '2']), undefined);
  assert.equal(getPointer(data, ['a', 'b', '01']), undefined);
  assert.equal(getPointer(data, ['a', 'toString']), undefined);
  assert.equal(getPointer(data, ['constructor']), undefined);
  assert.equal(getPointer(data, ['__proto__']), undefined);
});

test('lineOf: a pointer that does not exist gets the line of its nearest ancestor', () => {
  const { lines } = parseDocument('{\n"openapi": "3.0.3",\n"paths": {\n"/a": {}\n}\n}', 'x.json');
  assert.equal(lineOf(lines, '#/paths/~1a'), 4);
  assert.equal(lineOf(lines, '#/paths/~1a/get/security'), 4);
  assert.equal(lineOf(lines, '#/nothing/at/all'), 1);
});

test('findRefs: a $ref inside a file is local, any other is remote, and data under example or default is not read', () => {
  const data = parseDocument(json({
    openapi: '3.0.3',
    a: { $ref: '#/b' },
    b: { $ref: 'other.yaml#/x' },
    c: [{ $ref: 'https://example.test/schema.json' }],
    d: { example: { $ref: 'https://example.test/not-a-reference' }, default: { $ref: 'x' } },
    properties: { default: { $ref: '#/b' }, example: { $ref: '#/a' } }
  }), 'x.json').data;
  const refs = findRefs(data);
  assert.deepEqual(refs.local.map((r) => r.at).sort(), ['#/a', '#/properties/default', '#/properties/example']);
  assert.deepEqual(refs.remote.map((r) => r.at).sort(), ['#/b', '#/c/0']);
});

test('createResolver: follows a chain, and stops at a cycle, a broken reference and a remote one', () => {
  const data = parseDocument(json({ openapi: '3.0.3', a: { $ref: '#/b' }, b: { $ref: '#/c' }, c: { type: 'string' }, x: { $ref: '#/y' }, y: { $ref: '#/x' }, z: { $ref: '#/nope' }, w: { $ref: 'http://example.test/w' }, self: { $ref: '#/self' } }), 'x.json').data;
  const r = createResolver(data);
  const viaChain = r.resolve(data.a, '#/a');
  assert.deepEqual([JSON.stringify(viaChain.node), viaChain.pointer, viaChain.status], ['{"type":"string"}', '#/c', 'ok']);
  assert.equal(r.resolve(data.x, '#/x').status, 'cycle');
  assert.equal(r.resolve(data.self, '#/self').status, 'cycle');
  assert.equal(r.resolve(data.z, '#/z').status, 'broken');
  assert.equal(r.resolve(data.w, '#/w').status, 'remote');
  assert.deepEqual(r.resolve({ type: 'string' }, '#/q'), { node: { type: 'string' }, pointer: '#/q', status: 'ok' });
});

test('createResolver: a chain longer than the limit counts as a cycle', () => {
  const doc = { openapi: '3.0.3' };
  for (let i = 0; i < 40; i += 1) doc[`r${i}`] = { $ref: `#/r${i + 1}` };
  doc.r40 = { type: 'string' };
  const data = parseDocument(json(doc), 'x.json').data;
  assert.equal(createResolver(data).resolve(data.r0, '#/r0').status, 'cycle');
  assert.equal(createResolver(data, { ...DOC_LIMITS, maxRefChain: 64 }).resolve(data.r0, '#/r0').status, 'ok');
});

test('readBounded: reads a regular file whole; a missing file, a folder and a file over the limit are refused with the reason', async () => {
  await withFiles({ 'a.json': '{"x": 1}', 'sub/b.json': '{}', 'big.json': 'x'.repeat(50) }, async (dir) => {
    assert.equal((await readBounded(resolve(dir, 'a.json'))).toString(), '{"x": 1}');
    await assert.rejects(readBounded(resolve(dir, 'none.json')), (e) => e.reason === 'no such file');
    await assert.rejects(readBounded(resolve(dir, 'sub')), (e) => e.reason === 'a folder, not a file');
    await assert.rejects(readBounded(resolve(dir, 'big.json'), 10), (e) => /50 bytes is over the 10 byte limit/.test(e.reason));
    assert.equal(FILE_LIMITS.maxFileBytes, 10 * 1024 * 1024);
    assert.ok(fileError('p', 'why').message === 'p: why');
  });
});

test('readBounded: a symbolic link given as the path is followed, because the person who runs the tool gave it', async (t) => {
  await withFiles({ 'real.json': '{"x": 1}' }, async (dir) => {
    await mkdir(resolve(dir, 'sub'));
    try {
      await symlink(resolve(dir, 'real.json'), resolve(dir, 'sub/link.json'));
    } catch {
      t.skip('this system does not allow a symbolic link here');
      return;
    }
    assert.equal((await readBounded(resolve(dir, 'sub/link.json'))).toString(), '{"x": 1}');
  });
});

test('displayPath: relative to the base with forward slashes; outside the base it is absolute', async () => {
  await withFiles({ 'a/b.json': '{}' }, async (dir) => {
    assert.equal(displayPath(resolve(dir, 'a/b.json'), dir), 'a/b.json');
    assert.equal(displayPath(dir, dir), '.');
    assert.ok(!displayPath(resolve(dir, 'a/b.json'), resolve(dir, 'a')).includes('\\'));
    assert.ok(!displayPath(resolve(dir, '..', 'elsewhere', 'x.json'), dir).includes('\\'));
  });
});
