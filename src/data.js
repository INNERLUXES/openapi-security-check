// The names the checks rest on. Each one comes from an official page that is saved, with its address on the first
// line, in research/sources, and test/data.test.js compares this file with the saved text. Change a value here
// only after saving the new page text and updating docs/rules-and-sources.md. The checks in src/ use these
// constants and never write a field name or a category name of their own.

export const SOURCES = [
  { id: 'owasp-top-10', file: 'owasp-top-10.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/' },
  { id: 'owasp-api1', file: 'owasp-api1-broken-object-level-authorization.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/' },
  { id: 'owasp-api2', file: 'owasp-api2-broken-authentication.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/' },
  { id: 'owasp-api3', file: 'owasp-api3-broken-object-property-level-authorization.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/' },
  { id: 'owasp-api4', file: 'owasp-api4-unrestricted-resource-consumption.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/' },
  { id: 'owasp-api5', file: 'owasp-api5-broken-function-level-authorization.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/' },
  { id: 'owasp-api6', file: 'owasp-api6-unrestricted-access-to-sensitive-business-flows.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/' },
  { id: 'owasp-api7', file: 'owasp-api7-server-side-request-forgery.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/' },
  { id: 'owasp-api8', file: 'owasp-api8-security-misconfiguration.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/' },
  { id: 'owasp-api9', file: 'owasp-api9-improper-inventory-management.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/' },
  { id: 'owasp-api10', file: 'owasp-api10-unsafe-consumption-of-apis.txt', url: 'https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/' },
  { id: 'openapi-3.1.0', file: 'openapi-3.1.0.txt', url: 'https://spec.openapis.org/oas/v3.1.0' },
  { id: 'openapi-3.0.3', file: 'openapi-3.0.3.txt', url: 'https://spec.openapis.org/oas/v3.0.3' },
  { id: 'json-schema-validation', file: 'json-schema-validation.txt', url: 'https://json-schema.org/draft/2020-12/json-schema-validation' },
  { id: 'json-schema-core', file: 'json-schema-core.txt', url: 'https://json-schema.org/draft/2020-12/json-schema-core' }
];

const page = (id) => SOURCES.find((s) => s.id === id).url;

// The ten risks of the OWASP API Security Top 10, with the ID and the name exactly as the project writes them.
// checkable: false means that the description cannot show the risk, and the report says "not checked".
export const CATEGORIES = [
  { n: 1, id: 'API1:2023', name: 'Broken Object Level Authorization', source: page('owasp-api1'), checkable: true },
  { n: 2, id: 'API2:2023', name: 'Broken Authentication', source: page('owasp-api2'), checkable: true },
  { n: 3, id: 'API3:2023', name: 'Broken Object Property Level Authorization', source: page('owasp-api3'), checkable: true },
  { n: 4, id: 'API4:2023', name: 'Unrestricted Resource Consumption', source: page('owasp-api4'), checkable: true },
  { n: 5, id: 'API5:2023', name: 'Broken Function Level Authorization', source: page('owasp-api5'), checkable: true },
  { n: 6, id: 'API6:2023', name: 'Unrestricted Access to Sensitive Business Flows', source: page('owasp-api6'), checkable: false, reason: 'whether a flow such as buying a ticket or posting a comment can be abused when it is automated is a question about the business, which a description of the interface does not answer' },
  { n: 7, id: 'API7:2023', name: 'Server Side Request Forgery', source: page('owasp-api7'), checkable: true },
  { n: 8, id: 'API8:2023', name: 'Security Misconfiguration', source: page('owasp-api8'), checkable: true },
  { n: 9, id: 'API9:2023', name: 'Improper Inventory Management', source: page('owasp-api9'), checkable: true },
  { n: 10, id: 'API10:2023', name: 'Unsafe Consumption of APIs', source: page('owasp-api10'), checkable: false, reason: 'how the API treats the data it receives from third-party services happens inside the server, and a description lists only the operations the API offers' }
];

export const OWASP_INDEX_URL = page('owasp-top-10');

// Field names of the OpenAPI Specification 3.1.0 (and 3.0.3, which uses the same names for these fields).
export const FIELDS = {
  openapi: 'openapi',
  info: 'info',
  title: 'title',
  paths: 'paths',
  servers: 'servers',
  url: 'url',
  description: 'description',
  variables: 'variables',
  enum: 'enum',
  default: 'default',
  components: 'components',
  securitySchemes: 'securitySchemes',
  schemas: 'schemas',
  security: 'security',
  type: 'type',
  scheme: 'scheme',
  in: 'in',
  name: 'name',
  scopes: 'scopes',
  parameters: 'parameters',
  requestBody: 'requestBody',
  content: 'content',
  schema: 'schema',
  responses: 'responses',
  deprecated: 'deprecated',
  webhooks: 'webhooks',
  callbacks: 'callbacks',
  $ref: '$ref'
};

// The methods of a Path Item Object, in the order of the specification's table.
export const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

// The values of the type field of a Security Scheme Object and the values of "in" for an API key.
export const SCHEME_TYPES = { apiKey: 'apiKey', http: 'http', oauth2: 'oauth2', openIdConnect: 'openIdConnect', mutualTLS: 'mutualTLS' };
export const API_KEY_IN = { query: 'query', header: 'header', cookie: 'cookie' };
// The Basic Authentication sample of the specification: type http, scheme basic.
export const BASIC_SCHEME = 'basic';

// Keywords of the Schema Object. OpenAPI 3.1 takes them from JSON Schema 2020-12, OpenAPI 3.0.3 defines readOnly
// and additionalProperties in its own Schema Object.
export const SCHEMA = {
  type: 'type',
  properties: 'properties',
  items: 'items',
  allOf: 'allOf',
  anyOf: 'anyOf',
  oneOf: 'oneOf',
  enum: 'enum',
  const: 'const',
  format: 'format',
  readOnly: 'readOnly',
  additionalProperties: 'additionalProperties',
  unevaluatedProperties: 'unevaluatedProperties',
  maxItems: 'maxItems',
  maxLength: 'maxLength'
};

// The formats of JSON Schema 2020-12 for "resource identifiers" (section 7.3.5), which are the ones that hold a
// URL. "url" is not one of them: it is a name that tools use, and the check reads it as a convention.
export const URL_FORMATS = ['uri', 'uri-reference', 'iri', 'iri-reference'];
export const URL_FORMAT_CONVENTION = 'url';
// Formats whose value has a fixed shape and length, so a maxLength adds little.
export const FIXED_FORMATS = ['date', 'date-time', 'time', 'duration', 'uuid', 'ipv4', 'ipv6', 'binary'];

// Extensions the tool reads. The names are the tool's own: the specification says that an extension starts with
// "x-" (Specification Extensions), and OWASP does not define either name.
export const EXTENSIONS = {
  public: 'x-public',
  admin: 'x-admin'
};

// Status code of the Too Many Requests response, which a description lists under "responses".
export const TOO_MANY_REQUESTS = '429';

// The values of "in" of a Parameter Object, as the specification lists them for the parameter location.
export const PARAM_IN = { query: 'query', header: 'header', path: 'path', cookie: 'cookie' };

// Fields whose value is data (an example, a default, a constant, an enum, the value of an Example Object): a $ref
// written inside is not a reference. And fields whose value is a map of names, where a name such as "default" is
// the name of an item and not one of these fields.
export const DATA_FIELDS = ['example', 'default', 'const', 'enum', 'value'];
export const MAP_FIELDS = ['properties', 'patternProperties', 'schemas', 'responses', 'headers', 'examples', 'parameters', 'requestBodies', 'securitySchemes', 'links', 'callbacks', 'pathItems', 'paths', 'content', 'encoding', 'variables', 'scopes'];
