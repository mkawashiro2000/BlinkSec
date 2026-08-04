'use strict';
/**
 * Extracción del cuerpo crudo del nodo Webhook.
 *
 * Estos tests nacen de un fallo encontrado en el primer despliegue real, no de
 * un supuesto teórico. Con la opción "Raw Body" activada, n8n 1.72.1 **no**
 * rellena `$json.rawBody`: entrega el cuerpo como adjunto binario en base64.
 *
 * El síntoma en producción era un 401 `rawbody_ausente` en cada petición,
 * indistinguible a simple vista de un secreto HMAC mal configurado. Se habrían
 * perdido horas revisando secretos correctos.
 *
 * La carga de `ITEM_REAL_N8N_1_72` está copiada literalmente de una ejecución
 * capturada de la base de datos de n8n.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { extractRawBody, verifyRequest, computeSignature } = require('../../lib/gateway.js');

// Cuerpo con espaciado e indentación deliberados: si algo lo reserializa, el
// HMAC cambia. Es exactamente el escenario que rompe la verificación.
const CUERPO_ORIGINAL = '{\n  "rule": { "id": "5712" },\n  "data": { "srcip": "45.155.205.233" }\n}';

const ITEM_REAL_N8N_1_72 = {
  json: {
    headers: { 'content-type': 'application/json', 'x-blinksec-source': 'splunk' },
    params: {},
    query: {},
    body: { rule: { id: '5712' }, data: { srcip: '45.155.205.233' } },
    webhookUrl: 'https://localhost/webhook/blinksec/ingest',
    executionMode: 'production',
  },
  binary: {
    data: {
      data: Buffer.from(CUERPO_ORIGINAL, 'utf8').toString('base64'),
      mimeType: 'application/json',
    },
  },
};

test('extrae el cuerpo del adjunto binario (forma de n8n 1.72)', () => {
  assert.equal(extractRawBody(ITEM_REAL_N8N_1_72), CUERPO_ORIGINAL);
});

test('el cuerpo extraído conserva el espaciado byte a byte', () => {
  // La propiedad de la que depende toda la verificación HMAC.
  const extraido = extractRawBody(ITEM_REAL_N8N_1_72);
  assert.ok(extraido.includes('\n  "rule"'), 'se perdió la indentación');
  assert.equal(extraido.length, CUERPO_ORIGINAL.length);
});

test('acepta también la forma json.rawBody de otras versiones', () => {
  assert.equal(extractRawBody({ json: { rawBody: CUERPO_ORIGINAL } }), CUERPO_ORIGINAL);
});

test('acepta un rawBody entregado como Buffer', () => {
  const item = { json: { rawBody: Buffer.from(CUERPO_ORIGINAL, 'utf8') } };
  assert.equal(extractRawBody(item), CUERPO_ORIGINAL);
});

test('prefiere el binario cuando están las dos formas', () => {
  // El binario es la fuente fiable; json.rawBody podría venir de un nodo
  // intermedio que ya manipuló el contenido.
  const item = {
    json: { rawBody: 'cuerpo-manipulado' },
    binary: { data: { data: Buffer.from(CUERPO_ORIGINAL).toString('base64') } },
  };
  assert.equal(extractRawBody(item), CUERPO_ORIGINAL);
});

test('devuelve cadena vacía si no hay cuerpo crudo por ningún lado', () => {
  // Debe degradar a '' para que verifyRequest lance el rechazo explícito
  // 'rawbody_ausente', en vez de reventar con un TypeError indepurable.
  assert.equal(extractRawBody({ json: { body: { a: 1 } } }), '');
  assert.equal(extractRawBody({}), '');
  assert.equal(extractRawBody(null), '');
});

test('el JSON parseado NO sirve para verificar: reserializarlo rompe la firma', () => {
  // Demostración del fallo que motiva todo este módulo.
  const secreto = 'a'.repeat(64);
  const ts = '1800000000';

  const firmaCorrecta = computeSignature(CUERPO_ORIGINAL, secreto, ts);
  const reserializado = JSON.stringify(ITEM_REAL_N8N_1_72.json.body);

  assert.notEqual(reserializado, CUERPO_ORIGINAL, 'el reserializado debería diferir');
  assert.notEqual(computeSignature(reserializado, secreto, ts), firmaCorrecta);
});

test('verifyRequest valida usando el cuerpo extraído del binario', () => {
  // Camino completo tal y como corre dentro del nodo Code de WF-00.
  const secreto = 'b'.repeat(64);
  const ts = String(Math.floor(Date.now() / 1000));
  const firma = computeSignature(CUERPO_ORIGINAL, secreto, ts);

  const item = {
    ...ITEM_REAL_N8N_1_72,
    json: {
      ...ITEM_REAL_N8N_1_72.json,
      headers: {
        'x-blinksec-source': 'splunk',
        'x-blinksec-timestamp': ts,
        'x-blinksec-signature': `sha256=${firma}`,
      },
    },
  };

  const resultado = verifyRequest(
    { headers: item.json.headers, rawBody: extractRawBody(item) },
    { secrets: { splunk: secreto }, windowSeconds: 300 },
  );

  assert.equal(resultado.source, 'splunk');
  assert.equal(resultado.rawBody, CUERPO_ORIGINAL);
});
