'use strict';
/**
 * Tests del gateway de ingesta (WF-00).
 *
 * Estos son deliberadamente tests NEGATIVOS en su mayoría: el camino feliz de
 * un webhook es trivial, y lo que hunde un SOAR es aceptar algo que debió
 * rechazar. Cada test corresponde a un vector de ataque concreto.
 *
 *   node --test tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  verifyRequest,
  computeSignature,
  deriveAlertId,
  safeCompare,
  GatewayRejection,
} = require('../../lib/gateway.js');

const SECRETS = {
  wazuh: 'a'.repeat(64),
  splunk: 'b'.repeat(64),
  elastic: 'c'.repeat(64),
};
const NOW = 1_800_000_000; // epoch fijo para que los tests no dependan del reloj

/** Construye una petición legítima y firmada. */
function signedRequest(overrides = {}) {
  const source = overrides.source ?? 'wazuh';
  const body = overrides.rawBody ?? JSON.stringify({ rule: { id: '5710' }, agent: { name: 'web-01' } });
  const timestamp = String(overrides.timestamp ?? NOW);
  const secret = overrides.secret ?? SECRETS[source];
  const signature = overrides.signature ?? computeSignature(body, secret, timestamp);

  return {
    headers: {
      'x-blinksec-source': source,
      'x-blinksec-timestamp': timestamp,
      'x-blinksec-signature': signature,
      ...(overrides.headers ?? {}),
    },
    rawBody: body,
  };
}

const opts = { secrets: SECRETS, windowSeconds: 300, now: NOW };

// ---------------------------------------------------------------------------
// Camino feliz
// ---------------------------------------------------------------------------

test('acepta una petición correctamente firmada', () => {
  const result = verifyRequest(signedRequest(), opts);
  assert.equal(result.source, 'wazuh');
  assert.equal(result.timestamp, NOW);
});

test('acepta la firma con el prefijo sha256=', () => {
  const req = signedRequest();
  req.headers['x-blinksec-signature'] = 'sha256=' + req.headers['x-blinksec-signature'];
  assert.doesNotThrow(() => verifyRequest(req, opts));
});

test('las cabeceras son insensibles a mayúsculas', () => {
  const req = signedRequest();
  req.headers = {
    'X-BlinkSec-Source': req.headers['x-blinksec-source'],
    'X-BLINKSEC-TIMESTAMP': req.headers['x-blinksec-timestamp'],
    'X-Blinksec-Signature': req.headers['x-blinksec-signature'],
  };
  assert.doesNotThrow(() => verifyRequest(req, opts));
});

// ---------------------------------------------------------------------------
// Firma
// ---------------------------------------------------------------------------

test('rechaza una firma incorrecta', () => {
  const req = signedRequest({ signature: 'f'.repeat(64) });
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'firma_invalida');
});

test('rechaza una petición sin firma', () => {
  const req = signedRequest();
  delete req.headers['x-blinksec-signature'];
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'firma_ausente');
});

test('rechaza una firma calculada con el secreto de otro origen', () => {
  // Escenario real: alguien reutiliza el secreto de Splunk en el emisor de
  // Wazuh. Debe fallar, no "funcionar por casualidad".
  const req = signedRequest({ source: 'wazuh', secret: SECRETS.splunk });
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'firma_invalida');
});

test('rechaza si el cuerpo fue modificado tras firmarlo', () => {
  const req = signedRequest();
  // Un atacante intercepta y cambia la IP a bloquear por la del gateway
  // corporativo. La firma ya no cuadra.
  req.rawBody = req.rawBody.replace('web-01', 'dc-01');
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'firma_invalida');
});

test('la firma cubre el timestamp, no sólo el cuerpo', () => {
  // Sin incluir el timestamp en el material firmado, un atacante podría
  // capturar una petición válida y reenviarla más tarde con un timestamp
  // fresco, saltándose por completo la protección anti-replay.
  const req = signedRequest();
  req.headers['x-blinksec-timestamp'] = String(NOW + 10);
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'firma_invalida');
});

test('rechaza si falta rawBody (Raw Body desactivado en el nodo Webhook)', () => {
  const req = signedRequest();
  req.rawBody = '';
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'rawbody_ausente');
});

test('el cuerpo parseado y reserializado NO valida — rawBody es obligatorio', () => {
  // Documenta el fallo más común de integración: n8n parsea el JSON, se
  // reordenan las claves y se pierden los espacios, y el hash cambia.
  const original = '{"b":2,"a":1}';
  const reserialized = JSON.stringify(JSON.parse(original)); // -> {"b":2,"a":1} u orden distinto
  const ts = String(NOW);
  const sigOriginal = computeSignature(original, SECRETS.wazuh, ts);
  const sigReserialized = computeSignature(reserialized, SECRETS.wazuh, ts);
  // En este caso concreto el orden se conserva, pero basta un espacio:
  const conEspacios = '{"b": 2, "a": 1}';
  assert.notEqual(computeSignature(conEspacios, SECRETS.wazuh, ts), sigOriginal);
  assert.equal(sigReserialized, sigOriginal); // mismo texto -> mismo hash
});

// ---------------------------------------------------------------------------
// Replay / timestamp
// ---------------------------------------------------------------------------

test('rechaza un timestamp más viejo que la ventana', () => {
  const req = signedRequest({ timestamp: NOW - 301 });
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'timestamp_fuera_de_ventana');
});

test('acepta un timestamp justo en el borde de la ventana', () => {
  const req = signedRequest({ timestamp: NOW - 300 });
  assert.doesNotThrow(() => verifyRequest(req, opts));
});

test('rechaza un timestamp en el futuro fuera de ventana', () => {
  // Reloj desincronizado o intento de prolongar artificialmente la validez.
  const req = signedRequest({ timestamp: NOW + 600 });
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'timestamp_fuera_de_ventana');
});

test('rechaza un timestamp no numérico', () => {
  const req = signedRequest();
  req.headers['x-blinksec-timestamp'] = 'ayer';
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'timestamp_malformado');
});

test('rechaza una petición sin timestamp', () => {
  const req = signedRequest();
  delete req.headers['x-blinksec-timestamp'];
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'timestamp_ausente');
});

// ---------------------------------------------------------------------------
// Origen
// ---------------------------------------------------------------------------

test('rechaza un origen desconocido', () => {
  const req = signedRequest();
  req.headers['x-blinksec-source'] = 'chatgpt';
  assert.throws(() => verifyRequest(req, opts), (e) => e.code === 'origen_desconocido');
});

test('rechaza si no hay secreto configurado para el origen', () => {
  const req = signedRequest({ source: 'elastic' });
  assert.throws(
    () => verifyRequest(req, { ...opts, secrets: { wazuh: SECRETS.wazuh } }),
    (e) => e.code === 'secreto_no_configurado',
  );
});

test('el rechazo por origen desconocido devuelve 400, el resto 401', () => {
  const desconocido = new GatewayRejection('origen_desconocido', 'x');
  const firma = new GatewayRejection('firma_invalida', 'x');
  assert.equal(desconocido.httpStatus, 400);
  assert.equal(firma.httpStatus, 401);
});

// ---------------------------------------------------------------------------
// Comparación en tiempo constante
// ---------------------------------------------------------------------------

test('safeCompare devuelve false ante longitudes distintas sin lanzar', () => {
  // crypto.timingSafeEqual lanza si los buffers difieren en longitud; el
  // wrapper debe absorberlo, no propagar la excepción.
  assert.equal(safeCompare('abc', 'abcdef'), false);
  assert.equal(safeCompare('', 'a'), false);
});

test('safeCompare es correcto para iguales y distintos de misma longitud', () => {
  assert.equal(safeCompare('deadbeef', 'deadbeef'), true);
  assert.equal(safeCompare('deadbeef', 'deadbeee'), false);
});

// ---------------------------------------------------------------------------
// Idempotencia
// ---------------------------------------------------------------------------

test('deriveAlertId es determinista para la misma alerta', () => {
  const parts = { ruleId: '5710', eventTimestamp: '2026-08-02T10:00:00Z', host: 'web-01', srcIp: '1.2.3.4' };
  assert.equal(deriveAlertId('wazuh', parts), deriveAlertId('wazuh', parts));
});

test('deriveAlertId distingue eventos en momentos distintos', () => {
  const base = { ruleId: '5710', host: 'web-01', srcIp: '1.2.3.4' };
  const a = deriveAlertId('wazuh', { ...base, eventTimestamp: '2026-08-02T10:00:00Z' });
  const b = deriveAlertId('wazuh', { ...base, eventTimestamp: '2026-08-02T11:00:00Z' });
  assert.notEqual(a, b);
});

test('deriveAlertId distingue hosts y orígenes distintos', () => {
  const base = { ruleId: '5710', eventTimestamp: 'T', srcIp: '1.2.3.4' };
  assert.notEqual(deriveAlertId('wazuh', { ...base, host: 'a' }), deriveAlertId('wazuh', { ...base, host: 'b' }));
  assert.notEqual(deriveAlertId('wazuh', { ...base, host: 'a' }), deriveAlertId('splunk', { ...base, host: 'a' }));
});

test('deriveAlertId tolera campos ausentes sin colisionar', () => {
  // Un campo ausente no debe producir el mismo id que otro campo ausente en
  // otra posición (el separador "|" lo garantiza).
  const a = deriveAlertId('wazuh', { ruleId: 'x', host: undefined });
  const b = deriveAlertId('wazuh', { ruleId: undefined, host: 'x' });
  assert.notEqual(a, b);
});
