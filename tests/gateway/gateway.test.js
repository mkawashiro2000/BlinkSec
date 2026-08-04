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
  splunk: 'b'.repeat(64),
  elastic: 'c'.repeat(64),
};
const NOW = 1_800_000_000; // epoch fijo para que los tests no dependan del reloj

/** Construye una petición legítima y firmada. */
function signedRequest(overrides = {}) {
  const source = overrides.source ?? 'splunk';
  const body = overrides.rawBody ?? JSON.stringify({ sid: '5710', result: { host: 'web-01' } });
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
  assert.equal(result.source, 'splunk');
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
  // Escenario real: alguien reutiliza el secreto de Elastic en el emisor de
  // Splunk. Debe fallar, no "funcionar por casualidad".
  const req = signedRequest({ source: 'splunk', secret: SECRETS.elastic });
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
  const sigOriginal = computeSignature(original, SECRETS.splunk, ts);
  const sigReserialized = computeSignature(reserialized, SECRETS.splunk, ts);
  // En este caso concreto el orden se conserva, pero basta un espacio:
  const conEspacios = '{"b": 2, "a": 1}';
  assert.notEqual(computeSignature(conEspacios, SECRETS.splunk, ts), sigOriginal);
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
    () => verifyRequest(req, { ...opts, secrets: { splunk: SECRETS.splunk } }),
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

// ---------------------------------------------------------------------------
// Token de reanudación del Human-in-the-Loop
//
// Regresión de la vulnerabilidad más grave encontrada en la auditoría: la URL
// que genera el nodo Wait es /webhook-waiting/<executionId>/<sufijo>, con un
// executionId SECUENCIAL y un sufijo constante. Sin token, cualquiera que
// alcance el endpoint recorre ids y aprueba contenciones ajenas.
// ---------------------------------------------------------------------------

const { computeResumeToken, verifyResumeToken, sanitizeApprover } = require('../../lib/gateway.js');

const SECRETO_HITL = 'd'.repeat(64);

test('el token de reanudación es determinista para la misma ejecución y alerta', () => {
  assert.equal(
    computeResumeToken(42, 'abc123', SECRETO_HITL),
    computeResumeToken(42, 'abc123', SECRETO_HITL),
  );
});

test('el token de una ejecución NO sirve para otra', () => {
  // El escenario real del ataque: capturar un token legítimo (o el propio
  // analista reutilizando una URL vieja) y aplicarlo a otra ejecución en
  // espera para aprobar una contención distinta.
  const t = computeResumeToken(42, 'abc123', SECRETO_HITL);
  assert.equal(verifyResumeToken(t, 43, 'abc123', SECRETO_HITL), false);
});

test('el token de una alerta NO sirve para otra', () => {
  const t = computeResumeToken(42, 'abc123', SECRETO_HITL);
  assert.equal(verifyResumeToken(t, 42, 'otra-alerta', SECRETO_HITL), false);
});

test('un token válido se acepta', () => {
  const t = computeResumeToken(42, 'abc123', SECRETO_HITL);
  assert.equal(verifyResumeToken(t, 42, 'abc123', SECRETO_HITL), true);
});

test('sin token, sin secreto o con basura NUNCA se aprueba', () => {
  const t = computeResumeToken(42, 'abc123', SECRETO_HITL);
  assert.equal(verifyResumeToken(null, 42, 'abc123', SECRETO_HITL), false);
  assert.equal(verifyResumeToken('', 42, 'abc123', SECRETO_HITL), false);
  assert.equal(verifyResumeToken(t, 42, 'abc123', null), false, 'sin secreto debe rechazar, no pasar');
  assert.equal(verifyResumeToken('f'.repeat(32), 42, 'abc123', SECRETO_HITL), false);
  // Longitud distinta: no debe lanzar (timingSafeEqual exige igual longitud).
  assert.equal(verifyResumeToken('corto', 42, 'abc123', SECRETO_HITL), false);
});

test('el token no se puede adivinar desde el executionId (que es secuencial)', () => {
  // Verifica que el token realmente aporta entropía: ejecuciones contiguas
  // producen tokens sin relación entre sí.
  const tokens = [1, 2, 3, 4, 5].map((id) => computeResumeToken(id, 'abc123', SECRETO_HITL));
  assert.equal(new Set(tokens).size, 5);
  for (const t of tokens) assert.match(t, /^[a-f0-9]{32}$/);
});

test('sanitizeApprover acota el nombre autodeclarado del aprobador', () => {
  // El nombre viaja en la URL y acaba en containment_log.approved_by y en
  // Slack. No es una identidad verificada, pero no puede inyectar marcado ni
  // saltos de línea en el registro de auditoría.
  assert.equal(sanitizeApprover('j.martinez@corp.com'), 'j.martinez@corp.com');
  assert.equal(sanitizeApprover('ana lopez'), 'ana lopez');
  assert.equal(sanitizeApprover('<script>alert(1)</script>'), 'scriptalert1script');
  assert.equal(sanitizeApprover('linea1\nlinea2'), 'linea1linea2');
  assert.equal(sanitizeApprover('*negrita* `code`'), 'negrita code');
  assert.equal(sanitizeApprover('x'.repeat(200)).length, 64);
  assert.equal(sanitizeApprover(''), null);
  assert.equal(sanitizeApprover(null), null);
  assert.equal(sanitizeApprover(12345), null);
});

// ---------------------------------------------------------------------------
// Token estático (Elastic)
// ---------------------------------------------------------------------------

test('acepta un token estático para un origen que no puede firmar', () => {
  // Kibana rellena plantillas pero no ejecuta código: no puede calcular un
  // HMAC. Sin esta vía la ingesta de Elastic devolvía 401 SIEMPRE.
  const req = signedRequest({ source: 'elastic' });
  req.headers['x-blinksec-signature'] = 'token-fijo-de-elastic';
  const r = verifyRequest(req, {
    ...opts,
    secrets: {},
    staticTokens: { elastic: 'token-fijo-de-elastic' },
  });
  assert.equal(r.source, 'elastic');
  assert.equal(r.firmado, false, 'debe quedar marcado como NO firmado');
});

test('el token estático incorrecto se rechaza', () => {
  const req = signedRequest({ source: 'elastic' });
  req.headers['x-blinksec-signature'] = 'token-equivocado';
  assert.throws(
    () => verifyRequest(req, { ...opts, secrets: {}, staticTokens: { elastic: 'token-bueno' } }),
    (e) => e.code === 'firma_invalida',
  );
});

test('el token estático sigue sujeto a la ventana anti-replay', () => {
  const req = signedRequest({ source: 'elastic', timestamp: NOW - 301 });
  req.headers['x-blinksec-signature'] = 'token-fijo';
  assert.throws(
    () => verifyRequest(req, { ...opts, secrets: {}, staticTokens: { elastic: 'token-fijo' } }),
    (e) => e.code === 'timestamp_fuera_de_ventana',
  );
});

test('el HMAC tiene prioridad sobre el token estático', () => {
  // Si un origen tiene secreto de firma, el token estático NO debe abrir una
  // vía más débil en paralelo.
  const req = signedRequest({ source: 'elastic' });
  req.headers['x-blinksec-signature'] = 'token-fijo';
  assert.throws(
    () => verifyRequest(req, { ...opts, staticTokens: { elastic: 'token-fijo' } }),
    (e) => e.code === 'firma_invalida',
  );
});

test('un origen sin secreto NI token queda deshabilitado, no abierto', () => {
  // Con BLINKSEC_STATIC_TOKEN_ELASTIC vacío, Elastic debe rechazar todo — el
  // fallo seguro es no ingerir, nunca aceptar sin verificar.
  const req = signedRequest({ source: 'elastic' });
  assert.throws(
    () => verifyRequest(req, { ...opts, secrets: {}, staticTokens: { elastic: '' } }),
    (e) => e.code === 'secreto_no_configurado',
  );
});

test('una petición firmada correctamente se marca como firmada', () => {
  assert.equal(verifyRequest(signedRequest(), opts).firmado, true);
});
