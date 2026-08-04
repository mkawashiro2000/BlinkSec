'use strict';
/**
 * BlinkSec WF-00 — Gateway de ingesta.
 *
 * Se ejecuta en el nodo Code inmediatamente posterior al Webhook, ANTES de
 * cualquier lógica de negocio. Un webhook SOAR sin autenticar no es sólo una
 * fuga: quien conozca la URL puede fabricar alertas y provocar el bloqueo
 * automático de infraestructura legítima — una denegación de servicio
 * auto-infligida con la firma de la propia organización.
 *
 * Este módulo es puro (sin I/O) para poder testearse fuera de n8n. El acceso
 * a Redis vive en el workflow, no aquí.
 *
 * @injectable  — tools/build-workflows.js lo inyecta en el JSON del workflow.
 */

const crypto = require('crypto');

const HEADER_SIGNATURE = 'x-blinksec-signature';
const HEADER_TIMESTAMP = 'x-blinksec-timestamp';
const HEADER_SOURCE = 'x-blinksec-source';

const KNOWN_SOURCES = ['splunk', 'elastic'];

class GatewayRejection extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'GatewayRejection';
    this.code = code; // firma_invalida | timestamp_fuera_de_ventana | origen_desconocido | ...
    this.httpStatus = code === 'origen_desconocido' ? 400 : 401;
  }
}

/**
 * Comparación en tiempo constante.
 *
 * Una comparación con `===` filtra, por el tiempo que tarda en fallar, cuántos
 * bytes iniciales del hash acertó el atacante — suficiente para reconstruir la
 * firma byte a byte. timingSafeEqual exige buffers de igual longitud, así que
 * la comprobación de longitud va primero y de forma explícita.
 */
function safeCompare(a, b) {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Recalcula el HMAC sobre el cuerpo CRUDO.
 *
 * Éste es el error clásico que rompe toda integración de webhooks firmados:
 * usar el JSON ya parseado por n8n ($json.body). El parseo reordena claves,
 * normaliza espacios en blanco y cambia la representación de los números, de
 * modo que el hash jamás coincide con el que calculó el emisor. n8n expone el
 * cuerpo intacto en $json.rawBody sólo si el Webhook tiene rawBody activado.
 */
function computeSignature(rawBody, secret, timestamp) {
  // Se firma `timestamp.body` (esquema tipo Stripe): incluir el timestamp en
  // el material firmado impide que un atacante reutilice una firma válida con
  // un timestamp nuevo para saltarse la ventana anti-replay.
  const signedPayload = `${timestamp}.${rawBody}`;
  return crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex');
}

/**
 * Extrae el cuerpo crudo del item que entrega el nodo Webhook.
 *
 * Con la opción "Raw Body" activada, n8n **no** rellena `$json.rawBody` como
 * sugiere buena parte de la documentación: entrega el cuerpo como adjunto
 * binario en `binary.data.data`, codificado en base64. Verificado contra n8n
 * 1.72.1 — ver tests/gateway/rawbody.test.js con la carga real capturada de
 * una ejecución.
 *
 * La distinción es crítica y silenciosa: leer `$json.body` (el JSON ya
 * parseado) devuelve un objeto que al reserializar pierde el espaciado y
 * reordena claves, de modo que el HMAC NUNCA coincidiría y toda la ingesta
 * respondería 401 sin motivo aparente.
 *
 * Se admiten las dos formas para no depender de la versión de n8n.
 */
function extractRawBody(item) {
  if (!item) return '';

  // Forma 1 — n8n 1.72+: adjunto binario en base64.
  const bin = item.binary?.data;
  if (bin?.data) {
    return Buffer.from(bin.data, 'base64').toString('utf8');
  }

  // Forma 2 — algunas versiones y despliegues exponen rawBody en json.
  const json = item.json ?? item;
  if (typeof json.rawBody === 'string' && json.rawBody) return json.rawBody;
  if (Buffer.isBuffer(json.rawBody)) return json.rawBody.toString('utf8');

  return '';
}

function normalizeHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[String(k).toLowerCase()] = Array.isArray(v) ? v[0] : v;
  }
  return out;
}

/**
 * Verifica una petición de ingesta entrante.
 *
 * @param {object}  req
 * @param {object}  req.headers
 * @param {string}  req.rawBody      cuerpo sin parsear, tal cual llegó
 * @param {object}  opts
 * @param {object}  opts.secrets     { splunk, elastic }
 * @param {number}  opts.windowSeconds
 * @param {number}  opts.now         epoch en segundos (inyectable para tests)
 * @returns {{source: string, alertId: string, timestamp: number}}
 * @throws  {GatewayRejection}
 */
function verifyRequest(req, opts) {
  const headers = normalizeHeaders(req.headers);
  const windowSeconds = opts.windowSeconds ?? 300;
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  const source = String(headers[HEADER_SOURCE] || '').toLowerCase();
  if (!KNOWN_SOURCES.includes(source)) {
    throw new GatewayRejection('origen_desconocido', `Cabecera ${HEADER_SOURCE} ausente o no reconocida`);
  }

  const secret = opts.secrets?.[source];
  // Token estático: única opción para emisores que rellenan plantillas pero no
  // ejecutan código (el conector Webhook de Kibana), que por tanto no pueden
  // calcular un HMAC sobre el cuerpo. El HMAC SIEMPRE tiene prioridad: el token
  // estático sólo entra en juego si ese origen no tiene secreto de firma.
  const staticToken = secret ? null : opts.staticTokens?.[source];

  if (!secret && !staticToken) {
    // Configuración incompleta del servidor, no culpa del cliente. Se trata
    // como rechazo igualmente: sin credencial no se puede verificar nada.
    // Un origen sin secreto NI token queda deshabilitado, que es el
    // comportamiento seguro: rechazar, no aceptar cualquier cosa.
    throw new GatewayRejection('secreto_no_configurado', `No hay secreto HMAC ni token estático configurado para el origen "${source}"`);
  }

  const rawTimestamp = headers[HEADER_TIMESTAMP];
  if (!rawTimestamp) {
    throw new GatewayRejection('timestamp_ausente', `Falta la cabecera ${HEADER_TIMESTAMP}`);
  }
  const timestamp = Number(rawTimestamp);
  if (!Number.isFinite(timestamp)) {
    throw new GatewayRejection('timestamp_malformado', 'El timestamp no es numérico');
  }

  // Ventana bidireccional: un timestamp en el futuro es tan sospechoso como
  // uno viejo (reloj desincronizado o intento de alargar la validez).
  if (Math.abs(now - timestamp) > windowSeconds) {
    throw new GatewayRejection(
      'timestamp_fuera_de_ventana',
      `Desfase de ${Math.abs(now - timestamp)}s excede la ventana de ${windowSeconds}s`,
    );
  }

  const provided = headers[HEADER_SIGNATURE];
  if (!provided) {
    throw new GatewayRejection('firma_ausente', `Falta la cabecera ${HEADER_SIGNATURE}`);
  }

  const rawBody = typeof req.rawBody === 'string' ? req.rawBody : '';
  if (!rawBody) {
    // Sin cuerpo crudo no hay nada que firmar y n8n probablemente tiene
    // rawBody desactivado en el nodo Webhook. Fallar ruidosamente.
    throw new GatewayRejection('rawbody_ausente', 'rawBody vacío: ¿está activada la opción "Raw Body" en el nodo Webhook?');
  }

  // --- Vía de token estático (postura inferior, deliberada) ----------------
  // No cubre el cuerpo ni el timestamp: no protege contra manipulación del
  // payload en tránsito ni contra reenvío dentro de la ventana. Sólo impide el
  // POST anónimo. Se compensa con SIEM_ALLOWLIST estricta. Ver R-01.
  if (staticToken) {
    if (!safeCompare(provided, String(staticToken))) {
      throw new GatewayRejection('firma_invalida', 'El token estático no coincide');
    }
    return { source, timestamp, rawBody, firmado: false };
  }

  const expected = computeSignature(rawBody, secret, rawTimestamp);
  // Se admite el prefijo "sha256=" que usan varios emisores.
  const cleaned = provided.startsWith('sha256=') ? provided.slice(7) : provided;

  if (!safeCompare(cleaned, expected)) {
    throw new GatewayRejection('firma_invalida', 'La firma HMAC no coincide');
  }

  return { source, timestamp, rawBody, firmado: true };
}

// ---------------------------------------------------------------------------
// Token de reanudación del Human-in-the-Loop (WF-05)
// ---------------------------------------------------------------------------

/**
 * Token que autoriza reanudar una ejecución pausada en espera de aprobación.
 *
 * SIN esto, la URL de reanudación de n8n es adivinable: su forma es
 * `/webhook-waiting/<executionId>/<suffix>`, donde `executionId` es un entero
 * SECUENCIAL de la base de datos y `suffix` una constante. Cualquiera que
 * alcance el endpoint puede recorrer ids y aprobar contenciones ajenas — lo
 * que anula por completo el Human-in-the-Loop, que es el control central del
 * sistema. El endpoint tampoco distingue: responde 404 para un id inexistente,
 * de modo que sirve además para enumerar qué ejecuciones existen.
 *
 * El token se liga a la ejecución Y a la alerta: no vale reutilizar el de otra
 * alerta ni el de otra ejecución. Se trunca a 32 hex (128 bits) — de sobra
 * contra fuerza bruta y mantiene la URL manejable en un botón de Slack.
 */
function computeResumeToken(executionId, alertId, secret) {
  return crypto
    .createHmac('sha256', String(secret))
    .update(`${executionId}.${alertId}`, 'utf8')
    .digest('hex')
    .slice(0, 32);
}

/**
 * Verifica el token de reanudación en tiempo constante.
 *
 * Devuelve false ante cualquier duda (token ausente, secreto sin configurar,
 * longitud distinta). Quien llama DEBE tratar el false como rechazo, nunca
 * como "seguir adelante sin comprobar".
 */
function verifyResumeToken(token, executionId, alertId, secret) {
  if (!token || !secret) return false;
  return safeCompare(String(token), computeResumeToken(executionId, alertId, secret));
}

/**
 * Sanea el nombre que el aprobador declara de sí mismo en la URL.
 *
 * Es un dato AUTODECLARADO, no verificado: quien tiene el token puede escribir
 * cualquier nombre. Se acota para que no contamine el registro de auditoría ni
 * el mensaje de Slack (saltos de línea, marcado, longitud), pero el que quede
 * en `containment_log.approved_by` sigue siendo "quien dijo ser", no "quien
 * fue". Cerrarlo de verdad exige verificar la firma de Slack.
 */
function sanitizeApprover(nombre) {
  if (typeof nombre !== 'string') return null;
  const limpio = nombre.replace(/[^\w.@ -]/g, '').trim().slice(0, 64);
  return limpio || null;
}

/**
 * Identificador determinista de la alerta.
 *
 * Determinista y no aleatorio a propósito: es la clave de idempotencia. Si el
 * SIEM reenvía la misma alerta (reintento por timeout, doble configuración de
 * integración), debe producir exactamente el mismo alert_id para que WF-00 la
 * descarte en vez de abrir un segundo ticket y ejecutar la contención dos veces.
 *
 * Se incluye el timestamp del EVENTO, no el de recepción: dos ataques idénticos
 * en momentos distintos son incidentes distintos.
 */
function deriveAlertId(source, parts) {
  const material = [
    source,
    parts.ruleId ?? '',
    parts.eventTimestamp ?? '',
    parts.host ?? '',
    parts.srcIp ?? '',
  ].join('|');
  return crypto.createHash('sha256').update(material, 'utf8').digest('hex').slice(0, 32);
}

module.exports = {
  verifyRequest,
  extractRawBody,
  computeSignature,
  computeResumeToken,
  verifyResumeToken,
  sanitizeApprover,
  deriveAlertId,
  safeCompare,
  GatewayRejection,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  HEADER_SOURCE,
  KNOWN_SOURCES,
};
