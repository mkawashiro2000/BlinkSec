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

const KNOWN_SOURCES = ['wazuh', 'splunk', 'elastic'];

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
 * @param {object}  opts.secrets     { wazuh, splunk, elastic }
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
  if (!secret) {
    // Configuración incompleta del servidor, no culpa del cliente. Se trata
    // como rechazo igualmente: sin secreto no se puede verificar nada.
    throw new GatewayRejection('secreto_no_configurado', `No hay secreto HMAC configurado para el origen "${source}"`);
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

  const expected = computeSignature(rawBody, secret, rawTimestamp);
  // Se admite el prefijo "sha256=" que usan varios emisores.
  const cleaned = provided.startsWith('sha256=') ? provided.slice(7) : provided;

  if (!safeCompare(cleaned, expected)) {
    throw new GatewayRejection('firma_invalida', 'La firma HMAC no coincide');
  }

  return { source, timestamp, rawBody };
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
  computeSignature,
  deriveAlertId,
  safeCompare,
  GatewayRejection,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  HEADER_SOURCE,
  KNOWN_SOURCES,
};
