'use strict';
/**
 * BlinkSec WF-01 — Normalización.
 *
 * Convierte los esquemas heterogéneos de Splunk y Elastic en un único
 * contrato interno. Éste es el punto de desacople del sistema: todo lo que
 * está aguas abajo (enriquecimiento, scoring, contención) opera sobre el
 * esquema normalizado y no sabe de qué plataforma vino la alerta. Añadir un
 * tercer SIEM significa escribir un normalizador aquí y nada más.
 *
 * Wazuh se retiró como fuente de ingesta — ver docs/riesgos.md (R-19).
 *
 * Principio de diseño: los datos entrantes NUNCA son perfectos. Faltan campos,
 * llegan tipos inesperados y las plataformas cambian su formato entre
 * versiones. Este módulo falla de forma ruidosa y explícita, nunca propaga
 * `undefined` hacia una llamada de API que fallará de forma asíncrona e
 * indepurable tres nodos más adelante.
 *
 * @injectable
 */

const BLINKSEC_VERSION = '1.0';

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const HASH_RE = { md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i };
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

class NormalizationError extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'NormalizationError';
    this.details = details;
  }
}

// ---------------------------------------------------------------------------
// Utilidades de saneado
// ---------------------------------------------------------------------------

/** Acceso seguro a rutas anidadas: 'data.srcip' -> valor o undefined. */
function dig(obj, path) {
  return String(path)
    .split('.')
    .reduce((acc, k) => (acc == null ? undefined : acc[k]), obj);
}

/** Primer valor definido y no vacío de una lista de rutas candidatas. */
function firstOf(obj, paths) {
  for (const p of paths) {
    const v = dig(obj, p);
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

function isPublicIPv4(value) {
  if (typeof value !== 'string' || !IPV4_RE.test(value)) return false;
  const [a, b] = value.split('.').map(Number);
  if (a === 10) return false;                       // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC1918
  if (a === 192 && b === 168) return false;          // RFC1918
  if (a === 127) return false;                       // loopback
  if (a === 169 && b === 254) return false;          // link-local
  if (a === 0 || a >= 224) return false;             // reservado / multicast
  return true;
}

function classifyHash(value) {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  for (const [type, re] of Object.entries(HASH_RE)) {
    if (re.test(v)) return { value: v.toLowerCase(), type };
  }
  return null;
}

/**
 * Saneador de payloads sintácticamente irregulares.
 *
 * Elastic serializa alertas múltiples de formas que NO son JSON válido:
 *   - ndjson:            {...}\n{...}
 *   - coma terminal:     [{...},{...},]
 * Ambos casos revientan JSON.parse. Antes que fallar toda la ingesta por un
 * detalle de serialización aguas arriba, se recuperan aquí; el arreglo real
 * es del lado de Elastic (`.asJSON` / `{{#ParseHjson}}` en la plantilla
 * Mustache), pero el SOAR no puede depender de que alguien lo configure bien.
 */
function parseLoose(raw) {
  if (typeof raw !== 'string') return raw;
  const text = raw.trim();
  if (!text) throw new NormalizationError('Cuerpo vacío');

  try {
    return JSON.parse(text);
  } catch (_) {
    /* se intentan las recuperaciones de abajo */
  }

  // Coma terminal en arrays u objetos: [{},{},]  /  {"a":1,}
  const sinComaFinal = text.replace(/,\s*([\]}])/g, '$1');
  try {
    return JSON.parse(sinComaFinal);
  } catch (_) {
    /* siguiente intento */
  }

  // ndjson: una alerta por línea.
  const lineas = text.split('\n').map((l) => l.trim()).filter(Boolean);
  if (lineas.length > 1) {
    const objetos = [];
    for (const linea of lineas) {
      try {
        objetos.push(JSON.parse(linea.replace(/,\s*([\]}])/g, '$1')));
      } catch (_) {
        // Una línea corrupta no invalida el lote entero; se descarta y se
        // deja constancia en el resultado.
        objetos.push({ __blinksec_parse_error: linea.slice(0, 200) });
      }
    }
    if (objetos.some((o) => !o.__blinksec_parse_error)) return objetos;
  }

  throw new NormalizationError('No se pudo parsear el payload ni como JSON, ni con coma terminal, ni como ndjson', {
    preview: text.slice(0, 300),
  });
}

// ---------------------------------------------------------------------------
// Normalizadores por plataforma
// ---------------------------------------------------------------------------

function normalizeSplunk(a) {
  // La acción de alerta de Splunk envuelve la primera fila del evento en
  // `result`; con Better Webhooks el token $$full_result$$ puede traer más.
  const r = a.result ?? a._result ?? a;
  const ips = [];
  const srcIp = firstOf(r, ['src_ip', 'src', 'clientip']);
  const dstIp = firstOf(r, ['dest_ip', 'dest']);
  if (isPublicIPv4(srcIp)) ips.push({ value: srcIp, direction: 'src' });
  if (isPublicIPv4(dstIp)) ips.push({ value: dstIp, direction: 'dst' });

  const hashes = [];
  for (const p of ['file_hash', 'sha256', 'md5', 'process_hash']) {
    const h = classifyHash(dig(r, p));
    if (h) hashes.push(h);
  }

  return {
    source: 'splunk',
    rule: {
      id: String(firstOf(a, ['sid', 'search_name']) ?? ''),
      name: firstOf(a, ['search_name']) ?? '',
      // Splunk no expone un "level" comparable; se mapea la urgencia de ES
      // si existe, y si no se asume media (8) para no inflar la puntuación.
      level: mapSplunkUrgency(firstOf(r, ['urgency', 'severity'])),
      mitre: toArray(firstOf(r, ['annotations.mitre_attack', 'mitre_technique_id'])),
    },
    asset: {
      host: firstOf(r, ['host', 'dest', 'dest_nt_host']) ?? '',
      ip: isPublicIPv4(dstIp) ? dstIp : (firstOf(r, ['dest_ip']) ?? null),
    },
    identity: { user: firstOf(r, ['user', 'src_user']) ?? null, domain: firstOf(r, ['user_domain']) ?? null },
    artifacts: { ips, hashes, domains: [], urls: [] },
    eventTimestamp: firstOf(r, ['_time']) ?? firstOf(a, ['result._time']) ?? null,
    resultsLink: firstOf(a, ['results_link']) ?? null,
  };
}

function mapSplunkUrgency(u) {
  const m = { informational: 3, low: 5, medium: 8, high: 12, critical: 14 };
  if (typeof u === 'number') return u;
  return m[String(u ?? '').toLowerCase()] ?? 8;
}

function toArray(v) {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

function normalizeElastic(a) {
  const ctx = a.context ?? a;
  const ips = [];
  const srcIp = firstOf(ctx, ['source.ip', 'src_ip', 'client.ip']);
  const dstIp = firstOf(ctx, ['destination.ip', 'dest_ip', 'server.ip']);
  if (isPublicIPv4(srcIp)) ips.push({ value: srcIp, direction: 'src' });
  if (isPublicIPv4(dstIp)) ips.push({ value: dstIp, direction: 'dst' });

  const hashes = [];
  for (const p of ['file.hash.sha256', 'file.hash.md5', 'file.hash.sha1', 'process.hash.sha256']) {
    const h = classifyHash(dig(ctx, p));
    if (h) hashes.push(h);
  }

  return {
    source: 'elastic',
    rule: {
      id: String(firstOf(ctx, ['rule.id', 'kibana.alert.rule.uuid']) ?? ''),
      name: firstOf(ctx, ['rule.name', 'kibana.alert.rule.name']) ?? '',
      level: mapElasticSeverity(firstOf(ctx, ['rule.severity', 'kibana.alert.severity', 'event.severity'])),
      mitre: toArray(firstOf(ctx, ['rule.threat.technique.id'])),
    },
    asset: {
      host: firstOf(ctx, ['host.name', 'host.hostname', 'agent.name']) ?? '',
      ip: firstOf(ctx, ['host.ip']) ?? null,
    },
    identity: { user: firstOf(ctx, ['user.name']) ?? null, domain: firstOf(ctx, ['user.domain']) ?? null },
    artifacts: { ips, hashes, domains: [], urls: [] },
    eventTimestamp: firstOf(ctx, ['@timestamp', 'event.created']) ?? null,
  };
}

function mapElasticSeverity(s) {
  const m = { low: 5, medium: 8, high: 12, critical: 14 };
  if (typeof s === 'number') return Math.min(15, Math.max(0, s));
  return m[String(s ?? '').toLowerCase()] ?? 8;
}

const NORMALIZERS = { splunk: normalizeSplunk, elastic: normalizeElastic };

// ---------------------------------------------------------------------------
// Entrada pública
// ---------------------------------------------------------------------------

/**
 * Valida el resultado antes de dejarlo pasar aguas abajo.
 *
 * Una alerta sin artefactos no es enriquecible: no tiene ni IP ni hash que
 * consultar. Se deja pasar igualmente (puede ser una alerta legítima de
 * comportamiento, ej. escalada de privilegios local) pero se marca, y WF-03
 * la envía a investigación humana en lugar de intentar puntuarla.
 */
function validate(n) {
  const problemas = [];
  if (!n.asset.host) problemas.push('asset.host ausente');
  if (!n.rule.id) problemas.push('rule.id ausente');
  if (!Number.isFinite(n.rule.level)) problemas.push('rule.level no numérico');

  const totalArtefactos =
    n.artifacts.ips.length + n.artifacts.hashes.length + n.artifacts.domains.length + n.artifacts.urls.length;

  return {
    ok: problemas.length === 0,
    problemas,
    enriquecible: totalArtefactos > 0,
  };
}

/**
 * @param {string} source  'splunk' | 'elastic'
 * @param {object|string} payload  objeto ya parseado, o texto crudo
 * @returns {object[]} una o varias alertas normalizadas
 */
function normalize(source, payload) {
  const fn = NORMALIZERS[source];
  if (!fn) throw new NormalizationError(`No hay normalizador para el origen "${source}"`);

  const parsed = parseLoose(payload);
  const lote = Array.isArray(parsed) ? parsed : [parsed];

  return lote
    .filter((item) => item && !item.__blinksec_parse_error)
    .map((item) => {
      const n = fn(item);
      const v = validate(n);
      return {
        blinksec_version: BLINKSEC_VERSION,
        received_at: new Date().toISOString(),
        ...n,
        // asset.criticality lo rellena WF-01 consultando blinksec.assets;
        // aquí se deja el valor conservador para que, si esa consulta falla,
        // el sistema NO trate un activo desconocido como prescindible.
        asset: { ...n.asset, criticality: 'high' },
        validation: v,
        raw: item,
      };
    });
}

module.exports = {
  normalize,
  parseLoose,
  validate,
  isPublicIPv4,
  classifyHash,
  dig,
  firstOf,
  NormalizationError,
  BLINKSEC_VERSION,
};
