'use strict';
/**
 * BlinkSec WF-02 — Enriquecimiento con inteligencia de amenazas.
 *
 * Las llamadas HTTP las hacen los nodos HTTP Request de n8n en paralelo; este
 * módulo contiene lo que sí es testeable en frío: el parseo de cada respuesta
 * a una forma común, la política de caché y el manejo de proveedores caídos.
 *
 * Decisión central: el enriquecimiento es DEGRADABLE. Con proveedores caídos
 * el sistema sigue produciendo un veredicto, pero lo marca como parcial —
 * y WF-03 impone un techo de puntuación para que un enriquecimiento
 * incompleto no pueda disparar contención automática. Es preferible escalar
 * a un humano de más que aislar un servidor porque VirusTotal devolvió 503.
 *
 * Proveedores: AbuseIPDB, VirusTotal y CrowdSec CTI. GreyNoise e IBM X-Force
 * se retiraron del sistema — nunca llegó a haber credenciales operativas
 * para ninguno de los dos (GreyNoise sin clave real conectada; X-Force con
 * un 401 que se confirmó como problema de la propia cuenta de IBM, no de
 * este sistema). CrowdSec CTI las sustituye como tercera fuente para IPs
 * (no resuelve hashes, igual que AbuseIPDB). Ver docs/riesgos.md.
 *
 * @injectable
 */

/** TTL de caché en segundos, por tipo de veredicto. */
const CACHE_TTL = {
  // Un IoC limpio puede ensuciarse: TTL corto.
  clean: 3600,
  // Un IoC malicioso rara vez se vuelve benigno: TTL largo, y es el caso que
  // más consultas repetidas genera (misma botnet atacando en ráfaga).
  malicious: 86400,
  // Sin datos suficientes: reintentar pronto.
  inconclusive: 900,
  // Error del proveedor: no envenenar la caché con un fallo transitorio.
  error: 60,
};

const PROVIDERS = ['virustotal', 'abuseipdb', 'crowdsec'];

function cacheKey(provider, iocType, value) {
  return `blinksec:ioc:${provider}:${iocType}:${String(value).toLowerCase()}`;
}

/** Envoltura uniforme para cualquier respuesta de proveedor. */
function wrap(provider, { available, verdict = 'inconclusive', data = {}, error = null }) {
  return { provider, available, verdict, data, error };
}

// ---------------------------------------------------------------------------
// VirusTotal — API v3
// ---------------------------------------------------------------------------

function parseVirusTotal(res, httpStatus = 200) {
  // 404 = hash/IP desconocido para VT. Ausencia de evidencia, no evidencia de
  // ausencia: un binario de malware a medida nunca estará en VT.
  if (httpStatus === 404) {
    return wrap('virustotal', { available: true, verdict: 'unknown', data: { known: false } });
  }
  // 429 = cuota agotada. El free tier son 4 req/min: en una ráfaga de alertas
  // esto es lo normal, no lo excepcional. Por eso existe la caché.
  if (httpStatus === 429) {
    return wrap('virustotal', { available: false, error: 'rate_limited' });
  }
  if (httpStatus !== 200 || !res) {
    return wrap('virustotal', { available: false, error: `HTTP ${httpStatus}` });
  }

  const stats = res.data?.attributes?.last_analysis_stats ?? {};
  const malicious = Number(stats.malicious ?? 0);
  const suspicious = Number(stats.suspicious ?? 0);
  const harmless = Number(stats.harmless ?? 0);
  const undetected = Number(stats.undetected ?? 0);
  const total = malicious + suspicious + harmless + undetected;

  const attrs = res.data?.attributes ?? {};
  const data = {
    known: true,
    malicious,
    suspicious,
    total,
    ratio: total > 0 ? malicious / total : 0,
    // El nombre de familia que da el consenso, útil para el ticket.
    popularName: attrs.popular_threat_classification?.suggested_threat_label ?? null,
    reputation: attrs.reputation ?? null,
  };

  let verdict = 'inconclusive';
  if (total === 0) verdict = 'unknown';
  else if (malicious >= 5) verdict = 'malicious';
  else if (malicious >= 1) verdict = 'suspicious';
  else verdict = 'clean';

  return wrap('virustotal', { available: true, verdict, data });
}

// ---------------------------------------------------------------------------
// AbuseIPDB — API v2
// ---------------------------------------------------------------------------

function parseAbuseIPDB(res, httpStatus = 200) {
  if (httpStatus === 429) {
    return wrap('abuseipdb', { available: false, error: 'rate_limited' });
  }
  if (httpStatus !== 200 || !res?.data) {
    return wrap('abuseipdb', { available: false, error: `HTTP ${httpStatus}` });
  }

  const d = res.data;
  const score = Number(d.abuseConfidenceScore ?? 0);
  const data = {
    abuseConfidenceScore: score,
    totalReports: Number(d.totalReports ?? 0),
    distinctReporters: Number(d.numDistinctUsers ?? 0),
    countryCode: d.countryCode ?? null,
    isp: d.isp ?? null,
    usageType: d.usageType ?? null,
    lastReportedAt: d.lastReportedAt ?? null,
    // Una IP dentro de la propia allowlist de AbuseIPDB del usuario.
    isWhitelisted: d.isWhitelisted === true,
  };

  let verdict = 'clean';
  if (d.isWhitelisted === true) verdict = 'benign';
  else if (score >= 75) verdict = 'malicious';
  else if (score >= 25) verdict = 'suspicious';
  else if (score > 0) verdict = 'inconclusive';

  return wrap('abuseipdb', { available: true, verdict, data });
}

// ---------------------------------------------------------------------------
// CrowdSec CTI — /v2/smoke/{ip}
// ---------------------------------------------------------------------------

function parseCrowdSec(res, httpStatus = 200) {
  // 404 = IP nunca reportada a la red de CrowdSec. Ausencia de evidencia, no
  // evidencia de ausencia — igual que un hash desconocido para VirusTotal.
  if (httpStatus === 404) {
    return wrap('crowdsec', { available: true, verdict: 'unknown', data: { known: false } });
  }
  if (httpStatus === 429) {
    return wrap('crowdsec', { available: false, error: 'rate_limited' });
  }
  if (httpStatus !== 200 || !res) {
    return wrap('crowdsec', { available: false, error: `HTTP ${httpStatus}` });
  }

  // Escala 0-5 de CrowdSec CTI: cuánto de agresiva/amenazante es la IP según
  // el consenso de la red de sensores CrowdSec.
  const threat = Number(res.scores?.overall?.threat ?? 0);
  const aggressiveness = Number(res.scores?.overall?.aggressiveness ?? 0);
  const clasificaciones = (res.classifications?.classifications ?? []).map((c) => c.label ?? c.name).filter(Boolean);

  const data = {
    known: true,
    threat,
    aggressiveness,
    classifications: clasificaciones,
    backgroundNoise: res.background_noise_score != null ? Number(res.background_noise_score) : null,
  };

  let verdict = 'clean';
  if (threat >= 3 || clasificaciones.length > 0) verdict = 'malicious';
  else if (threat >= 1 || aggressiveness >= 1) verdict = 'suspicious';

  return wrap('crowdsec', { available: true, verdict, data });
}

// ---------------------------------------------------------------------------
// Agregación
// ---------------------------------------------------------------------------

const PARSERS = {
  virustotal: parseVirusTotal,
  abuseipdb: parseAbuseIPDB,
  crowdsec: parseCrowdSec,
};

/**
 * Consolida las respuestas de los nodos HTTP paralelos.
 *
 * Cada entrada es { provider, body, statusCode } tal y como la deja n8n con
 * "Continue on Fail" y "Never Error" activados — un proveedor caído llega
 * aquí como un statusCode != 200, no como una excepción que aborte el flujo.
 */
function aggregate(responses) {
  const enrichment = {};
  for (const provider of PROVIDERS) enrichment[provider] = wrap(provider, { available: false, error: 'no_consultado' });

  for (const r of responses ?? []) {
    const parser = PARSERS[r.provider];
    if (!parser) continue;
    try {
      enrichment[r.provider] = parser(r.body, r.statusCode ?? 200);
    } catch (e) {
      // Un cambio de esquema del proveedor no puede tumbar el SOAR entero.
      enrichment[r.provider] = wrap(r.provider, { available: false, error: `parse_error: ${e.message}` });
    }
  }

  // Se acota a proveedores conocidos: una errata en el nombre dentro del
  // workflow no debe crashear la agregación y con ella toda la ejecución.
  const consultados = (responses ?? []).map((r) => r.provider).filter((p) => PROVIDERS.includes(p));
  const ok = PROVIDERS.filter((p) => enrichment[p].available);
  const fallidos = consultados.filter((p) => !enrichment[p].available);

  return {
    ...enrichment,
    _meta: {
      providersOk: ok.length,
      providersFailed: fallidos.length,
      failed: fallidos,
      // "Parcial" significa: alguno de los proveedores que SÍ se consultó no
      // respondió. Que no se consulte VirusTotal porque la alerta no tiene
      // hashes no es una degradación.
      partial: fallidos.length > 0,
    },
  };
}

/** TTL que corresponde a un veredicto ya parseado. */
function ttlFor(result) {
  if (!result.available) return CACHE_TTL.error;
  if (['malicious', 'suspicious'].includes(result.verdict)) return CACHE_TTL.malicious;
  if (['clean', 'benign'].includes(result.verdict)) return CACHE_TTL.clean;
  return CACHE_TTL.inconclusive;
}

module.exports = {
  parseVirusTotal,
  parseAbuseIPDB,
  parseCrowdSec,
  aggregate,
  cacheKey,
  ttlFor,
  CACHE_TTL,
  PROVIDERS,
};
