'use strict';
/**
 * Tests de enriquecimiento (WF-02).
 *
 * El foco está en la degradación: qué ocurre cuando un proveedor devuelve 429,
 * 503, o un esquema que cambió sin avisar. En producción eso no es el caso
 * excepcional — con el free tier de VirusTotal (4 req/min) es el caso normal
 * durante una ráfaga de alertas.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseGreyNoise,
  parseVirusTotal,
  parseAbuseIPDB,
  parseXForce,
  aggregate,
  cacheKey,
  ttlFor,
  CACHE_TTL,
} = require('../../lib/enrich.js');

// ---------------------------------------------------------------------------
// GreyNoise
// ---------------------------------------------------------------------------

test('greynoise: un servicio comercial se marca benigno', () => {
  const r = parseGreyNoise({ business_service_intelligence: { found: true, name: 'Google Public DNS', trust_level: '1' } });
  assert.equal(r.verdict, 'benign');
  assert.equal(r.data.kind, 'business_service');
  assert.equal(r.data.name, 'Google Public DNS');
});

test('greynoise: 404 significa "no observada", no error', () => {
  // Distinción con consecuencias: tratarlo como error activaría el techo de
  // enriquecimiento parcial y bloquearía la contención de amenazas reales.
  const r = parseGreyNoise(null, 404);
  assert.equal(r.available, true);
  assert.equal(r.verdict, 'not_observed');
});

test('greynoise: extrae los metadatos v3 para el ticket', () => {
  const r = parseGreyNoise({
    internet_scanner_intelligence: {
      found: true,
      classification: 'malicious',
      actor: 'unknown',
      tls: { ja4: 't13d1516h2_8daaf6152771_b186095e22b6' },
      metadata: { carrier: 'Vodafone', rdns_parent: 'example.net' },
      raw_data: { scan: [{ port: 22 }, { port: 445 }] },
      cves: ['CVE-2024-3400'],
    },
  });
  assert.equal(r.verdict, 'malicious');
  assert.equal(r.data.ja4, 't13d1516h2_8daaf6152771_b186095e22b6');
  assert.equal(r.data.carrier, 'Vodafone');
  assert.deepEqual(r.data.destinationPorts, [22, 445]);
  assert.deepEqual(r.data.cves, ['CVE-2024-3400']);
});

test('greynoise: acepta los nombres de campo heredados de la v2', () => {
  // Compatibilidad durante la migración v2→v3: `riot` y `noise` en vez de los
  // nombres largos de la v3.
  const riot = parseGreyNoise({ riot: { found: true, name: 'Cloudflare', trust_level: '1' } });
  assert.equal(riot.verdict, 'benign');
  const noise = parseGreyNoise({ noise: { found: true, classification: 'malicious' } });
  assert.equal(noise.verdict, 'malicious');
});

test('greynoise: un 503 se marca no disponible', () => {
  const r = parseGreyNoise(null, 503);
  assert.equal(r.available, false);
  assert.match(r.error, /503/);
});

// ---------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------

test('virustotal: exige 5 motores para declarar malicioso', () => {
  const conCuatro = parseVirusTotal({ data: { attributes: { last_analysis_stats: { malicious: 4, suspicious: 0, harmless: 10, undetected: 56 } } } });
  assert.equal(conCuatro.verdict, 'suspicious');
  const conCinco = parseVirusTotal({ data: { attributes: { last_analysis_stats: { malicious: 5, suspicious: 0, harmless: 10, undetected: 55 } } } });
  assert.equal(conCinco.verdict, 'malicious');
});

test('virustotal: calcula el ratio de detección', () => {
  const r = parseVirusTotal({ data: { attributes: { last_analysis_stats: { malicious: 35, suspicious: 0, harmless: 5, undetected: 30 } } } });
  assert.equal(r.data.total, 70);
  assert.equal(r.data.ratio, 0.5);
});

test('virustotal: 404 es "desconocido", no error ni limpio', () => {
  // Un binario a medida no está en VT precisamente por ser dirigido. Tratarlo
  // como limpio sería el peor de los errores posibles.
  const r = parseVirusTotal(null, 404);
  assert.equal(r.available, true);
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.data.known, false);
});

test('virustotal: 429 se marca como no disponible por cuota', () => {
  const r = parseVirusTotal(null, 429);
  assert.equal(r.available, false);
  assert.equal(r.error, 'rate_limited');
});

test('virustotal: conserva la etiqueta de familia de malware', () => {
  const r = parseVirusTotal({
    data: {
      attributes: {
        last_analysis_stats: { malicious: 58, suspicious: 0, harmless: 0, undetected: 12 },
        popular_threat_classification: { suggested_threat_label: 'trojan.emotet/heodo' },
      },
    },
  });
  assert.equal(r.data.popularName, 'trojan.emotet/heodo');
});

test('virustotal: un informe sin motores es "unknown", no división por cero', () => {
  const r = parseVirusTotal({ data: { attributes: { last_analysis_stats: {} } } });
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.data.ratio, 0);
});

// ---------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------

test('abuseipdb: escalona el veredicto por confianza', () => {
  const casos = [
    [0, 'clean'],
    [10, 'inconclusive'],
    [40, 'suspicious'],
    [90, 'malicious'],
  ];
  for (const [conf, esperado] of casos) {
    const r = parseAbuseIPDB({ data: { abuseConfidenceScore: conf, totalReports: 1 } });
    assert.equal(r.verdict, esperado, `confianza ${conf} debería dar "${esperado}"`);
  }
});

test('abuseipdb: la lista blanca del proveedor prevalece sobre la puntuación', () => {
  const r = parseAbuseIPDB({ data: { abuseConfidenceScore: 40, isWhitelisted: true } });
  assert.equal(r.verdict, 'benign');
});

test('abuseipdb: un cuerpo sin data se marca no disponible', () => {
  assert.equal(parseAbuseIPDB({}, 200).available, false);
  assert.equal(parseAbuseIPDB(null, 200).available, false);
});

// ---------------------------------------------------------------------------
// X-Force
// ---------------------------------------------------------------------------

test('xforce: mapea la puntuación 1-10 a veredictos', () => {
  assert.equal(parseXForce({ score: 9 }).verdict, 'malicious');
  assert.equal(parseXForce({ score: 5 }).verdict, 'suspicious');
  assert.equal(parseXForce({ score: 1 }).verdict, 'inconclusive');
  assert.equal(parseXForce({ score: 0 }).verdict, 'clean');
});

test('xforce: acepta la respuesta envuelta en result', () => {
  const r = parseXForce({ result: { score: 8, cats: { Malware: 90 } } });
  assert.equal(r.verdict, 'malicious');
  assert.deepEqual(r.data.categories, ['Malware']);
});

// ---------------------------------------------------------------------------
// Agregación y degradación
// ---------------------------------------------------------------------------

test('aggregate: marca parcial si algún proveedor consultado falló', () => {
  const e = aggregate([
    { provider: 'greynoise', statusCode: 200, body: { internet_scanner_intelligence: { found: true, classification: 'benign' } } },
    { provider: 'virustotal', statusCode: 429, body: null },
  ]);
  assert.equal(e._meta.partial, true);
  assert.deepEqual(e._meta.failed, ['virustotal']);
  assert.equal(e._meta.providersOk, 1);
});

test('aggregate: no marca parcial si simplemente no se consultó un proveedor', () => {
  // Una alerta sin hashes no consulta VirusTotal. Eso no es una degradación
  // del enriquecimiento y no debe activar el techo de puntuación.
  const e = aggregate([
    { provider: 'greynoise', statusCode: 200, body: { internet_scanner_intelligence: { found: true, classification: 'benign' } } },
    { provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 0 } } },
  ]);
  assert.equal(e._meta.partial, false);
  assert.equal(e._meta.providersOk, 2);
});

test('aggregate: un cambio de esquema del proveedor no tumba el flujo', () => {
  // Se simula una respuesta que rompe el parser. Debe degradarse a "no
  // disponible", no propagar la excepción y abortar toda la ejecución.
  const e = aggregate([{ provider: 'virustotal', statusCode: 200, body: { data: { attributes: null } } }]);
  assert.ok(['unknown', 'inconclusive'].includes(e.virustotal.verdict) || e.virustotal.available === false);
});

test('aggregate: ignora proveedores desconocidos', () => {
  const e = aggregate([{ provider: 'proveedor-inventado', statusCode: 200, body: {} }]);
  assert.equal(e._meta.providersOk, 0);
});

test('aggregate: sin respuestas, todos quedan como no consultados', () => {
  const e = aggregate([]);
  assert.equal(e._meta.partial, false);
  assert.equal(e.greynoise.error, 'no_consultado');
});

// ---------------------------------------------------------------------------
// Caché
// ---------------------------------------------------------------------------

test('cacheKey normaliza a minúsculas para no duplicar entradas', () => {
  assert.equal(
    cacheKey('virustotal', 'hash', 'ABCDEF'),
    cacheKey('virustotal', 'hash', 'abcdef'),
  );
});

test('ttlFor da vida larga a lo malicioso y corta a lo limpio', () => {
  // Un IoC limpio puede ensuciarse en horas; uno malicioso rara vez se
  // rehabilita, y es el que más consultas repetidas genera (misma botnet
  // atacando en ráfaga). Es lo que hace viable el free tier de VirusTotal.
  assert.equal(ttlFor({ available: true, verdict: 'malicious' }), CACHE_TTL.malicious);
  assert.equal(ttlFor({ available: true, verdict: 'clean' }), CACHE_TTL.clean);
  assert.ok(CACHE_TTL.malicious > CACHE_TTL.clean);
});

test('ttlFor no envenena la caché con un fallo transitorio', () => {
  assert.equal(ttlFor({ available: false, error: 'rate_limited' }), CACHE_TTL.error);
  assert.ok(CACHE_TTL.error <= 60);
});
