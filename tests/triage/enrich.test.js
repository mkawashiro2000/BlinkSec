'use strict';
/**
 * Tests de enriquecimiento (WF-02).
 *
 * El foco está en la degradación: qué ocurre cuando un proveedor devuelve 429,
 * 503, o un esquema que cambió sin avisar. En producción eso no es el caso
 * excepcional — con el free tier de VirusTotal (4 req/min) es el caso normal
 * durante una ráfaga de alertas.
 *
 * Proveedores: AbuseIPDB, VirusTotal y CrowdSec CTI. GreyNoise e IBM X-Force
 * se retiraron del sistema — ver docs/riesgos.md.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseVirusTotal,
  parseAbuseIPDB,
  parseCrowdSec,
  aggregate,
  cacheKey,
  ttlFor,
  CACHE_TTL,
} = require('../../lib/enrich.js');

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
// CrowdSec CTI
// ---------------------------------------------------------------------------

test('crowdsec: 404 es "nunca reportada", no error ni limpio', () => {
  const r = parseCrowdSec(null, 404);
  assert.equal(r.available, true);
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.data.known, false);
});

test('crowdsec: 429 se marca como no disponible por cuota', () => {
  const r = parseCrowdSec(null, 429);
  assert.equal(r.available, false);
  assert.equal(r.error, 'rate_limited');
});

test('crowdsec: threat alto o presencia en una lista de bloqueo es malicioso', () => {
  const porThreat = parseCrowdSec({ scores: { overall: { threat: 4, aggressiveness: 2 } }, classifications: { classifications: [] } });
  assert.equal(porThreat.verdict, 'malicious');

  const porLista = parseCrowdSec({
    scores: { overall: { threat: 1, aggressiveness: 0 } },
    classifications: { classifications: [{ label: 'CrowdSec Community Blocklist' }] },
  });
  assert.equal(porLista.verdict, 'malicious');
  assert.deepEqual(porLista.data.classifications, ['CrowdSec Community Blocklist']);
});

test('crowdsec: actividad agresiva sin lista de bloqueo es sospechoso, no malicioso', () => {
  const r = parseCrowdSec({ scores: { overall: { threat: 1, aggressiveness: 1 } }, classifications: { classifications: [] } });
  assert.equal(r.verdict, 'suspicious');
});

test('crowdsec: sin señal alguna es limpio', () => {
  const r = parseCrowdSec({ scores: { overall: { threat: 0, aggressiveness: 0 } }, classifications: { classifications: [] } });
  assert.equal(r.verdict, 'clean');
});

// ---------------------------------------------------------------------------
// Agregación y degradación
// ---------------------------------------------------------------------------

test('aggregate: marca parcial si algún proveedor consultado falló', () => {
  const e = aggregate([
    { provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 0 } } },
    { provider: 'virustotal', statusCode: 429, body: null },
  ]);
  assert.equal(e._meta.partial, true);
  assert.deepEqual(e._meta.failed, ['virustotal']);
  assert.equal(e._meta.providersOk, 1);
});

test('aggregate: CrowdSec es best-effort — su fallo NO marca el enriquecimiento como parcial', () => {
  // El plan gratuito de CrowdSec CTI son 120 consultas/mes (~4/día). En
  // cualquier ráfaga real de alertas la cuota se agota en minutos. Si
  // CrowdSec contara como fuente core, un 429 suyo activaría el techo de
  // enriquecimiento parcial para TODAS las alertas del resto del día, con
  // AbuseIPDB y VirusTotal respondiendo perfectamente. No debe pasar.
  const e = aggregate([
    { provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 0 } } },
    { provider: 'virustotal', statusCode: 200, body: { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 10, undetected: 5 } } } } },
    { provider: 'crowdsec', statusCode: 429, body: null },
  ]);
  assert.equal(e._meta.partial, false);
  assert.deepEqual(e._meta.failed, []);
  assert.equal(e._meta.providersOk, 2);
  // El dato de CrowdSec sigue disponible para el ticket y el rationale de
  // scoring, sólo no cuenta para los techos de seguridad.
  assert.equal(e.crowdsec.available, false);
  assert.equal(e.crowdsec.error, 'rate_limited');
});

test('aggregate: no marca parcial si simplemente no se consultó un proveedor', () => {
  // Una alerta sin hashes no consulta VirusTotal por ese IoC. Eso no es una
  // degradación del enriquecimiento y no debe activar el techo de puntuación.
  const e = aggregate([{ provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 0 } } }]);
  assert.equal(e._meta.partial, false);
  assert.equal(e._meta.providersOk, 1);
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
  assert.equal(e.virustotal.error, 'no_consultado');
  assert.equal(e.abuseipdb.error, 'no_consultado');
  assert.equal(e.crowdsec.error, 'no_consultado');
});

test('aggregate: sólo conoce AbuseIPDB, VirusTotal y CrowdSec', () => {
  // GreyNoise e IBM X-Force se retiraron del sistema; este test fija esa
  // propiedad para que no vuelvan a aparecer sin que se note en la matriz de
  // confusión (ver docs/riesgos.md).
  const { PROVIDERS } = require('../../lib/enrich.js');
  assert.deepEqual([...PROVIDERS].sort(), ['abuseipdb', 'crowdsec', 'virustotal']);
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
