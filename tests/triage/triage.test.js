'use strict';
/**
 * Tests de triaje (WF-03) + matriz de confusión.
 *
 * Este fichero es el criterio de aceptación del proyecto. La regla que no se
 * negocia: CERO falsos positivos auto-contenidos. Un ticket de más cuesta
 * quince minutos de analista; un bloqueo automático equivocado sobre la VPN
 * corporativa cuesta una mañana de toda la empresa.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { score, ipInCidr, VERDICTS } = require('../../scoring/score.js');
const { aggregate } = require('../../lib/enrich.js');

const { cases } = JSON.parse(fs.readFileSync(path.join(__dirname, 'cases.json'), 'utf8'));

/** Ejecuta un caso del corpus de principio a fin (parseo + agregación + scoring). */
function evaluate(c) {
  const enrichment = aggregate(c.responses);
  return score(c.alert, enrichment, { allowlist: c.allowlist ?? [] });
}

// ---------------------------------------------------------------------------
// Caso por caso
// ---------------------------------------------------------------------------

for (const c of cases) {
  test(`${c.name} → ${c.expected}`, () => {
    const r = evaluate(c);
    assert.equal(
      r.verdict,
      c.expected,
      `Puntuación ${r.score}. Motivos:\n  - ${r.rationale.join('\n  - ')}`,
    );
    if (c.expectApproval !== undefined) {
      assert.equal(
        r.requiresApproval,
        c.expectApproval,
        `requiresApproval esperado ${c.expectApproval}, obtenido ${r.requiresApproval} (activo: ${c.alert.asset.criticality})`,
      );
    }
  });
}

// ---------------------------------------------------------------------------
// Matriz de confusión agregada
// ---------------------------------------------------------------------------

test('matriz de confusión: ningún falso positivo llega a contención automática', () => {
  const matriz = {};
  const violaciones = [];

  for (const c of cases) {
    const r = evaluate(c);
    const clave = `${c.expected} → ${r.verdict}`;
    matriz[clave] = (matriz[clave] ?? 0) + 1;

    // La violación inaceptable: un caso etiquetado como falso positivo que el
    // sistema clasifica como crítico y por tanto contiene sin preguntar.
    if (c.expected === 'false_positive' && r.verdict === VERDICTS.CRITICAL) {
      violaciones.push(`${c.name} (puntuación ${r.score})`);
    }
  }

  console.log('\n  Matriz de confusión (esperado → obtenido):');
  for (const [k, v] of Object.entries(matriz).sort()) console.log(`    ${k.padEnd(38)} ${v}`);

  assert.deepEqual(violaciones, [], `Falsos positivos auto-contenidos:\n${violaciones.join('\n')}`);
});

test('tasa de auto-cierre de falsos positivos ≥ 60%', () => {
  const fps = cases.filter((c) => c.expected === 'false_positive');
  const cerrados = fps.filter((c) => evaluate(c).verdict === VERDICTS.FALSE_POSITIVE);
  const tasa = cerrados.length / fps.length;

  console.log(`\n  Auto-cierre de FP: ${cerrados.length}/${fps.length} (${Math.round(tasa * 100)}%)`);
  assert.ok(tasa >= 0.6, `Tasa de auto-cierre ${Math.round(tasa * 100)}%, por debajo del 60% exigido`);
});

test('ninguna amenaza real se auto-cierra como falso positivo', () => {
  // El error simétrico: descartar solo un ataque en curso. Menos catastrófico
  // que contener de más, pero es exactamente el fallo que hace inservible un SOC.
  const amenazas = cases.filter((c) => c.expected !== 'false_positive');
  const descartadas = amenazas.filter((c) => evaluate(c).verdict === VERDICTS.FALSE_POSITIVE);
  assert.deepEqual(descartadas.map((c) => c.name), []);
});

// ---------------------------------------------------------------------------
// Propiedades invariantes del motor
// ---------------------------------------------------------------------------

test('el enriquecimiento parcial nunca alcanza el umbral crítico', () => {
  // Se fuerza el escenario más extremo posible: toda la evidencia apunta a
  // ataque, pero un proveedor no respondió.
  const alerta = {
    rule: { id: '1', level: 15 },
    asset: { host: 'h', criticality: 'low' },
    artifacts: { ips: [{ value: '1.2.3.4', direction: 'src' }], hashes: [] },
    validation: { ok: true, enriquecible: true },
  };
  const enrichment = aggregate([
    { provider: 'greynoise', statusCode: 200, body: { internet_scanner_intelligence: { found: true, classification: 'malicious' } } },
    { provider: 'virustotal', statusCode: 200, body: { data: { attributes: { last_analysis_stats: { malicious: 70, suspicious: 0, harmless: 0, undetected: 0 } } } } },
    { provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 100, totalReports: 999 } } },
    { provider: 'xforce', statusCode: 503, body: null }, // el único caído
  ]);
  const r = score(alerta, enrichment, {});
  assert.equal(r.verdict, VERDICTS.INVESTIGATE);
  assert.ok(r.caps.includes('partial_enrichment'));
  assert.ok(r.score <= 69);
});

test('la allowlist se evalúa antes del scoring y corta en seco', () => {
  const alerta = {
    rule: { id: '1', level: 15 },
    asset: { host: 'h', criticality: 'low' },
    artifacts: { ips: [{ value: '10.10.5.44', direction: 'src' }], hashes: [] },
    validation: { ok: true, enriquecible: true },
  };
  // Aunque toda la inteligencia grite "malicioso", una IP propia no se toca.
  const enrichment = aggregate([
    { provider: 'greynoise', statusCode: 200, body: { internet_scanner_intelligence: { found: true, classification: 'malicious' } } },
    { provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 100, totalReports: 999 } } },
  ]);
  const r = score(alerta, enrichment, { allowlist: ['10.10.5.0/24'] });
  assert.equal(r.verdict, VERDICTS.FALSE_POSITIVE);
  assert.equal(r.allowlisted, true);
  assert.equal(r.score, 0);
});

test('sin enriquecimiento alguno el veredicto es investigar, no contener ni descartar', () => {
  const alerta = {
    rule: { id: '1', level: 5 },
    asset: { host: 'h', criticality: 'medium' },
    artifacts: { ips: [], hashes: [] },
    validation: { ok: true, enriquecible: false },
  };
  const r = score(alerta, aggregate([]), {});
  assert.equal(r.verdict, VERDICTS.INVESTIGATE);
});

test('ninguna señal aislada alcanza el umbral crítico', () => {
  // Propiedad de diseño derivada de la línea base 35: la contención automática
  // exige SIEMPRE corroboración de al menos dos fuentes.
  const alerta = {
    rule: { id: '1', level: 10 },
    asset: { host: 'h', criticality: 'low' },
    artifacts: { ips: [{ value: '1.2.3.4', direction: 'src' }], hashes: [] },
    validation: { ok: true, enriquecible: true },
  };
  const senalesUnicas = [
    [{ provider: 'greynoise', statusCode: 200, body: { internet_scanner_intelligence: { found: true, classification: 'malicious' } } }],
    [{ provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 100, totalReports: 999 } } }],
    [{ provider: 'xforce', statusCode: 200, body: { score: 10, cats: { Malware: 100 } } }],
  ];
  for (const responses of senalesUnicas) {
    const r = score(alerta, aggregate(responses), {});
    assert.notEqual(r.verdict, VERDICTS.CRITICAL, `Una sola fuente (${responses[0].provider}) no debe bastar para contener`);
  }
});

test('la puntuación es determinista', () => {
  const c = cases[0];
  const a = evaluate(c);
  const b = evaluate(c);
  assert.deepEqual(a, b);
});

test('la puntuación siempre queda en [0, 100]', () => {
  for (const c of cases) {
    const r = evaluate(c);
    assert.ok(r.score >= 0 && r.score <= 100, `${c.name}: puntuación fuera de rango (${r.score})`);
  }
});

test('todo veredicto viene acompañado de sus motivos', () => {
  // El analista debe poder reconstruir por qué el sistema decidió aislar un
  // host. Un veredicto sin justificación es incauditable.
  for (const c of cases) {
    const r = evaluate(c);
    assert.ok(r.rationale.length > 0, `${c.name}: veredicto sin rationale`);
  }
});

test('los activos crown_jewel y high nunca se contienen sin aprobación', () => {
  for (const c of cases) {
    const r = evaluate(c);
    if (r.verdict === VERDICTS.CRITICAL && ['high', 'crown_jewel'].includes(c.alert.asset.criticality)) {
      assert.equal(r.requiresApproval, true, `${c.name}: activo crítico contenido sin HITL`);
    }
  }
});

test('never_isolate fuerza aprobación humana aunque el activo sea de baja criticidad', () => {
  const alerta = {
    rule: { id: '1', level: 15 },
    asset: { host: 'dc-01', criticality: 'low', never_isolate: true },
    artifacts: { ips: [{ value: '1.2.3.4', direction: 'src' }], hashes: [] },
    validation: { ok: true, enriquecible: true },
  };
  const enrichment = aggregate([
    { provider: 'greynoise', statusCode: 200, body: { internet_scanner_intelligence: { found: true, classification: 'malicious' } } },
    { provider: 'abuseipdb', statusCode: 200, body: { data: { abuseConfidenceScore: 100, totalReports: 999 } } },
    { provider: 'xforce', statusCode: 200, body: { score: 9, cats: {} } },
  ]);
  const r = score(alerta, enrichment, {});
  assert.equal(r.verdict, VERDICTS.CRITICAL);
  assert.equal(r.requiresApproval, true);
});

// ---------------------------------------------------------------------------
// Aritmética CIDR
// ---------------------------------------------------------------------------

test('ipInCidr resuelve correctamente los límites de rango', () => {
  assert.equal(ipInCidr('10.10.5.44', '10.10.5.0/24'), true);
  assert.equal(ipInCidr('10.10.6.1', '10.10.5.0/24'), false);
  assert.equal(ipInCidr('203.0.113.15', '203.0.113.0/28'), true);
  assert.equal(ipInCidr('203.0.113.16', '203.0.113.0/28'), false);
  assert.equal(ipInCidr('1.2.3.4', '1.2.3.4'), true);     // /32 implícito
  assert.equal(ipInCidr('1.2.3.5', '1.2.3.4'), false);
  assert.equal(ipInCidr('8.8.8.8', '0.0.0.0/0'), true);   // ruta por defecto
});

test('ipInCidr rechaza entradas malformadas sin lanzar', () => {
  assert.equal(ipInCidr('no-ip', '10.0.0.0/8'), false);
  assert.equal(ipInCidr('10.0.0.1', 'basura'), false);
  assert.equal(ipInCidr('10.0.0.1', '10.0.0.0/99'), false);
  assert.equal(ipInCidr(null, '10.0.0.0/8'), false);
});

test('ipInCidr maneja el bit alto sin desbordar el signo', () => {
  // El desplazamiento de bits en JavaScript produce enteros con signo; sin
  // el >>> 0 esta comprobación falla para todo el espacio 128.0.0.0+.
  assert.equal(ipInCidr('200.1.2.3', '200.0.0.0/8'), true);
  assert.equal(ipInCidr('255.255.255.255', '255.255.255.255/32'), true);
  assert.equal(ipInCidr('128.0.0.1', '128.0.0.0/1'), true);
  assert.equal(ipInCidr('127.255.255.255', '128.0.0.0/1'), false);
});
