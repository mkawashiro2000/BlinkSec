'use strict';
/**
 * Tests de normalización (WF-01).
 *
 * El criterio de aceptación de la Fase 2: tres plataformas con esquemas
 * completamente distintos deben producir el MISMO contrato. Si estos tests
 * pasan, añadir un cuarto SIEM no toca nada aguas abajo.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { normalize, parseLoose, isPublicIPv4, classifyHash, NormalizationError } = require('../../lib/normalize.js');

const fixture = (name) => fs.readFileSync(path.join(__dirname, name), 'utf8');

// ---------------------------------------------------------------------------
// Contrato común
// ---------------------------------------------------------------------------

const CAMPOS_OBLIGATORIOS = ['blinksec_version', 'source', 'rule', 'asset', 'identity', 'artifacts', 'validation'];

test('las dos plataformas producen el mismo contrato', () => {
  const casos = [
    ['splunk', fixture('splunk-native-alert.json')],
    ['elastic', fixture('elastic-ndjson-multi.ndjson')],
  ];

  for (const [source, payload] of casos) {
    const [alerta] = normalize(source, payload);
    for (const campo of CAMPOS_OBLIGATORIOS) {
      assert.ok(campo in alerta, `${source}: falta el campo "${campo}"`);
    }
    assert.equal(alerta.source, source);
    assert.ok(Array.isArray(alerta.artifacts.ips), `${source}: artifacts.ips debe ser array`);
    assert.ok(Array.isArray(alerta.artifacts.hashes), `${source}: artifacts.hashes debe ser array`);
    assert.equal(typeof alerta.rule.level, 'number', `${source}: rule.level debe ser numérico`);
  }
});

// ---------------------------------------------------------------------------
// Splunk
// ---------------------------------------------------------------------------

test('splunk: desenvuelve el subobjeto result', () => {
  const [a] = normalize('splunk', fixture('splunk-native-alert.json'));
  assert.equal(a.artifacts.ips[0].value, '185.220.101.47');
  assert.equal(a.identity.user, 'j.martinez');
  assert.equal(a.asset.host, 'vpn-gw-01');
});

test('splunk: mapea urgency a un nivel comparable con Wazuh', () => {
  const [a] = normalize('splunk', fixture('splunk-native-alert.json'));
  assert.equal(a.rule.level, 12); // urgency "high"
});

test('splunk: urgency ausente cae a 8, no a 0 ni a 15', () => {
  // Un default de 0 escondería alertas reales; uno de 15 dispararía
  // contención automática por un campo que simplemente no vino.
  const payload = JSON.stringify({ sid: 'x', search_name: 'y', result: { src_ip: '1.1.1.1', host: 'h' } });
  const [a] = normalize('splunk', payload);
  assert.equal(a.rule.level, 8);
});

test('splunk: conserva el enlace a los resultados para el ticket', () => {
  const [a] = normalize('splunk', fixture('splunk-native-alert.json'));
  assert.match(a.resultsLink, /^https:\/\/splunk\.example\.com/);
});

// ---------------------------------------------------------------------------
// Elastic — las rarezas de serialización
// ---------------------------------------------------------------------------

test('elastic: parsea ndjson multi-alerta como lote', () => {
  const alertas = normalize('elastic', fixture('elastic-ndjson-multi.ndjson'));
  assert.equal(alertas.length, 2);
  assert.equal(alertas[0].asset.host, 'lap-fin-204');
  assert.equal(alertas[1].asset.host, 'lap-fin-207');
  // Misma IP atacante en ambas: aguas abajo la caché de IoC lo aprovecha.
  assert.equal(alertas[0].artifacts.ips[0].value, alertas[1].artifacts.ips[0].value);
});

test('elastic: recupera un array con coma terminal (JSON inválido)', () => {
  const alertas = normalize('elastic', fixture('elastic-trailing-comma.json.broken'));
  assert.equal(alertas.length, 1);
  assert.equal(alertas[0].asset.host, 'web-02');
  assert.equal(alertas[0].artifacts.ips[0].value, '171.25.193.78');
});

test('parseLoose: una línea corrupta no invalida el lote entero', () => {
  const mixto = '{"context":{"host":{"name":"a"}}}\nESTO NO ES JSON\n{"context":{"host":{"name":"b"}}}';
  const alertas = normalize('elastic', mixto);
  assert.equal(alertas.length, 2);
});

test('parseLoose: lanza si no hay nada recuperable', () => {
  assert.throws(() => parseLoose('<html>502 Bad Gateway</html>'), NormalizationError);
});

test('parseLoose: lanza ante cuerpo vacío', () => {
  assert.throws(() => parseLoose('   '), NormalizationError);
});

// ---------------------------------------------------------------------------
// Validación estricta de entradas
// ---------------------------------------------------------------------------

test('marca como no válida una alerta sin host ni regla', () => {
  const [a] = normalize('splunk', JSON.stringify({ result: { src_ip: '8.8.8.8' } }));
  assert.equal(a.validation.ok, false);
  assert.ok(a.validation.problemas.includes('asset.host ausente'));
  assert.ok(a.validation.problemas.includes('rule.id ausente'));
});

test('marca como no enriquecible una alerta sin artefactos', () => {
  // Caso legítimo: escalada de privilegios local, sin IP ni hash. No debe
  // intentar puntuarse por reputación — va directa a investigación humana.
  const payload = JSON.stringify({
    sid: '5402',
    search_name: 'Successful sudo to ROOT executed',
    result: { host: 'app-03', urgency: 'low' },
  });
  const [a] = normalize('splunk', payload);
  assert.equal(a.validation.ok, true);
  assert.equal(a.validation.enriquecible, false);
});

test('un activo desconocido se asume crítico, no prescindible', () => {
  // Default conservador: si la consulta al inventario falla, el sistema debe
  // pedir aprobación humana antes de aislar, no asumir que da igual.
  const [a] = normalize('splunk', fixture('splunk-native-alert.json'));
  assert.equal(a.asset.criticality, 'high');
});

test('lanza ante un origen sin normalizador', () => {
  assert.throws(() => normalize('qradar', '{}'), NormalizationError);
});

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

test('isPublicIPv4 descarta rangos privados, loopback y reservados', () => {
  for (const priv of ['10.0.0.1', '172.16.5.5', '172.31.255.254', '192.168.1.1', '127.0.0.1', '169.254.1.1', '0.0.0.0', '224.0.0.1']) {
    assert.equal(isPublicIPv4(priv), false, `${priv} debería considerarse no pública`);
  }
  for (const pub of ['8.8.8.8', '45.155.205.233', '172.32.0.1', '192.169.0.1']) {
    assert.equal(isPublicIPv4(pub), true, `${pub} debería considerarse pública`);
  }
});

test('isPublicIPv4 rechaza octetos fuera de rango y basura', () => {
  for (const malo of ['999.1.1.1', '1.2.3', 'no-una-ip', '', null, undefined, 12345]) {
    assert.equal(isPublicIPv4(malo), false);
  }
});

test('classifyHash distingue md5/sha1/sha256 y normaliza a minúsculas', () => {
  assert.deepEqual(classifyHash('44D88612FEA8A8F36DE82E1278ABB02F'), {
    value: '44d88612fea8a8f36de82e1278abb02f',
    type: 'md5',
  });
  assert.equal(classifyHash('3395856ce81f2b7382dee72602f798b642f14140').type, 'sha1');
  assert.equal(classifyHash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f').type, 'sha256');
  assert.equal(classifyHash('demasiado-corto'), null);
});
