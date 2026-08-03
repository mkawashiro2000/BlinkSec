'use strict';
/**
 * Tests del compilador de workflows.
 *
 * Verifican la propiedad que sostiene todo el proyecto: **lo que se testea es
 * exactamente lo que se ejecuta**. Si la inyección se rompe, los tests de
 * lib/ y scoring/ seguirían en verde mientras producción ejecuta código viejo
 * — el modo de fallo más peligroso que puede tener este repo.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const RAIZ = path.join(__dirname, '..', '..');
const SRC = path.join(RAIZ, 'workflows', 'src');
const DIST = path.join(RAIZ, 'workflows', 'dist');

const { adaptarModulo, validarWorkflow } = require('../../tools/build-workflows.js');

const ficherosDist = () => fs.readdirSync(DIST).filter((f) => f.endsWith('.json'));
const leerDist = (f) => JSON.parse(fs.readFileSync(path.join(DIST, f), 'utf8'));

// ---------------------------------------------------------------------------
// Consistencia src ↔ dist
// ---------------------------------------------------------------------------

test('workflows/dist está al día respecto a src y a lib', () => {
  // Equivale a `npm run build -- --check`. Falla si alguien editó el JSON
  // compilado a mano, o cambió un módulo de lib/ sin recompilar.
  const r = execFileSync('node', [path.join(RAIZ, 'tools', 'build-workflows.js'), '--check'], {
    cwd: RAIZ,
    encoding: 'utf8',
  });
  assert.match(r, /Todos los workflows están al día/);
});

test('cada plantilla de src produce un compilado en dist', () => {
  const src = fs.readdirSync(SRC).filter((f) => f.endsWith('.json')).sort();
  assert.deepEqual(ficherosDist().sort(), src);
});

// ---------------------------------------------------------------------------
// Corrección de la inyección
// ---------------------------------------------------------------------------

test('ningún workflow compilado conserva marcadores sin resolver', () => {
  for (const f of ficherosDist()) {
    const texto = fs.readFileSync(path.join(DIST, f), 'utf8');
    assert.ok(!texto.includes('@blinksec-inject'), `${f}: quedó un marcador sin resolver`);
  }
});

test('el código inyectado no conserva module.exports', () => {
  // El sandbox del nodo Code no tiene `module`. Una exportación superviviente
  // lanza ReferenceError en la primera ejecución, en producción.
  for (const f of ficherosDist()) {
    for (const nodo of leerDist(f).nodes) {
      const code = nodo.parameters?.jsCode;
      if (!code) continue;
      assert.ok(!code.includes('module.exports'), `${f} → "${nodo.name}": module.exports superviviente`);
    }
  }
});

test('el código inyectado no ejecuta require de ficheros locales', () => {
  // n8n no puede resolver rutas del repo. Se admite un require local sólo si
  // está protegido por un ternario que nunca lo alcanza (el patrón de
  // scoring/score.js con BLINKSEC_WEIGHTS ya inyectado).
  for (const f of ficherosDist()) {
    for (const nodo of leerDist(f).nodes) {
      const code = nodo.parameters?.jsCode;
      if (!code) continue;
      for (const linea of code.split('\n')) {
        const m = linea.match(/require\(['"](\.[^'"]+)['"]\)/);
        if (!m) continue;
        assert.match(
          linea,
          /typeof\s+BLINKSEC_\w+\s*!==\s*'undefined'\s*\?/,
          `${f} → "${nodo.name}": require local alcanzable: ${linea.trim()}`,
        );
      }
    }
  }
});

test('sólo se permite require de crypto entre los módulos nativos', () => {
  // El compose declara NODE_FUNCTION_ALLOW_BUILTIN=crypto. Cualquier otro
  // builtin fallaría en ejecución; y pedir fs o child_process en un nodo Code
  // sería ejecución arbitraria dentro del SOAR.
  const permitidos = new Set(['crypto']);
  for (const f of ficherosDist()) {
    for (const nodo of leerDist(f).nodes) {
      const code = nodo.parameters?.jsCode;
      if (!code) continue;
      for (const m of code.matchAll(/require\(['"]([a-z_]+)['"]\)/g)) {
        assert.ok(permitidos.has(m[1]), `${f} → "${nodo.name}": require('${m[1]}') no permitido`);
      }
    }
  }
});

test('el gateway compilado contiene la verificación HMAC real', () => {
  const wf = leerDist('WF-00-gateway.json');
  const code = wf.nodes.find((n) => n.name === 'Verificar HMAC y Replay').parameters.jsCode;
  assert.ok(code.includes('function verifyRequest'), 'falta verifyRequest');
  assert.ok(code.includes('crypto.timingSafeEqual'), 'falta la comparación en tiempo constante');
  assert.ok(code.includes('createHmac'), 'falta el cálculo del HMAC');
});

test('el motor de triaje compilado lleva los pesos embebidos', () => {
  const wf = leerDist('WF-03-triaje.json');
  const code = wf.nodes.find((n) => n.name === 'Puntuar y decidir').parameters.jsCode;
  assert.ok(code.includes('const BLINKSEC_WEIGHTS = {'), 'los pesos no se inyectaron');
  assert.ok(code.includes('function score(alert, enrichment'), 'falta score()');

  // Los pesos embebidos deben ser idénticos a scoring/weights.json: si
  // divergen, el corpus etiquetado deja de validar lo que corre en producción.
  const pesosFichero = JSON.parse(fs.readFileSync(path.join(RAIZ, 'scoring', 'weights.json'), 'utf8'));
  const m = code.match(/const BLINKSEC_WEIGHTS = (\{[\s\S]*?\n\});/);
  assert.ok(m, 'no se pudo extraer el objeto de pesos inyectado');
  assert.deepEqual(JSON.parse(m[1]), pesosFichero);
});

// ---------------------------------------------------------------------------
// Validación estructural
// ---------------------------------------------------------------------------

test('todos los workflows siguen la convención de nomenclatura', () => {
  for (const f of ficherosDist()) {
    const wf = leerDist(f);
    assert.match(wf.name, /^\[BlinkSec\] WF-\d{2} - .+ - v\d+$/, `${f}: nombre "${wf.name}"`);
  }
});

test('ningún workflow supera los 20 nodos', () => {
  // Antipatrón de flujo monolítico: por encima de ese tamaño, aislar un fallo
  // deja de ser viable y la lógica debe extraerse a un subflujo.
  for (const f of ficherosDist()) {
    const wf = leerDist(f);
    assert.ok(wf.nodes.length <= 20, `${f}: ${wf.nodes.length} nodos`);
  }
});

test('todas las conexiones apuntan a nodos existentes', () => {
  // Una referencia rota hace que n8n importe el flujo con ramas silenciosamente
  // desconectadas: el flujo "funciona" pero no contiene nada.
  for (const f of ficherosDist()) {
    const wf = leerDist(f);
    const nombres = new Set(wf.nodes.map((n) => n.name));
    for (const [origen, con] of Object.entries(wf.connections ?? {})) {
      assert.ok(nombres.has(origen), `${f}: conexión desde "${origen}" inexistente`);
      for (const salidas of con.main ?? []) {
        for (const d of salidas ?? []) {
          assert.ok(nombres.has(d.node), `${f}: "${origen}" → "${d.node}" inexistente`);
        }
      }
    }
  }
});

test('todos los flujos salvo WF-99 declaran errorWorkflow', () => {
  for (const f of ficherosDist()) {
    const wf = leerDist(f);
    if (wf.name.includes('WF-99')) continue;
    assert.equal(wf.settings?.errorWorkflow, 'WF-99', `${f}: sin errorWorkflow`);
  }
});

test('los nodos HTTP hacia terceros declaran reintentos y timeout', () => {
  // Con APIs externas el fallo es una certeza, no una posibilidad. Un nodo sin
  // timeout puede colgar un worker indefinidamente.
  for (const f of ficherosDist()) {
    for (const nodo of leerDist(f).nodes) {
      if (nodo.type !== 'n8n-nodes-base.httpRequest') continue;
      assert.ok(nodo.retryOnFail, `${f} → "${nodo.name}": sin retryOnFail`);
      assert.ok(nodo.parameters?.options?.timeout, `${f} → "${nodo.name}": sin timeout`);
    }
  }
});

test('el webhook de ingesta exige rawBody', () => {
  // Sin rawBody, n8n entrega el JSON ya parseado y la firma HMAC no puede
  // recalcularse. Es el fallo de integración más común de todo el diseño.
  const wf = leerDist('WF-00-gateway.json');
  const webhook = wf.nodes.find((n) => n.type === 'n8n-nodes-base.webhook');
  assert.equal(webhook.parameters.options.rawBody, true);
});

// ---------------------------------------------------------------------------
// Unidades del compilador
// ---------------------------------------------------------------------------

test('adaptarModulo elimina use strict, requires locales y exports', () => {
  const fuente = [
    "'use strict';",
    "const { algo } = require('./otro.js');",
    "const crypto = require('crypto');",
    'function f() { return 1; }',
    'module.exports = {',
    '  f,',
    '};',
  ].join('\n');

  const salida = adaptarModulo(fuente, 'lib/prueba.js');
  assert.ok(!salida.includes("'use strict'"));
  assert.ok(!salida.includes("require('./otro.js')"));
  assert.ok(salida.includes("require('crypto')"), 'crypto debe conservarse');
  assert.ok(salida.includes('function f()'));
  assert.ok(!salida.includes('module.exports'));
  assert.ok(salida.includes('NO EDITAR AQUÍ'), 'falta la advertencia de fichero generado');
});

test('validarWorkflow rechaza nombres fuera de convención', () => {
  assert.throws(
    () => validarWorkflow({ name: 'mi flujo', nodes: [{ name: 'a', type: 't' }], connections: {} }, 'x.json'),
    /convención/,
  );
});

test('validarWorkflow rechaza conexiones a nodos inexistentes', () => {
  assert.throws(
    () =>
      validarWorkflow(
        {
          name: '[BlinkSec] WF-01 - Prueba - v1',
          nodes: [{ name: 'a', type: 't' }],
          connections: { a: { main: [[{ node: 'fantasma' }]] } },
        },
        'x.json',
      ),
    /inexistente/,
  );
});

test('validarWorkflow rechaza nombres de nodo duplicados', () => {
  // n8n permite importarlo, pero $('nombre') se vuelve ambiguo y devuelve
  // datos del nodo equivocado sin error visible.
  assert.throws(
    () =>
      validarWorkflow(
        {
          name: '[BlinkSec] WF-01 - Prueba - v1',
          nodes: [{ name: 'a', type: 't' }, { name: 'a', type: 't' }],
          connections: {},
        },
        'x.json',
      ),
    /duplicado/,
  );
});
