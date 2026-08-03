#!/usr/bin/env node
'use strict';
/**
 * BlinkSec — compilador de workflows.
 *
 * PROBLEMA QUE RESUELVE
 *
 * Los nodos Code de n8n no pueden hacer `require` de ficheros del repo: se
 * ejecutan en un sandbox sin sistema de ficheros. La consecuencia habitual es
 * que la lógica crítica acaba pegada a mano dentro del JSON del workflow,
 * duplicada respecto al código con tests. A los dos meses divergen, los tests
 * pasan en verde y producción se comporta de otra forma.
 *
 * Este compilador toma las plantillas de workflows/src/, sustituye los
 * marcadores `// @blinksec-inject: <ruta>` por el código real del módulo, y
 * escribe el resultado en workflows/dist/ listo para importar en n8n.
 *
 * Así existe una sola fuente de verdad: lo que se testea es exactamente lo que
 * se ejecuta.
 *
 * USO
 *   node tools/build-workflows.js            compila a workflows/dist/
 *   node tools/build-workflows.js --check    verifica que dist/ está al día
 *                                            (para CI: falla si alguien editó
 *                                            el JSON a mano sin recompilar)
 */

const fs = require('node:fs');
const path = require('node:path');

const RAIZ = path.join(__dirname, '..');
const SRC = path.join(RAIZ, 'workflows', 'src');
const DIST = path.join(RAIZ, 'workflows', 'dist');

const MARCADOR = /^(\s*)\/\/\s*@blinksec-inject:\s*(\S+)\s*$/;

/**
 * Adapta un módulo CommonJS al sandbox del nodo Code.
 *
 * Transformaciones:
 *   - Se elimina 'use strict' (el Code node ya es estricto).
 *   - Se eliminan los `require` de módulos internos del repo: sus funciones
 *     quedan en el mismo ámbito tras la inyección.
 *   - Se conserva `require('crypto')`, que n8n permite si el entorno declara
 *     NODE_FUNCTION_ALLOW_BUILTIN=crypto (ver docker-compose.yml).
 *   - Se elimina `module.exports`, que no existe en el sandbox.
 */
function adaptarModulo(codigo, rutaRelativa) {
  const lineas = codigo.split('\n');
  const salida = [];
  let enExports = false;

  for (const linea of lineas) {
    if (/^\s*'use strict';\s*$/.test(linea)) continue;

    // require de módulos locales del repo → fuera (se inyectan aparte)
    if (/^\s*const\s+\{[^}]*\}\s*=\s*require\(['"]\.[^'"]*['"]\);?\s*$/.test(linea)) continue;
    if (/^\s*const\s+\w+\s*=\s*require\(['"]\.[^'"]*['"]\);?\s*$/.test(linea)) continue;

    // module.exports = { ... }  (puede ocupar varias líneas)
    if (/^\s*module\.exports\s*=/.test(linea)) {
      enExports = true;
      if (/;\s*$/.test(linea) && linea.includes('}')) enExports = false;
      continue;
    }
    if (enExports) {
      if (/^\s*\};?\s*$/.test(linea)) enExports = false;
      continue;
    }

    salida.push(linea);
  }

  return [
    `// ─── inyectado desde ${rutaRelativa} — NO EDITAR AQUÍ ───`,
    `// Editar el fichero original y recompilar: npm run build`,
    ...salida,
    `// ─── fin de ${rutaRelativa} ───`,
  ].join('\n');
}

/** Resuelve los marcadores de inyección dentro de un bloque de código. */
function expandir(codigo, contexto) {
  return codigo
    .split('\n')
    .map((linea) => {
      const m = linea.match(MARCADOR);
      if (!m) return linea;

      const [, sangria, rutaRelativa] = m;
      const rutaAbsoluta = path.join(RAIZ, rutaRelativa);

      if (!fs.existsSync(rutaAbsoluta)) {
        throw new Error(`${contexto}: el marcador apunta a un fichero inexistente: ${rutaRelativa}`);
      }

      // Los .json se inyectan como constante, no como código.
      if (rutaRelativa.endsWith('.json')) {
        const nombre = path
          .basename(rutaRelativa, '.json')
          .replace(/[^a-zA-Z0-9]/g, '_')
          .toUpperCase();
        const contenido = fs.readFileSync(rutaAbsoluta, 'utf8');
        return `${sangria}const BLINKSEC_${nombre} = ${contenido.trim()};`;
      }

      const fuente = fs.readFileSync(rutaAbsoluta, 'utf8');
      return adaptarModulo(fuente, rutaRelativa)
        .split('\n')
        .map((l) => sangria + l)
        .join('\n');
    })
    .join('\n');
}

/** Recorre el workflow buscando parámetros jsCode y los expande. */
function compilarWorkflow(wf, nombreFichero) {
  let inyecciones = 0;

  for (const nodo of wf.nodes ?? []) {
    const code = nodo.parameters?.jsCode;
    if (typeof code !== 'string' || !MARCADOR.test(code.split('\n').find((l) => MARCADOR.test(l)) ?? '')) {
      // Se comprueba línea a línea porque el marcador nunca está en la primera.
      if (typeof code !== 'string' || !code.split('\n').some((l) => MARCADOR.test(l))) continue;
    }
    const expandido = expandir(code, `${nombreFichero} → nodo "${nodo.name}"`);
    if (expandido !== code) inyecciones++;
    nodo.parameters.jsCode = expandido;
  }

  return { wf, inyecciones };
}

/** Validación estructural: un JSON sintácticamente válido puede no ser importable. */
function validarWorkflow(wf, fichero) {
  const errores = [];

  if (!wf.name) errores.push('falta "name"');
  if (!Array.isArray(wf.nodes) || wf.nodes.length === 0) errores.push('sin nodos');

  const nombres = new Set();
  for (const n of wf.nodes ?? []) {
    if (!n.name) errores.push('un nodo sin "name"');
    if (!n.type) errores.push(`nodo "${n.name}" sin "type"`);
    if (nombres.has(n.name)) errores.push(`nombre de nodo duplicado: "${n.name}"`);
    nombres.add(n.name);
  }

  // Las conexiones deben referirse a nodos que existen; una referencia rota
  // hace que n8n importe el flujo con ramas silenciosamente desconectadas.
  for (const [origen, conexiones] of Object.entries(wf.connections ?? {})) {
    if (!nombres.has(origen)) errores.push(`conexión desde un nodo inexistente: "${origen}"`);
    for (const salidas of conexiones.main ?? []) {
      for (const destino of salidas ?? []) {
        if (!nombres.has(destino.node)) {
          errores.push(`"${origen}" conecta con un nodo inexistente: "${destino.node}"`);
        }
      }
    }
  }

  // Convención de nomenclatura del proyecto: [BlinkSec] WF-xx - Descripción - vN
  if (wf.name && !/^\[BlinkSec\]\s+WF-\d{2}\s+-\s+.+\s+-\s+v\d+$/.test(wf.name)) {
    errores.push(`el nombre "${wf.name}" no sigue la convención "[BlinkSec] WF-xx - Descripción - vN"`);
  }

  // Antipatrón de flujo monolítico: por encima de 20 nodos, aislar un fallo
  // se vuelve inviable y la lógica debe extraerse a un subflujo.
  if ((wf.nodes ?? []).length > 20) {
    errores.push(`${wf.nodes.length} nodos: supera el máximo de 20, extraer lógica a un subflujo`);
  }

  if (errores.length) {
    throw new Error(`${fichero}:\n  - ${errores.join('\n  - ')}`);
  }
}

function main() {
  const modoCheck = process.argv.includes('--check');

  if (!fs.existsSync(SRC)) {
    console.error(`No existe ${SRC}`);
    process.exit(1);
  }
  fs.mkdirSync(DIST, { recursive: true });

  const ficheros = fs.readdirSync(SRC).filter((f) => f.endsWith('.json')).sort();
  if (ficheros.length === 0) {
    console.error('No hay plantillas en workflows/src/');
    process.exit(1);
  }

  let desactualizados = 0;

  for (const fichero of ficheros) {
    const origen = JSON.parse(fs.readFileSync(path.join(SRC, fichero), 'utf8'));
    const { wf, inyecciones } = compilarWorkflow(origen, fichero);

    validarWorkflow(wf, fichero);

    const salida = JSON.stringify(wf, null, 2) + '\n';
    const destino = path.join(DIST, fichero);

    if (modoCheck) {
      const actual = fs.existsSync(destino) ? fs.readFileSync(destino, 'utf8') : null;
      if (actual !== salida) {
        console.error(`DESACTUALIZADO  ${fichero}`);
        desactualizados++;
      } else {
        console.log(`ok              ${fichero}`);
      }
    } else {
      fs.writeFileSync(destino, salida);
      console.log(`compilado       ${fichero}  (${wf.nodes.length} nodos, ${inyecciones} inyecciones)`);
    }
  }

  if (modoCheck && desactualizados > 0) {
    console.error(`\n${desactualizados} workflow(s) desactualizado(s). Ejecutar: npm run build`);
    process.exit(1);
  }

  console.log(modoCheck ? '\nTodos los workflows están al día.' : `\n${ficheros.length} workflow(s) en workflows/dist/`);
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`\nError de compilación:\n${e.message}`);
    process.exit(1);
  }
}

module.exports = { adaptarModulo, expandir, validarWorkflow };
