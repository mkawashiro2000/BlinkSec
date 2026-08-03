#!/usr/bin/env node
'use strict';
/**
 * BlinkSec — verificación de que docker-compose.yml propaga al contenedor
 * de Caddy toda variable que el Caddyfile referencia.
 *
 * PROBLEMA QUE RESUELVE
 *
 * El Caddyfile lee variables con `{$NOMBRE}` o `{$NOMBRE:-default}`. Si el
 * bloque `environment:` del servicio caddy en docker-compose.yml no incluye
 * una de ellas, Caddy no falla: cae en silencio al valor por defecto (si lo
 * hay) o a cadena vacía.
 *
 * Esto pasó de verdad en la Fase 7: `MGMT_ALLOWLIST` y `ACME_EMAIL` se leían
 * del Caddyfile pero nunca se pasaban desde compose. El `.env` del operador
 * restringía el acceso al editor de n8n a una red concreta, y Caddy lo
 * ignoraba sin decir nada, cayendo siempre al default hardcodeado de
 * "cualquier red privada". El fallo sólo se descubrió intentando verificar
 * en vivo que el 403 funcionaba de verdad.
 *
 * Este script no arregla nada: sólo hace imposible que ese desajuste pase
 * inadvertido otra vez.
 *
 * USO
 *   node tools/check-caddy-env.js
 */

const fs = require('node:fs');
const path = require('node:path');

const RAIZ = path.join(__dirname, '..');
const CADDYFILE = path.join(RAIZ, 'docker', 'Caddyfile');
const COMPOSE = path.join(RAIZ, 'docker', 'docker-compose.yml');

function variablesDelCaddyfile(texto) {
  // Sintaxis de placeholder de Caddy: {$VAR} o {$VAR:default} — un solo
  // signo ":", no ":-" como en shell. Con ":-" el regex anterior no casaba
  // "{$ACME_EMAIL:admin@example.com}" ni "{$MGMT_ALLOWLIST:10.0.0.0/8 ...}"
  // y el script pasaba en verde con la mitad de las variables sin detectar.
  const vistas = new Set();
  for (const m of texto.matchAll(/\{\$([A-Z0-9_]+)(:[^}]*)?\}/g)) {
    vistas.add(m[1]);
  }
  return vistas;
}

/**
 * Extrae las claves del bloque `environment:` del servicio caddy.
 *
 * Se hace con una lectura de línea simple, no con un parser YAML completo:
 * el fichero es estable y controlado por el repo, y así el script no suma
 * una dependencia sólo para esto.
 */
function variablesEnCompose(texto) {
  const lineas = texto.split('\n');
  const idxServicio = lineas.findIndex((l) => /^\s{2}caddy:\s*$/.test(l));
  if (idxServicio === -1) throw new Error('No se encontró el servicio "caddy" en docker-compose.yml');

  const idxEnv = lineas.findIndex((l, i) => i > idxServicio && /^\s{4}environment:\s*$/.test(l));
  if (idxEnv === -1) throw new Error('El servicio "caddy" no tiene bloque "environment:"');

  const vistas = new Set();
  for (let i = idxEnv + 1; i < lineas.length; i++) {
    const l = lineas[i];
    // Fin del bloque: una línea con menor o igual indentación que "environment:".
    if (/^\s{0,4}\S/.test(l) && !/^\s{6}/.test(l)) break;
    const m = l.match(/^\s{6}([A-Z0-9_]+):/);
    if (m) vistas.add(m[1]);
  }
  return vistas;
}

function main() {
  const caddyfile = fs.readFileSync(CADDYFILE, 'utf8');
  const compose = fs.readFileSync(COMPOSE, 'utf8');

  const requeridas = variablesDelCaddyfile(caddyfile);
  const propagadas = variablesEnCompose(compose);

  const faltantes = [...requeridas].filter((v) => !propagadas.has(v)).sort();

  if (faltantes.length > 0) {
    console.error('El Caddyfile referencia variables que docker-compose.yml no propaga al contenedor:');
    for (const v of faltantes) console.error(`  - ${v}`);
    console.error('\nCaddy caerá en silencio a su valor por defecto (o a vacío) para cada una.');
    console.error('Añadirlas al bloque "environment:" del servicio caddy en docker-compose.yml.');
    process.exit(1);
  }

  console.log(`OK: las ${requeridas.size} variables del Caddyfile (${[...requeridas].sort().join(', ')}) se propagan.`);
}

if (require.main === module) main();

module.exports = { variablesDelCaddyfile, variablesEnCompose };
