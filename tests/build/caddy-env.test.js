'use strict';
/**
 * Verifica que toda variable que el Caddyfile lee vía {$VAR} se propaga
 * desde docker-compose.yml al contenedor de caddy.
 *
 * Nace de un fallo real de la Fase 7: MGMT_ALLOWLIST y ACME_EMAIL se leían
 * en el Caddyfile pero nunca se declaraban en el bloque `environment:` del
 * servicio. Caddy no fallaba — caía en silencio al valor por defecto
 * hardcodeado ("cualquier red privada" para MGMT_ALLOWLIST), así que el
 * `.env` del operador quedaba sin efecto sin ningún error visible. Sólo
 * apareció al verificar en vivo que el 403 del editor funcionaba de verdad.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { variablesDelCaddyfile, variablesEnCompose } = require('../../tools/check-caddy-env.js');

const RAIZ = path.join(__dirname, '..', '..');
const caddyfile = fs.readFileSync(path.join(RAIZ, 'docker', 'Caddyfile'), 'utf8');
const compose = fs.readFileSync(path.join(RAIZ, 'docker', 'docker-compose.yml'), 'utf8');

test('toda variable {$VAR} del Caddyfile está en el environment del servicio caddy', () => {
  const requeridas = variablesDelCaddyfile(caddyfile);
  const propagadas = variablesEnCompose(compose);
  const faltantes = [...requeridas].filter((v) => !propagadas.has(v));
  assert.deepEqual(faltantes, [], `docker-compose.yml no propaga: ${faltantes.join(', ')}`);
});

test('detecta las dos sintaxis de placeholder de Caddy: con y sin valor por defecto', () => {
  // Caddy usa un solo ":" para el default (no ":-" como en shell). Este test
  // fija el comportamiento correcto para que una futura "simplificación" del
  // regex no vuelva a dejar pasar la mitad de las variables sin detectar.
  const texto = '{$SIN_DEFAULT} y {$CON_DEFAULT:valor por defecto con espacios}';
  const vistas = variablesDelCaddyfile(texto);
  assert.deepEqual([...vistas].sort(), ['CON_DEFAULT', 'SIN_DEFAULT']);
});

test('el Caddyfile de BlinkSec usa efectivamente las cuatro variables esperadas', () => {
  // Ancla el conjunto conocido: si alguien añade una variable nueva al
  // Caddyfile, este test lo hace visible en el diff en vez de dejarlo pasar
  // silenciosamente junto con los otros dos tests (que sólo comprueban el
  // subconjunto ya propagado).
  const vistas = variablesDelCaddyfile(caddyfile);
  assert.deepEqual([...vistas].sort(), ['ACME_EMAIL', 'MGMT_ALLOWLIST', 'N8N_HOST', 'SIEM_ALLOWLIST']);
});
