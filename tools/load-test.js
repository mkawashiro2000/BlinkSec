#!/usr/bin/env node
'use strict';
/**
 * BlinkSec — prueba de carga del gateway de ingesta.
 *
 * Mide DOS cosas que conviene no confundir, porque el documento de diseño
 * original las mezclaba en una sola cifra de "1.5 segundos":
 *
 *   1. CÓMPUTO PURO — cuánto tarda el motor de triaje en decidir. Es la cifra
 *      bonita, del orden de microsegundos, y es la que no importa
 *      operativamente porque nunca es el cuello de botella.
 *
 *   2. LATENCIA DEL GATEWAY — cuánto tarda una alerta firmada en ser aceptada
 *      y encolada, medido de extremo a extremo contra un n8n real. Ésta sí
 *      determina si el SOAR aguanta una tormenta de alertas.
 *
 * La latencia de extremo a extremo COMPLETA (incluido el enriquecimiento)
 * añade las llamadas a las APIs de inteligencia, que dominan el presupuesto:
 * entre 200 y 800 ms por proveedor, y con los límites de tasa del free tier
 * puede irse a segundos. Esa parte no se mide aquí porque exige claves reales.
 *
 * USO (dentro del contenedor, que es quien alcanza al webhook):
 *   docker compose cp ../tools/load-test.js n8n-webhook:/tmp/lt.js
 *   docker compose exec n8n-webhook node /tmp/lt.js <url> <secreto> [n] [concurrencia]
 */

const crypto = require('node:crypto');

const URL_WEBHOOK = process.argv[2] || 'http://localhost:5678/webhook/blinksec/ingest';
const SECRETO = process.argv[3];
const TOTAL = Number(process.argv[4] || 200);
const CONCURRENCIA = Number(process.argv[5] || 10);

if (!SECRETO) {
  console.error('Falta el secreto HMAC. Uso: node load-test.js <url> <secreto> [n] [concurrencia]');
  process.exit(1);
}

function firmar(cuerpo, secreto, ts) {
  return crypto.createHmac('sha256', secreto).update(`${ts}.${cuerpo}`, 'utf8').digest('hex');
}

/** Cada petición lleva una IP y timestamp distintos: alert_id único, sin colisión de idempotencia. */
function alerta(i) {
  return JSON.stringify({
    timestamp: new Date(Date.now() - i * 1000).toISOString(),
    rule: { level: 10, description: 'sshd: brute force', id: '5712', groups: ['sshd'] },
    agent: { id: String(100 + (i % 50)), name: `host-${i % 50}`, ip: '10.20.4.11' },
    manager: { name: 'wazuh-mgr-01' },
    id: `carga-${i}`,
    data: { srcip: `45.155.${Math.floor(i / 256) % 256}.${i % 256}`, dstuser: 'admin' },
  });
}

function percentil(arr, p) {
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
}

async function main() {
  console.log(`Enviando ${TOTAL} alertas firmadas, concurrencia ${CONCURRENCIA}\n`);

  const latencias = [];
  const estados = {};
  let siguiente = 0;

  const arranque = Date.now();

  async function trabajador() {
    for (;;) {
      const i = siguiente++;
      if (i >= TOTAL) return;

      const cuerpo = alerta(i);
      const ts = String(Math.floor(Date.now() / 1000));
      const t0 = process.hrtime.bigint();

      try {
        const res = await fetch(URL_WEBHOOK, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-BlinkSec-Source': 'wazuh',
            'X-BlinkSec-Timestamp': ts,
            'X-BlinkSec-Signature': `sha256=${firmar(cuerpo, SECRETO, ts)}`,
          },
          body: cuerpo,
        });
        await res.text();
        latencias.push(Number(process.hrtime.bigint() - t0) / 1e6);
        estados[res.status] = (estados[res.status] ?? 0) + 1;
      } catch (e) {
        estados[`error:${e.message.slice(0, 40)}`] = (estados[`error:${e.message.slice(0, 40)}`] ?? 0) + 1;
      }
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCIA }, trabajador));

  const segundos = (Date.now() - arranque) / 1000;

  console.log('Códigos de respuesta:');
  for (const [k, v] of Object.entries(estados)) console.log(`  ${k}: ${v}`);

  if (latencias.length === 0) {
    console.error('\nNinguna petición completó. Revisar que el webhook esté escuchando y el flujo activo.');
    process.exit(1);
  }

  console.log('\nLatencia del gateway (aceptar y encolar):');
  console.log(`  p50   ${percentil(latencias, 50).toFixed(1)} ms`);
  console.log(`  p95   ${percentil(latencias, 95).toFixed(1)} ms`);
  console.log(`  p99   ${percentil(latencias, 99).toFixed(1)} ms`);
  console.log(`  max   ${Math.max(...latencias).toFixed(1)} ms`);

  console.log('\nRendimiento:');
  console.log(`  ${(TOTAL / segundos).toFixed(1)} alertas/s  (${(60 * TOTAL / segundos).toFixed(0)} alertas/min)`);
  console.log(`  ${segundos.toFixed(1)} s en total`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
