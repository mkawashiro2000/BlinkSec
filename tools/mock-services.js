#!/usr/bin/env node
'use strict';
/**
 * BlinkSec — mocks de proveedores externos para el ensayo de contención de
 * la Fase 7 (WF-04, WF-05, WF-07).
 *
 * Sustituye a AbuseIPDB, VirusTotal, CrowdSec CTI y Cloudflare mientras no
 * hay credenciales ni infraestructura real disponibles. Escucha en HTTP
 * plano (sin TLS) y enruta por ruta, no por Host, así que un único proceso
 * basta para todos los proveedores dentro de la red docker interna.
 *
 * GreyNoise, IBM X-Force, Wazuh y TheHive se retiraron del sistema (ver
 * docs/riesgos.md) y ya no tienen mock aquí.
 *
 * NO ES CÓDIGO DE PRODUCCIÓN. Vive fuera de lib/ y workflows/ a propósito:
 * nunca se inyecta en un workflow ni se importa desde otro módulo del repo.
 *
 * Comportamiento configurable por variable de entorno, para poder ensayar
 * tanto el camino de contención como el de descarte con el mismo binario:
 *   MOCK_VERDICT=malicious   (default) intel maliciosa en ambas fuentes
 *   MOCK_VERDICT=benign      intel limpia — para confirmar que no contiene
 */

const http = require('node:http');

const PUERTO = Number(process.env.PORT || 80);
const VEREDICTO = process.env.MOCK_VERDICT || 'malicious';

function json(res, status, body) {
  const texto = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(texto) });
  res.end(texto);
}

function leerCuerpo(req) {
  return new Promise((resolve) => {
    let datos = '';
    req.on('data', (c) => (datos += c));
    req.on('end', () => {
      try {
        resolve(datos ? JSON.parse(datos) : {});
      } catch {
        resolve({});
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Respuestas de inteligencia — forma real de cada API, no un atajo simplificado
// ---------------------------------------------------------------------------

function abuseipdb() {
  const conf = VEREDICTO === 'benign' ? 0 : 97;
  return {
    data: {
      abuseConfidenceScore: conf,
      totalReports: VEREDICTO === 'benign' ? 0 : 812,
      numDistinctUsers: VEREDICTO === 'benign' ? 0 : 140,
      countryCode: 'ZZ',
      isp: 'Mock Hosting',
      isWhitelisted: false,
    },
  };
}

function virustotal(esHash) {
  if (VEREDICTO === 'benign') {
    return { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 40, undetected: 30 } } } };
  }
  return {
    data: {
      attributes: {
        last_analysis_stats: { malicious: 55, suspicious: 4, harmless: 1, undetected: 10 },
        popular_threat_classification: { suggested_threat_label: 'mock.trojan/ensayo' },
      },
    },
  };
}

function crowdsec() {
  if (VEREDICTO === 'benign') {
    return { scores: { overall: { threat: 0, aggressiveness: 0 } }, classifications: { classifications: [] } };
  }
  return {
    scores: { overall: { threat: 4, aggressiveness: 3 } },
    classifications: { classifications: [{ label: 'CrowdSec Community Blocklist' }] },
  };
}

// ---------------------------------------------------------------------------
// Servidor
// ---------------------------------------------------------------------------

const registro = [];

const servidor = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'mock'}`);
  const entrada = { metodo: req.method, ruta: url.pathname, hora: new Date().toISOString() };

  // --- Inteligencia de amenazas -------------------------------------------
  if (url.pathname === '/api/v2/check') return json(res, 200, abuseipdb());
  if (url.pathname.startsWith('/api/v3/files/')) return json(res, 200, virustotal(true));
  if (url.pathname.startsWith('/api/v3/ip_addresses/')) return json(res, 200, virustotal(false));
  if (url.pathname.startsWith('/v2/smoke/')) return json(res, 200, crowdsec());

  // --- Cloudflare: bloqueo y reversión de IP -------------------------------
  if (url.pathname.match(/^\/accounts\/[^/]+\/firewall\/access_rules\/rules$/) && req.method === 'POST') {
    const cuerpo = await leerCuerpo(req);
    registro.push({ ...entrada, cuerpo });
    console.log(`[mock-cloudflare] regla creada: ${JSON.stringify(cuerpo)}`);
    return json(res, 200, { success: true, result: { id: `mock-rule-${Date.now()}` } });
  }
  if (url.pathname.match(/^\/accounts\/[^/]+\/firewall\/access_rules\/rules\/[^/]+$/) && req.method === 'DELETE') {
    registro.push({ ...entrada });
    console.log(`[mock-cloudflare] regla eliminada: ${url.pathname}`);
    return json(res, 200, { success: true });
  }

  // --- Introspección para las aserciones del ensayo ------------------------
  if (url.pathname === '/_mock/log') return json(res, 200, registro);
  if (url.pathname === '/_mock/reset') {
    registro.length = 0;
    return json(res, 200, { ok: true });
  }

  json(res, 404, { error: 'ruta no simulada', pathname: url.pathname });
});

servidor.listen(PUERTO, () => {
  console.log(`mock-services escuchando en :${PUERTO} — MOCK_VERDICT=${VEREDICTO}`);
});
