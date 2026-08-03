#!/usr/bin/env node
'use strict';
/**
 * BlinkSec — mocks de proveedores externos para el ensayo de contención de
 * la Fase 7 (WF-04, WF-05, WF-07).
 *
 * Sustituye a GreyNoise, AbuseIPDB, VirusTotal, IBM X-Force, Wazuh y TheHive
 * mientras no hay credenciales ni infraestructura real disponibles. Escucha
 * en HTTP plano (sin TLS) y enruta por ruta, no por Host, así que un único
 * proceso basta para todos los proveedores dentro de la red docker interna.
 *
 * NO ES CÓDIGO DE PRODUCCIÓN. Vive fuera de lib/ y workflows/ a propósito:
 * nunca se inyecta en un workflow ni se importa desde otro módulo del repo.
 *
 * Comportamiento configurable por variable de entorno, para poder ensayar
 * tanto el camino de contención como el de descarte con el mismo binario:
 *   MOCK_VERDICT=malicious   (default) intel maliciosa en las 4 fuentes
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

function greynoise() {
  if (VEREDICTO === 'benign') {
    return { business_service_intelligence: { found: false }, internet_scanner_intelligence: { found: false } };
  }
  return {
    internet_scanner_intelligence: {
      found: true,
      classification: 'malicious',
      actor: 'mock-botnet',
      last_seen: new Date().toISOString().slice(0, 10),
      cves: ['CVE-2024-9999'],
    },
  };
}

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

function xforce() {
  if (VEREDICTO === 'benign') return { score: 0, cats: {} };
  return { score: 9, cats: { Malware: 95, 'Botnet Command and Control Server': 80 } };
}

// ---------------------------------------------------------------------------
// Servidor
// ---------------------------------------------------------------------------

const registro = [];

const servidor = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'mock'}`);
  const entrada = { metodo: req.method, ruta: url.pathname, hora: new Date().toISOString() };

  // --- Inteligencia de amenazas -------------------------------------------
  if (url.pathname.startsWith('/v3/ip/')) return json(res, 200, greynoise());
  if (url.pathname === '/api/v2/check') return json(res, 200, abuseipdb());
  if (url.pathname.startsWith('/api/v3/files/')) return json(res, 200, virustotal(true));
  if (url.pathname.startsWith('/api/v3/ip_addresses/')) return json(res, 200, virustotal(false));
  if (url.pathname.startsWith('/malware/') || url.pathname.startsWith('/ipr/')) return json(res, 200, xforce());

  // --- Wazuh: ejecución y reversión de respuesta activa -------------------
  if (url.pathname === '/active-response' && req.method === 'PUT') {
    const cuerpo = await leerCuerpo(req);
    registro.push({ ...entrada, cuerpo });
    console.log(`[mock-wazuh] active-response: ${JSON.stringify(cuerpo)}`);
    return json(res, 200, { error: 0, data: { affected_items: [cuerpo.agents_list ?? []] } });
  }

  // --- TheHive --------------------------------------------------------------
  if (url.pathname === '/api/v1/alert' && req.method === 'POST') {
    const cuerpo = await leerCuerpo(req);
    registro.push({ ...entrada, cuerpo });
    console.log(`[mock-thehive] alerta creada: ${cuerpo.title ?? cuerpo.sourceRef ?? '(sin título)'}`);
    return json(res, 201, { _id: `mock-ticket-${Date.now()}` });
  }
  if (url.pathname === '/api/v1/alert/_bulk' && req.method === 'POST') {
    const cuerpo = await leerCuerpo(req);
    registro.push({ ...entrada, cuerpo });
    return json(res, 200, { ok: true });
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
