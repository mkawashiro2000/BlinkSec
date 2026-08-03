'use strict';
/**
 * BlinkSec WF-03 — Motor de puntuación y triaje.
 *
 * Éste es el cerebro del SOAR y, por tanto, la parte con más capacidad de
 * hacer daño. Un motor de scoring mal calibrado que auto-contiene falsos
 * positivos es peor que no tener SOAR: destruye la confianza del equipo en la
 * automatización y provoca cortes de servicio con la firma de la organización.
 *
 * Por eso:
 *   - Los pesos viven en weights.json, versionados aparte del código.
 *   - La función es pura y determinista: mismas entradas, misma salida.
 *   - Cada decisión emite su `rationale`, que se adjunta al ticket. Un analista
 *     debe poder reconstruir POR QUÉ el sistema decidió aislar un host.
 *   - Existen techos que impiden auto-contener con información insuficiente.
 *
 * @injectable
 */

// El build inyecta weights.json aquí; fuera de n8n se carga del fichero.
const WEIGHTS = typeof BLINKSEC_WEIGHTS !== 'undefined' ? BLINKSEC_WEIGHTS : require('./weights.json');

const VERDICTS = { FALSE_POSITIVE: 'false_positive', INVESTIGATE: 'investigate', CRITICAL: 'critical' };

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

/**
 * Comprueba si una IP está en la allowlist propia.
 *
 * Se evalúa ANTES de cualquier puntuación, no después. Bloquear el rango del
 * proxy corporativo o del concentrador VPN es el error más caro que puede
 * cometer un SOAR: una denegación de servicio auto-infligida sobre los propios
 * empleados, ejecutada a velocidad de máquina y con permisos de administrador.
 */
function isAllowlisted(ip, allowlist) {
  if (!ip || !Array.isArray(allowlist)) return false;
  return allowlist.some((cidr) => ipInCidr(ip, cidr));
}

function ipToLong(ip) {
  const partes = String(ip).split('.');
  if (partes.length !== 4) return null;
  let out = 0;
  for (const p of partes) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = (out << 8) + n;
  }
  return out >>> 0;
}

function ipInCidr(ip, cidr) {
  const [base, bitsRaw] = String(cidr).split('/');
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  const ipLong = ipToLong(ip);
  const baseLong = ipToLong(base);
  if (ipLong === null || baseLong === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipLong & mask) === (baseLong & mask);
}

// ---------------------------------------------------------------------------
// Señales individuales
// ---------------------------------------------------------------------------

function scoreGreyNoise(gn, w, rationale) {
  if (!gn?.available) return 0;
  const s = w.signals;

  if (gn.verdict === 'benign' && gn.data?.kind === 'business_service') {
    rationale.push(`GreyNoise: servicio comercial conocido (${gn.data.name ?? 'sin nombre'}) → descarte fuerte`);
    return s.greynoise_business_service;
  }
  if (gn.verdict === 'benign') {
    rationale.push(`GreyNoise: escáner benigno documentado (${gn.data?.actor ?? 'actor desconocido'})`);
    return s.greynoise_benign_scanner;
  }
  if (gn.verdict === 'malicious') {
    rationale.push(`GreyNoise: escáner clasificado como malicioso (${gn.data?.actor ?? 'actor desconocido'})`);
    return s.greynoise_malicious_scanner;
  }
  if (gn.verdict === 'suspicious') {
    rationale.push('GreyNoise: escáner sospechoso');
    return s.greynoise_suspicious_scanner;
  }
  if (gn.verdict === 'not_observed') {
    // No aparecer en el ruido de fondo de internet es LEVEMENTE agravante: la
    // IP no escanea indiscriminadamente, luego el contacto contigo es más
    // probablemente dirigido. Peso pequeño: también es lo normal en IPs
    // domésticas o de móvil.
    rationale.push('GreyNoise: IP no observada en el ruido de internet (posible actividad dirigida)');
    return s.greynoise_not_observed;
  }
  return 0;
}

function scoreVirusTotal(vt, w, rationale) {
  if (!vt?.available) return 0;
  const s = w.signals;

  if (vt.verdict === 'malicious') {
    // Escalado por proporción de motores, no binario: 40/70 motores es una
    // señal mucho más fuerte que 5/70, que suele ser ruido heurístico.
    const ratio = clamp(vt.data?.ratio ?? 0, 0, 1);
    const puntos = Math.round(s.virustotal_malicious_max * clamp(ratio * 3, 0.4, 1));
    rationale.push(
      `VirusTotal: ${vt.data.malicious}/${vt.data.total} motores lo marcan como malicioso` +
        (vt.data.popularName ? ` (${vt.data.popularName})` : ''),
    );
    return puntos;
  }
  if (vt.verdict === 'suspicious') {
    rationale.push(`VirusTotal: ${vt.data.malicious}/${vt.data.total} motores — señal débil`);
    return s.virustotal_suspicious;
  }
  if (vt.verdict === 'clean') {
    rationale.push(`VirusTotal: limpio en ${vt.data.total} motores`);
    return s.virustotal_clean;
  }
  // 'unknown' (no conocido por VT) no puntúa en ninguna dirección: un binario
  // a medida es desconocido para VT precisamente por ser dirigido.
  if (vt.verdict === 'unknown') rationale.push('VirusTotal: artefacto desconocido (sin veredicto)');
  return 0;
}

function scoreAbuseIPDB(ab, w, rationale) {
  if (!ab?.available) return 0;
  const s = w.signals;

  if (ab.data?.isWhitelisted) {
    rationale.push('AbuseIPDB: IP en lista blanca del proveedor');
    return s.abuseipdb_whitelisted;
  }
  const conf = clamp(Number(ab.data?.abuseConfidenceScore ?? 0), 0, 100);
  if (conf === 0) {
    // IP conocida por AbuseIPDB sin ningún reporte: evidencia débil de
    // benignidad, no ausencia de información.
    rationale.push('AbuseIPDB: sin reportes de abuso');
    return s.abuseipdb_clean;
  }

  const puntos = Math.round((conf / 100) * s.abuseipdb_max);
  rationale.push(
    `AbuseIPDB: confianza de abuso ${conf}% con ${ab.data.totalReports} reportes de ${ab.data.distinctReporters} fuentes`,
  );
  return puntos;
}

function scoreXForce(xf, w, rationale) {
  if (!xf?.available) return 0;
  const s = w.signals;
  if (xf.verdict === 'malicious') {
    rationale.push(`IBM X-Force: riesgo ${xf.data.score}/10 (${xf.data.categories.join(', ') || 'sin categoría'})`);
    return s.xforce_malicious;
  }
  if (xf.verdict === 'suspicious') {
    rationale.push(`IBM X-Force: riesgo ${xf.data.score}/10`);
    return s.xforce_suspicious;
  }
  return 0;
}

function scoreRuleLevel(alert, w, rationale) {
  const nivel = Number(alert?.rule?.level ?? 0);
  if (nivel >= w.rule_level.high_threshold) {
    rationale.push(`Regla de detección de severidad alta (nivel ${nivel})`);
    return w.signals.rule_level_high;
  }
  if (nivel >= w.rule_level.medium_threshold) {
    rationale.push(`Regla de detección de severidad media (nivel ${nivel})`);
    return w.signals.rule_level_medium;
  }
  return 0;
}

function scoreAsset(alert, w, rationale) {
  const c = alert?.asset?.criticality;
  if (c === 'crown_jewel') {
    rationale.push('Activo clasificado como crítico para el negocio');
    return w.signals.asset_crown_jewel;
  }
  if (c === 'high') {
    rationale.push('Activo de criticidad alta');
    return w.signals.asset_high;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Función principal
// ---------------------------------------------------------------------------

/**
 * @param {object} alert       alerta normalizada (contrato de lib/normalize.js)
 * @param {object} enrichment  salida de lib/enrich.js aggregate()
 * @param {object} [options]
 * @param {string[]} [options.allowlist]  CIDRs propios
 * @param {object}   [options.weights]    override de pesos (para tests)
 * @returns {{score, verdict, requiresApproval, rationale, caps, allowlisted}}
 */
function score(alert, enrichment, options = {}) {
  const w = options.weights ?? WEIGHTS;
  const rationale = [];
  const capsAplicados = [];

  // --- Puerta 0: allowlist propia ------------------------------------------
  const ipsAlerta = (alert?.artifacts?.ips ?? []).map((i) => i.value);
  const ipAllowlisted = ipsAlerta.find((ip) => isAllowlisted(ip, options.allowlist ?? []));
  if (ipAllowlisted) {
    return {
      score: 0,
      verdict: VERDICTS.FALSE_POSITIVE,
      requiresApproval: false,
      allowlisted: true,
      rationale: [`IP ${ipAllowlisted} pertenece a un rango propio en la allowlist — nunca se contiene`],
      caps: ['allowlist'],
      weightsVersion: w.version,
    };
  }

  // --- Suma de señales ------------------------------------------------------
  // Línea base: "alerta sin contexto → se investiga". Deliberadamente por
  // debajo del punto medio, de modo que ninguna señal aislada alcance el
  // umbral crítico: la contención automática exige siempre corroboración.
  let bruto = w.base ?? 35;
  rationale.push(`Línea base sin contexto: ${bruto}`);

  bruto += scoreGreyNoise(enrichment?.greynoise, w, rationale);
  bruto += scoreVirusTotal(enrichment?.virustotal, w, rationale);
  bruto += scoreAbuseIPDB(enrichment?.abuseipdb, w, rationale);
  bruto += scoreXForce(enrichment?.xforce, w, rationale);
  bruto += scoreRuleLevel(alert, w, rationale);
  bruto += scoreAsset(alert, w, rationale);

  let puntuacion = clamp(Math.round(bruto), 0, 100);

  // --- Techos de seguridad --------------------------------------------------
  // Estos NO son ajustes finos: son la diferencia entre un sistema que escala
  // cuando duda y uno que actúa a ciegas.
  const meta = enrichment?._meta ?? {};

  if (meta.partial) {
    if (puntuacion > w.caps.partial_enrichment) {
      puntuacion = w.caps.partial_enrichment;
      rationale.push(
        `TECHO: enriquecimiento parcial (caídos: ${(meta.failed ?? []).join(', ')}) — no se permite contención automática`,
      );
      capsAplicados.push('partial_enrichment');
    }
  }

  if (alert?.validation?.enriquecible === false) {
    if (puntuacion > w.caps.unenrichable) {
      puntuacion = w.caps.unenrichable;
      rationale.push('TECHO: alerta sin artefactos consultables — requiere análisis humano');
      capsAplicados.push('unenrichable');
    }
  }

  if ((meta.providersOk ?? 0) === 1 && puntuacion > w.caps.single_provider) {
    puntuacion = w.caps.single_provider;
    rationale.push('TECHO: un solo proveedor de inteligencia disponible — fuente única sin corroborar');
    capsAplicados.push('single_provider');
  }

  // --- Veredicto ------------------------------------------------------------
  let verdict;
  if (puntuacion < w.thresholds.false_positive) verdict = VERDICTS.FALSE_POSITIVE;
  else if (puntuacion > w.thresholds.critical) verdict = VERDICTS.CRITICAL;
  else verdict = VERDICTS.INVESTIGATE;

  // --- ¿Necesita aprobación humana? ----------------------------------------
  // Sólo aplica a los casos críticos; los demás no contienen nada.
  const criticidad = alert?.asset?.criticality;
  const neverIsolate = alert?.asset?.never_isolate === true;
  const requiresApproval =
    verdict === VERDICTS.CRITICAL && (neverIsolate || criticidad === 'crown_jewel' || criticidad === 'high');

  if (requiresApproval) {
    rationale.push(
      neverIsolate
        ? 'Activo marcado never_isolate: la contención exige aprobación humana explícita'
        : `Activo de criticidad "${criticidad}": la contención pasa por Human-in-the-Loop`,
    );
  }

  return {
    score: puntuacion,
    verdict,
    requiresApproval,
    allowlisted: false,
    rationale,
    caps: capsAplicados,
    weightsVersion: w.version,
  };
}

module.exports = { score, isAllowlisted, ipInCidr, VERDICTS, WEIGHTS };
