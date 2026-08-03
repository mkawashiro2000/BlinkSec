'use strict';
/**
 * BlinkSec WF-04 — Planificación de contención.
 *
 * Este módulo NO ejecuta nada: decide QUÉ acciones corresponden y construye,
 * para cada una, su acción inversa exacta. La ejecución la hacen los nodos
 * HTTP Request de n8n.
 *
 * Regla de oro del proyecto: toda acción de contención nace con su reversión
 * y su fecha de caducidad. Un SOAR que bloquea para siempre acumula, en un
 * año, miles de reglas de firewall que nadie se atreve a tocar porque nadie
 * recuerda por qué están. La reversión se construye en el momento de decidir
 * la acción — no se reconstruye después, cuando ya se perdió el contexto.
 *
 * @injectable
 */

/** Duración por defecto del bloqueo, en horas, según la confianza. */
const TTL_HORAS = {
  block_ip: 24,          // reevaluar al día siguiente; las IPs de botnet rotan
  isolate_host: 4,       // un host aislado sin atención en 4 h es una escalada
  revoke_session: 0,     // irreversible por naturaleza: no se "des-revoca"
  kill_process: 0,       // idem
};

class ContainmentPlanError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ContainmentPlanError';
  }
}

function horasEnMs(h) {
  return h * 3600 * 1000;
}

// ---------------------------------------------------------------------------
// Constructores de acción
// ---------------------------------------------------------------------------

/**
 * Bloqueo de IP en el perímetro.
 *
 * El `undo_payload` guarda el identificador de la regla creada. Se rellena
 * tras la ejecución con la respuesta de la API (WF-04 hace un UPDATE sobre
 * containment_log): sin el rule_id, revertir exige buscar a ciegas entre
 * cientos de reglas.
 */
function blockIp(ip, platform, ctx) {
  const base = {
    action_type: 'block_ip',
    target: ip,
    platform,
    reversible: true,
    ttl_hours: TTL_HORAS.block_ip,
  };

  if (platform === 'wazuh_ar') {
    return {
      ...base,
      request: {
        method: 'PUT',
        // La API de Wazuh dispara el script de respuesta activa en los agentes.
        path: '/active-response',
        body: {
          command: '!firewall-drop',
          // Sin agents_list, Wazuh lo propaga a TODA la flota. Se acota al
          // agente afectado salvo que se pida explícitamente lo contrario.
          agents_list: ctx.agentId ? [ctx.agentId] : [],
          arguments: [ip],
        },
      },
      undo_payload: {
        method: 'PUT',
        path: '/active-response',
        body: {
          command: '!firewall-drop-stop',
          agents_list: ctx.agentId ? [ctx.agentId] : [],
          arguments: [ip],
        },
      },
    };
  }

  if (platform === 'cloudflare') {
    return {
      ...base,
      request: {
        method: 'POST',
        path: `/accounts/${ctx.accountId}/firewall/access_rules/rules`,
        body: {
          mode: 'block',
          configuration: { target: 'ip', value: ip },
          notes: `BlinkSec ${ctx.alertId} — caduca ${ctx.expiresAt}`,
        },
      },
      // El id de la regla no se conoce hasta después de crearla; el flujo lo
      // sustituye con la respuesta antes de persistir en containment_log.
      undo_payload: {
        method: 'DELETE',
        path: `/accounts/${ctx.accountId}/firewall/access_rules/rules/{{RULE_ID}}`,
        requires: ['RULE_ID'],
      },
    };
  }

  throw new ContainmentPlanError(`Plataforma de bloqueo de IP no soportada: ${platform}`);
}

/**
 * Aislamiento de endpoint.
 *
 * CrowdStrike mantiene un túnel cifrado hacia el host aislado para que el
 * equipo forense siga teniendo acceso: se corta la red del atacante, no la
 * investigación.
 */
function isolateHost(hostId, ctx) {
  return {
    action_type: 'isolate_host',
    target: hostId,
    platform: 'crowdstrike',
    reversible: true,
    ttl_hours: TTL_HORAS.isolate_host,
    request: {
      method: 'POST',
      path: '/devices/entities/devices-actions/v2?action_name=contain',
      body: { ids: [hostId] },
    },
    undo_payload: {
      method: 'POST',
      path: '/devices/entities/devices-actions/v2?action_name=lift_containment',
      body: { ids: [hostId] },
    },
    context: { alertId: ctx.alertId },
  };
}

/**
 * Revocación de sesiones de identidad.
 *
 * Irreversible a propósito: "des-revocar" una sesión no existe ni tiene
 * sentido. El coste para el usuario legítimo es volver a autenticarse, que es
 * asumible; por eso esta acción no exige el mismo nivel de aprobación que
 * aislar un servidor.
 */
function revokeSession(user, platform, ctx) {
  const base = {
    action_type: 'revoke_session',
    target: user,
    platform,
    reversible: false,
    ttl_hours: TTL_HORAS.revoke_session,
    undo_payload: { note: 'No reversible: el usuario debe reautenticarse. Sin impacto permanente.' },
    context: { alertId: ctx.alertId },
  };

  if (platform === 'entra_id') {
    return {
      ...base,
      request: { method: 'POST', path: `/users/${user}/revokeSignInSessions`, body: {} },
    };
  }
  if (platform === 'google_workspace') {
    return {
      ...base,
      request: { method: 'POST', path: `/admin/directory/v1/users/${user}/signOut`, body: {} },
    };
  }
  throw new ContainmentPlanError(`Directorio de identidad no soportado: ${platform}`);
}

// ---------------------------------------------------------------------------
// Planificador
// ---------------------------------------------------------------------------

/**
 * Construye el plan de contención de una alerta ya triada.
 *
 * @param {object} alert     alerta normalizada
 * @param {object} verdict   salida de scoring/score.js
 * @param {object} config    { platforms: {...}, accountId, agentId, now }
 * @returns {{actions: object[], requiresApproval: boolean, skipped: string[]}}
 */
function planContainment(alert, verdict, config = {}) {
  const skipped = [];

  // Nunca se contiene nada que no sea crítico. Redundante con WF-03, a
  // propósito: es la última barrera antes de tocar producción.
  if (verdict.verdict !== 'critical') {
    return { actions: [], requiresApproval: false, skipped: ['veredicto_no_critico'] };
  }
  if (verdict.allowlisted) {
    return { actions: [], requiresApproval: false, skipped: ['ip_en_allowlist'] };
  }
  if (verdict.caps?.length) {
    // Cinturón y tirantes: si algún techo se aplicó, el veredicto no debería
    // ser crítico. Si llega aquí, hay un bug aguas arriba — no se contiene.
    return { actions: [], requiresApproval: true, skipped: [`techo_aplicado:${verdict.caps.join(',')}`] };
  }

  const now = config.now ?? Date.now();
  const actions = [];
  const ctx = {
    alertId: alert.alert_id,
    agentId: config.agentId ?? alert.agent_id,
    accountId: config.accountId,
  };

  // --- Bloqueo de las IPs de origen ---------------------------------------
  const platformIp = config.platforms?.ip ?? 'wazuh_ar';
  for (const { value, direction } of alert.artifacts?.ips ?? []) {
    // Sólo se bloquean IPs de origen (atacante) y destino de C2. Bloquear una
    // IP de destino legítima cortaría un servicio propio.
    if (!['src', 'dst'].includes(direction)) continue;
    const expiresAt = new Date(now + horasEnMs(TTL_HORAS.block_ip)).toISOString();
    actions.push({ ...blockIp(value, platformIp, { ...ctx, expiresAt }), expires_at: expiresAt });
  }

  // --- Aislamiento del endpoint -------------------------------------------
  // Sólo si hay evidencia en el propio host (un hash malicioso), no por una
  // IP atacante externa: que alguien te escanee no justifica desconectarte.
  const hayHashMalicioso = (alert.artifacts?.hashes ?? []).length > 0;
  if (hayHashMalicioso && config.platforms?.endpoint) {
    if (alert.asset?.never_isolate) {
      skipped.push('activo_marcado_never_isolate');
    } else {
      const expiresAt = new Date(now + horasEnMs(TTL_HORAS.isolate_host)).toISOString();
      actions.push({ ...isolateHost(alert.asset.host, ctx), expires_at: expiresAt });
    }
  }

  // --- Revocación de identidad --------------------------------------------
  if (alert.identity?.user && config.platforms?.identity) {
    const expiresAt = new Date(now + horasEnMs(1)).toISOString(); // sólo para el registro
    actions.push({ ...revokeSession(alert.identity.user, config.platforms.identity, ctx), expires_at: expiresAt });
  }

  return {
    actions,
    requiresApproval: verdict.requiresApproval === true,
    skipped,
  };
}

/** Acciones cuya caducidad ya venció y siguen sin revertir (WF-07). */
function dueForReversal(rows, now = Date.now()) {
  return (rows ?? []).filter(
    (r) => !r.reverted_at && r.undo_payload && new Date(r.expires_at).getTime() <= now,
  );
}

module.exports = {
  planContainment,
  blockIp,
  isolateHost,
  revokeSession,
  dueForReversal,
  TTL_HORAS,
  ContainmentPlanError,
};
