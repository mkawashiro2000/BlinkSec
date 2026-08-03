'use strict';
/**
 * Tests de planificación de contención (WF-04).
 *
 * Lo que se verifica aquí no es que el sistema sepa bloquear, sino que sepa
 * NO bloquear: las barreras que impiden que una decisión automática toque
 * producción sin fundamento.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { planContainment, blockIp, isolateHost, revokeSession, dueForReversal, ContainmentPlanError } = require('../../lib/containment.js');

const AHORA = Date.UTC(2026, 7, 2, 12, 0, 0);

const alertaCritica = {
  alert_id: 'abc123',
  agent_id: '004',
  rule: { id: '5712', level: 12 },
  asset: { host: 'web-01', criticality: 'low' },
  identity: { user: null },
  artifacts: { ips: [{ value: '45.155.205.233', direction: 'src' }], hashes: [] },
};

const veredictoCritico = { verdict: 'critical', requiresApproval: false, allowlisted: false, caps: [] };

// ---------------------------------------------------------------------------
// Barreras de seguridad
// ---------------------------------------------------------------------------

test('no planifica nada si el veredicto no es crítico', () => {
  for (const v of ['false_positive', 'investigate']) {
    const plan = planContainment(alertaCritica, { ...veredictoCritico, verdict: v }, { now: AHORA });
    assert.equal(plan.actions.length, 0);
    assert.ok(plan.skipped.includes('veredicto_no_critico'));
  }
});

test('no planifica nada sobre una IP en allowlist', () => {
  const plan = planContainment(alertaCritica, { ...veredictoCritico, allowlisted: true }, { now: AHORA });
  assert.equal(plan.actions.length, 0);
  assert.ok(plan.skipped.includes('ip_en_allowlist'));
});

test('no contiene si se aplicó algún techo, aunque el veredicto llegue como crítico', () => {
  // Esta combinación sólo puede darse por un bug aguas arriba. La última
  // barrera antes de producción no confía en que WF-03 sea correcto.
  const plan = planContainment(
    alertaCritica,
    { ...veredictoCritico, caps: ['partial_enrichment'] },
    { now: AHORA },
  );
  assert.equal(plan.actions.length, 0);
  assert.equal(plan.requiresApproval, true);
  assert.match(plan.skipped[0], /techo_aplicado/);
});

test('respeta never_isolate y lo deja registrado', () => {
  const alerta = {
    ...alertaCritica,
    asset: { host: 'dc-01', criticality: 'crown_jewel', never_isolate: true },
    artifacts: { ips: [], hashes: [{ value: 'a'.repeat(64), type: 'sha256' }] },
  };
  const plan = planContainment(alerta, veredictoCritico, {
    now: AHORA,
    platforms: { endpoint: 'crowdstrike' },
  });
  assert.ok(!plan.actions.some((a) => a.action_type === 'isolate_host'));
  assert.ok(plan.skipped.includes('activo_marcado_never_isolate'));
});

test('propaga requiresApproval desde el veredicto', () => {
  const plan = planContainment(alertaCritica, { ...veredictoCritico, requiresApproval: true }, { now: AHORA });
  assert.equal(plan.requiresApproval, true);
  // Las acciones se planifican igualmente: el flujo las ejecuta sólo tras el
  // botón de Slack. Planificar no es ejecutar.
  assert.ok(plan.actions.length > 0);
});

// ---------------------------------------------------------------------------
// Reversibilidad — la regla de oro
// ---------------------------------------------------------------------------

test('toda acción nace con undo_payload y expires_at', () => {
  const alerta = {
    ...alertaCritica,
    identity: { user: 'j.martinez@corp.com' },
    artifacts: {
      ips: [{ value: '45.155.205.233', direction: 'src' }],
      hashes: [{ value: 'b'.repeat(64), type: 'sha256' }],
    },
  };
  const plan = planContainment(alerta, veredictoCritico, {
    now: AHORA,
    agentId: '004',
    platforms: { ip: 'wazuh_ar', endpoint: 'crowdstrike', identity: 'entra_id' },
  });

  assert.equal(plan.actions.length, 3);
  for (const a of plan.actions) {
    assert.ok(a.undo_payload, `${a.action_type} sin undo_payload`);
    assert.ok(a.expires_at, `${a.action_type} sin expires_at`);
    assert.ok(new Date(a.expires_at).getTime() > AHORA, `${a.action_type}: caducidad en el pasado`);
  }
});

test('el bloqueo de IP en Wazuh se acota al agente afectado', () => {
  // Sin agents_list, Wazuh propaga la respuesta activa a TODA la flota. Ese
  // es el fallo que convierte una contención en un incidente propio.
  const accion = blockIp('1.2.3.4', 'wazuh_ar', { agentId: '004' });
  assert.deepEqual(accion.request.body.agents_list, ['004']);
  assert.equal(accion.undo_payload.body.command, '!firewall-drop-stop');
  assert.deepEqual(accion.undo_payload.body.agents_list, ['004']);
});

test('el bloqueo en Cloudflare declara que su reversión necesita el RULE_ID', () => {
  const accion = blockIp('1.2.3.4', 'cloudflare', { accountId: 'acc1', alertId: 'x', expiresAt: 'y' });
  assert.deepEqual(accion.undo_payload.requires, ['RULE_ID']);
  assert.match(accion.undo_payload.path, /\{\{RULE_ID\}\}/);
});

test('el aislamiento de endpoint es reversible con lift_containment', () => {
  const accion = isolateHost('host-abc', { alertId: 'x' });
  assert.match(accion.request.path, /action_name=contain/);
  assert.match(accion.undo_payload.path, /action_name=lift_containment/);
  assert.equal(accion.reversible, true);
});

test('la revocación de sesión se declara explícitamente irreversible', () => {
  const accion = revokeSession('u@corp.com', 'entra_id', { alertId: 'x' });
  assert.equal(accion.reversible, false);
  assert.match(accion.undo_payload.note, /reautenticarse/);
});

test('lanza ante plataformas no soportadas en vez de fallar en silencio', () => {
  assert.throws(() => blockIp('1.2.3.4', 'firewall-inventado', {}), ContainmentPlanError);
  assert.throws(() => revokeSession('u', 'ldap-casero', {}), ContainmentPlanError);
});

// ---------------------------------------------------------------------------
// Selección de acciones
// ---------------------------------------------------------------------------

test('no aísla el endpoint por una IP atacante externa sin hash en el host', () => {
  // Que alguien te escanee no justifica desconectar tu servidor de la red.
  const plan = planContainment(alertaCritica, veredictoCritico, {
    now: AHORA,
    platforms: { ip: 'wazuh_ar', endpoint: 'crowdstrike' },
  });
  assert.ok(!plan.actions.some((a) => a.action_type === 'isolate_host'));
  assert.ok(plan.actions.some((a) => a.action_type === 'block_ip'));
});

test('no planifica acciones para plataformas no configuradas', () => {
  const alerta = { ...alertaCritica, identity: { user: 'u@corp.com' } };
  const plan = planContainment(alerta, veredictoCritico, { now: AHORA, platforms: { ip: 'wazuh_ar' } });
  assert.ok(!plan.actions.some((a) => a.action_type === 'revoke_session'));
});

test('bloquea tanto la IP de origen como el destino de C2', () => {
  const alerta = {
    ...alertaCritica,
    artifacts: {
      ips: [
        { value: '45.155.205.233', direction: 'src' },
        { value: '171.25.193.78', direction: 'dst' },
      ],
      hashes: [],
    },
  };
  const plan = planContainment(alerta, veredictoCritico, { now: AHORA, platforms: { ip: 'wazuh_ar' } });
  assert.equal(plan.actions.filter((a) => a.action_type === 'block_ip').length, 2);
});

// ---------------------------------------------------------------------------
// Reversión programada (WF-07)
// ---------------------------------------------------------------------------

test('dueForReversal selecciona sólo lo vencido y sin revertir', () => {
  const filas = [
    { id: 1, expires_at: new Date(AHORA - 1000).toISOString(), reverted_at: null, undo_payload: {} },
    { id: 2, expires_at: new Date(AHORA + 100000).toISOString(), reverted_at: null, undo_payload: {} },
    { id: 3, expires_at: new Date(AHORA - 5000).toISOString(), reverted_at: '2026-08-02T11:00:00Z', undo_payload: {} },
    { id: 4, expires_at: new Date(AHORA - 5000).toISOString(), reverted_at: null, undo_payload: null },
  ];
  const pendientes = dueForReversal(filas, AHORA).map((r) => r.id);
  assert.deepEqual(pendientes, [1]);
});

test('dueForReversal tolera una lista vacía o ausente', () => {
  assert.deepEqual(dueForReversal([], AHORA), []);
  assert.deepEqual(dueForReversal(undefined, AHORA), []);
});
