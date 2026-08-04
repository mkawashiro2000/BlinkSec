-- BlinkSec — esquema de dominio.
-- Se ejecuta una sola vez, al inicializar el volumen de Postgres.
-- Vive junto a la BD de n8n pero en su propio schema para que una migración
-- de n8n no arrastre estas tablas.

CREATE SCHEMA IF NOT EXISTS blinksec;

-- ---------------------------------------------------------------------------
-- Inventario de activos.
--
-- Es un PRERREQUISITO, no un extra: `criticality` es lo que decide si una
-- contención se ejecuta sola o pasa por aprobación humana. Sin este dato el
-- sistema no distingue aislar un portátil de aislar la BD de producción, y
-- WF-03 fuerza HITL para todo (comportamiento fail-safe por diseño).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blinksec.assets (
    id            BIGSERIAL PRIMARY KEY,
    hostname      TEXT NOT NULL,
    ip            INET,
    criticality   TEXT NOT NULL DEFAULT 'medium'
                  CHECK (criticality IN ('low','medium','high','crown_jewel')),
    owner_team    TEXT,
    business_unit TEXT,
    -- Si es true, la contención automática de red está prohibida para este
    -- activo aunque la puntuación sea máxima (ej. controladores de dominio).
    never_isolate BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hostname)
);
CREATE INDEX IF NOT EXISTS assets_ip_idx ON blinksec.assets (ip);

-- ---------------------------------------------------------------------------
-- Allowlist de rangos propios.
--
-- Se evalúa ANTES del scoring, no después. Bloquear el rango del proxy
-- corporativo o de la VPN es el fallo más caro que puede cometer un SOAR:
-- una denegación de servicio auto-infligida sobre los propios empleados.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blinksec.ip_allowlist (
    id         BIGSERIAL PRIMARY KEY,
    cidr       CIDR NOT NULL UNIQUE,
    reason     TEXT NOT NULL,
    added_by   TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO blinksec.ip_allowlist (cidr, reason, added_by) VALUES
    ('10.0.0.0/8',     'RFC1918 — red interna',            'bootstrap'),
    ('172.16.0.0/12',  'RFC1918 — red interna',            'bootstrap'),
    ('192.168.0.0/16', 'RFC1918 — red interna',            'bootstrap'),
    ('127.0.0.0/8',    'loopback',                          'bootstrap')
ON CONFLICT (cidr) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Alertas procesadas — idempotencia duradera.
--
-- Redis cubre la ventana de 24 h; esta tabla es el registro persistente que
-- sobrevive a un reinicio de Redis y sostiene el UPSERT de ticketing.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blinksec.alerts (
    alert_id       TEXT PRIMARY KEY,
    source         TEXT NOT NULL,
    rule_id        TEXT,
    rule_name      TEXT,
    asset_hostname TEXT,
    score          INTEGER,
    verdict        TEXT CHECK (verdict IN ('false_positive','investigate','critical')),
    partial_enrichment BOOLEAN NOT NULL DEFAULT FALSE,
    ticket_ref     TEXT,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at   TIMESTAMPTZ,
    -- Payload normalizado, NO el crudo: el crudo contiene más PII de la que
    -- necesitamos retener. Ver docs/runbook-privacidad.md.
    normalized     JSONB
);
CREATE INDEX IF NOT EXISTS alerts_received_idx ON blinksec.alerts (received_at DESC);
CREATE INDEX IF NOT EXISTS alerts_verdict_idx  ON blinksec.alerts (verdict);

-- ---------------------------------------------------------------------------
-- Log de contención.
--
-- Regla de oro del proyecto: toda acción de contención se registra con su
-- acción inversa y un expires_at. Nada se bloquea para siempre sin revisión.
-- WF-07 (programado) recorre esta tabla y propone reversiones.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blinksec.containment_log (
    id           BIGSERIAL PRIMARY KEY,
    alert_id     TEXT NOT NULL REFERENCES blinksec.alerts(alert_id),
    action_type  TEXT NOT NULL
                 CHECK (action_type IN ('block_ip','isolate_host','revoke_session','kill_process')),
    target       TEXT NOT NULL,
    -- CHECK explícito: una errata en el nombre de la plataforma haría que
    -- WF-07 nunca encontrara la fila para revertirla, dejando una regla de
    -- firewall activa para siempre sin que nada lo señale. Wazuh se retiró del
    -- sistema (ver docs/riesgos.md, R-19); hoy sólo cloudflare está operativa,
    -- las demás las construye lib/containment.js pero no hay ruta que las
    -- ejecute todavía.
    platform     TEXT NOT NULL
                 CHECK (platform IN ('cloudflare','crowdstrike','entra_id','google_workspace')),
    -- Comando/llamada exacta para deshacer. Se rellena en el momento de
    -- ejecutar, no se reconstruye después.
    undo_payload JSONB NOT NULL,
    approved_by  TEXT,                       -- NULL = automático; usuario Slack si hubo HITL
    executed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    reverted_at  TIMESTAMPTZ,
    revert_error TEXT
);
CREATE INDEX IF NOT EXISTS containment_pending_idx
    ON blinksec.containment_log (expires_at)
    WHERE reverted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Métricas de latencia — separa el tiempo de cómputo del extremo a extremo.
-- La cifra de "1.5 s" es CPU del workflow; lo que importa operativamente es
-- e2e_ms, dominado por las APIs de inteligencia y sus límites de tasa.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blinksec.metrics (
    id            BIGSERIAL PRIMARY KEY,
    alert_id      TEXT NOT NULL,
    e2e_ms        INTEGER NOT NULL,
    enrich_ms     INTEGER,
    compute_ms    INTEGER,
    cache_hits    INTEGER DEFAULT 0,
    cache_misses  INTEGER DEFAULT 0,
    providers_ok  INTEGER,
    providers_failed INTEGER,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS metrics_recorded_idx ON blinksec.metrics (recorded_at DESC);
