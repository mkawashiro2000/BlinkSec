# BlinkSec — Plan de Proyecto

> **Estado a 2026-08-02.** Fases 0 a 6 implementadas y cubiertas por 140 tests
> en verde; Fase 7 (endurecimiento y pase a producción) pendiente, porque
> requiere un despliegue real. Ver [README.md](README.md) para el estado del
> código y [docs/riesgos.md](docs/riesgos.md) para lo que queda abierto.
>
> Dos desviaciones del plan original, ambas por motivos que aparecieron al
> construir:
>
> - **Línea base de puntuación 35, no 50.** Con base 50 una sola señal negativa
>   casi nunca bajaba de 20, así que los falsos positivos evidentes no se
>   auto-cerraban. Con base 35 ninguna señal aislada alcanza el umbral crítico:
>   la contención automática exige siempre corroboración de dos fuentes.
> - **Nuevo módulo `tools/build-workflows.js`.** Los nodos Code de n8n no pueden
>   hacer `require` de ficheros del repo, así que la lógica probada y la
>   ejecutada habrían acabado duplicadas y divergentes. El compilador las
>   mantiene como una sola fuente de verdad, y CI falla si divergen.

**SOAR de código abierto sobre n8n.** Ingesta de alertas SIEM/EDR → normalización → enriquecimiento con inteligencia de amenazas → triaje por puntuación → contención automatizada → ticketing y auditoría.

Objetivo operativo: reducir el ciclo alerta→contención de 15–30 min manuales a ~1.5 s de ejecución computacional, con Human-in-the-Loop en las acciones de alto impacto.

---

## 0. Supuestos y decisiones de arranque

Estos son los defaults que asumo; cámbialos y el plan se adapta sin reestructurarse.

| Decisión | Default asumido | Alternativa |
|---|---|---|
| SIEM primario para el MVP | Wazuh (open source, control total del `ossec.conf`) | Splunk / Elastic Security |
| Despliegue de n8n | Docker Compose, modo `queue` con Redis + Postgres | n8n Cloud (descarta control de `N8N_*` y redacción de logs) |
| Reverse proxy | Caddy (TLS automático + rate limiting) | NGINX + certbot |
| Ticketing | TheHive (nativo de seguridad) | Jira |
| ChatOps | Slack (Block Kit para HITL) | Discord (sin botones nativos equivalentes) |
| Contención de red MVP | Wazuh Active Response (iptables en el agente) | Cloudflare WAF / Palo Alto |

**Riesgo estructural que señalo desde ya:** el número de 1.5 s es tiempo de CPU del workflow, no latencia de extremo a extremo. Las APIs de VirusTotal/AbuseIPDB/GreyNoise imponen 200–800 ms cada una y sus límites de tasa (VT free: 4 req/min) dominan el presupuesto real. El plan mide **ambas** métricas por separado y usa caché de IoCs para que el free tier no sea el cuello de botella.

---

## 1. Arquitectura objetivo

```
  Wazuh / Splunk / Elastic
            │  (HTTPS POST + HMAC-SHA256 + X-Timestamp)
            ▼
   Caddy  ── rate limit, límite de payload, mTLS opcional
            ▼
  ┌─────────────────────────────────────────────┐
  │  n8n (queue mode)                           │
  │                                             │
  │  [WF-00] Gateway: verifica HMAC, replay,    │
  │          idempotencia (alert_id → Redis)    │
  │            ▼                                │
  │  [WF-01] Normalizador → esquema BlinkSec    │
  │            ▼                                │
  │  [WF-02] Enriquecimiento (paralelo)         │
  │     VirusTotal │ AbuseIPDB │ GreyNoise v3   │
  │     │ IBM X-Force │ caché Redis por IoC     │
  │            ▼                                │
  │  [WF-03] Scoring y triaje  →  <20 / 20-70 / >70 │
  │       ├── bajo   → cierra alerta en SIEM    │
  │       ├── medio  → ticket TheHive           │
  │       └── crítico→ [WF-04] Contención       │
  │                     └─ [WF-05] HITL si el   │
  │                        activo es crítico    │
  │            ▼                                │
  │  [WF-06] Ticketing + Slack + auditoría      │
  │  [WF-99] Error Trigger global               │
  └─────────────────────────────────────────────┘
```

Cada `[WF-xx]` es un subflujo independiente invocado con **Execute Sub-workflow**. Ningún flujo supera ~15 nodos. Nomenclatura: `[BlinkSec] WF-02 - Enriquecimiento IoC - v1`.

### Esquema normalizado (contrato interno)

Todo lo que sale de WF-01 cumple este contrato. Es el punto de desacople que hace el resto agnóstico al origen.

```json
{
  "blinksec_version": "1.0",
  "alert_id": "<uuid determinista: sha256(origen+rule_id+ts+host)>",
  "source": "wazuh|splunk|elastic",
  "received_at": "<ISO8601>",
  "rule": { "id": "5710", "name": "...", "level": 10, "mitre": ["T1110"] },
  "asset": { "host": "...", "ip": "...", "criticality": "low|medium|high|crown_jewel" },
  "identity": { "user": "...", "domain": "..." },
  "artifacts": {
    "ips":    [{ "value": "1.2.3.4", "direction": "src|dst" }],
    "hashes": [{ "value": "...", "type": "md5|sha1|sha256" }],
    "domains": [], "urls": []
  },
  "raw": { }
}
```

`asset.criticality` viene de un **inventario de activos** (CSV/Postgres) — es lo que decide si la contención es automática o pasa por HITL. Sin este campo, el sistema no puede distinguir aislar un portátil de aislar la base de datos de producción; es un prerrequisito, no un extra.

---

## 2. Fases de ejecución

### Fase 0 — Infraestructura (2–3 días)

- `docker-compose.yml`: n8n (main + 2 workers + webhook process), Postgres, Redis, Caddy.
- Variables endurecidas: `N8N_PAYLOAD_SIZE_MAX=2`, `N8N_ENCRYPTION_KEY`, `EXECUTIONS_DATA_PRUNE=true`, `EXECUTIONS_DATA_MAX_AGE=168` (7 d éxito) y `EXECUTIONS_DATA_PRUNE_MAX_COUNT`, ejecuciones fallidas retenidas 30 d.
- Secretos fuera del repo: `.env` con `chmod 600` + `.gitignore`; nunca credenciales en el JSON del workflow.
- Caddy: TLS, `rate_limit` por IP de origen, cabeceras de seguridad, allowlist de IPs del SIEM.
- Repo Git inicializado con estructura definida en §4.

**Entregable:** n8n accesible en HTTPS, `curl` a un webhook de prueba devuelve 200; un `curl` desde IP no autorizada devuelve 403.

### Fase 1 — Gateway seguro (WF-00) (2 días)

Se construye **antes** que cualquier lógica de negocio. Un webhook SOAR sin autenticar es un vector de denegación de servicio auto-infligido: quien conozca la URL puede provocar bloqueos masivos de IPs legítimas.

Nodo Code inmediatamente después del Webhook:

1. HMAC-SHA256 sobre `$json.rawBody` (**no** sobre el JSON parseado — el parseo reordena claves y normaliza espacios, la firma jamás coincidiría), secreto desde `$env`, comparación con `crypto.timingSafeEqual` sobre buffers.
2. Replay: `Math.abs(now - X-Timestamp) > 300s` → descarta.
3. Nonce/idempotencia: `SETNX blinksec:nonce:<alert_id>` en Redis con TTL 24 h. Si ya existe → 200 y termina, sin re-ejecutar acciones.
4. Fallo → responde 401 y emite a WF-99.

**Entregable:** suite de tests negativos (`tests/gateway/`) — firma mala, timestamp viejo, replay, payload de 5 MB — todos rechazados.

### Fase 2 — Ingesta y normalización (WF-01) (3–4 días)

- Wazuh: bloque `<integration>` en `/var/ossec/etc/ossec.conf` + wrapper `integrations/custom-n8n.py` (filtrado local por nivel/regla antes de salir del servidor, firma HMAC, timestamp). Documentar permisos `750 root:ossec` y símbolo ejecutable.
- Splunk: `Better Webhooks` (Hurricane Labs) por tokens `$$full_result$$` y cabeceras de auth; la acción nativa no admite cabeceras personalizadas y queda descartada.
- Elastic: conector de Kibana con plantillas Mustache; nodo saneador obligatorio para `ndjson` (`{...}\n{...}`) y arrays con coma terminal (`[{},{},]`), usando `.asJSON` / `{{#ParseHjson}}` del lado de Elastic y un parser tolerante del lado n8n.
- Validación estricta: si falta `asset.host` o los artefactos están vacíos → rama de datos malformados a WF-99, nunca continuar con `undefined`.

**Entregable:** tres payloads de muestra reales (uno por plataforma) en `tests/fixtures/`, los tres producen el mismo esquema normalizado.

### Fase 3 — Enriquecimiento (WF-02) (4–5 días)

- Consulta en paralelo: GreyNoise `/v3/ip` (endpoint único que consolida scanners + RIOT; la v2 exigía dos llamadas), AbuseIPDB `/api/v2/check`, VirusTotal `/api/v3/files/{id}` y `/ip_addresses/{id}`, IBM X-Force (token dinámico → cabecera `Bearer`).
- **Caché de IoCs en Redis** con TTL diferenciado: 1 h para veredictos limpios, 24 h para maliciosos, 15 min para inconclusos. Es lo que hace viable el free tier de VirusTotal.
- Cada nodo HTTP: `Retry on Fail` con backoff exponencial (HTTP 429/5xx), timeout 10 s, `Continue on Fail` para que la caída de un proveedor no anule el enriquecimiento completo.
- Salida: objeto `enrichment` con un bloque por proveedor + `available: true|false` por cada uno.

**Entregable:** flujo que ante 4 proveedores, con 2 caídos, sigue produciendo un veredicto y lo marca como parcial.

### Fase 4 — Scoring y triaje (WF-03) (3 días)

Nodo Code con función de puntuación **versionada y testeable en aislamiento** (`scoring/score.js`, mismo código que se pega en el nodo, con tests en Jest).

Modelo propuesto (0–100, pesos ajustables en `scoring/weights.json`):

| Señal | Aporte |
|---|---|
| GreyNoise `classification: benign` / RIOT | −40 (veto suave de falso positivo) |
| GreyNoise `classification: malicious` | +30 |
| VirusTotal ≥5 motores maliciosos | +35 (escalado por ratio) |
| AbuseIPDB `abuseConfidenceScore` | +0…25 (proporcional) |
| Nivel de regla Wazuh ≥12 | +15 |
| `asset.criticality = crown_jewel` | +10 y fuerza HITL |
| Enriquecimiento parcial | techo de 69 (nunca auto-contiene con datos incompletos) |

Bifurcación: `<20` falso positivo → cierra en SIEM · `20–70` → ticket para investigación · `>70` → contención.

**Entregable:** batería de ≥20 casos de prueba etiquetados a mano (10 FP conocidos, 10 amenazas reales) con la matriz de confusión resultante. Este es el criterio de aceptación real del proyecto — un SOAR que auto-contiene falsos positivos es peor que no tener SOAR.

### Fase 5 — Contención (WF-04) + HITL (WF-05) (4–5 días)

- **Red:** Wazuh Active Response (`custom-ar.py` → iptables/Windows Firewall) en el MVP; Cloudflare/Palo Alto por HTTP Request en la iteración siguiente.
- **Identidad:** revocación de tokens de sesión y forzado de cambio de contraseña vía Entra ID / Google Workspace.
- **Endpoint:** aislamiento de host en CrowdStrike Falcon (mantiene el túnel forense).
- **Regla de oro:** toda acción de contención va acompañada de su acción inversa documentada y de un TTL. Nada se bloquea para siempre sin revisión — se registra en `containment_log` (Postgres) con `expires_at`, y un flujo programado propone la reversión.
- **HITL (WF-05):** si `asset.criticality ∈ {high, crown_jewel}` o la acción es aislamiento de endpoint → mensaje Slack con Block Kit ("Bloquear IP" / "Ignorar"), nodo **Wait** que genera la URL de reanudación. Timeout de 15 min → escala a guardia y no ejecuta nada por defecto (fail-safe, no fail-open).

**Entregable:** ensayo controlado en laboratorio — IP de prueba bloqueada, revertida, y evidencia en `containment_log`.

### Fase 6 — Ticketing, notificación y observabilidad (WF-06, WF-99) (2–3 días)

- TheHive/Jira: ticket con agente, regla, puntuaciones por proveedor, acciones ejecutadas y enlace a la ejecución de n8n. UPSERT por `alert_id`, nunca INSERT ciego.
- Slack: mensaje formateado por severidad al canal del SOC.
- WF-99 (Error Trigger global): notifica al canal de guardia con enlace de depuración; distingue error transitorio (reintentar) de error de configuración 401/403 (fallo rápido).
- Redacción de logs: sanitizar PII y claves API antes de que persistan en la tabla de ejecuciones. La base de ejecuciones del SOAR no puede convertirse en una filtración secundaria.
- Métricas: `alertas/h`, `% auto-cerradas`, `% escaladas`, `MTTC`, latencia p50/p95 **de extremo a extremo**, tasa de acierto de caché.

### Fase 7 — Endurecimiento y pase a producción (3–4 días)

- Prueba de carga: 500 alertas/min sostenidas; verificar que el modo queue escala y que no hay OOM.
- Simulacro de fallo: matar Redis, Postgres y un proveedor de TI en caliente.
- Runbook de reversión (<10 min): `git revert` del JSON del workflow + reimportación.
- Ejercicio de mesa con el equipo SOC sobre 5 escenarios reales.

---

## 3. Cronograma

| Semana | Contenido |
|---|---|
| 1 | Fase 0 + Fase 1 (infra y gateway seguro) |
| 2 | Fase 2 + inicio Fase 3 |
| 3 | Fase 3 + Fase 4 (con la batería de casos etiquetados) |
| 4 | Fase 5 (contención + HITL) |
| 5 | Fase 6 + Fase 7 |

~5 semanas a dedicación completa para MVP productivo con Wazuh. Splunk y Elastic se suman después, sin tocar nada aguas abajo de WF-01 — ese es el retorno del contrato normalizado.

---

## 4. Estructura del repositorio

```
BlinkSec/
├── README.md
├── PLAN.md
├── docker/            compose, Caddyfile, .env.example
├── workflows/         WF-00…WF-99 exportados como JSON (versionados)
├── scoring/           score.js, weights.json, tests
├── integrations/
│   ├── wazuh/         ossec.conf snippet, custom-n8n.py, custom-ar.py
│   ├── splunk/        config de Better Webhooks
│   └── elastic/       plantillas Mustache del conector
├── tests/
│   ├── gateway/       tests negativos de HMAC/replay/tamaño
│   ├── fixtures/      payloads reales por plataforma
│   └── triage/        casos etiquetados + matriz de confusión
├── docs/              runbooks, diagrama de arquitectura, catálogo de activos
└── .gitignore         (.env, credenciales, exports con secretos)
```

Los JSON de workflow se exportan y commitean en cada cambio: dan historial de diffs y rollback en minutos. Nunca exportar con credenciales embebidas.

---

## 5. Criterios de aceptación

1. Ningún webhook procesa una petición sin firma HMAC válida y ventana temporal vigente.
2. Un `alert_id` duplicado nunca genera un segundo ticket ni una segunda acción de contención.
3. Con 2 de 4 proveedores de inteligencia caídos, el sistema sigue produciendo veredictos y jamás auto-contiene con enriquecimiento parcial.
4. Falsos positivos auto-cerrados ≥60 % del volumen total, con **0 falsos positivos auto-contenidos** en la batería etiquetada.
5. Toda acción de contención es reversible y está registrada con su `expires_at`.
6. Activos `high`/`crown_jewel` nunca se contienen sin aprobación humana; el timeout de HITL no ejecuta nada.
7. Ningún flujo supera 20 nodos; la lógica compartida vive en subflujos.

---

## 6. Riesgos abiertos

| Riesgo | Mitigación |
|---|---|
| Límites de tasa de VirusTotal free (4 req/min) | Caché Redis por IoC; encolado; considerar tier de pago si el volumen lo exige |
| Bloqueo auto-infligido de IP legítima (proxy corporativo, VPN) | Allowlist de rangos propios evaluada **antes** del scoring, no después |
| El inventario de activos no existe o está desactualizado | Prerrequisito bloqueante de la Fase 5; sin él, todo pasa por HITL |
| Deriva de esquema del SIEM tras una actualización | Fixtures en CI; el saneador de WF-01 falla ruidosamente, nunca en silencio |
| PII en la base de ejecuciones | Redacción + poda agresiva desde la Fase 0, no al final |
```

Siguiente paso natural: Fase 0 — te levanto el `docker-compose.yml` endurecido, el `Caddyfile` y el esqueleto del repo.
