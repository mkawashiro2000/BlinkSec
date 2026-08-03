# Runbook · Despliegue

## 1. Infraestructura

```bash
cp docker/.env.example docker/.env && chmod 600 docker/.env
```

Generar cada secreto:

```bash
openssl rand -base64 32   # POSTGRES_PASSWORD, REDIS_PASSWORD, N8N_ENCRYPTION_KEY
openssl rand -hex 32      # BLINKSEC_HMAC_SECRET_* (uno por plataforma)
```

`N8N_ENCRYPTION_KEY` se guarda además fuera del servidor. Si se pierde, todas
las credenciales almacenadas en n8n son irrecuperables y hay que recrearlas a
mano.

Ajustar `SIEM_ALLOWLIST` (IPs de los colectores) y `MGMT_ALLOWLIST` (desde
dónde se abre el editor). El editor de n8n expuesto a internet es ejecución
remota de código con pasos extra.

```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps
```

El esquema de Postgres se crea solo la primera vez desde
`docker/initdb/01-blinksec-schema.sql`. Si el volumen ya existía, aplicarlo a
mano.

Verificación:

```bash
curl -sk https://TU_HOST/webhook/blinksec/ingest -X POST -d '{}' -o /dev/null -w '%{http_code}\n'
```

Desde una IP fuera de `SIEM_ALLOWLIST` debe responder `403`. Desde una IP
autorizada, `401` (sin firma). Un `200` aquí significa que el gateway no está
verificando: parar y revisar antes de seguir.

## 2. Credenciales en n8n

Los nodos referencian credenciales por id. Hay que crearlas con estos nombres:

| Id | Tipo | Notas |
|---|---|---|
| `blinksec-pg` | Postgres | mismos datos que el `.env` |
| `blinksec-redis` | Redis | con contraseña |
| `blinksec-greynoise` | Header Auth | `key: <API key>` |
| `blinksec-abuseipdb` | Header Auth | `Key: <API key>` + `Accept: application/json` |
| `blinksec-virustotal` | Header Auth | `x-apikey: <API key>` |
| `blinksec-xforce` | Basic Auth | usuario = API key, contraseña = API password |
| `blinksec-thehive` | Header Auth | `Authorization: Bearer <key>` |
| `blinksec-wazuh` | Header Auth | `Authorization: Bearer <JWT>` |
| `blinksec-slack` | Slack API | scopes `chat:write`, `chat:write.public` |

## 3. Workflows

```bash
npm run build
```

Importar los ficheros de `workflows/dist/` en orden inverso de dependencia
(WF-99 primero, WF-00 último), porque cada uno referencia al siguiente.

Tras importar, en cada flujo salvo WF-99: *Settings → Error Workflow → WF-99*.
El campo `errorWorkflow` del JSON usa el nombre lógico, no el id que n8n asigna
al importar, así que hay que reasignarlo a mano una vez.

Igual con los nodos *Execute Sub-workflow*: apuntan a `WF-01`, `WF-02`… y hay
que seleccionar el flujo real en el desplegable.

## 4. Datos de dominio

Sin esto el sistema funciona pero no automatiza: todo activo desconocido se
trata como `high` y toda contención pide aprobación humana.

```sql
INSERT INTO blinksec.assets (hostname, ip, criticality, owner_team, never_isolate) VALUES
  ('db-prod-01',  '10.20.9.40', 'crown_jewel', 'plataforma', true),
  ('web-01',      '10.20.4.11', 'medium',      'web',        false),
  ('honeypot-01', '10.20.99.5', 'low',         'seguridad',  false);

-- Lo más importante de todo el despliegue: los rangos que NUNCA se bloquean.
INSERT INTO blinksec.ip_allowlist (cidr, reason, added_by) VALUES
  ('203.0.113.0/28', 'Salida de la VPN corporativa', 'despliegue'),
  ('198.51.100.0/24','Proxy de salida de oficina',   'despliegue'),
  ('10.10.5.0/24',   'Escáner de vulnerabilidades del SOC', 'despliegue');
```

Omitir la allowlist es el error más caro posible: un bloqueo automático sobre
la VPN desconecta a toda la plantilla en teletrabajo.

## 5. Wazuh

```bash
cp integrations/wazuh/custom-n8n.py /var/ossec/integrations/custom-n8n
chown root:wazuh /var/ossec/integrations/custom-n8n
chmod 750 /var/ossec/integrations/custom-n8n

cp integrations/wazuh/custom-ar.py /var/ossec/active-response/bin/custom-ar
chown root:wazuh /var/ossec/active-response/bin/custom-ar
chmod 750 /var/ossec/active-response/bin/custom-ar
```

El nombre del wrapper **no lleva extensión**: Wazuh busca el ejecutable por el
valor de `<name>` del bloque `<integration>`.

Insertar `integrations/wazuh/ossec.conf.snippet.xml` dentro de `<ossec_config>`
en `/var/ossec/etc/ossec.conf`, poniendo el secreto real en `<api_key>`, y:

```bash
systemctl restart wazuh-manager
tail -f /var/ossec/logs/integrations-blinksec.log
```

Si aparece `401`, el secreto de `ossec.conf` no coincide con
`BLINKSEC_HMAC_SECRET_WAZUH`. Si aparece `403`, falta la IP del manager en
`SIEM_ALLOWLIST`.

## 6. Ensayo controlado

**Antes de conectar producción.** En laboratorio:

1. Enviar una alerta de prueba con una IP conocida y benigna (8.8.8.8).
   Esperado: veredicto `false_positive`, sin contención, sin ticket.
2. Enviar una alerta con una IP de prueba maliciosa sobre un activo `low`.
   Esperado: veredicto `critical`, bloqueo ejecutado, fila en
   `containment_log` con `undo_payload` y `expires_at`.
3. Forzar la reversión:
   ```sql
   UPDATE blinksec.containment_log SET expires_at = now() - interval '1 minute'
   WHERE reverted_at IS NULL;
   ```
   Esperar a WF-07 y comprobar que `reverted_at` se rellena y la regla de
   iptables desaparece del agente.
4. Repetir el paso 2 con un activo `crown_jewel`. Esperado: mensaje en Slack
   con botones y **ninguna acción** hasta pulsar. Dejar expirar los 15 min y
   comprobar que se escala a guardia sin ejecutar nada.
5. Reenviar la misma alerta del paso 2. Esperado: descartada por idempotencia,
   sin segundo ticket ni segunda contención.

Si el paso 4 o el 5 no se comportan como se describe, no conectar producción.

## 7. Reversión de un despliegue

Los workflows están versionados en Git como JSON:

```bash
git log --oneline workflows/dist/
git checkout <commit> -- workflows/dist/
```

Reimportar en n8n sobrescribiendo. Objetivo: menos de 10 minutos desde la
detección del problema.
