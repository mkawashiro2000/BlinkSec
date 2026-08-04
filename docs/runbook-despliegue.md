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

> **Si cambias cualquier valor de `docker/.env` después de que los
> contenedores ya están arriba**, `docker compose restart` **no basta**: sólo
> reinicia el proceso con las variables que el contenedor ya tenía cargadas
> al crearse, no relee el `.env`. El síntoma es un 403/comportamiento viejo
> que persiste sin ningún error visible — se probó en la práctica cambiando
> `MGMT_ALLOWLIST` y el contenedor de Caddy siguió aplicando el valor
> anterior tras el restart. Hace falta recrear el contenedor:
> ```bash
> docker compose up -d --force-recreate caddy
> ```
> (o el servicio que corresponda; para n8n-main/webhook/worker aplica igual).

Antes de levantar nada, comprobar que `docker-compose.yml` propaga al
contenedor de Caddy toda variable que el `Caddyfile` referencia:

```bash
npm run check:caddy-env
```

> Esto no es opcional. En el primer despliegue, `MGMT_ALLOWLIST` y
> `ACME_EMAIL` se leían en el `Caddyfile` pero el compose no los declaraba en
> el `environment:` del servicio — Caddy caía en silencio a su default
> hardcodeado (*cualquier red privada*) y el `.env` del operador no tenía
> ningún efecto sobre el acceso al editor. Sin error visible. Ver R-12 en
> `docs/riesgos.md`.

Caddy usa una imagen construida en el propio compose (necesita el módulo
`caddy-ratelimit`, ausente en la imagen oficial); la primera vez tarda varios
minutos en compilar:

```bash
docker compose -f docker/docker-compose.yml build caddy
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps
```

El esquema de Postgres se crea solo la primera vez desde
`docker/initdb/01-blinksec-schema.sql`. Si el volumen ya existía, aplicarlo a
mano.

**Verificación de la capa perimetral.** Los tres controles se prueban por
separado — cada uno protege contra algo distinto y ha fallado de forma
independiente en el pasado:

```bash
# 1. Superficie pública: 403 fuera de SIEM_ALLOWLIST, 400/401 dentro (sin firma)
curl -sk https://TU_HOST/webhook/blinksec/ingest -X POST -d '{}' -o /dev/null -w '%{http_code}\n'
```

Un `200` aquí significa que el gateway no está verificando la firma: parar y
revisar antes de seguir.

```bash
# 2. Editor: 403 desde fuera de MGMT_ALLOWLIST
curl -sk https://TU_HOST/ -o /dev/null -w '%{http_code}\n'
```

Probar este paso **desde una máquina fuera de `MGMT_ALLOWLIST`**, no desde el
propio servidor — localhost y la red interna suelen colar por accidente dentro
del rango permitido, y eso es exactamente lo que ocultó el fallo de R-12 en
las pruebas iniciales.

```bash
# 3. Rate limiting: tras el umbral configurado (120/min por defecto),
#    las peticiones extra devuelven 429 y se recuperan pasada la ventana.
for i in $(seq 1 130); do
  curl -sk -o /dev/null -w '%{http_code}\n' https://TU_HOST/webhook/blinksec/ingest -X POST -d '{}'
done | sort | uniq -c
```

Debe aparecer un bloque de `429` a partir de la petición 121 aproximadamente.
Si todas dan el mismo código, el módulo `rate_limit` no está activo — revisar
que la imagen se construyó con `Dockerfile.caddy` y no con `caddy:2.8-alpine`
a secas.

## 2. Credenciales en n8n

Se pueden importar por CLI en lugar de crearlas a mano. Preparar un fichero con
la forma siguiente (**fuera del repo**: contiene secretos en claro; n8n los
cifra al importar con `N8N_ENCRYPTION_KEY`):

```json
[
  { "id": "blinksec-pg", "name": "BlinkSec Postgres", "type": "postgres",
    "data": { "host": "postgres", "port": 5432, "database": "blinksec",
              "user": "blinksec", "password": "...", "ssl": "disable" } },
  { "id": "blinksec-redis", "name": "BlinkSec Redis", "type": "redis",
    "data": { "host": "redis", "port": 6379, "password": "...", "database": 0 } }
]
```

```bash
docker compose -f docker/docker-compose.yml cp /ruta/creds.json n8n-main:/tmp/creds.json
docker compose -f docker/docker-compose.yml exec n8n-main n8n import:credentials --input=/tmp/creds.json
docker compose -f docker/docker-compose.yml exec n8n-main rm -f /tmp/creds.json
```

Borrar el fichero de origen después. Los ids **deben** ser exactamente los que
esperan los nodos:

| Id | Tipo | Notas |
|---|---|---|
| `blinksec-pg` | Postgres | mismos datos que el `.env` |
| `blinksec-redis` | Redis | con contraseña |
| `blinksec-abuseipdb` | Header Auth | `Key: <API key>` + `Accept: application/json` |
| `blinksec-virustotal` | Header Auth | `x-apikey: <API key>` |
| `blinksec-crowdsec` | Header Auth | `x-api-key: <API key>` (obtenida en app.crowdsec.net → CTI) |
| `blinksec-cloudflare` | Header Auth | `Authorization: Bearer <API Token>` |
| `blinksec-slack` | Slack API | scopes `chat:write`, `chat:write.public` |

## 3. Workflows

```bash
npm run build
```

```bash
docker compose -f docker/docker-compose.yml exec n8n-main n8n import:workflow --separate --input=/workflows/dist
```

No hay orden de importación ni paso de enlazado manual: cada workflow lleva un
**id determinista** (`blinksecwf00gtwy`, `blinksecwf01norm`…) y las referencias
cruzadas apuntan directamente a esos ids. La importación es idempotente —
ejecutarla dos veces actualiza, no duplica.

> Esto importa más de lo que parece. Sin id estable, `n8n import:workflow` crea
> un workflow nuevo en cada importación en lugar de actualizar el existente. En
> las pruebas de despliegue eso dejó **dos gateways**, con el antiguo todavía
> activo atendiendo tráfico después de desplegar un arreglo de seguridad, y sin
> ningún error visible. `npm run build` lo bloquea si falta el id.

Activar los dos workflows con disparador propio. **No es sólo el gateway**:
WF-07 (reversión programada) también tiene su propio trigger —
`scheduleTrigger`, cada 15 minutos— y si no se activa nunca revierte nada,
sin ningún error visible (las contenciones simplemente se acumulan sin
caducar). El resto de subflujos NO se activan: los invoca WF-00/WF-02/…
directamente.

```bash
docker compose -f docker/docker-compose.yml exec n8n-main n8n update:workflow --id=blinksecwf00gtwy --active=true
docker compose -f docker/docker-compose.yml exec n8n-main n8n update:workflow --id=blinksecwf07revr --active=true
```

La activación sólo surte efecto al reiniciar:

```bash
docker compose -f docker/docker-compose.yml restart n8n-main n8n-webhook
```

Verificar que ambos quedaron activos:

```sql
SELECT id, active FROM workflow_entity WHERE id IN ('blinksecwf00gtwy', 'blinksecwf07revr');
```

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

## 5. Wazuh y TheHive — retirados del sistema

Wazuh (como fuente de ingesta y como plataforma de contención vía
active-response) y TheHive (como destino de ticketing) se retiraron por
completo del sistema. Ver R-19 en `riesgos.md` para el porqué. Quedan dos
fuentes de ingesta (Splunk, Elastic) y Cloudflare como única plataforma de
bloqueo de IP; el ticketing vive sólo en Postgres (WF-06) hasta que se
conecte una plataforma externa real.

## 6. Verificación del gateway y de las credenciales

Antes de nada, comprobar que el gateway rechaza lo que debe. Con el secreto de
`BLINKSEC_HMAC_SECRET_SPLUNK`:

```bash
docker compose -f docker/docker-compose.yml cp tools/load-test.js n8n-webhook:/tmp/lt.js
```

```bash
docker compose -f docker/docker-compose.yml exec n8n-webhook node /tmp/lt.js http://localhost:5678/webhook/blinksec/ingest "$BLINKSEC_HMAC_SECRET_SPLUNK" 20 4
```

Todas las respuestas deben ser `200`. Una petición sin firma debe dar `401`, y
una con `X-BlinkSec-Source` desconocido, `400`.

**Verificar las credenciales de inteligencia una por una.** Una clave mal
copiada no falla de forma visible: VirusTotal puede devolver respuestas que el
sistema interpreta como "IoC desconocido" en lugar de como error, y el SOAR
quedaría ciego pareciendo sano (ver R-09 en `riesgos.md`).

La comprobación concreta: enviar una alerta con `8.8.8.8` como `srcip` y
confirmar en la ejecución de WF-02 que AbuseIPDB y VirusTotal responden con
`200` (revisar `_meta.failed` en el `enrichment` de la ejecución).

```sql
SELECT verdict, score, partial_enrichment FROM blinksec.alerts ORDER BY received_at DESC LIMIT 5;
```

Con esas dos credenciales correctas, `partial_enrichment` debe ser `false`.

> **CrowdSec CTI es una tercera fuente best-effort, no core** (ver R-18 en
> `riesgos.md`): el plan gratuito son sólo 120 consultas/mes, así que su
> nodo puede devolver `429` con normalidad sin que `partial_enrichment` se
> active — sólo AbuseIPDB y VirusTotal cuentan para ese techo. Verificar su
> credencial por separado con **una única** alerta de prueba, no con
> `load-test.js`: agotaría la cuota mensual entera en segundos.
>
> GreyNoise e IBM X-Force se retiraron del sistema — nunca hubo credenciales
> operativas para ninguno de los dos. Ver R-14 y R-17 en `riesgos.md`.

## 7. Ensayo controlado

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

## 8. Reversión de un despliegue

Los workflows están versionados en Git como JSON:

```bash
git log --oneline workflows/dist/
git checkout <commit> -- workflows/dist/
```

Reimportar en n8n sobrescribiendo. Objetivo: menos de 10 minutos desde la
detección del problema.
