# Runbook · Idempotencia

## El problema

Los webhooks se disparan por duplicado. Wazuh reintenta si el POST expira,
Elastic puede reenviar un lote entero cuando sólo una alerta es nueva, y una
integración configurada dos veces por descuido entrega todo dos veces.

Sin control, cada duplicado abre un ticket y **ejecuta la contención otra vez**.
Con una tormenta de alertas, el SOC acaba con cientos de tickets duplicados que
tapan los incidentes reales.

## Tres capas

BlinkSec defiende en tres puntos independientes. Ninguno es suficiente solo.

### 1. `alert_id` determinista (`lib/gateway.js`)

```
alert_id = sha256(source | rule_id | event_timestamp | host | src_ip)[:32]
```

Derivado del contenido, no aleatorio. La misma alerta produce siempre el mismo
id. Se incluye el timestamp **del evento**, no el de recepción: dos ataques
idénticos en momentos distintos son incidentes distintos y deben tratarse por
separado.

### 2. Nonce en Redis (WF-00), TTL 24 h

Primera línea, rápida. Cubre la reentrega inmediata, que es el caso frecuente.

### 3. UPSERT en Postgres (WF-01) y `sourceRef` en TheHive (WF-06)

Capa duradera. Sobrevive a un reinicio de Redis. `ON CONFLICT DO UPDATE` con
`RETURNING (xmax = 0) AS es_nueva` distingue una inserción real de una
actualización: si la alerta ya existía, es un reenvío.

## R-05: la semántica SETNX

**El problema.** La capa 2 necesita "escribe sólo si no existe" —SETNX— en una
sola operación atómica. El nodo Redis de n8n expone `set` con TTL, pero que sea
SETNX real depende de la versión.

Con un `SET` normal, dos entregas simultáneas de la misma alerta pasan las dos:
ambas escriben, ninguna ve a la otra. Las capas 1 y 3 acotan el daño, pero la
ventana de carrera existe.

**Verificación en el despliegue real:**

```bash
docker compose -f docker/docker-compose.yml exec redis \
  redis-cli -a "$REDIS_PASSWORD" SET blinksec:test valor NX EX 60
# → OK

docker compose -f docker/docker-compose.yml exec redis \
  redis-cli -a "$REDIS_PASSWORD" SET blinksec:test otro NX EX 60
# → (nil)  ← esto es lo que debe salir
```

Después, disparar dos veces la misma alerta contra el webhook y comprobar que
sólo se crea un ticket.

## Patrón alternativo si el nodo no soporta SETNX

Sustituir el nodo `Reclamar nonce (Redis)` de WF-00 por esta secuencia:

1. **Redis → `get`** sobre `{{ $json.idempotencyKey }}`, con
   `alwaysOutputData: true` y `onError: continueRegularOutput`.
2. **IF** — ¿el valor está vacío?
   - **Sí** → 3. **No** → responder 200 y terminar (duplicado).
3. **Redis → `set`** con TTL 86400.
4. Continuar a WF-01.

Sigue habiendo una ventana de carrera entre el paso 1 y el 3, pero es de
milisegundos y las capas 3 la cubren.

**Opción robusta**: reemplazar los dos nodos por un único nodo Code que hable
con Redis mediante un script Lua (`SET key val NX EX 86400` es atómico en el
servidor). Exige habilitar el módulo `redis` en
`NODE_FUNCTION_ALLOW_EXTERNAL`, lo que amplía la superficie del sandbox — una
compensación que hay que decidir a la vista del volumen real.

## Qué NO es idempotente, a propósito

- **`revoke_session`** — revocar dos veces no tiene efecto adicional.
- **`kill_process`** — matar un proceso ya muerto no hace nada.
- **`block_ip` en `custom-ar.py`** — comprueba con `iptables -C` antes de
  insertar, así que repetirlo no acumula reglas duplicadas.

El único caso con efecto acumulativo real sería crear reglas en un WAF externo
sin comprobar antes. Por eso el `undo_payload` de Cloudflare declara
explícitamente que necesita el `RULE_ID` devuelto por la API.
