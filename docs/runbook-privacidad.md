# Runbook · Privacidad y retención

Un SOAR ve todo lo que ve el SIEM: nombres de usuario, IPs internas, rutas de
ficheros, y con frecuencia credenciales en claro dentro de líneas de log. n8n
persiste por defecto los datos de cada nodo de cada ejecución.

Sin controles, **la base de ejecuciones del SOAR se convierte en una filtración
secundaria**: un repositorio no diseñado para datos sensibles, con toda la
telemetría del SIEM dentro, y probablemente con más gente teniendo acceso al
editor de n8n que a la consola del SIEM.

## Controles implementados

### 1. Recorte en origen (`send_to_blinksec.py`)

El emisor de Splunk descarta los campos internos (`_raw`, `_indextime`, …)
antes de construir el payload — conserva sólo `_time`, que sí importa para
el triaje. `_raw` es el campo que más veces contiene credenciales, porque
recoge la línea de log íntegra.

Los datos que nunca se necesitaron no pueden filtrarse: recortar en el emisor
es más efectivo que sanear en el destino.

### 2. Retención acotada (`docker-compose.yml`)

```
EXECUTIONS_DATA_PRUNE=true
EXECUTIONS_DATA_MAX_AGE=168          # 7 días
EXECUTIONS_DATA_PRUNE_MAX_COUNT=25000
EXECUTIONS_DATA_SAVE_ON_PROGRESS=false
EXECUTIONS_DATA_SAVE_MANUAL_EXECUTIONS=false
```

Siete días cubren la depuración de un incidente reciente. Las ejecuciones
fallidas conviene retenerlas más (30 días) porque son las que se investigan
tarde; se ajusta desde la UI de n8n por flujo.

### 3. Saneado antes del ticket (WF-06)

La función `sanear()` elimina recursivamente `raw`, `full_log`, `rawBody`,
`password`, `token`, `api_key` y `secret` antes de componer la descripción.

Es el punto donde los datos **salen del perímetro del SOC** hacia una
plataforma que ve mucha más gente. El saneado va aquí, no al final.

### 4. Lo que se persiste en Postgres

`blinksec.alerts.normalized` guarda el payload **normalizado**, no el crudo. El
contrato normalizado sólo contiene lo que el triaje necesita.

> Nota: `lib/normalize.js` adjunta el objeto `raw` al resultado para facilitar
> la depuración. WF-01 lo persiste tal cual. **Si la política de datos de la
> organización lo exige, eliminar `raw` antes del INSERT** — es un cambio de
> una línea en el nodo `Registrar alerta (UPSERT)`.

## Riesgo residual

El payload crudo **sí** atraviesa WF-00 y WF-01 y queda en los datos de
ejecución durante la ventana de retención. Los controles acotan la exposición
en tiempo, no la eliminan.

Para entornos con requisitos estrictos:

- Reducir `EXECUTIONS_DATA_MAX_AGE` a 24-48 h.
- Poner `EXECUTIONS_DATA_SAVE_ON_SUCCESS=none` y retener sólo los fallos. Se
  pierde capacidad de depuración a cambio de exposición mínima.
- Cifrado en reposo del volumen de Postgres.

## Verificación periódica

Qué se está guardando de verdad:

```sql
SELECT
  date_trunc('day', "startedAt") AS dia,
  count(*)                        AS ejecuciones,
  pg_size_pretty(sum(pg_column_size(data))) AS tamano
FROM execution_data
JOIN execution_entity ON execution_entity.id = execution_data."executionId"
GROUP BY 1 ORDER BY 1 DESC LIMIT 14;
```

Si la poda funciona, no debe haber filas de más de 7 días.

Búsqueda de patrones que no deberían estar ahí:

```sql
SELECT "executionId"
FROM execution_data
WHERE data ILIKE '%password=%' OR data ILIKE '%BEGIN PRIVATE KEY%'
LIMIT 10;
```

Un resultado no vacío significa que el recorte en origen no está cubriendo
algún camino. Investigar qué regla lo genera y ampliar el filtro de
`send_to_blinksec.py`.

## Acceso

- El editor de n8n sólo es alcanzable desde `MGMT_ALLOWLIST` (ver `Caddyfile`).
- Los accesos al editor deben tratarse como accesos a datos del SIEM, con el
  mismo control que la consola del SIEM de origen.
- El acceso a `/webhook/*` no da visibilidad sobre datos: sólo permite enviar,
  y sin la firma HMAC ni eso.
