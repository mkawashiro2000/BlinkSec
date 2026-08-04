# Integración Elastic Security → BlinkSec

Elastic se conecta mediante un **conector Webhook** de Kibana, configurado como
acción de una regla de detección.

## El problema real: serialización

El conector de Kibana construye el cuerpo con plantillas Mustache. Con una sola
alerta funciona sin sorpresas. Con **alertas múltiples** —una regla que dispara
sobre varios documentos a la vez— Elastic produce salidas que **no son JSON
válido**:

**Caso A — ndjson (JSON delimitado por saltos de línea)**
```
{"context":{...}}
{"context":{...}}
```
`JSON.parse` falla: hay dos objetos concatenados sin array que los contenga.

**Caso B — array con coma terminal**
```json
[{"context":{...}},{"context":{...}},]
```
Válido en JavaScript relajado, inválido en JSON estricto.

Ambos casos vienen de iterar variables de contexto con `{{#context.alerts}}`
sin cerrar correctamente la estructura.

## Defensa en dos capas

**Capa 1 — arreglarlo en origen.** Es el arreglo correcto. Usar `.asJSON` sobre
las variables de array, que emite JSON estricto:

```
{{#context.alerts}}...{{/context.alerts}}     ← produce ndjson o comas colgando
{{context.alerts.asJSON}}                     ← produce un array JSON válido
```

**Capa 2 — tolerarlo en destino.** `lib/normalize.js` incluye `parseLoose()`,
que recupera ambos formatos. Existe porque el SOAR no puede depender de que
todas las reglas de detección, escritas por gente distinta a lo largo de meses,
estén bien configuradas. Una regla mal plantillada debe degradar esa alerta, no
tumbar la ingesta.

Los dos casos están cubiertos por tests:
`tests/fixtures/normalize.test.js` → «elastic: parsea ndjson multi-alerta» y
«elastic: recupera un array con coma terminal».

## Firma HMAC

El conector Webhook de Kibana **sí** admite cabeceras personalizadas, pero **no
puede calcular un HMAC**: no ejecuta código, sólo rellena plantillas. Hay dos
salidas:

1. **Token estático en cabecera** (más débil). Un secreto fijo en
   `X-BlinkSec-Signature` no es una firma: no cubre el cuerpo ni el timestamp,
   así que no protege contra manipulación ni reenvío. Sólo evita el POST
   anónimo. Aceptable únicamente si Elastic y n8n comparten una red privada y
   la allowlist del proxy está bien puesta.

2. **Reenvío firmado desde Logstash o una Function** (recomendado). Un salto
   intermedio que firma con el mismo esquema que Splunk.

Este repo asume la **opción 1 con allowlist de red estricta** para Elastic, y lo
declara como una diferencia real de postura de seguridad respecto a las otras
dos plataformas. Está anotado en `docs/riesgos.md` porque no es un detalle de
implementación: es una excepción consciente al modelo de amenaza.

## Configuración del conector

Kibana → *Stack Management* → *Connectors* → *Create connector* → *Webhook*.

- **Method**: POST
- **URL**: `https://soar.example.com/webhook/blinksec/ingest`
- **Headers**: los de `connector-headers.json`
- **Body**: el de `connector-body.mustache`
