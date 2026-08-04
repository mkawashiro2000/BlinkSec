# BlinkSec

SOAR de código abierto sobre n8n. Ingesta alertas de Splunk o Elastic
Security, las enriquece con inteligencia de amenazas, las tría con un motor de
puntuación auditable y ejecuta contramedidas — con intervención humana
obligatoria donde el impacto lo justifica.

```
SIEM ──HMAC──▶ WF-00 gateway ──▶ WF-01 normalizar ──▶ WF-02 enriquecer
                                                            │
                                                     WF-03 triaje
                                          ┌─────────────────┼─────────────────┐
                                    <20 falso positivo  20-70 investigar  >70 crítico
                                          │                 │                 │
                                   registrar métrica   WF-06 ticket    WF-04 despacha
                                                                       ┌──────┴──────┐
                                                                sin aprobación   WF-05 HITL
                                                                       │        (Slack + Wait)
                                                                       └──────┬──────┘
                                                                       WF-08 ejecuta
                                                                     y registra la
                                                                        contención
```

## Estado

MVP funcional, **desplegado y verificado en ejecución real** sobre n8n 1.72.1
(Docker, modo queue, Postgres + Redis + Caddy). 173 tests en verde.

> **Se le pasó una auditoría de seguridad completa** que encontró dos fallos
> críticos **en vivo**: el Human-in-the-Loop se podía saltar por completo desde
> fuera, y el sistema perdía alertas en silencio. Ambos corregidos y
> verificados. El detalle íntegro está en R-21 de
> [docs/riesgos.md](docs/riesgos.md); el resumen honesto, en
> [Lo que NO está verificado](#lo-que-no-está-verificado).

Verificado de extremo a extremo contra el despliegue:

- Los 10 workflows importan y se enlazan entre sí sin pasos manuales.
- El gateway acepta la firma válida y rechaza los 6 vectores de ataque
  probados: firma incorrecta, firma ausente, cuerpo alterado, reenvío con
  timestamp caducado, secreto de otro origen y origen desconocido.
- El pipeline completo corre: ingesta → normalización → enriquecimiento →
  triaje → ticketing, con la alerta persistida y el veredicto justificado
  línea a línea.
- **Con los proveedores de inteligencia caídos, el enriquecimiento se marca
  como parcial y no se ejecuta ninguna contención.** Es la propiedad de
  seguridad central del sistema y está comprobada en ejecución, no sólo en
  test.
- Simulacros de caída de Redis y Postgres, con recuperación automática
  verificada.
- **Capa perimetral (Caddy) probada de extremo a extremo**: TLS, allowlist de
  gestión (403 real fuera de rango) y rate limiting (120 eventos/min, con
  `429` a partir del umbral y recuperación tras la ventana). Se encontró y
  corrigió un fallo real: `docker-compose.yml` no propagaba `MGMT_ALLOWLIST`
  ni `ACME_EMAIL` al contenedor, así que Caddy ignoraba en silencio la
  restricción del `.env` y caía a su default de "cualquier red privada". Ver
  R-12 en `docs/riesgos.md`. Ahora hay un chequeo dedicado
  (`npm run check:caddy-env`) que lo bloquea en CI.
- **Contención y Human-in-the-Loop probados** contra un stack de mocks
  (Cloudflare, AbuseIPDB, VirusTotal, CrowdSec CTI): auto-contención sobre
  activo de baja criticidad, aprobación vía el webhook de reanudación de n8n,
  rechazo explícito, y timeout real (el `wait-tracker` reanuda solo tras la
  ventana, sin ejecutar nada). Se encontró y corrigió una limitación
  arquitectónica de n8n: un subflujo con su propio nodo `Wait`, invocado por un
  padre que también queda pausado esperando su retorno, pierde el valor de
  retorno al reanudar — sin ningún error. Se resolvió extrayendo la ejecución
  de la contención a un subflujo aparte, **WF-08**. Ver R-13.
- **Las tres fuentes de inteligencia responden `200` en la misma ejecución
  real**: AbuseIPDB, VirusTotal y CrowdSec CTI, con `partial_enrichment: false`
  y veredicto coherente.
- **Lotes multi-alerta verificados**: un POST de Elastic con 2 alertas produce
  2 alertas persistidas, cada una con su veredicto propio calculado de forma
  independiente, y reenviar el lote no duplica nada.

### Lo que NO está verificado

Honestamente, y por orden de importancia:

- **El botón de aprobación de Slack nunca se ha pulsado de verdad.** La
  auditoría descubrió que las URLs de los botones se construían con `{{ }}`
  dentro de una plantilla de JavaScript, donde son texto literal: **los botones
  nunca funcionaron**. Pasó inadvertido porque toda la verificación del HITL se
  hizo golpeando el webhook de reanudación directamente. Está corregido, pero
  el camino Slack→botón→reanudación sigue sin probarse contra un Slack real.
- **Cloudflare nunca ha ejecutado un bloqueo real.** La credencial está
  conectada y el flujo verificado contra un mock fiel, pero ninguna regla de
  firewall se ha creado ni revertido de verdad.
- **No hay ninguna plataforma de ticketing externa.** TheHive y Wazuh se
  retiraron del sistema (R-19); el registro vive sólo en Postgres, con
  notificación a Slack.
- **La ingesta de Elastic está deshabilitada por defecto.** Funciona (se
  corrigieron dos fallos que la hacían imposible), pero con
  `BLINKSEC_STATIC_TOKEN_ELASTIC` vacío el origen queda cerrado — el fallo
  seguro. Su postura de seguridad es realmente inferior a la de Splunk: Kibana
  no puede firmar, sólo mandar un token fijo (R-01).
- **Ningún test ejercita el cableado de los workflows**, sólo los módulos por
  separado. Es el motivo de que tres fallos reales convivieran con la suite en
  verde. Es la deuda técnica más importante que queda abierta (R-21).

Ver [Antes de producción](#antes-de-producción) y
[docs/riesgos.md](docs/riesgos.md) para el detalle completo.

### Rendimiento medido

| Métrica | Valor | Objetivo del plan |
|---|---|---|
| Rendimiento | 110–140 alertas/min | 500 alertas/min |
| Gateway p50 | ~2 000 ms | — |
| Triaje (cómputo) | ~400 ms | — |
| Enriquecimiento con proveedores caídos | ~23 s | — |

Medido en Raspberry Pi 5 (4 núcleos ARM, 8 GB) con toda la pila en la misma
máquina, así que es un suelo. El cuello de botella no es el cómputo del triaje
sino los backoff de reintento de las APIs externas: la cifra de "1.5 s" del
diseño original describe el cómputo puro, no la latencia que percibe el SOC.

## Arranque rápido

```bash
cp docker/.env.example docker/.env && chmod 600 docker/.env
```

Rellenar `docker/.env` (cada campo indica cómo generarlo). El despliegue completo, paso a paso y con las verificaciones obligatorias, está en [docs/runbook-despliegue.md](docs/runbook-despliegue.md):

```bash
docker compose -f docker/docker-compose.yml up -d
```

Compilar e importar los workflows:

```bash
npm run build
```

Los ficheros de `workflows/dist/` se importan en n8n. Hay que crear las
credenciales con los ids que esperan los nodos (`blinksec-pg`,
`blinksec-redis`, `blinksec-abuseipdb`, …) y activar los flujos.

> **Dos avisos que cuestan tiempo si se pasan por alto.**
> `BLINKSEC_HITL_TOKEN_SECRET` no es opcional: sin él WF-05 falla a propósito,
> en vez de mandar un botón que cualquiera podría pulsar.
> Y hay que activar **dos** workflows, no uno: `blinksecwf00gtwy` (el gateway)
> y `blinksecwf07revr` (la reversión programada, que tiene su propio
> `scheduleTrigger`). Si el segundo queda inactivo, las contenciones nunca
> caducan y nada lo señala.

Verificar todo antes de tocar nada:

```bash
npm run verify
```

## Decisiones de diseño

Las que explican por qué el código es como es.

**El gateway va primero, no al final.** Un webhook SOAR sin firmar no es sólo
una fuga: quien conozca la URL puede fabricar alertas y provocar el bloqueo
automático de infraestructura legítima. Firma HMAC-SHA256 sobre el cuerpo
crudo, ventana anti-replay de 300 s e idempotencia por `alert_id` determinista.
Ver `lib/gateway.js` y `tests/gateway/`.

**La línea base de puntuación es 35, no 50.** Consecuencia deliberada: ninguna
señal aislada alcanza el umbral crítico de 70. La contención automática exige
siempre corroboración de al menos dos fuentes independientes.

**Un enriquecimiento parcial nunca contiene.** Si un proveedor de inteligencia
no respondió, la puntuación queda topada en 69 y el caso se escala a un humano.
Es preferible un ticket de más a aislar un servidor porque VirusTotal devolvió
un 503.

**Toda contención nace con su reversión.** Cada acción se registra en
`containment_log` con su `undo_payload` y su `expires_at`. WF-07 recorre la
tabla cada 15 minutos y revierte lo vencido. Sin esto, en un año se acumulan
miles de reglas de firewall que nadie se atreve a tocar.

**El timeout del Human-in-the-Loop es rechazo.** Si nadie aprueba en 15
minutos, no se ejecuta nada y se escala a guardia. La alternativa convertiría
la aprobación humana en un retardo decorativo. **Un token inválido se trata
igual que un timeout**: rechazo, nunca "aprobar de todas formas".

**La URL de reanudación del HITL lleva su propio token HMAC.** La que genera
n8n por sí sola no es un secreto: su forma es
`/webhook-waiting/<executionId>/<sufijo>`, con un `executionId` **secuencial**
y un sufijo constante, y el endpoint responde `404` en vez de `401`, así que
sirve para enumerar ejecuciones. Sin token, cualquiera capaz de alcanzar el
proxy podía recorrer ids y ejecutar contenciones reales. El token se liga a la
ejecución **y** a la alerta. Ver `computeResumeToken` en `lib/gateway.js` y
R-21 en `docs/riesgos.md`.

**Cada alerta de un lote recorre el pipeline por su cuenta.** Un POST de
Elastic puede traer N alertas, pero WF-02 en adelante están diseñados para una.
Los nodos `Execute Workflow` van en `mode: each` y el `alert_id` se deriva del
**contenido** de cada alerta, no de su posición en el lote — si no, la misma
alerta cambia de identidad según dónde viaje y se duplica el ticket.

**La allowlist se evalúa antes del scoring.** Bloquear el rango de la VPN
corporativa es el error más caro que puede cometer un SOAR: una denegación de
servicio auto-infligida, a velocidad de máquina y con permisos de
administrador.

**Lo que se testea es lo que se ejecuta.** Los nodos Code de n8n no pueden
hacer `require` de ficheros del repo, así que la lógica crítica suele acabar
duplicada dentro del JSON del workflow — y divergiendo. `tools/build-workflows.js`
inyecta los módulos reales en tiempo de compilación, y CI falla si `dist/`
queda desincronizado.

## Estructura

```
lib/            módulos de dominio, puros y testeables (gateway, normalize, enrich, containment)
scoring/        motor de triaje + pesos versionados aparte
workflows/src/  plantillas de workflow con marcadores de inyección
workflows/dist/ compilados, listos para importar en n8n  ← generado, no editar
tools/          compilador, validador y mock-services.js (mocks de Cloudflare/intel para ensayos sin credenciales)
integrations/   lado SIEM: Splunk, Elastic
tests/          gateway · fixtures · triage · build
docker/         compose endurecido, Caddy, esquema de Postgres
docs/           runbooks y registro de riesgos
```

## Tests

```bash
npm test
```

| Suite | Qué cubre |
|---|---|
| `tests/gateway/` | HMAC, replay, idempotencia, token de reanudación del HITL |
| `tests/fixtures/` | Normalización de las dos plataformas al contrato común |
| `tests/triage/` | Corpus etiquetado de 20 casos + matriz de confusión |
| `tests/build/` | Que `dist/` refleja `lib/` y `scoring/`, y las reglas anti-fallo-silencioso |

El corpus de triaje es el criterio de aceptación real: 10 falsos positivos y 10
amenazas etiquetados a mano. La regla que no se negocia es **cero falsos
positivos auto-contenidos**.

> **Dos advertencias honestas.**
>
> Los pesos y el corpus los escribió la misma mano, así que hoy esto es un
> arnés de regresión, no validación independiente. El valor real llega al
> re-etiquetar con alertas de producción.
>
> Y, más importante: **estos tests cubren los módulos, no el cableado de los
> workflows.** La auditoría encontró tres fallos reales —uno de ellos con
> pérdida de alertas en producción— conviviendo con la suite entera en verde,
> porque ninguno vivía dentro de un módulo: vivían en cómo los nodos de n8n se
> conectan entre sí. Una suite verde aquí **no** significa que el pipeline
> desplegado funcione.

## Antes de producción

1. **Poblar `blinksec.assets`.** Sin inventario, todo activo se asume `high` y
   toda contención pasa por aprobación humana. El sistema funciona, pero no
   automatiza.
2. **Revisar `blinksec.ip_allowlist`.** Añadir proxies, VPN, escáneres de
   vulnerabilidades y rangos de oficina. Los RFC1918 vienen precargados.
3. **Verificar cada credencial de inteligencia una por una.** Una clave mal
   copiada no falla de forma visible: el sistema puntuaría todo como "IoC
   desconocido" y quedaría ciego pareciendo sano (R-09). El runbook indica la
   comprobación concreta.
4. **Sustituir el endpoint de ejemplo**: `soar.example.com` aparece en
   workflows e integraciones.
5. **Validar el nodo Redis de WF-00.** La idempotencia necesita semántica
   SETNX; según la versión del nodo puede requerir el patrón alternativo de
   `docs/runbook-idempotencia.md`.
6. **Repetir el ensayo de contención contra la infraestructura real** (no
   el mock): bloquear una IP de prueba en Cloudflare real, verificar el
   registro, verificar la reversión. El flujo en sí ya está verificado
   contra un mock fiel (R-13), incluida la sustitución del `RULE_ID` que
   Cloudflare asigna a cada regla (ver R-19); lo que falta es la
   integración con la API real.
7. **Probar el botón de Slack de verdad**, no sólo el webhook de reanudación.
   Los botones estuvieron rotos desde el principio y nadie lo notó porque toda
   la verificación se hizo golpeando el webhook a mano (R-21). Mandar una
   alerta que exija aprobación, pulsar el botón en Slack y confirmar que la
   contención se ejecuta con el token válido — y que manipular el token la
   rechaza.
8. **Añadir tests del cableado de los workflows** y una guarda en el compilador
   contra `.first()` aguas abajo de una fuente multi-item. Es la deuda que
   permitió que tres fallos reales convivieran con la suite en verde (R-21).
9. **Conectar una plataforma de ticketing externa**, si se necesita una:
   TheHive se retiró del sistema (R-19) y WF-06 hoy sólo registra en
   Postgres y notifica por Slack.
10. **Re-etiquetar el corpus** con 100+ alertas reales y recalcular la matriz.

Los riesgos abiertos y las excepciones conscientes al modelo de amenaza están
en [docs/riesgos.md](docs/riesgos.md). Merece la pena leer **R-21** (auditoría
de seguridad), **R-22** (los nodos Code ven la clave de cifrado) y **R-23** (el
aprobador es autodeclarado) antes de exponer esto a tráfico real.

## Licencia

MIT.
