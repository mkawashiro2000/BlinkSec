# Registro de riesgos

Riesgos abiertos y excepciones conscientes al modelo de amenaza. Se documentan
aquí porque un riesgo aceptado y escrito es una decisión de ingeniería; el mismo
riesgo sin escribir es una sorpresa esperando fecha.

## R-19 · Wazuh y TheHive reales, sin conectar (ABIERTO)

WF-08 (`Ejecutar contención`) y WF-06 (`Crear alerta en TheHive`) siguen
apuntando a placeholders — `https://wazuh.example.com:55000/active-response`
y `https://thehive.example.com/api/v1/alert` respectivamente. Todo lo
probado de extremo a extremo contra "Wazuh" y "TheHive" en R-13 fue en
realidad contra `tools/mock-services.js`, nunca contra las APIs reales.
Las credenciales `blinksec-wazuh` y `blinksec-thehive` existen en n8n pero
sin URL real que las use.

**Wazuh**: se evaluó Wazuh Cloud (`console.cloud.wazuh.com`) como opción
gestionada — descartado porque crear un *environment* cuesta **$632/mes**,
desproporcionado para este proyecto. La alternativa es autoalojar Wazuh
(es open source, sin coste de licencia), pero el manager+indexer+dashboard
completo recomienda oficialmente 4 GB+ sólo para el indexer (basado en
OpenSearch) y en la práctica ronda 8 GB dedicados. La Raspberry Pi de este
proyecto tiene 7.6 GB totales, de los cuales sólo ~4.5 GB están realmente
libres (contando caché liberable), **compartidos con ~20 contenedores
ajenos a BlinkSec** (Nextcloud, Jellyfin, Sonarr/Radarr, Kensho, etc.).
Instalar el stack completo de Wazuh aquí arriesgaba dejar sin memoria a
esos otros servicios del mismo host, no sólo a BlinkSec.

**Decisión**: queda pendiente hasta que haya una máquina con más margen
—otro equipo, una VM aparte, o un plan más barato de Wazuh Cloud si
existe— donde alojar Wazuh sin competir por RAM con el resto de la
infraestructura de este servidor. No se creó ningún *environment* de pago
en Wazuh Cloud.

**TheHive**: aún sin URL real proporcionada — nunca se llegó a confirmar
si hay una instancia propia o gestionada disponible. Sigue abierto,
sin decisión tomada todavía.

Mientras tanto, WF-06 y WF-08 siguen probados sólo contra el mock (ver
R-13) — funcionalmente correctos, pero sin verificar contra las APIs
reales, como ya advertía el README antes de esta sesión.

## R-18 · CrowdSec CTI como reemplazo de GreyNoise/X-Force (CERRADO — verificado en ejecución real)

Tras retirar GreyNoise e IBM X-Force (R-14, R-17), se incorporó **CrowdSec
CTI** (`https://cti.api.crowdsec.net/v2/smoke/{ip}`) como tercera fuente de
inteligencia para IPs, junto a AbuseIPDB y VirusTotal. Se eligió por tener
un nivel gratuito con una clave fácil de obtener desde `app.crowdsec.net`
(a diferencia de GreyNoise Community, cuya clave nunca se localizó en la
UI, y de X-Force, bloqueado por un problema de cuenta de IBM).

**Diseño**: `lib/enrich.js` → `parseCrowdSec()` interpreta la escala 0-5 de
`scores.overall.threat`/`aggressiveness` y la lista `classifications.classifications`
(pertenencia a blocklists de la comunidad CrowdSec). Un `threat >= 3` o
cualquier clasificación presente se trata como `malicious`; `threat >= 1` o
`aggressiveness >= 1` sin clasificación como `suspicious`; el resto,
`clean`. `scoring/weights.json` (versión 5) añade `crowdsec_malicious_max`
(20, escalado por `threat/5`), `crowdsec_suspicious` (+8) y `crowdsec_clean`
(-8) — pesos deliberadamente más bajos que los de VirusTotal/AbuseIPDB
porque CrowdSec es una fuente de corroboración adicional, no la primaria.

**Descubierto al conectar la clave real: el plan gratuito son sólo 120
consultas al mes (~4/día).** Con el volumen medido del sistema (110–140
alertas/min, ver README) esa cuota se agota en minutos ante cualquier
ráfaga real. Si CrowdSec se tratara como fuente "core" igual que AbuseIPDB
o VirusTotal, un `429` suyo habría activado el techo de enriquecimiento
parcial (`scoring/weights.json` → `caps.partial_enrichment`, 69) para
**todas** las alertas del resto del día — el proveedor más débil y de
menor cuota habría podido bloquear la contención automática de todo el
sistema, aunque las otras dos fuentes respondieran con normalidad.

**Corregido antes de que llegara a producción.** `lib/enrich.js` distingue
ahora `PROVIDERS` (los tres, se parsean e informan al ticket) de
`CORE_PROVIDERS` (`abuseipdb`, `virustotal` — los únicos que cuentan para
`_meta.partial`, `_meta.providersOk` y el techo `single_provider`).
CrowdSec queda como fuente **best-effort**: cuando responde dentro de
cuota, su veredicto sigue sumando en `scoring/score.js` como corroboración
extra (positiva o negativa); cuando no responde —cuota agotada, caída,
lo que sea— se ignora sin más, sin degradar el resto del enriquecimiento.
Cubierto por el test `aggregate: CrowdSec es best-effort — su fallo NO
marca el enriquecimiento como parcial` en `tests/triage/enrich.test.js`.

**Bug real encontrado al verificar en vivo: hostname equivocado.** El nodo
"CrowdSec CTI" apuntaba a `cti.crowdsec.net`, un dominio que **no existe**
(NXDOMAIN, confirmado tanto desde dentro del contenedor `n8n-main` como
desde el propio host — no es un problema de DNS de Docker como R-15, el
dominio simplemente no resuelve para nadie). El hostname real de la API es
**`cti.api.crowdsec.net`** — confirmado con `curl` directo, que devuelve
`403 {"message":"Forbidden"}` sin clave, la respuesta esperable de un
endpoint real que exige autenticación. Corregido en
`workflows/src/WF-02-enriquecimiento.json` antes de que esto se notara en
el corpus de tests (que nunca ejercita el hostname real, sólo el parseo de
la respuesta) — sólo apareció al enviar una alerta real contra n8n y leer
el error del nodo (`getaddrinfo ENOTFOUND cti.crowdsec.net`) directamente
de `execution_data`. Recordatorio de por qué la verificación en ejecución
real importa más que "los tests pasan".

**Aplicado al despliegue en vivo — pasó por el mismo bug de UI que
X-Force, resuelto igual: importación por CLI.** Con el hostname
corregido, una primera credencial `blinksec-crowdsec` creada desde la UI
de n8n devolvía `403 {"message":"Forbidden"}` en ejecución real. Se aisló
con un `curl -i -H "x-api-key: <clave>" https://cti.api.crowdsec.net/v2/smoke/8.8.8.8`
ejecutado por el operador directamente, fuera de n8n: la clave funcionaba
perfectamente (`200`, respuesta real de CrowdSec) — así que el 403 era un
problema de cómo había quedado guardada la credencial en n8n, no de la
clave ni de la cuenta. Mismo bug de fondo que R-17 documentó para
X-Force: el formulario de credenciales de n8n puede no persistir
correctamente el valor de un campo de contraseña al editarlo.

**Resuelto sin tocar la UI de credenciales**: se borró la credencial rota
y se importó de nuevo por `n8n import:credentials` con un JSON que incluye
directamente `"id": "blinksec-crowdsec"` (el operador escribió el fichero
y ejecutó el import él mismo en el servidor; el valor de la clave nunca
pasó por este chat). Al usar el id literal desde el import, no hizo falta
ningún parche en caliente de `workflow_entity` — el nodo ya apuntaba al id
correcto de fábrica. **Verificado con una alerta real**: los tres nodos
(AbuseIPDB, VirusTotal, CrowdSec CTI) responden `200` en la misma
ejecución.

Queda como recomendación operativa para el futuro: si aparece de nuevo el
bug de `__n8n_BLANK_VALUE_...` al crear o editar cualquier credencial de
n8n, no reintentar en el formulario — ir directo a `n8n
import:credentials` con el id literal, como aquí y en R-17.

**Consecuencia real de tener tres fuentes de IP en vez de dos**: mejora el
margen de corroboración para IPs *cuando CrowdSec tiene cuota disponible*,
pero no es una garantía — con 4 consultas/día es, en la práctica, una
señal ocasional, no sistemática. Tampoco cambia nada para hashes —
CrowdSec CTI, igual que AbuseIPDB, no resuelve hashes. El techo
`single_provider` para alertas sólo-por-hash (ver R-17) sigue aplicando
exactamente igual.

## R-01 · Elastic no firma sus peticiones (ACEPTADO con compensación)

**Qué pasa.** El conector Webhook de Kibana rellena plantillas, no ejecuta
código: no puede calcular un HMAC sobre el cuerpo. La cabecera
`X-BlinkSec-Signature` que envía es un **token estático**, no una firma.

**Por qué importa.** Un token estático no cubre el cuerpo ni el timestamp. No
protege contra manipulación del payload en tránsito ni contra reenvío. Sólo
impide el POST anónimo.

**Compensación.** `SIEM_ALLOWLIST` estricta en el Caddyfile, restringida a la
IP del nodo de Kibana, y despliegue en red privada. La postura de seguridad de
la ingesta de Elastic es **medible pero realmente inferior** a la de Wazuh y
Splunk, que sí firman.

**Cómo cerrarlo.** Un salto intermedio (Logstash con filtro Ruby, o una función
serverless) que reciba de Elastic y reenvíe firmado con el esquema común. Es la
única forma de igualar la postura.

## R-02 · Cuota de VirusTotal (MITIGADO, no eliminado)

**Qué pasa.** El free tier son 4 peticiones/minuto. Una ráfaga de 50 alertas de
la misma campaña agota la cuota en segundos.

**Mitigación implementada.** Caché de IoC en Redis con TTL diferenciado (24 h
para veredictos maliciosos, que son los que más se repiten), backoff de 20 s en
los reintentos —mayor que la ventana de cuota, porque reintentar a los 2 s
garantiza un segundo 429— y degradación explícita: un 429 marca el
enriquecimiento como parcial y activa el techo de puntuación.

**Riesgo residual.** Con volumen alto sostenido, VirusTotal estará caído de
facto la mayor parte del tiempo y muchas amenazas reales quedarán topadas en
"investigar" en lugar de contenerse. **Eso es correcto por diseño**, pero anula
buena parte del beneficio de automatización. Si el volumen lo justifica, el tier
de pago no es opcional.

## R-03 · El inventario de activos no existe o está obsoleto (BLOQUEANTE)

**Qué pasa.** `asset.criticality` decide si una contención se ejecuta sola o
pasa por un humano. Sale de `blinksec.assets`, que hay que poblar y mantener.

**Comportamiento por defecto.** Activo desconocido → `criticality = 'high'` →
toda contención pasa por aprobación humana. El sistema falla hacia el lado
seguro, no hacia el cómodo.

**Riesgo real.** No es que el sistema rompa: es que **no automatiza nada** y el
equipo concluye que el SOAR no sirve, cuando lo que falta es el inventario. Un
inventario que envejece degrada el sistema en silencio.

**Acción.** Sincronización periódica desde la CMDB o desde el propio inventario
de agentes de Wazuh. Alerta operativa si el porcentaje de `inventoryHit: false`
supera un umbral.

## R-04 · El corpus de triaje no es validación independiente (ABIERTO)

**Qué pasa.** Los pesos de `scoring/weights.json` y los 20 casos de
`tests/triage/cases.json` se escribieron en la misma sesión y por la misma
mano. La matriz de confusión sale perfecta porque está construida para salir
perfecta.

**Qué vale hoy.** Como arnés de regresión es útil de verdad: un cambio de pesos
que rompa un caso conocido se detecta al instante.

**Qué no vale.** No dice nada sobre el rendimiento con alertas reales. La tasa
de auto-cierre del 100% sobre este corpus no se va a reproducir en producción.

**Acción.** Fase 7: re-etiquetar con 100+ alertas reales de las primeras
semanas, etiquetadas por un analista que no haya visto los pesos, y recalcular.
Ajustar pesos contra ese corpus, nunca contra el sintético.

## R-05 · Semántica SETNX del nodo Redis (ABIERTO)

**Qué pasa.** La idempotencia de WF-00 exige "escribe sólo si no existe". El
nodo Redis de n8n expone `set` con TTL, pero la disponibilidad de SETNX real
varía según versión.

**Por qué importa.** Con un `SET` normal, dos entregas simultáneas de la misma
alerta pasan ambas: se abren dos tickets y la contención se ejecuta dos veces.
Postgres da una segunda capa (UPSERT por `alert_id`, y `sourceRef` en TheHive),
pero la ventana de carrera existe.

**Acción.** Verificar en el despliegue real; si no hay SETNX, aplicar el patrón
alternativo de `runbook-idempotencia.md`.

## R-06 · La contención corre como root en los agentes (ACEPTADO)

**Qué pasa.** `custom-ar.py` se ejecuta con privilegios de root en cada agente
de Wazuh y puede modificar iptables y terminar procesos.

**Salvaguardas implementadas.** Rechazo de IPs privadas, loopback y reservadas
—una regla contra el rango de gestión deja el servidor inaccesible y sin forma
de revertir en remoto—; lista de procesos intocables (systemd, sshd, los propios
demonios de Wazuh); PID mínimo de 100; identificación de procesos **por hash del
binario, nunca por nombre**, porque el nombre lo controla el atacante.

**Riesgo residual.** Un compromiso del manager de Wazuh o del propio n8n
concede ejecución con privilegios en toda la flota. Es inherente a cualquier
EDR con respuesta activa, no específico de BlinkSec, pero conviene tenerlo
escrito: **el SOAR es ahora un activo de criticidad máxima** y debe protegerse
como tal.

## R-07 · PII en la base de ejecuciones (MITIGADO)

**Qué pasa.** n8n persiste por defecto los datos de cada nodo. En un SOAR eso
incluye IPs corporativas, nombres de usuario y logs crudos.

**Mitigación.** Poda a 7 días para ejecuciones exitosas y 30 para fallidas;
recorte de `full_log` a 512 caracteres en el emisor de Wazuh; saneado explícito
en WF-06 antes de escribir el ticket.

**Riesgo residual.** El payload crudo sí pasa por WF-00 y WF-01 y queda en la
ejecución durante la ventana de retención. Ver `runbook-privacidad.md`.

## R-08 · Rendimiento muy por debajo del objetivo (MEDIDO, ABIERTO)

**Ya no es una estimación.** Medido contra el despliegue real:

| Métrica | Valor |
|---|---|
| Rendimiento | **110–140 alertas/min** |
| Latencia del gateway p50 | ~2 000 ms |
| Latencia del gateway p95 | ~4 000 ms |
| Objetivo del plan | 500 alertas/min |

Hardware: Raspberry Pi 5, 4 núcleos ARM, 8 GB, con Postgres, Redis, n8n-main,
n8n-webhook y 2 workers **en la misma máquina**. No es hardware de producción,
así que la cifra es un suelo, no un techo.

Dónde se va el tiempo, medido por flujo:

- **WF-02 enriquecimiento: ~23 s** con los cuatro proveedores fallando. Domina
  todo lo demás. Es la suma de los backoff de reintento — y el de VirusTotal
  son 20 s × 3 intentos por diseño, porque reintentar antes garantiza otro 429.
  Bajo caída total de proveedores, el backoff correcto para las cuotas es
  catastrófico para el rendimiento.
- **WF-00 gateway: ~1,5 s**, del cual una parte es persistir los datos de
  ejecución en Postgres.
- **WF-03 triaje: ~0,4 s**. El cómputo de scoring es irrelevante en el
  presupuesto, justo como se anticipaba.

**Conclusión sobre la cifra de "1.5 segundos" del documento original**: no se
corresponde con nada medible de extremo a extremo. El cómputo puro de decisión
sí está en ese orden o por debajo, pero la latencia que percibe el SOC la
dominan las APIs externas.

**Acciones pendientes**: acotar el peor caso de WF-02 (presupuesto total de
reintentos, no por nodo); medir en hardware x86 representativo; evaluar
`EXECUTIONS_DATA_SAVE_ON_SUCCESS=none` para quitar la escritura de ejecución
del camino crítico.

## R-09 · Una clave de API ausente puede parecer un dato válido (ABIERTO)

Descubierto al medir sin claves configuradas. Con las cuatro credenciales de
inteligencia ausentes, el enriquecimiento reportó **3 proveedores disponibles
de 4**: GreyNoise y VirusTotal devolvieron respuestas que los parsers
interpretan legítimamente como "IoC no observado" / "desconocido", no como
fallo.

**Por qué importa.** Un despliegue con una clave mal copiada no fallaría de
forma visible: puntuaría todas las alertas como si la inteligencia hubiera
respondido "no sé nada de esta IP". El sistema parecería sano y estaría ciego.

**Mitigación actual.** Los códigos 401 y 403 sí se tratan como no disponible, y
el paso 6 del runbook de despliegue obliga a verificar cada credencial antes de
conectar producción.

**Cómo cerrarlo.** Un flujo de comprobación de credenciales que consulte un IoC
conocido de cada proveedor (por ejemplo 8.8.8.8, que GreyNoise debe clasificar
como servicio comercial) y avise si la respuesta no es la esperada.

## R-11 · Una caída de Redis o Postgres pierde alertas (MEDIDO, ABIERTO)

Simulacros ejecutados contra el despliegue real, matando cada dependencia en
caliente mientras entraba tráfico:

| Dependencia caída | Comportamiento observado | Consecuencia |
|---|---|---|
| **Redis** | El proceso de webhooks **se cierra solo a los 10 s** (`Exiting process due to Redis connection error`). Las peticiones fallan a nivel de conexión. | Alertas perdidas en el cable, **sin ninguna traza en BlinkSec** |
| **Postgres** | El webhook sigue en pie y responde **500** con 5–10 s de latencia | Alertas perdidas, pero el error sí queda registrado |

**Recuperación**: automática en ambos casos. Al volver la dependencia, el
proceso de webhooks arranca de nuevo por sí solo y vuelve a aceptar tráfico.
Verificado.

**Por qué importa más de lo que parece.** Wazuh **no reintenta** las
integraciones: lo que no entra en el momento, no entra nunca. Una caída de
Redis de dos minutos es una ventana ciega de dos minutos en el SOC, y en el
caso de Redis ni siquiera queda constancia del lado del SOAR — sólo en el log
del manager de Wazuh.

El caso de Redis es peor por partida doble: el fallo es silencioso desde la
perspectiva del SOAR, y es precisamente el modo en que un atacante querría
tumbarlo antes de actuar.

**Acciones pendientes**:

- Monitorización externa del endpoint de ingesta (no autoalojada en la misma
  máquina) que alerte si deja de responder.
- Vigilar `integrations-blinksec.log` en el manager de Wazuh: un pico de fallos
  de red ahí es la única señal de una ventana ciega.
- Evaluar un buffer duradero delante del webhook para absorber caídas cortas.
- Redis con alta disponibilidad si el SLA lo exige; el modo queue lo convierte
  en un punto único de fallo para la ingesta.

## R-17 · Estado real de las credenciales de inteligencia conectadas (CERRADO — GreyNoise y X-Force retirados del sistema)

Verificado en ejecución real contra n8n, enviando una alerta firmada con
`1.1.1.1` como IP y comprobando el código de respuesta HTTP de cada
proveedor (nunca las claves en sí — sólo los `statusCode` que devuelve cada
nodo):

| Proveedor | Estado | Evidencia |
|---|---|---|
| **AbuseIPDB** | ✅ Funciona | `200`, respuesta real y coherente para 1.1.1.1 (Cloudflare, `isWhitelisted: true`) |
| **VirusTotal** | ✅ Funciona | `200`, respuesta real y coherente (`attributes.reputation`, análisis de motores) |
| ~~GreyNoise~~ | Retirado | Nunca se localizó una clave de API operativa en la cuenta Community de GreyNoise pese a varios intentos guiados. Ver R-14. |
| ~~IBM X-Force~~ | Retirado | `401 Not authorized`, confirmado **no ser un problema de n8n ni de BlinkSec**: el mismo 401 se reproduce con `curl -u '<key>:<password>'` directo contra `api.xforce.ibmcloud.com`, ejecutado por el propio operador desde su máquina, fuera de este sistema por completo. El problema está en la cuenta/clave de IBM X-Force Exchange, no resoluble desde aquí. |

**Decisión operativa: se retiraron GreyNoise e IBM X-Force del sistema por
completo**, en vez de dejarlos "pendientes" indefinidamente. Ninguno de los
dos llegó a tener nunca una credencial operativa real. Se eliminó su código
de `lib/enrich.js`, `scoring/score.js` y `scoring/weights.json`, sus nodos
HTTP de `workflows/src/WF-02-enriquecimiento.json`, sus mocks de
`tools/mock-services.js`, y su cobertura de tests. El motor de triaje quedó
recalibrado sólo sobre AbuseIPDB y VirusTotal (`scoring/weights.json`
versión 4).

**Consecuencia real del recorte, no cosmética**: con AbuseIPDB e IBM X-Force
fuera, VirusTotal queda como el único proveedor capaz de resolver un
**hash** (AbuseIPDB sólo resuelve IPs). Toda alerta enriquecible sólo por
hash es, por tanto, siempre de fuente única, y el techo `single_provider`
(69) le impide alcanzar `critical` en solitario — antes X-Force podía
corroborar un hash malicioso junto a VirusTotal y sí alcanzar `critical`.
El corpus de `tests/triage/cases.json` (casos AM-02 y AM-06) se recalculó
para reflejar este comportamiento real: pasaron de `critical` a
`investigate`. Es un compromiso deliberado — malware detectado sólo por
hash, sin corroboración de una segunda fuente, ahora siempre pasa por un
analista en vez de auto-contenerse.

**Nota histórica sobre la credencial de X-Force creada por la UI**, ya sin
efecto tras retirar el proveedor: al depurar el 401 se descubrió y corrigió
un problema real de proceso — la credencial se había recreado **desde la UI
de n8n** por un bug de la propia UI (`__n8n_BLANK_VALUE_...` al editar el
campo de contraseña de una credencial existente, que no guardaba el valor
nuevo). Una credencial creada desde la UI recibe un **id interno generado
por n8n**, distinto del id literal que el nodo del workflow espera y que sí
usan las credenciales importadas por CLI. El nodo y la credencial en
cuestión ya no existen en el sistema, así que esto queda documentado sólo
como antecedente para el próximo bug de UI similar que aparezca con otro
proveedor.

Con las dos credenciales de inteligencia que quedan operativas, el sistema
funciona con normalidad — el techo de enriquecimiento parcial de
`scoring/weights.json` sigue haciendo su trabajo: ningún veredicto puede
alcanzar `critical` sin, como mínimo, corroboración de fuentes.

## R-16 · Tailscale enmascara el origen real ante Docker (ACEPTADO, no es un bug)

Tras corregir el DNS (R-15), el acceso al editor por la IP de Tailscale del
servidor seguía dando 403 — con `MGMT_ALLOWLIST` correctamente puesto a
`100.64.0.0/10`. Diagnóstico completo, de la capa de red hacia arriba:

1. `tcpdump` en la interfaz `tailscale0` confirmó que el paquete llega al
   host con la IP real del cliente (`100.67.98.80`, el MacBook) intacta.
2. Pero Caddy, dentro del contenedor, ve `remote_ip = 172.24.0.1` — la
   puerta de enlace de la red Docker de este proyecto, no la IP real.
3. La reescritura ocurre en una regla propia de `tailscaled`
   (`ts-postrouting` en la tabla `nat`): **enmascara TODO el tráfico que
   Tailscale reenvía desde `tailscale0` hacia otra red** — aquí, la red
   `blinksec` de Docker. Es como Tailscale garantiza que el tráfico de
   vuelta sepa regresar por `tailscale0` cuando el destino (la red de
   Docker) no tiene ninguna ruta de vuelta hacia `100.64.0.0/10`.

**Esto no es un fallo de configuración de este host ni de BlinkSec — es
arquitectura estándar e intencionada de Tailscale** para cualquier tráfico
que reenvía hacia una red que no es nativamente parte del tailnet. Se
reproduce igual en cualquier despliegue con Tailscale delante de un
contenedor Docker.

**Consecuencia real, no cosmética.** Caddy nunca puede ver la IP individual
de cada dispositivo Tailscale por este camino: todos llegan como
`172.24.0.1`. El `remote_ip` de `MGMT_ALLOWLIST` deja de poder distinguir
"tu MacBook autorizado" de "cualquier otro dispositivo del mismo tailnet" —
la allowlist de Caddy por esta vía es, en la práctica, un cheque en blanco
para cualquier miembro del tailnet, no una lista de dispositivos concretos.

**Aceptado conscientemente, no ignorado.** El control de acceso real para
este camino ya lo hace Tailscale mismo: sólo dispositivos autorizados en el
tailnet (gestionados por sus propias ACLs, fuera de este repo) pueden
siquiera enviar un paquete a la IP de Tailscale del servidor. La allowlist
de `MGMT_ALLOWLIST` sigue siendo la barrera real y efectiva para el acceso
por LAN (`192.168.0.0/16`) y cualquier otra ruta sin NAT de por medio —
sólo queda debilitada específicamente para el camino vía Tailscale.

**Aplicado**: `MGMT_ALLOWLIST` incluye ahora `172.24.0.1/32` (la puerta de
enlace de la red `blinksec` de Docker) además del rango de Tailscale. Esa
dirección concreta depende de la subred que Docker asigne a este proyecto —
si la red se recrea desde cero, puede cambiar; verificar con
`docker network inspect docker_blinksec` si `MGMT_ALLOWLIST` deja de
coincidir tras una recreación completa del stack.

## R-15 · Sin DNS a internet desde los contenedores (CERRADO, alcance de todo el host)

Al conectar la credencial real de Slack, n8n reportaba "Couldn't connect with
these settings" — parecía un problema del token, y no lo era. Diagnóstico
desde el servidor: `fetch('https://slack.com/...')` desde dentro del
contenedor `n8n-main` fallaba con `EAI_AGAIN` (fallo de resolución DNS), pese
a que el propio host resolvía `slack.com` sin problema.

**Causa: el host no propaga ningún servidor de nombres externo a Docker.**
`/etc/resolv.conf` del host no lista ningún `nameserver` explícito
(gestiona DNS vía `systemd-resolved` sin volcarlo al fichero), así que Docker
no tiene de dónde heredar uno para los contenedores — su comentario interno
lo deja explícito: `NO EXTERNAL NAMESERVERS DEFINED`.

**Alcance confirmado: todo el host, no sólo BlinkSec.** Un contenedor
completamente ajeno a este proyecto (`nextcloud`) presenta exactamente el
mismo aviso. Es plausible que otros servicios en esta máquina que dependan de
salida a internet desde dentro de un contenedor tengan el mismo problema sin
haberlo notado todavía.

**Corregido sólo para BlinkSec**, sin tocar la configuración del demonio
Docker del host (eso afectaría a Nextcloud, Jellyfin, Kensho y todo lo demás
que corre en esta máquina — fuera del alcance de este proyecto y de mi
autorización para tocarlo sin más). `docker-compose.yml` declara
`dns: [1.1.1.1, 8.8.8.8]` en el ancla compartida de los tres servicios de n8n.
Verificado con una llamada real a `slack.com` desde el contenedor tras
recrearlo.

**Recomendación pendiente, no aplicada**: si otros proyectos de este host
también dependen de resolución DNS externa desde dentro de un contenedor
(no sólo BlinkSec), vale la pena revisar si conviene arreglarlo a nivel del
demonio Docker (`/etc/docker/daemon.json` → `"dns": [...]`) en vez de
repetir `dns:` en cada `docker-compose.yml` del host — decisión del
operador, no tomada aquí.

## R-14 · GreyNoise Community en vez de tier de pago (CERRADO — GreyNoise retirado del sistema, ver R-17)

**Superado por R-17: GreyNoise se retiró del sistema por completo.** Nunca
se logró localizar una clave de API operativa en la cuenta GreyNoise pese a
varios intentos guiados (la cuenta Community, a diferencia del tier de
pago, no expone la clave en el lugar habitual de la UI). En vez de seguir
troubleshooteando indefinidamente, se decidió eliminar GreyNoise del
sistema — código, workflow, tests y documentación — junto con IBM X-Force
(R-17). Lo que sigue es el análisis histórico de cuando GreyNoise sí estuvo
conectado (con la clave de prueba de la Fase 7), conservado como contexto
de por qué la adaptación Community-vs-pago ya no aplica: el parser
`parseGreyNoise()` que describe fue eliminado de `lib/enrich.js`.

---

La cuenta real conectada era GreyNoise **Community** (nivel gratuito), no el
tier de pago que asumía el diseño original. Dos endpoints distintos, dos
formas de respuesta completamente distintas del mismo proveedor:

| | Tier de pago (`/v3/ip/{ip}`) | Community (`/v3/community/{ip}`) |
|---|---|---|
| Forma | Anidada: `internet_scanner_intelligence`, `business_service_intelligence` | Plana: `{classification, riot, noise, name, link, last_seen}` |
| Metadatos | JA4, CVEs, puertos de destino, carrier, rDNS | Ninguno |
| Clasificaciones | `benign` / `suspicious` / `malicious` / `unknown` | `benign` / `malicious` / `unknown` — **sin `suspicious`** |

**Adaptado, no bloqueado.** `lib/enrich.js` → `parseGreyNoise()` detecta cuál
de las dos formas llegó por la PRESENCIA de las claves anidadas de pago, no
por una variable de configuración: si la cuenta pasa a un tier de pago más
adelante, sólo hay que cambiar la URL en el nodo HTTP de WF-02 (documentado
en su propia nota) — el parser se adapta solo, sin tocar código ni el motor
de scoring, que nunca sabe cuál de las dos respondió. Cubierto por
`tests/triage/enrich.test.js`.

**Riesgo residual real, no de implementación.** Con Community, GreyNoise
nunca devuelve la clasificación intermedia `suspicious` — sólo benigno,
malicioso o desconocido. La señal `greynoise_suspicious_scanner` (+10 en
`scoring/weights.json`) queda, en la práctica, inalcanzable mientras la
cuenta sea Community: no es un bug, es una pérdida de fidelidad de la fuente.
Tampoco hay metadatos para el ticket (JA4, CVEs, puertos) que sí aportaría el
tier de pago. No cambia ninguna propiedad de seguridad del sistema — sólo
reduce cuánto contexto adicional aporta esta fuente en concreto.

## R-13 · Contención y Human-in-the-Loop verificados en ejecución real (CERRADO, con una limitación arquitectónica de n8n corregida)

Se levantó un stack de mocks (`tools/mock-services.js`, servidor HTTP plano que
simula Wazuh, TheHive, GreyNoise, AbuseIPDB, VirusTotal e IBM X-Force) para
ensayar WF-04, WF-05 y WF-07 sin credenciales ni infraestructura real. Los
hostnames de ejemplo se redirigen al mock por alias de red interna, sólo
dentro del proyecto.

**Verificado de extremo a extremo, contra n8n real:**

| Escenario | Resultado |
|---|---|
| Alerta maliciosa, activo de baja criticidad | Contención automática ejecutada contra el mock, `containment_log` con `undo_payload` y `expires_at` |
| Alerta maliciosa, activo de alta criticidad, analista aprueba | HITL → resumeUrl real → contención ejecutada, `approved_by` con el nombre del analista |
| Alerta maliciosa, activo de alta criticidad, analista rechaza | HITL → `containment_log` permanece vacío, sin ticket adicional |
| Alerta maliciosa, activo de alta criticidad, sin respuesta | El `wait-tracker` de n8n reanuda solo al vencer la ventana; `aprobado=false`, cero contención, escalado a guardia registrado |

**El fallo real, y el más caro de encontrar de toda la Fase 7.** La
arquitectura original tenía WF-04 invocando a WF-05 con
`waitForSubWorkflow: true` (esperando su resultado) para leer `aprobado` tras
la decisión del analista. En ejecución real, WF-05 calculaba correctamente
`aprobado: true` en su propia ejecución — pero WF-04, al reanudar, recibía
`aprobado: undefined`. **La aprobación se perdía en la frontera entre los dos
workflows, sin ningún error.**

La causa: cuando un subflujo con su propio nodo `Wait` se invoca desde un
llamador que también queda pausado esperando su retorno (una ejecución
"waiting" anidada dentro de otra), n8n no propaga de forma fiable el valor de
retorno del hijo hacia el padre al reanudar. No hay documentación oficial que
lo advierta; se encontró por eliminación tras descartar — cada una tras su
propio ciclo de prueba — la hipótesis del payload perdido por Split Out, la
de un `webhookSuffix` con barra inicial redundante y la de un `webhookSuffix`
evaluado con el contexto de item equivocado.

**Corregido mediante un cambio de arquitectura, no un parche.** Se extrajo la
ejecución real de la contención a un nuevo subflujo, **WF-08 — Ejecutar y
registrar contención**. Ni WF-04 ni WF-05 esperan ya el uno al otro:

- WF-04 pasó a ser un despachador puro: planifica, y según requiera
  aprobación o no, invoca WF-05 o WF-08 con `waitForSubWorkflow: false`
  (fire-and-forget) y termina ahí.
- WF-05, tras resolver la decisión (aprobar, rechazar o expirar), invoca WF-08
  directamente por su cuenta — nunca devuelve el control a un padre que
  quedó pausado.
- WF-08 contiene la lógica de ejecución que antes vivía en WF-04: separar
  acciones, ejecutar contra la plataforma, registrar en `containment_log`,
  invocar el ticketing.

La regla queda además como guarda permanente en el compilador
(`tools/build-workflows.js` → `validarReferenciasCruzadas`): cualquier nodo
Execute Workflow con `waitForSubWorkflow: true` que apunte a un workflow con
su propio nodo Wait hace fallar el build. Cubierto por
`tests/build/build.test.js`.

**Lección que queda escrita**: para HITL con nodos `Wait` en n8n, el
subflujo que contiene el `Wait` debe ser el que **continúa la cadena hacia
adelante** tras resolverse, nunca uno al que se le pide devolver un valor
hacia arriba. Es el patrón contrario al que parece natural al diseñar
(padre-espera-a-hijo), y vale la pena mantenerlo así de explícito para
cualquier subflujo HITL que se añada en el futuro.

## R-12 · Caddy verificado en ejecución real (CERRADO, con un fallo real corregido)

La capa perimetral (TLS, allowlist de red, rate limiting) estuvo sin ejecutar
ni una sola vez hasta este punto. Se levantó el build propio con el módulo
`caddy-ratelimit` y se probaron los tres controles contra el proxy real:

| Control | Prueba | Resultado |
|---|---|---|
| TLS | Petición HTTPS firmada de extremo a extremo a través de Caddy | `200 {"accepted":true}` |
| Allowlist de gestión | Petición al editor desde fuera de `MGMT_ALLOWLIST` | `403` |
| Rate limiting | 130 peticiones seguidas contra `/webhook/*` (límite 120/min) | 119 pasan, 11 con `429`; recupera tras la ventana |

**El fallo real, encontrado al intentar verificar el 403.** `docker-compose.yml`
sólo propagaba `N8N_HOST` y `SIEM_ALLOWLIST` al contenedor de Caddy.
`MGMT_ALLOWLIST` y `ACME_EMAIL` se leen en el Caddyfile pero **nunca llegaban**:
Caddy caía en silencio a su default hardcodeado
(`10.0.0.0/8 172.16.0.0/12 192.168.0.0/16`, es decir *cualquier red privada*).
El `.env` del operador restringiendo el acceso al editor no tenía ningún
efecto, y no había ningún error que lo señalara — la primera prueba con la red
docker de este host dio `200` porque esa red cae dentro del default, no porque
la configuración propia estuviera funcionando.

**Corregido**: las cuatro variables se propagan ahora en
`docker-compose.yml`. Se añadió `tools/check-caddy-env.js`, que compara
estáticamente las variables `{$VAR}` que el Caddyfile referencia contra las
que el compose declara, y falla si falta alguna. Cableado en
`npm run verify`, en CI y con test dedicado
(`tests/build/caddy-env.test.js`) — la misma clase de guarda que ya existía
para los workflows de n8n, aplicada aquí a la infraestructura.

**Riesgo residual.** El chequeo es sintáctico: detecta que la variable se
propaga, no que el valor sea el correcto. Sigue siendo responsabilidad del
runbook de despliegue verificar el 403 real tras cambiar `MGMT_ALLOWLIST`,
como se hizo aquí — no basta con confiar en que "el nombre de la variable
coincide".

## R-10 · Modos de fallo silencioso de n8n (CERRADOS, con guardas)

El primer despliegue real destapó cinco fallos que **no producían ningún
error**: la ejecución se marcaba como exitosa y las alertas se perdían o se
puntuaban sobre datos vacíos. Todos están corregidos y con una regla que los
bloquea en compilación (`tools/build-workflows.js`), pero se dejan escritos
porque son la clase de fallo que reaparece al añadir un nodo nuevo:

1. **`rawBody` no existe.** n8n 1.72 entrega el cuerpo crudo como adjunto
   binario en base64, no en `$json.rawBody`. Sin esto, todo 401.
2. **Sin `id` estable, cada importación duplica el workflow.** Quedó activo el
   gateway de la versión anterior tras desplegar un arreglo de seguridad.
3. **Un `SELECT` sin filas detiene la rama en silencio.** Con el inventario de
   activos vacío se descartaban todas las alertas.
4. **`queryReplacement` separa por comas**, así que se rompe con JSON
   serializado.
5. **Un nodo Postgres sustituye el item por su resultado.** Aguas abajo llegaba
   la fila de la base de datos en vez de la alerta, y el triaje caía siempre a
   "investigar" — incluidos los casos críticos.

El patrón común: **n8n prefiere continuar antes que fallar**. Para un SOAR eso
es peligroso, porque un flujo que "termina bien" sin haber hecho nada es
indistinguible de uno que funciona.
