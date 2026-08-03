# Registro de riesgos

Riesgos abiertos y excepciones conscientes al modelo de amenaza. Se documentan
aquí porque un riesgo aceptado y escrito es una decisión de ingeniería; el mismo
riesgo sin escribir es una sorpresa esperando fecha.

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
