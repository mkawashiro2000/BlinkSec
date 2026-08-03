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

## R-08 · Sin pruebas de carga (ABIERTO)

Nada de esto se ha ejecutado bajo volumen. El modo queue con 2 workers y
concurrencia 10 debería sostener el objetivo de 500 alertas/min, pero es una
estimación, no una medición. Fase 7.
