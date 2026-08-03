# BlinkSec

SOAR de código abierto sobre n8n. Ingesta alertas de Wazuh, Splunk o Elastic
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
                                    cerrar en SIEM     WF-06 ticket    WF-04 contención
                                                                              │
                                                                       WF-05 aprobación
                                                                        humana si aplica
```

## Estado

MVP funcional. El núcleo lógico —gateway, normalización, enriquecimiento,
scoring y planificación de contención— está implementado y cubierto por **140
tests**. Los workflows compilan y validan estructuralmente.

**No verificado contra un despliegue real**: no se ha ejecutado con un n8n
levantado, ni contra las APIs reales de los proveedores, ni con un manager de
Wazuh. Lo que falta para producción está en [Antes de producción](#antes-de-producción).

## Arranque rápido

```bash
cp docker/.env.example docker/.env && chmod 600 docker/.env
```

Rellenar `docker/.env` (cada campo indica cómo generarlo), y después:

```bash
docker compose -f docker/docker-compose.yml up -d
```

Compilar e importar los workflows:

```bash
npm run build
```

Los ficheros de `workflows/dist/` se importan en n8n. Hay que crear las
credenciales con los ids que esperan los nodos (`blinksec-pg`,
`blinksec-redis`, `blinksec-greynoise`, …) y activar los flujos.

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
la aprobación humana en un retardo decorativo.

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
tools/          compilador y validador de workflows
integrations/   lado SIEM: Wazuh, Splunk, Elastic
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
| `tests/gateway/` | HMAC, replay, idempotencia; interoperabilidad real Python↔JS |
| `tests/fixtures/` | Normalización de las tres plataformas al contrato común |
| `tests/triage/` | Corpus etiquetado de 20 casos + matriz de confusión |
| `tests/build/` | Que `dist/` refleja `lib/` y `scoring/` |

El corpus de triaje es el criterio de aceptación real: 10 falsos positivos y 10
amenazas etiquetados a mano. La regla que no se negocia es **cero falsos
positivos auto-contenidos**.

> Advertencia honesta: los pesos y el corpus los escribió la misma mano, así que
> hoy esto es un arnés de regresión, no validación independiente. El valor real
> llega al re-etiquetar con alertas de producción — está en la Fase 7.

## Antes de producción

1. **Poblar `blinksec.assets`.** Sin inventario, todo activo se asume `high` y
   toda contención pasa por aprobación humana. El sistema funciona, pero no
   automatiza.
2. **Revisar `blinksec.ip_allowlist`.** Añadir proxies, VPN, escáneres de
   vulnerabilidades y rangos de oficina. Los RFC1918 vienen precargados.
3. **Sustituir los endpoints de ejemplo**: `wazuh.example.com`,
   `thehive.example.com` y `soar.example.com` aparecen en workflows e
   integraciones.
4. **Validar el nodo Redis de WF-00.** La idempotencia necesita semántica
   SETNX; según la versión del nodo puede requerir el patrón alternativo de
   `docs/runbook-idempotencia.md`.
5. **Ensayo de contención en laboratorio** antes de conectar producción:
   bloquear una IP de prueba, verificar el registro, verificar la reversión.
6. **Re-etiquetar el corpus** con 100+ alertas reales y recalcular la matriz.

Los riesgos abiertos y las excepciones conscientes al modelo de amenaza están
en [docs/riesgos.md](docs/riesgos.md).

## Licencia

MIT.
