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

MVP funcional, **desplegado y verificado en ejecución real** sobre n8n 1.72.1
(Docker, modo queue, Postgres + Redis + Caddy). 155 tests en verde.

Verificado de extremo a extremo contra el despliegue:

- Los 9 workflows importan y se enlazan entre sí sin pasos manuales.
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

Lo que **no** está verificado: las APIs reales de inteligencia (no hay claves),
un manager de Wazuh real, y la contención real sobre un firewall. Ver
[Antes de producción](#antes-de-producción) y [docs/riesgos.md](docs/riesgos.md).

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
| `tests/build/` | Que `dist/` refleja `lib/` y `scoring/`, y las reglas anti-fallo-silencioso |

El corpus de triaje es el criterio de aceptación real: 10 falsos positivos y 10
amenazas etiquetados a mano. La regla que no se negocia es **cero falsos
positivos auto-contenidos**.

> Advertencia honesta: los pesos y el corpus los escribió la misma mano, así que
> hoy esto es un arnés de regresión, no validación independiente. El valor real
> llega al re-etiquetar con alertas de producción.

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
4. **Sustituir los endpoints de ejemplo**: `wazuh.example.com`,
   `thehive.example.com` y `soar.example.com` aparecen en workflows e
   integraciones.
5. **Validar el nodo Redis de WF-00.** La idempotencia necesita semántica
   SETNX; según la versión del nodo puede requerir el patrón alternativo de
   `docs/runbook-idempotencia.md`.
6. **Ensayo de contención en laboratorio** antes de conectar producción:
   bloquear una IP de prueba, verificar el registro, verificar la reversión.
7. **Re-etiquetar el corpus** con 100+ alertas reales y recalcular la matriz.

Los riesgos abiertos y las excepciones conscientes al modelo de amenaza están
en [docs/riesgos.md](docs/riesgos.md).

## Licencia

MIT.
