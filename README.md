## BlinkSec
SOAR de código abierto sobre n8n. Ingesta alertas de Splunk o Elastic Security, las enriquece con inteligencia de amenazas, las tría con un motor de puntuación auditable y ejecuta contramedidas — con intervención humana obligatoria (HITL) donde el impacto lo justifica.

Plaintext
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
## Estado del Proyecto
BlinkSec es un MVP funcional y resiliente, diseñado con la seguridad del propio sistema como prioridad. Está desplegado y verificado en ejecución real sobre n8n 1.72.1 (Docker, modo queue, Postgres + Redis + Caddy).
- 173 tests en verde: Pipeline completo verificado de extremo a extremo (ingesta → normalización → enriquecimiento → triaje → ticketing).
- Auditoría superada: Se sometió a una auditoría de seguridad rigurosa (detalles en docs/riesgos.md). Los vectores de ataque (saltos de HITL, pérdida de alertas) fueron identificados y parcheados.
- Gateway blindado: Rechaza firmas incorrectas, reenvíos caducados (anti-replay), orígenes desconocidos y cuerpos alterados.
- Resiliencia comprobada: Funciona incluso con proveedores de inteligencia caídos (el enriquecimiento se marca como parcial y evita falsas contenciones automáticas). Se recupera automáticamente de caídas simuladas de Redis y Postgres.
- Procesamiento por Lotes (Batches): Soporte nativo para payloads multi-alerta; cada alerta se evalúa de forma aislada y persistente.
## Arranque Rápido
Genera tu archivo de entorno y configura los parámetros (cada campo en el .env.example indica cómo generarlo). Tienes el despliegue paso a paso en docs/runbook-despliegue.md.

Bash
cp docker/.env.example docker/.env && chmod 600 docker/.env
docker compose -f docker/docker-compose.yml up -d
Compilar e importar los workflows en n8n:

Bash
npm run build
Importa los ficheros de workflows/dist/ en tu instancia de n8n. Crea las credenciales necesarias (blinksec-pg, blinksec-redis, blinksec-abuseipdb, etc.) y activa los flujos.

## Notas críticas de despliegue:
El token BLINKSEC_HITL_TOKEN_SECRET no es opcional. Sin él, el WF-05 (HITL) fallará por diseño para evitar aprobaciones no autorizadas.
Asegúrate de activar dos workflows principales: blinksecwf00gtwy (Gateway) y blinksecwf07revr (Reversión programada). Si omites el segundo, las reglas de contención nunca caducarán.
Verifica tu entorno antes de inyectar tráfico:

Bash
npm run verify
## Rendimiento
Las métricas base demuestran la viabilidad del sistema (Medido en Raspberry Pi 5 - 4 núcleos ARM, 8 GB). Nota: El cuello de botella principal reside en los backoffs de las APIs externas, no en el cómputo del SOAR.

Métrica	Valor Observado	Objetivo del Sistema
Rendimiento Global	110–140 alertas/min	500 alertas/min
Latencia Gateway (p50)	~2,000 ms	—
Triaje (Cómputo puro)	~400 ms	—
Fallback (APIs caídas)	~23 s	—
## Decisiones de Diseño
La arquitectura de BlinkSec se basa en principios de "falla seguro" (fail-safe) y operaciones defensivas:
El Gateway va primero, no al final: Un webhook SOAR sin firmar es una vulnerabilidad crítica. Usamos firma HMAC-SHA256 sobre el cuerpo crudo y una ventana anti-replay de 300s.
La línea base de puntuación es 35, no 50: Ninguna señal aislada alcanza el umbral crítico (70). La contención automática exige siempre corroboración de al menos dos fuentes independientes.
Un enriquecimiento parcial nunca contiene: Si un proveedor como VirusTotal devuelve un 503, la alerta se topa en 69 puntos y escala a un humano. Preferimos un ticket de más que aislar un servidor legítimo.
Toda contención nace con su reversión: Cada acción registra su undo_payload y expires_at. El WF-07 limpia proactivamente para evitar la acumulación técnica de reglas de firewall huérfanas.
El timeout del HITL significa RECHAZO: Si un humano no aprueba en 15 minutos, no se ejecuta la contención. El token de la URL de reanudación está ligado criptográficamente a la alerta específica.
La Allowlist precede al Scoring: Evaluar IPs confiables antes de procesar evita denegaciones de servicio auto-infligidas contra infraestructura crítica (VPNs, proxies corporativos).
## Hoja de Ruta y Validaciones Pendientes
Aunque el núcleo del sistema es sólido, las siguientes integraciones están en fase de validación (mocked) y requieren pruebas en tu entorno de producción antes de un despliegue total:
Aprobación HITL vía Slack: La validación se ha realizado contra el webhook de n8n; requiere pruebas end-to-end con un bot de Slack real.
Contención en Cloudflare: El flujo está verificado contra un mock fiel que simula la API de Cloudflare, pero la creación/reversión de reglas de firewall reales está pendiente de ejecución en vivo.
Ticketing Externo: Actualmente el registro vive en Postgres con notificaciones a Slack (TheHive/Wazuh fueron retirados temporalmente).
Ingesta vía Elastic: Deshabilitada por defecto. Funciona, pero depende de tokens estáticos en lugar de firmas dinámicas (menor postura de seguridad que Splunk).
Tests E2E de Workflows: La suite de tests actual cubre los módulos de dominio de forma aislada. Ampliar la cobertura al "cableado" entre nodos de n8n es la principal prioridad técnica.
## Estructura del Proyecto
lib/ - Módulos de dominio, puros y testeables (gateway, normalize, enrich, containment).
scoring/ - Motor de triaje y pesos versionados de forma independiente.
workflows/src/ - Plantillas de workflow con marcadores de inyección.
workflows/dist/ - Compilados listos para importar a n8n (Generado automáticamente, no editar).
tools/ - Compilador, validador y servicios mock para ensayos sin credenciales.
integrations/ - Lado SIEM: Splunk, Elastic.
tests/ - Suite de pruebas (Gateway, fixtures, triaje, compilación).
docker/ - Compose endurecido, Caddy, esquemas de Postgres.
docs/ - Runbooks de operación y registro de riesgos.
## Suite de Pruebas
Bash
npm test
Nuestro corpus de triaje es el estándar de aceptación: 10 falsos positivos y 10 amenazas reales. La regla inquebrantable del sistema es mantener cero falsos positivos auto-contenidos.

## Checklist de Pre-Producción
Antes de abrir BlinkSec a tráfico real, completa estos pasos (detalles en docs/riesgos.md):
[ ] Poblar blinksec.assets: Sin un inventario, todo se asume de criticidad High y requiere intervención humana.
[ ] Configurar blinksec.ip_allowlist: Añade proxies, VPNs, escáneres y redes de oficina (RFC1918 ya incluidos).
[ ] Verificar credenciales CTI: Una API key errónea no falla ruidosamente; ciega el sistema devolviendo "IoC desconocido".
[ ] Reemplazar endpoints: Cambia todas las menciones de soar.example.com en las integraciones.
[ ] Validar semántica de Redis: Confirma que tu nodo Redis soporta SETNX para garantizar la idempotencia de alertas (ver docs/runbook-idempotencia.md).
[ ] Simulacro Fire-Drill: Ejecuta un ensayo real contra tu infraestructura (ej. bloqueando una IP de prueba en tu Cloudflare de producción y verificando su reversión).
[ ] Re-etiquetar el corpus: Alimenta el sistema con ~100 alertas reales de tu entorno para calibrar el motor de scoring.
## Licencia
Este proyecto está bajo la Licencia MIT - ver el archivo LICENSE para más detalles.
