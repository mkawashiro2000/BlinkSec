#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlinkSec — integración Wazuh → n8n.

Ubicación en el manager:  /var/ossec/integrations/custom-n8n
Permisos:                 750  root:wazuh   (ejecutable, sin extensión .py)

Wazuh invoca este script con:
    custom-n8n <ruta_alerta_json> <api_key> <hook_url>

Por qué un wrapper en lugar del webhook nativo de Wazuh:

  1. FIRMA HMAC. El bloque <integration> de Wazuh no permite inyectar
     cabeceras personalizadas, así que no puede firmar sus peticiones. Sin
     firma, el webhook del SOAR acepta cualquier POST de cualquiera — y quien
     conozca la URL puede fabricar alertas que provoquen el bloqueo automático
     de infraestructura legítima.

  2. FILTRADO LOCAL. Descartar aquí lo que nunca se va a procesar ahorra a n8n
     una ejecución completa, y a las APIs de inteligencia una consulta de
     cuota. En un manager con 500 agentes la diferencia es de órdenes de
     magnitud.

  3. RECORTE DE PII. La alerta cruda de Wazuh incluye el full_log completo.
     Se envía sólo lo que el SOAR necesita.
"""

import hashlib
import hmac
import json
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler

try:
    import requests
except ImportError:
    sys.stderr.write("BlinkSec: falta el módulo 'requests'. Instalar con: /var/ossec/framework/python/bin/pip3 install requests\n")
    sys.exit(1)

# --------------------------------------------------------------------------
# Configuración
# --------------------------------------------------------------------------

LOG_PATH = "/var/ossec/logs/integrations-blinksec.log"
TIMEOUT_SEGUNDOS = 10

# Nivel mínimo. Duplica el <level> del ossec.conf a propósito: si alguien
# afloja la configuración XML sin revisar, este suelo sigue en pie.
NIVEL_MINIMO = 7

# Reglas que nunca se envían aunque superen el nivel mínimo: ruido conocido
# que sólo consumiría cuota de las APIs de inteligencia.
REGLAS_EXCLUIDAS = {
    "502",    # Ossec server started
    "503",    # Ossec agent started
    "504",    # Ossec agent disconnected
    "530",    # Agent stopped
    "1002",   # Unknown problem somewhere in the system (demasiado genérico)
}

# Grupos de reglas que interesan aunque el nivel sea moderado.
GRUPOS_PRIORITARIOS = {"authentication_failures", "syscheck", "rootcheck", "attack", "web_attack", "sca"}

logger = logging.getLogger("blinksec")
logger.setLevel(logging.INFO)


def _configurar_log():
    """Registro en fichero, con degradación a stderr.

    Si el directorio de logs de Wazuh no existe (entorno de test, contenedor
    recortado, permisos mal puestos), el script debe seguir funcionando: no
    poder escribir el log nunca puede ser motivo de que se pierdan alertas.
    """
    formato = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    try:
        handler = RotatingFileHandler(LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3)
    except OSError:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formato)
    logger.addHandler(handler)


_configurar_log()


# --------------------------------------------------------------------------
# Filtrado
# --------------------------------------------------------------------------

def debe_enviarse(alerta):
    """Decide si la alerta merece una ejecución del SOAR.

    Devuelve (bool, motivo) para que el descarte quede registrado: un filtro
    silencioso es indistinguible de una integración rota.
    """
    regla = alerta.get("rule", {})
    nivel = int(regla.get("level", 0))
    rule_id = str(regla.get("id", ""))
    grupos = set(regla.get("groups", []))

    if rule_id in REGLAS_EXCLUIDAS:
        return False, f"regla {rule_id} en lista de exclusión"

    if nivel >= NIVEL_MINIMO:
        return True, f"nivel {nivel} >= {NIVEL_MINIMO}"

    if grupos & GRUPOS_PRIORITARIOS and nivel >= 5:
        return True, f"grupo prioritario {grupos & GRUPOS_PRIORITARIOS} con nivel {nivel}"

    return False, f"nivel {nivel} por debajo del umbral"


def recortar(alerta):
    """Reduce la alerta a lo que el SOAR necesita.

    El full_log completo puede contener credenciales en claro, rutas de
    usuario y contenido de ficheros. No hay motivo para que eso viaje al SOAR
    y acabe persistido en su base de ejecuciones. Se envía truncado.
    """
    salida = {
        "timestamp": alerta.get("timestamp"),
        "id": alerta.get("id"),
        "rule": {
            k: alerta.get("rule", {}).get(k)
            for k in ("id", "level", "description", "groups", "mitre", "firedtimes")
        },
        "agent": alerta.get("agent", {}),
        "manager": alerta.get("manager", {}),
        "location": alerta.get("location"),
        "decoder": alerta.get("decoder", {}),
        "data": alerta.get("data", {}),
    }

    if "syscheck" in alerta:
        salida["syscheck"] = alerta["syscheck"]

    full_log = alerta.get("full_log")
    if full_log:
        salida["full_log"] = full_log[:512]

    return salida


# --------------------------------------------------------------------------
# Envío firmado
# --------------------------------------------------------------------------

def enviar(hook_url, secreto, payload):
    """POST firmado con HMAC-SHA256.

    El material firmado es "<timestamp>.<cuerpo>", igual que el esquema de
    Stripe. Incluir el timestamp dentro de la firma impide que un atacante
    capture una petición válida y la reenvíe más tarde con un timestamp
    fresco para saltarse la ventana anti-replay.

    Se serializa UNA sola vez y se firma exactamente esa cadena de bytes. Si
    se serializara dos veces (una para firmar, otra para enviar), cualquier
    diferencia de orden o espaciado rompería la verificación en el otro
    extremo — el fallo de integración más común y más difícil de diagnosticar.
    """
    cuerpo = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    timestamp = str(int(time.time()))

    firma = hmac.new(
        secreto.encode("utf-8"),
        f"{timestamp}.{cuerpo}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    cabeceras = {
        "Content-Type": "application/json",
        "X-BlinkSec-Source": "wazuh",
        "X-BlinkSec-Timestamp": timestamp,
        "X-BlinkSec-Signature": f"sha256={firma}",
    }

    respuesta = requests.post(
        hook_url,
        data=cuerpo.encode("utf-8"),
        headers=cabeceras,
        timeout=TIMEOUT_SEGUNDOS,
    )
    return respuesta


def main():
    if len(sys.argv) < 4:
        logger.error("Argumentos insuficientes: se esperaba <alerta> <api_key> <hook_url>")
        sys.exit(1)

    ruta_alerta = sys.argv[1]
    secreto = sys.argv[2]      # Wazuh pasa aquí el <api_key> del ossec.conf
    hook_url = sys.argv[3]

    if not secreto or secreto == "-":
        logger.error("Sin secreto HMAC: revisar <api_key> en el bloque <integration> del ossec.conf")
        sys.exit(1)

    try:
        with open(ruta_alerta, "r", encoding="utf-8") as f:
            alerta = json.load(f)
    except (OSError, ValueError) as e:
        logger.error("No se pudo leer la alerta %s: %s", ruta_alerta, e)
        sys.exit(1)

    enviar_si, motivo = debe_enviarse(alerta)
    if not enviar_si:
        logger.info("Descartada regla %s: %s", alerta.get("rule", {}).get("id"), motivo)
        sys.exit(0)

    payload = recortar(alerta)

    try:
        r = enviar(hook_url, secreto, payload)
    except requests.RequestException as e:
        # Wazuh no reintenta las integraciones. Se registra con detalle para
        # que la pérdida sea detectable; si esto aparece de forma sostenida,
        # el SOAR está ciego y hay que saberlo.
        logger.error("Fallo de red enviando la alerta %s: %s", alerta.get("id"), e)
        sys.exit(1)

    if r.status_code == 200:
        logger.info("Enviada regla %s (%s) — %s", payload["rule"]["id"], motivo, r.status_code)
    elif r.status_code == 401:
        logger.error(
            "401 del SOAR: la firma no valida. Comprobar que <api_key> en ossec.conf "
            "coincide con BLINKSEC_HMAC_SECRET_WAZUH en el .env de n8n."
        )
    elif r.status_code == 403:
        logger.error("403 del SOAR: la IP de este manager no está en SIEM_ALLOWLIST del Caddyfile.")
    else:
        logger.error("Respuesta inesperada %s: %s", r.status_code, r.text[:300])


if __name__ == "__main__":
    main()
