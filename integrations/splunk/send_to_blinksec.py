#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlinkSec — script de alerta de Splunk.

Ubicación:  $SPLUNK_HOME/bin/scripts/send_to_blinksec.py
Permisos:   750  splunk:splunk

Splunk invoca los scripts de alerta con 8 argumentos posicionales y entrega
los resultados comprimidos en la ruta del argumento 8. Se documentan aquí
porque la referencia oficial es escueta y el orden importa:

    argv[1]  número de eventos
    argv[2]  términos de búsqueda
    argv[3]  cadena de búsqueda completa
    argv[4]  nombre de la alerta
    argv[5]  motivo del disparo
    argv[6]  enlace a los resultados
    argv[7]  (obsoleto, siempre vacío)
    argv[8]  ruta al results.csv.gz

Se usa un script propio en lugar de Better Webhooks para que las tres
plataformas de origen compartan EXACTAMENTE el mismo esquema de firma. Un solo
camino de firma es un solo camino que auditar, y evita que una actualización
de una app de terceros rompa la ingesta en silencio.

Self-test (no necesita Splunk):
    python3 send_to_blinksec.py --self-test
"""

import csv
import gzip
import hashlib
import hmac
import json
import os
import sys
import time

HOOK_URL = os.environ.get("BLINKSEC_HOOK_URL", "https://soar.example.com/webhook/blinksec/ingest")
SECRETO = os.environ.get("BLINKSEC_HMAC_SECRET_SPLUNK", "")
TIMEOUT = 10

# Máximo de filas del resultado que se envían. Una búsqueda mal acotada puede
# devolver decenas de miles de eventos; enviarlos todos revienta el límite de
# payload del proxy (2 MB) y no aporta nada al triaje.
MAX_FILAS = 20


def firmar(cuerpo, secreto, timestamp):
    """HMAC-SHA256 sobre '<timestamp>.<cuerpo>'.

    Idéntico al esquema de integrations/wazuh/custom-n8n.py y verificado por
    lib/gateway.js. Incluir el timestamp en el material firmado impide reenviar
    una petición capturada con un timestamp nuevo.
    """
    return hmac.new(
        secreto.encode("utf-8"),
        f"{timestamp}.{cuerpo}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def leer_resultados(ruta_gz):
    """Extrae las primeras filas del results.csv.gz de Splunk."""
    if not ruta_gz or not os.path.exists(ruta_gz):
        return []
    filas = []
    with gzip.open(ruta_gz, "rt", encoding="utf-8", errors="replace") as f:
        for i, fila in enumerate(csv.DictReader(f)):
            if i >= MAX_FILAS:
                break
            # Los campos internos de Splunk (_raw, _indextime...) abultan mucho
            # y no aportan al triaje. Se conserva _time, que sí importa.
            filas.append({k: v for k, v in fila.items() if not k.startswith("_") or k == "_time"})
    return filas


def construir_payload(argv):
    filas = leer_resultados(argv[8] if len(argv) > 8 else None)
    return {
        "sid": os.environ.get("SPLUNK_ARG_SID", ""),
        "search_name": argv[4] if len(argv) > 4 else "",
        "results_link": argv[6] if len(argv) > 6 else "",
        "event_count": argv[1] if len(argv) > 1 else "0",
        # WF-01 espera la primera fila en `result`; el resto viaja en
        # `all_results` por si el analista lo necesita en el ticket.
        "result": filas[0] if filas else {},
        "all_results": filas[1:] if len(filas) > 1 else [],
    }


def enviar(payload):
    import urllib.error
    import urllib.request

    cuerpo = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    timestamp = str(int(time.time()))

    peticion = urllib.request.Request(
        HOOK_URL,
        data=cuerpo.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-BlinkSec-Source": "splunk",
            "X-BlinkSec-Timestamp": timestamp,
            "X-BlinkSec-Signature": "sha256=" + firmar(cuerpo, SECRETO, timestamp),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(peticion, timeout=TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "replace")[:300]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:300]
    except urllib.error.URLError as e:
        return 0, str(e)


def self_test():
    """Comprueba la firma sin depender de Splunk ni de la red."""
    secreto = "f" * 64
    cuerpo = json.dumps({"a": 1}, separators=(",", ":"), sort_keys=True)
    ts = "1800000000"
    firma = firmar(cuerpo, secreto, ts)

    esperado = hmac.new(secreto.encode(), f"{ts}.{cuerpo}".encode(), hashlib.sha256).hexdigest()
    assert firma == esperado, "La firma no es reproducible"
    assert len(firma) == 64, "Longitud de firma inesperada"

    print("Self-test OK")
    print(f"  cuerpo firmado : {ts}.{cuerpo}")
    print(f"  firma          : sha256={firma}")
    print("\nPara verificarlo contra el gateway:")
    print("  node -e \"const g=require('./lib/gateway.js');console.log(g.computeSignature("
          f"'{cuerpo}','{secreto}','{ts}'))\"")
    return 0


def main():
    if "--self-test" in sys.argv:
        sys.exit(self_test())

    if not SECRETO:
        sys.stderr.write("BlinkSec: falta BLINKSEC_HMAC_SECRET_SPLUNK en el entorno de Splunk\n")
        sys.exit(1)

    estado, respuesta = enviar(construir_payload(sys.argv))

    if estado == 200:
        sys.exit(0)
    if estado == 401:
        sys.stderr.write("BlinkSec 401: la firma no valida. Revisar BLINKSEC_HMAC_SECRET_SPLUNK.\n")
    elif estado == 403:
        sys.stderr.write("BlinkSec 403: la IP de este search head no está en SIEM_ALLOWLIST.\n")
    else:
        sys.stderr.write(f"BlinkSec: respuesta inesperada {estado}: {respuesta}\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
