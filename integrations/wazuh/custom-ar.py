#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BlinkSec — respuesta activa personalizada en el agente.

Ubicación:  /var/ossec/active-response/bin/custom-ar
            (en macOS: /Library/Ossec/active-response/bin/custom-ar)
Permisos:   750  root:wazuh

Wazuh entrega por STDIN un JSON con {command: add|delete, parameters: {...}}.

Este script existe para las contenciones que firewall-drop no cubre: matar un
proceso por hash. Para el bloqueo de IP se usa firewall-drop, que ya viene
probado con Wazuh y conoce las particularidades de cada plataforma.

SALVAGUARDAS (esto corre como root en un servidor de producción):
  - Allowlist local: nunca se bloquea una IP privada ni la del propio manager.
    Una regla de iptables contra el rango de gestión deja el servidor
    inaccesible y sin forma de revertir en remoto.
  - Nunca se mata un proceso con PID < 100 ni de una lista de procesos
    críticos: matar systemd o sshd convierte una contención en una caída.
  - Toda acción es idempotente: repetirla no rompe nada.
"""

import ipaddress
import json
import os
import re
import subprocess
import sys
import syslog

# --------------------------------------------------------------------------
# Salvaguardas
# --------------------------------------------------------------------------

# Procesos que jamás se terminan, por mucho que su hash coincida. Un falso
# positivo sobre uno de estos convierte la respuesta en el incidente.
PROCESOS_INTOCABLES = {
    "systemd", "init", "sshd", "wazuh-agentd", "wazuh-execd", "wazuh-modulesd",
    "kernel", "kthreadd", "dockerd", "containerd", "kubelet",
}

PID_MINIMO = 100

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def log(mensaje, prioridad=syslog.LOG_INFO):
    syslog.openlog("blinksec-ar", syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(prioridad, mensaje)


def ip_bloqueable(valor):
    """Rechaza todo lo que no sea una IP pública enrutable.

    Bloquear una IP privada aquí significa cortar la red de gestión, la de
    monitorización o la del propio manager de Wazuh — y hacerlo con una regla
    que impide conectarse para quitarla.
    """
    try:
        ip = ipaddress.ip_address(valor)
    except ValueError:
        return False, f"'{valor}' no es una IP válida"

    if ip.is_private:
        return False, f"{valor} es privada: bloquearla cortaría la red interna"
    if ip.is_loopback:
        return False, f"{valor} es loopback"
    if ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return False, f"{valor} está en un rango reservado"
    if ip.is_unspecified:
        return False, "IP no especificada"

    return True, "ok"


# --------------------------------------------------------------------------
# Acciones
# --------------------------------------------------------------------------

def matar_por_hash(hash_objetivo):
    """Termina los procesos cuyo ejecutable coincide con el hash indicado.

    Se recorre /proc y se calcula el hash del binario en disco. Deliberadamente
    NO se usa pkill por nombre: el nombre de un proceso lo controla el
    atacante, el hash del binario no.
    """
    if not HASH_RE.match(hash_objetivo or ""):
        return 1, f"Hash con formato inválido: {hash_objetivo!r}"

    import hashlib

    algoritmo = {32: "md5", 40: "sha1", 64: "sha256"}[len(hash_objetivo)]
    objetivo = hash_objetivo.lower()
    terminados = []
    omitidos = []

    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        pid = int(pid_dir)
        if pid < PID_MINIMO:
            continue

        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/comm", "r") as f:
                nombre = f.read().strip()
        except (OSError, PermissionError):
            continue

        if nombre in PROCESOS_INTOCABLES:
            omitidos.append(f"{nombre}({pid}): proceso crítico")
            continue

        try:
            h = hashlib.new(algoritmo)
            with open(exe, "rb") as f:
                for bloque in iter(lambda: f.read(65536), b""):
                    h.update(bloque)
        except (OSError, PermissionError):
            continue

        if h.hexdigest().lower() != objetivo:
            continue

        try:
            os.kill(pid, 15)  # SIGTERM primero: dar oportunidad de cerrar limpio
            terminados.append(f"{nombre}({pid})")
        except OSError as e:
            omitidos.append(f"{nombre}({pid}): {e}")

    if omitidos:
        log(f"Procesos omitidos: {', '.join(omitidos)}", syslog.LOG_WARNING)

    if terminados:
        log(f"Terminados por hash {objetivo[:16]}...: {', '.join(terminados)}")
        return 0, f"Terminados: {', '.join(terminados)}"

    # Que no haya nada que matar es un resultado correcto, no un fallo: el
    # proceso pudo terminar solo entre la detección y la respuesta.
    return 0, "Ningún proceso coincidente en ejecución"


def bloquear_ip(ip, quitar=False):
    """Regla de iptables idempotente.

    Se comprueba con -C antes de -A: repetir la contención (webhook duplicado,
    alerta reenviada) no debe acumular reglas idénticas.
    """
    ok, motivo = ip_bloqueable(ip)
    if not ok:
        log(f"Bloqueo RECHAZADO para {ip}: {motivo}", syslog.LOG_ERR)
        return 1, motivo

    regla = ["INPUT", "-s", ip, "-j", "DROP"]

    existe = subprocess.run(["iptables", "-C", *regla], capture_output=True).returncode == 0

    if quitar:
        if not existe:
            return 0, f"No había regla para {ip}"
        r = subprocess.run(["iptables", "-D", *regla], capture_output=True)
        log(f"Desbloqueada {ip}")
        return r.returncode, f"Desbloqueada {ip}"

    if existe:
        return 0, f"{ip} ya estaba bloqueada (idempotente)"

    r = subprocess.run(["iptables", "-I", *regla], capture_output=True)
    if r.returncode == 0:
        log(f"Bloqueada {ip}")
        return 0, f"Bloqueada {ip}"
    return r.returncode, r.stderr.decode()[:200]


# --------------------------------------------------------------------------

def main():
    try:
        entrada = json.loads(sys.stdin.read())
    except ValueError as e:
        log(f"Entrada JSON inválida: {e}", syslog.LOG_ERR)
        sys.exit(1)

    comando = entrada.get("command")          # add | delete
    params = entrada.get("parameters", {})
    extra = params.get("extra_args", [])
    alerta = params.get("alert", {})

    # Formato invocado por WF-04:  ["--action", "block_ip|kill_hash", "--value", "<x>"]
    accion = None
    valor = None
    for i, arg in enumerate(extra):
        if arg == "--action" and i + 1 < len(extra):
            accion = extra[i + 1]
        elif arg == "--value" and i + 1 < len(extra):
            valor = extra[i + 1]

    if not accion:
        # Invocación clásica de Wazuh: la IP viene en la propia alerta.
        accion = "block_ip"
        valor = alerta.get("data", {}).get("srcip")

    if not valor:
        log("Sin valor sobre el que actuar", syslog.LOG_ERR)
        sys.exit(1)

    if accion == "block_ip":
        codigo, mensaje = bloquear_ip(valor, quitar=(comando == "delete"))
    elif accion == "kill_hash":
        if comando == "delete":
            # Un proceso terminado no se "des-termina". Se registra y se sale
            # con éxito para que la reversión no quede marcada como fallida.
            log(f"Reversión no aplicable para kill_hash {valor}")
            codigo, mensaje = 0, "kill_hash no es reversible"
        else:
            codigo, mensaje = matar_por_hash(valor)
    else:
        log(f"Acción no soportada: {accion}", syslog.LOG_ERR)
        codigo, mensaje = 1, f"Acción no soportada: {accion}"

    print(json.dumps({"ok": codigo == 0, "message": mensaje}))
    sys.exit(codigo)


if __name__ == "__main__":
    main()
