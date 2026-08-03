'use strict';
/**
 * Interoperabilidad de firma Python ↔ JavaScript.
 *
 * El emisor firma en Python (custom-n8n.py) y el verificador valida en
 * JavaScript (lib/gateway.js). Si ambas implementaciones divergen —distinto
 * material firmado, distinta codificación, distinto separador— el resultado es
 * un 401 permanente que parece un problema de credenciales y no lo es.
 *
 * Este test ejecuta el Python REAL del repo y valida su firma con el JS REAL
 * del repo. Es la única forma de que un cambio en uno rompa el test en lugar
 * de romper la producción.
 *
 * Se omite automáticamente si no hay python3 en el entorno.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const { verifyRequest } = require('../../lib/gateway.js');

const SECRETO = 'f'.repeat(64);
const RUTA_WRAPPER = path.join(__dirname, '..', '..', 'integrations', 'wazuh', 'custom-n8n.py');

function hayPython() {
  try {
    execFileSync('python3', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Invoca las funciones reales del wrapper de Wazuh vía un shim que importa el
 * fichero por ruta, para no duplicar la lógica de firma en el test.
 */
function firmarConPython(payloadObj) {
  const shim = `
import importlib.util, json, sys, types

# 'requests' no hace falta para firmar; se inyecta un stub para poder importar
# el wrapper sin instalar la dependencia en el entorno de test.
stub = types.ModuleType("requests")
stub.post = lambda *a, **k: None
class _RE(Exception): pass
stub.RequestException = _RE
sys.modules["requests"] = stub

spec = importlib.util.spec_from_file_location("custom_n8n", ${JSON.stringify(RUTA_WRAPPER)})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

payload = json.loads(sys.stdin.read())

capturado = {}
def fake_post(url, data=None, headers=None, timeout=None):
    capturado["body"] = data.decode("utf-8")
    capturado["headers"] = headers
    class R: status_code = 200; text = ""
    return R()
stub.post = fake_post

mod.enviar("https://ejemplo/hook", ${JSON.stringify(SECRETO)}, payload)
print(json.dumps(capturado))
`;

  const salida = execFileSync('python3', ['-c', shim], {
    input: JSON.stringify(payloadObj),
    encoding: 'utf8',
  });
  return JSON.parse(salida);
}

test('la firma generada por custom-n8n.py valida en lib/gateway.js', { skip: !hayPython() && 'python3 no disponible' }, () => {
  const payload = {
    timestamp: '2026-08-02T09:14:22.113+0000',
    rule: { id: '5712', level: 10, description: 'sshd: brute force' },
    agent: { id: '004', name: 'web-01' },
    data: { srcip: '45.155.205.233' },
  };

  const { body, headers } = firmarConPython(payload);

  // Se verifica exactamente lo que Python puso en el cable.
  const resultado = verifyRequest(
    { headers, rawBody: body },
    { secrets: { wazuh: SECRETO }, windowSeconds: 300, now: Number(headers['X-BlinkSec-Timestamp']) },
  );

  assert.equal(resultado.source, 'wazuh');
});

test('un cuerpo alterado tras la firma de Python es rechazado por JS', { skip: !hayPython() && 'python3 no disponible' }, () => {
  const { body, headers } = firmarConPython({ rule: { id: '1' }, data: { srcip: '1.2.3.4' } });

  // El atacante en el camino cambia la IP a bloquear por la del gateway propio.
  const alterado = body.replace('1.2.3.4', '10.0.0.1');
  assert.notEqual(alterado, body);

  assert.throws(
    () =>
      verifyRequest(
        { headers, rawBody: alterado },
        { secrets: { wazuh: SECRETO }, windowSeconds: 300, now: Number(headers['X-BlinkSec-Timestamp']) },
      ),
    (e) => e.code === 'firma_invalida',
  );
});

test('el wrapper de Python emite las tres cabeceras que espera el gateway', { skip: !hayPython() && 'python3 no disponible' }, () => {
  const { headers } = firmarConPython({ rule: { id: '1' } });
  assert.equal(headers['X-BlinkSec-Source'], 'wazuh');
  assert.ok(headers['X-BlinkSec-Timestamp']);
  assert.match(headers['X-BlinkSec-Signature'], /^sha256=[a-f0-9]{64}$/);
});
