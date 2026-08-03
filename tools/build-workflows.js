#!/usr/bin/env node
'use strict';
/**
 * BlinkSec — compilador de workflows.
 *
 * PROBLEMA QUE RESUELVE
 *
 * Los nodos Code de n8n no pueden hacer `require` de ficheros del repo: se
 * ejecutan en un sandbox sin sistema de ficheros. La consecuencia habitual es
 * que la lógica crítica acaba pegada a mano dentro del JSON del workflow,
 * duplicada respecto al código con tests. A los dos meses divergen, los tests
 * pasan en verde y producción se comporta de otra forma.
 *
 * Este compilador toma las plantillas de workflows/src/, sustituye los
 * marcadores `// @blinksec-inject: <ruta>` por el código real del módulo, y
 * escribe el resultado en workflows/dist/ listo para importar en n8n.
 *
 * Así existe una sola fuente de verdad: lo que se testea es exactamente lo que
 * se ejecuta.
 *
 * USO
 *   node tools/build-workflows.js            compila a workflows/dist/
 *   node tools/build-workflows.js --check    verifica que dist/ está al día
 *                                            (para CI: falla si alguien editó
 *                                            el JSON a mano sin recompilar)
 */

const fs = require('node:fs');
const path = require('node:path');

const RAIZ = path.join(__dirname, '..');
const SRC = path.join(RAIZ, 'workflows', 'src');
const DIST = path.join(RAIZ, 'workflows', 'dist');

const MARCADOR = /^(\s*)\/\/\s*@blinksec-inject:\s*(\S+)\s*$/;

/**
 * Adapta un módulo CommonJS al sandbox del nodo Code.
 *
 * Transformaciones:
 *   - Se elimina 'use strict' (el Code node ya es estricto).
 *   - Se eliminan los `require` de módulos internos del repo: sus funciones
 *     quedan en el mismo ámbito tras la inyección.
 *   - Se conserva `require('crypto')`, que n8n permite si el entorno declara
 *     NODE_FUNCTION_ALLOW_BUILTIN=crypto (ver docker-compose.yml).
 *   - Se elimina `module.exports`, que no existe en el sandbox.
 */
function adaptarModulo(codigo, rutaRelativa) {
  const lineas = codigo.split('\n');
  const salida = [];
  let enExports = false;

  for (const linea of lineas) {
    if (/^\s*'use strict';\s*$/.test(linea)) continue;

    // require de módulos locales del repo → fuera (se inyectan aparte)
    if (/^\s*const\s+\{[^}]*\}\s*=\s*require\(['"]\.[^'"]*['"]\);?\s*$/.test(linea)) continue;
    if (/^\s*const\s+\w+\s*=\s*require\(['"]\.[^'"]*['"]\);?\s*$/.test(linea)) continue;

    // module.exports = { ... }  (puede ocupar varias líneas)
    if (/^\s*module\.exports\s*=/.test(linea)) {
      enExports = true;
      if (/;\s*$/.test(linea) && linea.includes('}')) enExports = false;
      continue;
    }
    if (enExports) {
      if (/^\s*\};?\s*$/.test(linea)) enExports = false;
      continue;
    }

    salida.push(linea);
  }

  return [
    `// ─── inyectado desde ${rutaRelativa} — NO EDITAR AQUÍ ───`,
    `// Editar el fichero original y recompilar: npm run build`,
    ...salida,
    `// ─── fin de ${rutaRelativa} ───`,
  ].join('\n');
}

/** Resuelve los marcadores de inyección dentro de un bloque de código. */
function expandir(codigo, contexto) {
  return codigo
    .split('\n')
    .map((linea) => {
      const m = linea.match(MARCADOR);
      if (!m) return linea;

      const [, sangria, rutaRelativa] = m;
      const rutaAbsoluta = path.join(RAIZ, rutaRelativa);

      if (!fs.existsSync(rutaAbsoluta)) {
        throw new Error(`${contexto}: el marcador apunta a un fichero inexistente: ${rutaRelativa}`);
      }

      // Los .json se inyectan como constante, no como código.
      if (rutaRelativa.endsWith('.json')) {
        const nombre = path
          .basename(rutaRelativa, '.json')
          .replace(/[^a-zA-Z0-9]/g, '_')
          .toUpperCase();
        const contenido = fs.readFileSync(rutaAbsoluta, 'utf8');
        return `${sangria}const BLINKSEC_${nombre} = ${contenido.trim()};`;
      }

      const fuente = fs.readFileSync(rutaAbsoluta, 'utf8');
      return adaptarModulo(fuente, rutaRelativa)
        .split('\n')
        .map((l) => sangria + l)
        .join('\n');
    })
    .join('\n');
}

/** Recorre el workflow buscando parámetros jsCode y los expande. */
function compilarWorkflow(wf, nombreFichero) {
  let inyecciones = 0;

  for (const nodo of wf.nodes ?? []) {
    const code = nodo.parameters?.jsCode;
    if (typeof code !== 'string' || !MARCADOR.test(code.split('\n').find((l) => MARCADOR.test(l)) ?? '')) {
      // Se comprueba línea a línea porque el marcador nunca está en la primera.
      if (typeof code !== 'string' || !code.split('\n').some((l) => MARCADOR.test(l))) continue;
    }
    const expandido = expandir(code, `${nombreFichero} → nodo "${nodo.name}"`);
    if (expandido !== code) inyecciones++;
    nodo.parameters.jsCode = expandido;
  }

  return { wf, inyecciones };
}

/** Validación estructural: un JSON sintácticamente válido puede no ser importable. */
function validarWorkflow(wf, fichero) {
  const errores = [];

  if (!wf.name) errores.push('falta "name"');
  if (!Array.isArray(wf.nodes) || wf.nodes.length === 0) errores.push('sin nodos');

  // `active` no tiene default en el importador: sin este campo,
  // `n8n import:workflow` aborta el lote entero con un error de constraint
  // NOT NULL en workflow_entity. Sólo se descubre desplegando.
  if (typeof wf.active !== 'boolean') {
    errores.push('falta "active" (booleano): n8n import:workflow lo exige y no lo asume');
  }

  // `id` determinista. Sin él, `n8n import:workflow` no puede hacer upsert y
  // CREA UN DUPLICADO en cada reimportación. En un SOAR eso significa acabar
  // con dos gateways, y que el que quedó activo sea el de la versión anterior:
  // se despliega un arreglo de seguridad y el tráfico lo sigue atendiendo el
  // código viejo, sin ningún error visible.
  if (!wf.id) {
    errores.push('falta "id": sin id estable cada importación duplica el workflow en lugar de actualizarlo');
  } else if (!/^blinksecwf\d{2}[a-z]{4}$/.test(wf.id)) {
    errores.push(`id "${wf.id}" fuera de convención (blinksecwfNNxxxx, 16 caracteres)`);
  }

  const nombres = new Set();
  for (const n of wf.nodes ?? []) {
    if (!n.name) errores.push('un nodo sin "name"');
    if (!n.type) errores.push(`nodo "${n.name}" sin "type"`);
    if (nombres.has(n.name)) errores.push(`nombre de nodo duplicado: "${n.name}"`);
    nombres.add(n.name);
  }

  // Las conexiones deben referirse a nodos que existen; una referencia rota
  // hace que n8n importe el flujo con ramas silenciosamente desconectadas.
  for (const [origen, conexiones] of Object.entries(wf.connections ?? {})) {
    if (!nombres.has(origen)) errores.push(`conexión desde un nodo inexistente: "${origen}"`);
    for (const salidas of conexiones.main ?? []) {
      for (const destino of salidas ?? []) {
        if (!nombres.has(destino.node)) {
          errores.push(`"${origen}" conecta con un nodo inexistente: "${destino.node}"`);
        }
      }
    }
  }

  // Convención de nomenclatura del proyecto: [BlinkSec] WF-xx - Descripción - vN
  if (wf.name && !/^\[BlinkSec\]\s+WF-\d{2}\s+-\s+.+\s+-\s+v\d+$/.test(wf.name)) {
    errores.push(`el nombre "${wf.name}" no sigue la convención "[BlinkSec] WF-xx - Descripción - vN"`);
  }

  // Un Execute Workflow Trigger con lista de campos vacía NO propaga nada al
  // subflujo: llega un objeto vacío y el flujo se ejecuta "con éxito" sobre
  // datos inexistentes. En el primer despliegue real esto hacía que WF-02
  // planificara cero consultas de inteligencia y que el veredicto saliera de
  // la línea base, sin que nada fallara visiblemente.
  for (const nodo of wf.nodes ?? []) {
    if (nodo.type !== 'n8n-nodes-base.executeWorkflowTrigger') continue;
    const fuente = nodo.parameters?.inputSource;
    const campos = nodo.parameters?.workflowInputs?.values ?? [];
    if (fuente !== 'passthrough' && campos.length === 0) {
      errores.push(
        `nodo "${nodo.name}": trigger de subflujo sin inputSource "passthrough" ni campos declarados — no recibiría datos`,
      );
    }
  }

  // Un SELECT de Postgres que no devuelve filas produce CERO items, y n8n
  // detiene esa rama sin error: la ejecución queda marcada como exitosa y la
  // alerta desaparece. Encontrado en el primer despliegue real, con el
  // inventario de activos vacío — que es el estado normal el primer día.
  for (const nodo of wf.nodes ?? []) {
    if (nodo.type !== 'n8n-nodes-base.postgres') continue;
    const q = String(nodo.parameters?.query ?? '').trim().toUpperCase();

    if (q.startsWith('SELECT') && nodo.alwaysOutputData !== true) {
      errores.push(
        `nodo "${nodo.name}": SELECT sin alwaysOutputData — si no hay filas, la rama se detiene en silencio`,
      );
    }

    // queryReplacement en formato "csv" separa los parámetros por comas, así
    // que se rompe con cualquier valor que contenga una: JSON serializado,
    // mensajes de error, descripciones de regla. El síntoma es un
    // NodeOperationError "The input string ended unexpectedly".
    // La forma correcta es una expresión que devuelva un array.
    const qr = nodo.parameters?.options?.queryReplacement;
    if (typeof qr === 'string' && qr.startsWith('=') && !/^=\{\{\s*\[/.test(qr)) {
      errores.push(
        `nodo "${nodo.name}": queryReplacement en formato csv — usar una expresión de array "={{ [a, b] }}"`,
      );
    }
  }

  // n8n-nodes-base.splitOut descarta TODOS los demás campos del item por
  // defecto (include: "noOtherFields" es el default implícito cuando no se
  // declara "include"). Sin "include: allOtherFields", cualquier campo que
  // el nodo siguiente necesite del item original (alert_id, aprobadoPor...)
  // llega undefined, y el fallo se manifiesta varios nodos más adelante como
  // un error genérico de tipo del nodo consumidor, no como algo que apunte a
  // Split Out. Encontrado en el ensayo de contención de la Fase 7: la fila de
  // containment_log no se insertaba y el mensaje no mencionaba en ningún
  // sitio "Split Out" ni "campos perdidos".
  for (const nodo of wf.nodes ?? []) {
    if (nodo.type !== 'n8n-nodes-base.splitOut') continue;
    if (nodo.parameters?.include !== 'allOtherFields') {
      errores.push(
        `nodo "${nodo.name}": Split Out sin include:"allOtherFields" — descarta todos los campos salvo el separado`,
      );
    }
  }

  // Postgres y HTTP Request SUSTITUYEN el item por su propio resultado (filas
  // de la consulta / cuerpo de la respuesta). Si uno de estos alimenta
  // directamente a un nodo que necesita campos del payload ORIGINAL — otro
  // Postgres, otro HTTP Request, un subflujo, un enrutador o un Split Out —
  // aguas abajo llegan datos que no son los suyos y el flujo continúa "con
  // éxito" sobre ellos.
  //
  // Encontrado dos veces en el ensayo de la Fase 7, con síntomas que no se
  // parecían entre sí: primero con Postgres (WF-02 planificaba cero consultas
  // de inteligencia, todas las alertas acababan en "investigar"); después con
  // HTTP Request (WF-04: "Ejecutar contención" alimentaba directamente a
  // "Registrar en containment_log", que fallaba con un mensaje genérico del
  // propio Postgres — "Query Parameters must be a string..." — sin ninguna
  // mención al HTTP Request que en realidad causaba el problema).
  const porNombre = new Map((wf.nodes ?? []).map((n) => [n.name, n]));
  const DESTRUCTORES_DE_PAYLOAD = new Set(['n8n-nodes-base.postgres', 'n8n-nodes-base.httpRequest']);
  const CONSUMIDORES_DE_PAYLOAD = new Set([
    'n8n-nodes-base.executeWorkflow',
    'n8n-nodes-base.switch',
    'n8n-nodes-base.splitOut',
    ...DESTRUCTORES_DE_PAYLOAD,
  ]);

  // Campos que un HTTP Request SÍ deja legítimamente en $json: leer
  // $json.body.algo es leer la respuesta a propósito (ej. el _id que devolvió
  // TheHive al crear el ticket), no una suposición rota sobre datos previos.
  // Postgres no tiene un equivalente estable (las columnas del SELECT/RETURNING
  // varían por consulta), así que para Postgres cualquier $json suelto se trata
  // como sospechoso.
  const CAMPOS_PROPIOS_HTTP = ['body', 'headers', 'statusCode', 'statusMessage'];

  for (const [origen, conexiones] of Object.entries(wf.connections ?? {})) {
    const nodoOrigen = porNombre.get(origen);
    if (!DESTRUCTORES_DE_PAYLOAD.has(nodoOrigen?.type)) continue;

    const esHttp = nodoOrigen.type === 'n8n-nodes-base.httpRequest';
    const etiquetaOrigen = esHttp ? 'HTTP Request' : 'Postgres';

    for (const salidas of conexiones.main ?? []) {
      for (const destino of salidas ?? []) {
        const nodoDestino = porNombre.get(destino.node);
        if (!nodoDestino || !CONSUMIDORES_DE_PAYLOAD.has(nodoDestino.type)) continue;

        // Se descartan las referencias inmunes antes de buscar $json suelto:
        //   - $('Nombre de nodo').json  → no depende de lo que dejó el nodo
        //     inmediatamente anterior.
        //   - $json.body / $json.headers / etc. (sólo si el origen es HTTP)
        //     → lectura deliberada de la propia respuesta.
        let texto = JSON.stringify(nodoDestino.parameters ?? {}).replace(
          /\$\(\s*['"][^'"]*['"]\s*\)\.\s*json\b/g,
          '',
        );
        if (esHttp) {
          const patronPropios = new RegExp(`\\$json(\\?)?\\.(${CAMPOS_PROPIOS_HTTP.join('|')})\\b`, 'g');
          texto = texto.replace(patronPropios, '');
        }

        if (!/\$json\b/.test(texto)) continue;

        errores.push(
          `"${origen}" (${etiquetaOrigen}) alimenta directamente a "${destino.node}", que usa \$json: ` +
            'intercalar un nodo Code que restaure el payload',
        );
      }
    }
  }

  // Antipatrón de flujo monolítico: por encima de 20 nodos, aislar un fallo
  // se vuelve inviable y la lógica debe extraerse a un subflujo.
  if ((wf.nodes ?? []).length > 20) {
    errores.push(`${wf.nodes.length} nodos: supera el máximo de 20, extraer lógica a un subflujo`);
  }

  if (errores.length) {
    throw new Error(`${fichero}:\n  - ${errores.join('\n  - ')}`);
  }
}

/**
 * Comprueba que toda referencia entre workflows resuelve a un id existente.
 *
 * n8n importa sin quejarse un flujo que apunta a un subflujo inexistente: el
 * editor lo muestra con normalidad y el fallo sólo aparece con la primera
 * alerta real, en forma de rama que no ejecuta nada. Para un SOAR eso es una
 * contención que silenciosamente nunca ocurre.
 */
function validarReferenciasCruzadas(compilados) {
  const conocidos = new Map(compilados.map(({ wf }) => [wf.id, wf.name]));
  // Necesario para la regla de espera anidada, más abajo: qué workflows
  // contienen su propio nodo Wait.
  const tieneWait = new Map(
    compilados.map(({ wf }) => [wf.id, (wf.nodes ?? []).some((n) => n.type === 'n8n-nodes-base.wait')]),
  );
  const errores = [];

  for (const { fichero, wf } of compilados) {
    const errorWf = wf.settings?.errorWorkflow;
    if (errorWf && !conocidos.has(errorWf)) {
      errores.push(`${fichero}: errorWorkflow "${errorWf}" no corresponde a ningún workflow del repo`);
    }

    for (const nodo of wf.nodes ?? []) {
      if (nodo.type !== 'n8n-nodes-base.executeWorkflow') continue;
      const destino = nodo.parameters?.workflowId?.value;
      if (!destino) {
        errores.push(`${fichero} → "${nodo.name}": sin workflowId`);
        continue;
      }
      if (!conocidos.has(destino)) {
        errores.push(`${fichero} → "${nodo.name}": apunta a "${destino}", que no existe`);
        continue;
      }

      // n8n no propaga de forma fiable el valor de retorno de un subflujo con
      // su propio nodo Wait cuando el llamador (waitForSubWorkflow=true) queda
      // TAMBIÉN en pausa esperándolo. Encontrado en el ensayo de HITL de la
      // Fase 7: el subflujo calculaba el valor correcto en su propia
      // ejecución, pero el llamador recibía undefined al reanudar — sin
      // ningún error. El subflujo con el Wait debe continuar la cadena por su
      // cuenta (invocando el siguiente paso él mismo), nunca devolver el
      // control a un padre que quedó pausado.
      const espera = nodo.parameters?.options?.waitForSubWorkflow === true;
      if (espera && tieneWait.get(destino)) {
        errores.push(
          `${fichero} → "${nodo.name}": waitForSubWorkflow=true hacia "${destino}", que contiene un nodo Wait`,
        );
      }
    }
  }

  if (errores.length) {
    throw new Error(`Referencias cruzadas rotas:\n  - ${errores.join('\n  - ')}`);
  }

  console.log(`\nReferencias cruzadas verificadas: ${conocidos.size} workflows enlazados entre sí.`);
}

function main() {
  const modoCheck = process.argv.includes('--check');

  if (!fs.existsSync(SRC)) {
    console.error(`No existe ${SRC}`);
    process.exit(1);
  }
  fs.mkdirSync(DIST, { recursive: true });

  const ficheros = fs.readdirSync(SRC).filter((f) => f.endsWith('.json')).sort();
  if (ficheros.length === 0) {
    console.error('No hay plantillas en workflows/src/');
    process.exit(1);
  }

  let desactualizados = 0;
  const compilados = [];

  for (const fichero of ficheros) {
    const origen = JSON.parse(fs.readFileSync(path.join(SRC, fichero), 'utf8'));
    const { wf, inyecciones } = compilarWorkflow(origen, fichero);

    validarWorkflow(wf, fichero);
    compilados.push({ fichero, wf });

    const salida = JSON.stringify(wf, null, 2) + '\n';
    const destino = path.join(DIST, fichero);

    if (modoCheck) {
      const actual = fs.existsSync(destino) ? fs.readFileSync(destino, 'utf8') : null;
      if (actual !== salida) {
        console.error(`DESACTUALIZADO  ${fichero}`);
        desactualizados++;
      } else {
        console.log(`ok              ${fichero}`);
      }
    } else {
      fs.writeFileSync(destino, salida);
      console.log(`compilado       ${fichero}  (${wf.nodes.length} nodos, ${inyecciones} inyecciones)`);
    }
  }

  validarReferenciasCruzadas(compilados);

  if (modoCheck && desactualizados > 0) {
    console.error(`\n${desactualizados} workflow(s) desactualizado(s). Ejecutar: npm run build`);
    process.exit(1);
  }

  console.log(modoCheck ? '\nTodos los workflows están al día.' : `\n${ficheros.length} workflow(s) en workflows/dist/`);
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`\nError de compilación:\n${e.message}`);
    process.exit(1);
  }
}

module.exports = { adaptarModulo, expandir, validarWorkflow, validarReferenciasCruzadas };
