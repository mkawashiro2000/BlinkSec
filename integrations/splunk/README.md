# Integración Splunk → BlinkSec

## Por qué no se usa la acción de alerta nativa

Splunk trae una acción `webhook` de serie, y es tentadora. No sirve aquí por
una razón que no tiene rodeo: **no admite cabeceras HTTP personalizadas**. Sin
cabeceras no hay `X-BlinkSec-Signature`, y sin firma el gateway de BlinkSec
(WF-00) rechaza la petición con un 401.

Las limitaciones de la acción nativa:

| Limitación | Consecuencia para el SOAR |
|---|---|
| Sin cabeceras personalizadas | Imposible firmar con HMAC ni autenticar |
| Payload de estructura fija | `result` sólo contiene la primera fila del evento |
| Sin control del cuerpo | No se puede emitir el esquema que espera WF-01 |

La opción soportada es **Better Webhooks** (Hurricane Labs), disponible en
Splunkbase. Permite tokens dinámicos en el cuerpo, cabeceras arbitrarias y
firma HMAC-SHA256.

## Configuración con Better Webhooks

En la alerta guardada → *Trigger Actions* → *Better Webhook*:

**URL**
```
https://soar.example.com/webhook/blinksec/ingest
```

**Cabeceras**
```
Content-Type: application/json
X-BlinkSec-Source: splunk
```

Better Webhooks calcula la firma HMAC y añade la cabecera de firma según su
propia configuración (`HMAC Secret` + algoritmo SHA256). Hay que ajustar el
nombre de la cabecera de firma a `X-BlinkSec-Signature` y el secreto al valor
de `BLINKSEC_HMAC_SECRET_SPLUNK`.

**Cuerpo**
```json
{
  "sid": "$$sid$$",
  "search_name": "$$search_name$$",
  "results_link": "$$results_link$$",
  "result": $$full_result$$
}
```

## El detalle que rompe la firma

Better Webhooks **no envía un timestamp propio** en el formato que espera
BlinkSec. Hay dos caminos:

1. **Recomendado** — incluir el timestamp en el cuerpo y derivarlo en WF-00.
   Exige una variante del verificador, porque el material firmado de BlinkSec
   es `<timestamp>.<cuerpo>` y el timestamp debe venir en cabecera.

2. **Más simple y el que usa este repo** — un script de alerta intermedio
   (`send_to_blinksec.py`), igual en espíritu al wrapper de Wazuh, que firma
   con el mismo esquema. Elimina la dependencia de una app de terceros y hace
   que las tres plataformas compartan exactamente el mismo verificador.

Se documenta la opción 1 porque muchos despliegues ya tienen Better Webhooks
instalado, pero **la opción 2 es la soportada**: un solo camino de firma es un
solo camino que auditar.

## Comprobación

```bash
python3 integrations/splunk/send_to_blinksec.py --self-test
```
