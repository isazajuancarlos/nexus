#!/usr/bin/env bash
# Stub de nuclei que EMITE un hallazgo y LUEGO se cuelga más que el timeout de la
# fase. Modela el caso real: nuclei transmite hallazgos según los encuentra y la
# fase expira (acotada por el presupuesto) antes de que termine. Sirve para
# probar que la salida ya emitida SOBREVIVE al SIGKILL (Fix A).
echo '{"template-id":"CVE-2023-9999","info":{"severity":"critical"},"matched-at":"https://a.example.com/late"}'
# Vaciar el buffer y darle a Rust tiempo de leer la línea antes de dormir.
sleep 30
# Esta segunda línea NO debería llegar: el proceso ya fue matado.
echo '{"template-id":"NUNCA","info":{"severity":"low"},"matched-at":"https://z/never"}'
