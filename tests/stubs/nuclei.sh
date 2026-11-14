#!/usr/bin/env bash
# Stub de nuclei para pruebas: emite JSONL determinista según los -tags.
# STUB_FAIL=1 simula un fallo de red (para probar el backoff anti-baneo).
if [ -n "$STUB_FAIL" ]; then echo "connection refused" >&2; exit 1; fi
tags=""
while [ $# -gt 0 ]; do
  case "$1" in -tags) tags="$2"; shift ;; esac
  shift
done
if echo "$tags" | grep -q cve; then
  echo '{"template-id":"CVE-2023-0001","info":{"severity":"critical"},"matched-at":"https://a.example.com/x"}'
  echo '{"template-id":"CVE-2023-0002","info":{"severity":"high"},"matched-at":"https://b.example.com/y"}'
fi
if echo "$tags" | grep -q xss; then
  echo '{"template-id":"reflected-xss","info":{"severity":"medium"},"matched-at":"https://c.example.com/z"}'
fi
echo 'linea-basura-no-json'   # prueba el conteo de líneas ilegibles
exit 0
