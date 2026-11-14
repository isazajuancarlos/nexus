#!/usr/bin/env bash
# Stub de nuclei que emite UN hallazgo de severidad info (ruido no pagable en H1)
# y UNO critical (pagable). Sirve para probar que el filtro por severidad guarda
# solo el pagable — como los 7 'info' de braze que antes saturaban la cola manual.
echo '{"template-id":"missing-sri","info":{"severity":"info"},"matched-at":"https://a.example.com/x"}'
echo '{"template-id":"CVE-2023-0001","info":{"severity":"critical"},"matched-at":"https://a.example.com/y"}'
exit 0
