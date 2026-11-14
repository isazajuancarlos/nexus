#!/usr/bin/env bash
# Stub de Chromium: crea el archivo de screenshot indicado en --screenshot=PATH.
out=""
for a in "$@"; do case "$a" in --screenshot=*) out="${a#--screenshot=}";; esac; done
[ -n "$out" ] && printf 'PNG-STUB' > "$out"
exit 0
