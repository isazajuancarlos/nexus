#!/usr/bin/env bash
# Stub de ffuf: escribe JSON con un resultado /admin en el archivo -o.
u=""; o=""
while [ $# -gt 0 ]; do case "$1" in -u) u="$2"; shift ;; -o) o="$2"; shift ;; esac; shift; done
base="${u%/FUZZ}"
[ -n "$o" ] && printf '{"results":[{"url":"%s/admin","status":200}]}' "$base" > "$o"
