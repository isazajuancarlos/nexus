#!/usr/bin/env bash
# Stub de subfinder: emite un par de subdominios por dominio (-d).
d=""
while [ $# -gt 0 ]; do
  case "$1" in -d) d="$2"; shift ;; esac
  shift
done
[ -n "$d" ] && { echo "www.$d"; echo "api.$d"; }
exit 0
