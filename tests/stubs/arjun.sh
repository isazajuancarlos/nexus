#!/usr/bin/env bash
# Stub de arjun: escribe JSON {primera_url:["hidden"]} en el archivo -oJ.
i=""; o=""
while [ $# -gt 0 ]; do case "$1" in -i) i="$2"; shift ;; -oJ) o="$2"; shift ;; esac; shift; done
first=$(head -1 "$i" 2>/dev/null)
[ -n "$o" ] && printf '{"%s":["hidden"]}' "$first" > "$o"
