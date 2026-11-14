#!/usr/bin/env bash
# Stub de katana: -list <archivo> → emite /crawled por host.
f=""
while [ $# -gt 0 ]; do case "$1" in -list) f="$2"; shift ;; esac; shift; done
[ -f "$f" ] && while IFS= read -r h; do [ -n "$h" ] && echo "${h%/}/crawled"; done < "$f"
