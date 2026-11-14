#!/usr/bin/env bash
# Stub de httpx: por cada subdominio del archivo (-l) emite un host vivo https.
f=""
while [ $# -gt 0 ]; do
  case "$1" in -l) f="$2"; shift ;; esac
  shift
done
if [ -f "$f" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && echo "https://$line"
  done < "$f"
fi
exit 0
