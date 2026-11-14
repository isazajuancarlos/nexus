#!/usr/bin/env bash
# Stub de xsstrike: decide según la URL (-u).
url=""
while [ $# -gt 0 ]; do
  case "$1" in -u) url="$2"; shift ;; esac
  shift
done
case "$url" in
  *vuln*) echo "Vulnerable webpage found. Payload: <script>alert(1)</script>" ;;
  *)      echo "No parameter found to test for XSS" ;;
esac
exit 0
