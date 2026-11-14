#!/usr/bin/env bash
# Stub de sqlmap: decide según la URL (-u) para poder probar los 3 caminos.
url=""
while [ $# -gt 0 ]; do
  case "$1" in -u) url="$2"; shift ;; esac
  shift
done
case "$url" in
  *vuln*) echo "sqlmap identified the following injection point. Parameter 'id' is vulnerable. Type: UNION-based" ;;
  *waf*)  echo "403 Forbidden - WAF/IPS detected, the back-end request was blocked" ;;
  *)      echo "all tested parameters do not appear to be injectable" ;;
esac
exit 0
