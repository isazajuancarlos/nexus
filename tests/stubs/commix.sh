#!/usr/bin/env bash
# Stub de commix: decide según la URL (-u).
url=""
while [ $# -gt 0 ]; do
  case "$1" in -u) url="$2"; shift ;; esac
  shift
done
case "$url" in
  *vuln*) echo "The parameter is vulnerable to command injection" ;;
  *)      echo "not injectable" ;;
esac
exit 0
