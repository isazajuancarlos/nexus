#!/usr/bin/env bash
# Stub de gau: emite URLs de archivo para el dominio (último argumento).
d="${@: -1}"
echo "https://$d/archived1"
echo "https://$d/page.php?id=1"
