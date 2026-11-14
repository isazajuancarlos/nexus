#!/usr/bin/env bash
# Un ciclo del cazador autónomo de NEXUS. Rota al SIGUIENTE programa H1 (que paga
# y con submission abierto), hace recon acotado + scan (nuclei) + deep-verify +
# auto-envío (si NEXUS_AUTO_SUBMIT=1 en el .env). Pensado para un systemd timer.
#
# Diseño responsable:
#   - Un programa por ciclo (rotación por cursor) → cobertura gradual, sin hammering.
#   - --safe-mode: rate/concurrencia bajos, cooldowns con jitter (anti-baneo).
#   - Lista de programas cacheada de arkadiyt (solo los que PAGAN y abiertos).
#
# Para RESTRINGIR a programas que permiten automatización (ver su política): edita
# a mano ~/nexus/handles.txt (un handle por línea) y hazlo de solo lectura
# (chmod 444) para que este script no lo sobrescriba.
set -uo pipefail
cd /home/debian/nexus || exit 1

HANDLES=handles.txt
CURSOR=.cursor

# Cache semanal de la lista de programas (si no es de solo lectura y está vieja).
if [ -w "$HANDLES" ] || [ ! -e "$HANDLES" ]; then
  if [ ! -s "$HANDLES" ] || [ -n "$(find "$HANDLES" -mtime +7 2>/dev/null)" ]; then
    curl -s --max-time 120 \
      https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json \
    | python3 -c 'import sys,json
d=json.load(sys.stdin)
print("\n".join(p["handle"] for p in d if p.get("offers_bounties") and p.get("submission_state")=="open"))' \
      > "$HANDLES.tmp" 2>/dev/null && mv "$HANDLES.tmp" "$HANDLES"
  fi
fi

total=$(wc -l < "$HANDLES" 2>/dev/null || echo 0)
[ "$total" -gt 0 ] || { echo "sin handles en $HANDLES"; exit 0; }

# Cursor: rota al siguiente programa.
idx=$(cat "$CURSOR" 2>/dev/null || echo 0)
case "$idx" in ''|*[!0-9]*) idx=0 ;; esac
[ "$idx" -ge "$total" ] && idx=0
handle=$(sed -n "$((idx+1))p" "$HANDLES")
echo $(( (idx + 1) % total )) > "$CURSOR"

echo "[$(date +%FT%T)] ciclo $((idx+1))/$total → programa: $handle"
./nexus --safe-mode --only "$handle" recon || echo "recon falló para $handle"
./nexus --safe-mode scan --program "$handle" || echo "scan falló para $handle"
echo "[$(date +%FT%T)] ciclo $handle terminado"
