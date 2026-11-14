#!/usr/bin/env bash
# Aprovisiona las herramientas de verificación profunda y evidencia en el VPS.
# commix NO está en apt de Debian 13; sqlmap/commix/xsstrike se instalan por git
# (son tools Python). chromium sí está en apt. Ejecutar en el VPS:
#   scp deploy/provision-deep-tools.sh debian@192.99.42.108:~ && ssh debian@... 'bash provision-deep-tools.sh'
set -uo pipefail

DEST="${HOME}/tools"
mkdir -p "$DEST"
command -v git >/dev/null || sudo -n apt-get install -y git

echo "[*] chromium (apt) para evidencia..."
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y chromium 2>&1 | tail -2 || echo "  chromium: revisar"

clone() { # repo destino
  if [ -d "$DEST/$2" ]; then
    echo "  $2 ya existe"
  else
    git clone --depth 1 "https://github.com/$1.git" "$DEST/$2"
  fi
}
echo "[*] Clonando sqlmap / commix / XSStrike..."
clone "sqlmapproject/sqlmap" "sqlmap-src"
clone "commixproject/commix" "commix-src"
clone "s0md3v/XSStrike"      "XSStrike"

echo "[*] venv para XSStrike (Debian 13 = PEP 668)..."
python3 -m venv "$DEST/XSStrike/venv"
"$DEST/XSStrike/venv/bin/pip" install -q --upgrade pip
"$DEST/XSStrike/venv/bin/pip" install -q -r "$DEST/XSStrike/requirements.txt" 2>&1 | tail -3 || echo "  xsstrike deps: revisar"

echo "[*] Wrappers ejecutables..."
cat > "$DEST/sqlmap" <<'WRAP'
#!/usr/bin/env bash
exec python3 /home/debian/tools/sqlmap-src/sqlmap.py "$@"
WRAP
cat > "$DEST/commix" <<'WRAP'
#!/usr/bin/env bash
exec python3 /home/debian/tools/commix-src/commix.py "$@"
WRAP
cat > "$DEST/xsstrike" <<'WRAP'
#!/usr/bin/env bash
exec /home/debian/tools/XSStrike/venv/bin/python /home/debian/tools/XSStrike/xsstrike.py "$@"
WRAP
chmod +x "$DEST/sqlmap" "$DEST/commix" "$DEST/xsstrike"

echo
echo "[*] Verificación:"
"$DEST/sqlmap" --version 2>&1 | head -1
echo -n "commix: "; "$DEST/commix" --version 2>&1 | grep -iE "v[0-9]|commix" | head -1
echo -n "xsstrike: "; "$DEST/xsstrike" --help >/dev/null 2>&1 && echo "OK (--help corre)" || echo "revisar"
echo -n "chromium: "; command -v chromium || echo FALTA
echo
echo "[✓] Añade al .env de nexus:"
echo "  NEXUS_SQLMAP_PATH=$DEST/sqlmap"
echo "  NEXUS_COMMIX_PATH=$DEST/commix"
echo "  NEXUS_XSSTRIKE_PATH=$DEST/xsstrike"
echo "  NEXUS_CHROMIUM_PATH=$(command -v chromium || echo chromium)"
