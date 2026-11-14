#!/usr/bin/env bash
# Aprovisiona las herramientas externas que NEXUS orquesta, en el VPS Debian 13.
# El VPS no trae Go ni los binarios de ProjectDiscovery. Ejecutar en el servidor:
#   scp deploy/provision-tools.sh debian@192.99.42.108:~ && ssh debian@192.99.42.108 'bash provision-tools.sh'
set -euo pipefail

DEST="${HOME}/tools"
mkdir -p "$DEST"

# 1. Go (toolchain) si no está.
if ! command -v go >/dev/null 2>&1; then
  GO_VER="1.24.0"
  echo "[*] Instalando Go ${GO_VER}..."
  curl -sSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
  export PATH="$PATH:/usr/local/go/bin"
fi
export GOBIN="$DEST"

# 2. Herramientas de ProjectDiscovery + enhanced recon (motor real del pipeline).
echo "[*] Instalando subfinder / httpx / nuclei / katana ..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
echo "[*] Instalando gau / waybackurls / ffuf ..."
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/ffuf/ffuf/v2@latest
echo "[*] Instalando arjun (pip) ..."
pipx install arjun 2>/dev/null || pip install --user arjun || true

# 3. Plantillas de nuclei (una vez; luego nexus corre con -disable-update-check).
"$DEST/nuclei" -update-templates -silent || true

echo
echo "[✓] Herramientas en $DEST"
echo "    Añade al .env de nexus:"
for t in subfinder httpx nuclei katana gau waybackurls ffuf; do
  echo "      NEXUS_$(echo "$t" | tr 'a-z' 'A-Z')_PATH=$DEST/$t"
done
echo "      NEXUS_ARJUN_PATH=\$(command -v arjun)"
