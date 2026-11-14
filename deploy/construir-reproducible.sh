#!/usr/bin/env bash
# Construye el binario de nexus de forma REPRODUCIBLE y ANCLABLE.
#
# El problema que resuelve: un `cargo build --release` suelto produce bytes que
# dependen del toolchain de la máquina, así que no se puede afirmar «lo que corre
# en el VPS es la compilación del commit X» (directiva 31). Esto lo fija:
#
#   - imagen base por DIGEST inmutable, no por la etiqueta móvil `1-bookworm`
#     (una etiqueta la reescribe quien controla el repositorio; el digest no);
#   - deps 100% vendorizadas, CARGO_HOME vacío → sin red, sin caché (el positivo
#     de control de `.cargo/config.toml`);
#   - ruta fija `/build` → sin rutas absolutas de esta máquina en el binario;
#   - el perfil release ya trae `codegen-units=1`, `lto=fat`, `strip`.
#
# MEDIDO el 2026-08-19: dos corridas limpias del commit d8c4492570aa con el
# digest de abajo dieron el MISMO md5 (4a40cac94623dad0ee88228b65044302).
# Repetir esta orden en cualquier máquina con docker reproduce esos bytes.
#
# Bash y no Rust (directiva 38): es pegamento de despliegue de la misma familia
# que sus vecinos `provision-tools.sh` / `nexus-cycle.sh`, envolviendo docker+tar;
# un binario Rust que llama a docker añadiría un paso de compilación sin ganar
# seguridad aquí.
#
# ANCLAJE, en dos tiempos:
#   1) Antes de desplegar: correr esto, apuntar (commit, digest, md5).
#   2) Tras subir el binario: `md5sum` en el VPS DEBE dar ese mismo md5.
# Desde entonces el binario del VPS está anclado a su fuente. Sobre un binario
# hecho con `cargo build` suelto NO se puede hacer hacia atrás: hay que
# redesplegar el que sale de aquí.
set -euo pipefail

# rust:1-bookworm = rustc 1.97.1 el 2026-08-19. Al subir de toolchain (directiva
# 35: línea estable, con motivo) se cambia este digest Y se re-mide el md5.
IMG=rust@sha256:14bc9c5966e7b3a385794b3d5389a8765668342025fbcc7b2e3d2866ac4bd8c3

REPO=$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)
SALIDA_DIR=${1:-"$REPO/target/reproducible"}
commit=$(git -C "$REPO" rev-parse --short=12 HEAD)
sucio=""
git -C "$REPO" diff --quiet 2>/dev/null || sucio=" (ÁRBOL SUCIO: el md5 no ancla a ningún commit)"

mkdir -p "$SALIDA_DIR"
# El SRC se tarea en el HOST y entra por STDIN — NO por bind-mount `-v $REPO:/src`.
# Motivo (medido 2026-11-06, openSUSE): si el contenedor corre con uid REMAPEADO y el
# repo cuelga de un directorio padre no atravesable (p. ej. /mnt/data en 0710, privado a
# propósito), el bind-mount da `tar: /src: Cannot open: Permission denied` y aborta el
# build con binario vacío. El tar host-side lo lee el usuario que invoca (que sí entra a
# su propio repo) e incluye `vendor/`; va al contenedor por stdin. El binario sale por
# STDOUT (`cat`) y el log de cargo a STDERR (`>&2`). Mismos `--exclude`, misma imagen por
# digest y mismo `cargo build --offline` → bytes idénticos a la receta del bind-mount
# (comprobado: reproduce el mismo md5).
tar -C "$REPO" --exclude=./target --exclude=./.git -cf - . | \
docker run --rm -i "$IMG" bash -euo pipefail -c '
  rm -rf /build && mkdir /build
  tar -C /build -xf -
  cd /build
  export CARGO_HOME=$(mktemp -d)
  cargo build --release --offline >&2
  cat target/release/nexus
' > "$SALIDA_DIR/nexus"
md5=$(md5sum "$SALIDA_DIR/nexus" | cut -d' ' -f1)

echo "commit   $commit$sucio"
echo "imagen   $IMG"
echo "md5      $md5"
echo "binario  $SALIDA_DIR/nexus"
echo
echo "Verificar contra el VPS (tras desplegar ESTE binario):"
echo "  ssh debian@192.99.42.108 md5sum /home/debian/nexus/nexus   # debe dar $md5"
