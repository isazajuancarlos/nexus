-- PUERTA DE INTEGRIDAD DEL AUTO-ENVÍO H1 (port del operator-approval-loop de ECC,
-- estudio de fuente 2026-09-19, adaptado al auto-envío YA autorizado de nexus).
--
-- El motivo, medido en el propio código: hoy `autosubmit::run` hace el POST a H1 y
-- LUEGO `db::mark_reported` (autosubmit.rs:187-189). Si el proceso muere entre el POST
-- exitoso y el mark, el reporte NO tiene report_id todavía y en la próxima corrida se
-- REENVÍA — doble envío que quema Signal. Y el texto que sale (`build_submission`) no
-- está atado por hash al que pasó la puerta de evidencia: si se regenera distinto entre
-- la decisión y el POST, sale texto no verificado.
--
-- Esto ata la decisión al SHA256 del texto EXACTO (directiva 31: al ARTEFACTO, no a la
-- rama) y da idempotencia con una máquina claim→dispatching→sent. NO envía nada ni
-- decide payabilidad: solo concede/niega permiso de despacho de UN texto ya aprobado.
-- No toca las clases conocidas ni el auto-envío autorizado; lo endurece.

PRAGMA foreign_keys = ON;

-- Instantánea INMUTABLE del texto que pasó la puerta de evidencia. NUNCA se UPDATE-a:
-- regenerar el reporte crea OTRA fila con epoch nuevo. Una aprobación vieja queda atada
-- a su epoch/sha y no puede liberar texto reescrito.
CREATE TABLE IF NOT EXISTS envio_snapshot (
  id            INTEGER PRIMARY KEY,
  report_key    TEXT NOT NULL,            -- clave estable del grupo: 'programa::vuln_name'
  texto         TEXT NOT NULL,            -- el cuerpo EXACTO aprobado; begin_dispatch entrega ESTE
  texto_sha256  TEXT NOT NULL,            -- sha256 hex de `texto` (huella para detectar reescritura)
  evidencia     TEXT NOT NULL,            -- por qué pasó la puerta (execution_confirmed, ratio, clase)
  epoch         INTEGER NOT NULL,         -- decision epoch; avanza en cada re-snapshot
  created_ts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_envio_snapshot_key ON envio_snapshot(report_key);

-- Permiso de despacho de UN envío. Máquina: claimed → dispatching → sent
-- (o cancelled desde claimed; o unknown desde dispatching cuando el worker se
-- reinició y el POST pudo haber salido — ese NO se reintenta solo).
CREATE TABLE IF NOT EXISTS envio_claim (
  id            INTEGER PRIMARY KEY,
  report_key    TEXT NOT NULL,
  snapshot_id   INTEGER NOT NULL REFERENCES envio_snapshot(id),
  token         TEXT NOT NULL UNIQUE,
  state         TEXT NOT NULL CHECK (state IN ('claimed','dispatching','sent','cancelled','unknown')),
  coordinate    TEXT,                     -- report_id devuelto por H1 (solo en 'sent')
  created_ts    INTEGER NOT NULL,
  updated_ts    INTEGER NOT NULL
);

-- A lo sumo UN claim NO-terminal por report_key: bloquea el segundo envío en vuelo
-- (la garantía de exclusión real; no depende del nivel de aislamiento de la tx).
CREATE UNIQUE INDEX IF NOT EXISTS uniq_envio_claim_en_vuelo
ON envio_claim(report_key) WHERE state IN ('claimed','dispatching');

-- Un report_key que ya llegó a 'sent' o quedó 'unknown' no se vuelve a despachar:
-- lo hace cumplir el código de claim() (no se puede expresar como índice parcial
-- junto al de arriba sin colisionar), y queda como receipt permanente aquí.
CREATE INDEX IF NOT EXISTS idx_envio_claim_terminal
ON envio_claim(report_key, state);
