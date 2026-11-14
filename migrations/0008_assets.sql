-- Fase 2.2 (ASM): histórico de assets/subdominios por programa, para diffear la
-- superficie entre corridas y avisar SOLO de lo NUEVO (el valor del ASM está en
-- el diff, no en el escaneo puntual). También es la tabla que la detección de
-- subdomain takeover (2.3) reutiliza: un host que dejó de responder o cambió es
-- justo lo que se rastrea aquí.
CREATE TABLE IF NOT EXISTS assets_historicos (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program_name TEXT NOT NULL,
    asset        TEXT NOT NULL,
    primera_vez  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultima_vez   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_name, asset)
);
CREATE INDEX IF NOT EXISTS ix_assets_prog ON assets_historicos(program_name);
