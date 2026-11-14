-- Juego de identidades por programa para el motor de control de acceso (autz).
-- IDOR/BAC necesita repetir la MISMA petición con 2+ sesiones y comparar; aquí
-- viven esas sesiones. Decisión de Juan (2026-08-19): config manual por programa
-- —él registra 2 cuentas en los objetivos que valgan y pega aquí sus cookies/
-- token—; el motor corre SOLO en programas con identidades montadas.
--
-- `papel`: 'dueno' | 'par' | 'menor' | 'anonimo' (el anónimo no lleva cabeceras).
-- `cabeceras`: JSON [["Cookie","session=..."],["Authorization","Bearer ..."]].
-- Son sesiones de CUENTAS DE PRUEBA, no credenciales de Juan; caducan y se
-- refrescan a mano. UNIQUE(program,papel): una identidad por papel y programa.
CREATE TABLE IF NOT EXISTS identidades (
    id           INTEGER PRIMARY KEY,
    program_name TEXT NOT NULL,
    papel        TEXT NOT NULL,
    cabeceras    TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(program_name, papel)
);
CREATE INDEX IF NOT EXISTS idx_identidades_programa ON identidades(program_name);
