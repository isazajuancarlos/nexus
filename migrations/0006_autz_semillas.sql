-- URLs SEMILLA para el motor de control de acceso (autz): las URLs de recursos
-- PROPIOS del dueño (su álbum privado, sus ajustes, /account/...), que el recon
-- pasivo NO descubre porque son privadas —no salen en wayback ni en un crawl sin
-- sesión—. El motor las repite con cada identidad para ver si una que no debería
-- las alcanza. Las pega Juan a mano, junto con las identidades del programa.
CREATE TABLE IF NOT EXISTS autz_semillas (
    id           INTEGER PRIMARY KEY,
    program_name TEXT NOT NULL,
    url          TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(program_name, url)
);
CREATE INDEX IF NOT EXISTS idx_autz_semillas_programa ON autz_semillas(program_name);
