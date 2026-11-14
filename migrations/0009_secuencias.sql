-- SECUENCIAS — la memoria de adaptación del cazador (analogía ARNm, 2026-08-23).
--
-- El problema que resuelve, en la voz de Juan: «nuclei parece muy estático y esa
-- es una gran debilidad cuando los sistemas cambian y se protegen». Una plantilla
-- es una firma fija: el día que el objetivo se endurece, deja de casar y devuelve
-- SECO. Un virus, en cambio, no lleva una firma sino un método de adaptación:
-- muta contra el entorno concreto y GUARDA la secuencia que funcionó.
--
-- Esta tabla ES ese "guardar la secuencia". Cada fila es una variante mutada de
-- una sonda que CONSIGUIÓ ejecución confirmada contra un host concreto, llaveada
-- a la HUELLA DE DEFENSA del host en el momento de confirmarla.
--
-- DOS invariantes, y son la diferencia entre criar un virus y acumular ruido:
--
--   1. SELECCIÓN (directiva 20/32). Una secuencia solo se escribe si el oráculo
--      DURO la confirmó — el mismo `execution_confirmed` que gatea el auto-envío,
--      no la heurística de la herramienta. En el código eso es un TESTIGO
--      (`OraculoConfirmado`) que no se puede construir sin ejecución confirmada:
--      guardar sin oráculo no es un bug que se cuela, es código que no compila.
--      Sin esto, "guardar lo que devolvió algo" cría falsos positivos con memoria.
--
--   2. CADUCIDAD (directiva 31: el veredicto se ancla a un ARTEFACTO, no a una
--      rama). La `huella_defensa` es la postura defensiva del host cuando la
--      secuencia funcionó. Al reencontrar el host, si su huella ACTUAL difiere,
--      la secuencia se marca `caducada` y NO se re-lanza: el huésped mutó su
--      defensa, la vieja secuencia ya no describe el entorno. Una secuencia sin
--      huella vigente es un dato que caduca sin avisar — aquí caduca a la vista.
--
-- La huella se guarda como CADENA CANÓNICA legible (no un hash) a propósito: en
-- un dictamen técnico-jurídico hay que poder MOSTRAR por qué una secuencia dejó
-- de valer, y "s=403;waf=cloudflare;muro=1" se lee; un hash no.

CREATE TABLE IF NOT EXISTS secuencias (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    program_name    TEXT NOT NULL,
    host            TEXT NOT NULL,                    -- el "huésped" / entorno
    familia         TEXT NOT NULL,                    -- autz-idor|bypass-403|ssrf-oob|...
    huella_defensa  TEXT NOT NULL,                    -- postura defensiva AL confirmar (canónica)
    mutacion        TEXT NOT NULL,                    -- la variante parametrizada que funcionó (JSON canónico)
    evidencia_ref   TEXT,                             -- ref al finding/oráculo que la confirmó
    repro_ratio     TEXT,                             -- N/M del gate de reproducibilidad
    veces_confirmada INTEGER NOT NULL DEFAULT 1,      -- cuántas veces el oráculo la revalidó
    caducada        INTEGER NOT NULL DEFAULT 0,       -- 1 si la huella del host cambió desde que se confirmó
    creada_en       TEXT NOT NULL DEFAULT (datetime('now')),
    confirmada_en   TEXT NOT NULL DEFAULT (datetime('now')),
    -- Una mutación es única por (host, familia, contenido): la MISMA técnica
    -- contra el MISMO host es la misma secuencia, se revalida (veces_confirmada++),
    -- no se duplica.
    UNIQUE(host, familia, mutacion)
);

CREATE INDEX IF NOT EXISTS ix_secuencias_host_familia ON secuencias(host, familia);
CREATE INDEX IF NOT EXISTS ix_secuencias_vigentes ON secuencias(host, familia, caducada);
