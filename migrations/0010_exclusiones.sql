-- Memoria NEGATIVA por causa: el inverso de `secuencias`.
--
-- `secuencias` guarda la sonda que GANÓ contra un host (para re-lanzarla). Esta
-- guarda por qué una (host, clase) se EXCLUYÓ, para que la próxima decisión sea
-- por CAUSA y no un "seco" indistinto (directiva 30: un negativo no es una sola
-- cosa; qué haces después depende de su causa). Como en `secuencias`, la clave es
-- la HUELLA de defensa del host: si la huella cambia, el veredicto negativo caduca
-- (el entorno ya no es el que lo produjo) y se reintenta con normalidad.
--
-- La política por causa NO vive en la tabla (es lógica pura en `exclusiones.rs`,
-- directiva 32): la fila guarda el HECHO observado (causa + huella), y el oráculo
-- deriva la ACCIÓN. Así una causa cambia de política sin migración de datos.
CREATE TABLE IF NOT EXISTS exclusiones (
    id            INTEGER PRIMARY KEY,
    host          TEXT NOT NULL,
    clase         TEXT NOT NULL,   -- la fase/clase: ssrf, ssrf_oob, dast, autz, nuclei…
    causa         TEXT NOT NULL,   -- tiempo|inop_transitoria|inop_permanente|metodos_agotados|inexistencia|esteril
    huella        TEXT NOT NULL,   -- huella de defensa del host cuando se registró (PosturaDefensa::huella)
    veces         INTEGER NOT NULL DEFAULT 1,   -- cuántas veces se ha reafirmado la misma causa
    registrado_en TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, clase)
);
-- No hace falta un índice sobre (host, clase): el UNIQUE ya crea uno, y toda
-- consulta va por esa pareja (obs. de la revisión: un índice extra sería redundante).
