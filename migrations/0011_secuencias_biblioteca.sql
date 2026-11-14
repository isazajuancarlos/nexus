-- SECUENCIAS → BIBLIOTECA DE VARIANTES (reforma, 2026-08-26, diseño de Juan).
--
-- El problema con el diseño original: `secuencias` guardaba SOLO los aciertos
-- (`OraculoConfirmado`), y con 0 aciertos en toda la historia la memoria estaba
-- vacía — el motor adaptativo nunca acumuló nada. La observación de Juan: arnm
-- debe nutrirse también de los FRACASOS. Una variante que fracasó en el sitio A
-- (que la parcheó) es candidata en el sitio B (otra config): guardar la variante
-- aunque fracase permite RECICLARLA en otro sitio.
--
-- El activo que acumula deja de ser un veredicto y pasa a ser la BIBLIOTECA DE
-- VARIANTES. Economía: GENERAR una variante es caro y con riesgo brain; RECICLAR
-- una guardada es barato y sin riesgo. El diseño maximiza reciclaje: en cada sitio
-- nuevo se re-lanza la biblioteca (barato) y solo se GENERA cuando se agota.
--
-- Esta migración añade la cara del FRACASO a la tabla existente, sin tocar el
-- camino de replay confirmado (que ya está probado):
--
--   - `veces_refutada`: cuántas veces esta variante se probó en este host y el
--     oráculo NO confirmó. No exige testigo (no es una afirmación de éxito, es su
--     opuesto). Una fila puede ser confirmada-aquí (veces_confirmada>=1),
--     refutada-aquí (veces_confirmada=0, veces_refutada>=1), o ambas con el tiempo.
--
--   - `intentada_en`: marca del último intento (confirmado o no), para observar la
--     actividad reciente sin confundirla con `confirmada_en` (que es solo aciertos).
--
-- La SELECCIÓN sobrevive: el testigo `OraculoConfirmado` sigue exigido para SUMAR
-- un acierto (`veces_confirmada`); guardar un refutado escribe en `veces_refutada`,
-- que no afirma nada. El puntaje del reciclaje (confirmadas primero, luego las
-- menos-refutadas) es lo que mantiene la biblioteca como laboratorio y no como
-- ruido — y el oráculo LIMPIO hace que ese puntaje seleccione EDGE, no varianza
-- (la diferencia con brain).

ALTER TABLE secuencias ADD COLUMN veces_refutada INTEGER NOT NULL DEFAULT 0;
ALTER TABLE secuencias ADD COLUMN intentada_en   TEXT;

-- El reciclaje cross-host agrupa por `mutacion` a través de TODOS los hosts de una
-- familia; este índice sirve ese GROUP BY sin escanear la tabla entera.
CREATE INDEX IF NOT EXISTS ix_secuencias_familia_mutacion ON secuencias(familia, mutacion);
