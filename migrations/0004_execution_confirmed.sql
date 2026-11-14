-- Auto-envío seguro. Separa DOS hechos que hasta ahora colapsaban en uno
-- (directiva 32: un valor con dos significados son dos campos):
--   exploitable          = la HERRAMIENTA externa lo cree explotable (heurística).
--   execution_confirmed  = NEXUS lo VIO ejecutar/reproducir de verdad (navegador
--                          real para XSS; sqlmap/commix que explotan; re-fetch
--                          reproducible para exposición).
-- El auto-envío a H1 se gatea sobre `execution_confirmed`, no sobre `exploitable`:
-- era el hueco por el que un FP (reflexión inerte marcada "verified" por xsstrike)
-- podía auto-enviarse. Ningún humano revisa antes del POST, así que el listón es
-- ejecución probada, no la palabra de la herramienta.
ALTER TABLE findings ADD COLUMN execution_confirmed INTEGER NOT NULL DEFAULT 0;

-- Reproducibilidad: "aciertos/intentos" del gate (p. ej. "3/3"). Un hallazgo que
-- solo dispara 1 de 3 veces lo cierra el triager de H1 como "not reproducible" y
-- quema señal en el programa; se registra para no auto-enviar lo intermitente.
ALTER TABLE findings ADD COLUMN repro_ratio TEXT;
