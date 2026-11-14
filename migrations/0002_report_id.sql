-- Auto-envío (F-submit): guardar el id del reporte creado en H1 para no duplicar.
ALTER TABLE findings ADD COLUMN report_id TEXT;
