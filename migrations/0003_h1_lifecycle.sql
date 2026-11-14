-- Paridad con hack/: ciclo de vida de envío a H1 + evidencia PoC + asociación de
-- scope. Campos que el gate, el submitter y `sync` necesitan.
ALTER TABLE findings ADD COLUMN h1_state TEXT;             -- new|triaged|resolved|duplicate|informative
ALTER TABLE findings ADD COLUMN h1_submitted_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN bounty_amount TEXT;        -- string, agnóstico de moneda ("500.00")
ALTER TABLE findings ADD COLUMN structured_scope_id TEXT; -- id de la regla de scope de H1 (activo)
ALTER TABLE findings ADD COLUMN raw_evidence TEXT;         -- PoC crudo de la herramienta (cuerpo del reporte)
ALTER TABLE findings ADD COLUMN cwe TEXT;                  -- CWE del template (para weakness_id)

-- El scope guardado necesita el id de la regla (para structured_scope_id) y su tipo.
ALTER TABLE program_scopes ADD COLUMN h1_scope_id TEXT;
