//! Verificación profunda: clasifica un hallazgo, elige herramienta (SQLMap/
//! XSStrike/Commix) y diagnostica el error para decidir el reintento adaptativo.
//! Portado de `deep_scanner.py`. El motor (las herramientas) sigue siendo
//! subprocess; lo que se migra —y donde Rust gana— es la MÁQUINA DE ESTADOS
//! tipada: un `ErrorType` no reintentable no puede colarse por el camino de
//! reintento porque el tipo no lo permite.

use crate::protection::backoff;

/// Tipo de vulnerabilidad. Determina la herramienta de verificación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnType {
    Sqli,
    Xss,
    Cmdi,
    Ssrf,
    Lfi,
    Rce,
    Redirect,
    Exposure,
    /// Insecure Direct Object Reference: una identidad obtiene el recurso de OTRA
    /// (privesc horizontal / BOLA). Lo detecta el motor `autz`, no una plantilla.
    Idor,
    /// Broken Access Control a nivel de función/endpoint: privesc vertical o fuga
    /// sin autenticar de algo que debería exigir sesión. También del motor `autz`.
    Bac,
    Other,
}

impl VulnType {
    /// Herramienta que verifica este tipo (None = revisión manual).
    pub fn tool(&self) -> Option<&'static str> {
        match self {
            VulnType::Sqli => Some("sqlmap"),
            VulnType::Xss => Some("xsstrike"),
            VulnType::Cmdi => Some("commix"),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            VulnType::Sqli => "sqli",
            VulnType::Xss => "xss",
            VulnType::Cmdi => "cmdi",
            VulnType::Ssrf => "ssrf",
            VulnType::Lfi => "lfi",
            VulnType::Rce => "rce",
            VulnType::Redirect => "redirect",
            VulnType::Exposure => "exposure",
            VulnType::Idor => "idor",
            VulnType::Bac => "bac",
            VulnType::Other => "other",
        }
    }
}

/// Clasifica por patrones en el nombre/descripción (de classify_vulnerability).
pub fn classify(name: &str) -> VulnType {
    let n = name.to_lowercase();
    let has = |ps: &[&str]| ps.iter().any(|p| n.contains(p));
    if has(&["sqli", "sql-inject", "sql inject", "database.error"]) {
        VulnType::Sqli
    } else if has(&["xss", "cross-site-script", "cross site script"]) {
        VulnType::Xss
    } else if has(&["cmdi", "command-inject", "command inject", "shell-inject"]) {
        VulnType::Cmdi
    } else if has(&["ssrf", "server-side-request"]) {
        VulnType::Ssrf
    } else if has(&["lfi", "path-travers", "file-read"]) {
        VulnType::Lfi
    } else if has(&["rce", "remote-code"]) {
        VulnType::Rce
    } else if has(&["open-redirect", "url-redirect", "redirect"]) {
        VulnType::Redirect
    } else if has(&["exposure", "api-key", "secret", "token"]) {
        VulnType::Exposure
    } else {
        VulnType::Other
    }
}

/// ¿`v` contiene `t` en un LÍMITE de palabra por la izquierda (inicio de cadena o
/// tras un carácter no alfanumérico)? Permite prefijos —`tls-cifrado` casa
/// `tls-cifrado-3des`— pero NO substrings embebidos: `hsts` NO casa dentro de una
/// palabra que lo contenga por casualidad (directiva 17/23: un `vuln_name` kebab es
/// código estructurado, no una cadena cruda; el casado ancho fabrica falsos match).
fn tiene_token(v: &str, t: &str) -> bool {
    let b = v.as_bytes();
    let mut i = 0;
    while let Some(p) = v[i..].find(t) {
        let pos = i + p;
        if pos == 0 || !b[pos - 1].is_ascii_alphanumeric() {
            return true;
        }
        i = pos + 1;
    }
    false
}

/// Clases de config/higiene/divulgación SIN impacto directo, que H1/Intigriti
/// cierran como Informative y que por tanto NO deben llenar la cola manual ni
/// enviarse. LISTA NEGRA explícita: se enumera lo PROVABLEMENTE ruidoso y TODO lo
/// demás —incluido lo desconocido, el RCE de `bespoke` y un crítico nuevo de
/// `nuclei`— va a MANUAL (lado seguro; dir. 20/30: un detector nunca esconde lo
/// que no reconoce).
///
/// Historia (directiva 23/33): el 2026-08-26 se probó invertir a lista BLANCA
/// («cuáles SÍ»), y la revisión midió que enterraba `hybris-consola-scripting-
/// expuesta` (RCE crítico) por no casar ningún token —el desconocido caía al lado
/// SILENCIOSO—. Se volvió a la lista negra, ampliando la antigua WONT_FIX con las
/// 4 clases que de verdad inundaban la cola: protocolo/cipher TLS, SSH-kex y
/// GraphQL-introspection. Casado por límite de palabra (`tiene_token`).
fn es_config_ruidosa(v: &str) -> bool {
    const RUIDOSA: &[&str] = &[
        // divulgación / fingerprinting sin impacto
        "backend-server", "server-version", "version-detect", "tech-detect",
        "version-banner", "banner", "waf-detect", "cdn-detect", "favicon-detect",
        "robots-txt", "options-method", "http-missing",
        // cabeceras de seguridad ausentes (defensa en profundidad, no vuln directa)
        "missing-security-headers", "security-headers", "subresource-integrity", "sri-not",
        "x-frame-options", "x-content-type", "xcto", "clickjack", "cache-control",
        "header-csp", "csp-missing", "referrer-missing", "hsts", "no-https-redirect",
        // flags de cookies (en inglés y en español, que emite `cabeceras.rs`)
        "cookies-without", "cookie-without", "cookie-sin", "httponly", "samesite",
        // correo / DNS informativo
        "spf-record", "spf-detect", "dmarc-detect", "dns-saas-service", "dns-waf-detect",
        "email-spoofing",
        // === las 4 clases que inundaban la cola (revisión 2026-08-26) ===
        "tls-protocolo", "tls-cifrado", "cifrado-3des", "cifrado-rc4", "cipher-weak",
        "ssh-weakkey", "weakkey-exchange", "exchange-algo", "ssh-weak",
        "introspection",
    ];
    RUIDOSA.iter().any(|s| tiene_token(v, s))
}

/// ¿El hallazgo NO debe llenar la cola manual ni auto-enviarse (es informativo)?
/// Config ruidosa conocida, MÁS dos refinamientos que podan subconjuntos benignos
/// (claves publicables; debug/rpc sobre host no productivo). Todo lo que no case
/// aquí va a MANUAL — el desconocido al lado ruidoso, nunca al silencioso. Puro y
/// testable; llamado desde la poda P0 de `deepscan`.
pub fn is_informational_class(vuln_name: &str, url: &str) -> bool {
    let v = vuln_name.to_lowercase();
    // Regla base: solo la config/higiene PROVABLEMENTE ruidosa es INFORMATIONAL.
    if es_config_ruidosa(&v) {
        return true;
    }
    // Claves PUBLICABLES: públicas por diseño (su par SECRETO no se divulga aquí),
    // así que una plantilla que las marca es divulgación SIN impacto — fue el FP
    // medido el 2026-08-21: `razorpay-clientid-disclosure` clasificado HIGH sobre
    // truecaller.com, cuando el `key_id` de Razorpay es la clave de cliente,
    // pública a propósito. Lista ESPECÍFICA (directiva 23: se enumeran las
    // variantes publicables; los templates del SECRETO —`*-secret`, `sk_live`—
    // NO están aquí y siguen su curso normal: un `razorpay-key-secret` no casa).
    const CLAVES_PUBLICABLES: &[&str] = &[
        "razorpay-clientid", "razorpay-client-id",
        "stripe-publishable", "publishable-key",
        "recaptcha-site-key",
        "mapbox-public",
        "paypal-client-id",
    ];
    if CLAVES_PUBLICABLES.iter().any(|s| v.contains(s)) {
        return true;
    }
    // Debug/RPC/status sobre host NO productivo → intencional.
    let debugish = ["debug", "rpc", "actuator", "swagger", "phpinfo", "status-page", "metrics-endpoint"]
        .iter().any(|s| v.contains(s));
    if debugish && host_es_no_productivo(&crate::scope::host_of(url).to_lowercase()) {
        return true;
    }
    false
}

/// ¿El host es de un entorno NO productivo (test/staging/…)? Casa el marcador a
/// LÍMITES DE ETIQUETA DNS (separadores `.` y `-`), NO por substring: antes
/// `latest.api.com` contenía «test» y `quates.com` contenía «uat», así que un
/// debug/rpc REAL en producción se podaba como informativo y se PERDÍA — un falso
/// negativo que esconde un hallazgo pagable (revisión 2026-08-23, obs Q5).
/// Precio aceptado y su pareja (directiva 33): un marcador EMBEBIDO en una etiqueta
/// compuesta sin separador (`xlayertestrpc`) ya no se reconoce como testnet, así
/// que su debug/rpc pasa a revisión MANUAL en vez de podarse. Es la dirección
/// segura: nunca esconder un hallazgo posiblemente real (directiva 23: enumerar lo
/// no-productivo por límite de etiqueta, no listar excepciones a un substring).
fn host_es_no_productivo(host: &str) -> bool {
    const MARCADORES: &[&str] = &["test", "staging", "sandbox", "dev", "qa", "uat", "preprod"];
    host.split('.')
        .flat_map(|etiqueta| etiqueta.split('-'))
        .any(|parte| MARCADORES.contains(&parte))
}

/// Diagnóstico del error. Separado en transitorio (reintentable) y permanente:
/// el `is_retryable()` es lo que impide reintentar en vano (directiva 23: la
/// regla enumera lo que SÍ es reintentable; el resto, no).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    // Transitorios
    Timeout,
    WafBlocked,
    RateLimited,
    NetworkError,
    TargetSlow,
    // Permanentes
    ToolCrash,
    InvalidUrl,
    AuthRequired,
    TargetDead,
    SslError,
    // Parcial
    PartialScan,
    // Sin error
    None,
}

impl ErrorType {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ErrorType::Timeout
                | ErrorType::WafBlocked
                | ErrorType::RateLimited
                | ErrorType::NetworkError
                | ErrorType::TargetSlow
                | ErrorType::PartialScan
        )
    }
}

/// Diagnostica la salida de una herramienta buscando patrones. Portado de
/// `_diagnose_output`.
pub fn diagnose_output(output: &str) -> ErrorType {
    let o = output.to_lowercase();
    let has = |p: &str| o.contains(p);
    if has("timed out") || has("timeout") {
        ErrorType::Timeout
    } else if has("waf") || has("blocked") || has("403 forbidden") {
        ErrorType::WafBlocked
    } else if has("429") || has("rate limit") || has("too many requests") {
        ErrorType::RateLimited
    } else if has("connection refused") || has("could not resolve") || has("network is unreachable") {
        ErrorType::NetworkError
    } else if has("ssl") || has("certificate") {
        ErrorType::SslError
    } else if has("401") || has("unauthorized") || has("authentication required") {
        ErrorType::AuthRequired
    } else if has("traceback") || has("segmentation fault") || has("panic") {
        ErrorType::ToolCrash
    } else if has("invalid url") || has("malformed") {
        ErrorType::InvalidUrl
    } else {
        ErrorType::None
    }
}

/// Estrategia de verificación (parámetros que se adaptan por error).
#[derive(Debug, Clone)]
pub struct VerificationStrategy {
    pub timeout: u64,
    pub level: u8,        // nivel SQLMap
    pub risk: u8,         // riesgo SQLMap
    pub delay: f64,       // pausa entre peticiones
    pub tamper: Vec<String>, // scripts tamper (bypass WAF)
}

impl Default for VerificationStrategy {
    fn default() -> Self {
        Self { timeout: 120, level: 1, risk: 1, delay: 0.0, tamper: Vec::new() }
    }
}

impl VerificationStrategy {
    /// Ajusta la estrategia según el error observado. Solo tiene sentido si el
    /// error es reintentable — el tipo obliga a comprobarlo antes.
    pub fn adjusted_for(&self, err: ErrorType) -> Self {
        let mut s = self.clone();
        match err {
            ErrorType::Timeout | ErrorType::TargetSlow => s.timeout = (s.timeout * 2).min(600),
            ErrorType::WafBlocked => {
                s.tamper = vec!["space2comment".into(), "randomcase".into()];
                s.delay = s.delay.max(2.0);
            }
            ErrorType::RateLimited => s.delay = s.delay.max(5.0),
            ErrorType::NetworkError => s.delay = s.delay.max(1.0),
            _ => {}
        }
        s
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
    None,
}

/// Decide si reintentar y cuándo (segundos de espera). Devuelve None si no se
/// debe reintentar (error permanente o reintentos agotados).
pub fn plan_retry(err: ErrorType, retry_count: u32, max_retries: u32) -> Option<u64> {
    if !err.is_retryable() || retry_count >= max_retries {
        return None;
    }
    // backoff 60s base, techo 1h (de deep_scanner: 1→2→4→8 min ... max 1hr).
    Some(backoff(60, 3600, retry_count + 1))
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
            Confidence::None => "none",
        }
    }
}

// ==============================================================================
// VERIFICACIÓN REAL (F3): construcción de comandos + intérpretes puros + runner.
// Portado de deep_scanner.py (_verify_*_with_strategy). Las herramientas
// (sqlmap/xsstrike/commix) se invocan como subprocess; los INTÉRPRETES de su
// salida son puros y testables.
// ==============================================================================

/// Resultado de verificar un hallazgo.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub verified: bool,
    pub confidence: Confidence,
    pub tool: String,
    pub details: String,
    pub exploitable: bool,
    /// EJECUCIÓN/reproducción probada de verdad (navegador real para XSS; una
    /// herramienta que EXPLOTA como sqlmap/commix; re-fetch reproducible para
    /// exposición). Distinto de `exploitable`, que es la heurística de la
    /// herramienta (directiva 32). SOLO esto habilita el auto-envío a H1.
    pub execution_confirmed: bool,
    pub error: ErrorType,
    pub evidence: Option<String>,
    /// PoC crudo de la herramienta (últimos ~2000 chars), para el cuerpo del reporte (S6).
    pub raw: Option<String>,
}

impl Outcome {
    /// Sin herramienta automática para este tipo → revisión manual.
    fn manual() -> Self {
        Self { verified: false, confidence: Confidence::None, tool: "manual".into(),
               details: "sin verificador automático; revisión manual".into(),
               exploitable: false, execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    }
    /// La herramienta no está instalada → no se puede verificar aún.
    fn tool_missing(tool: &str) -> Self {
        Self { verified: false, confidence: Confidence::None, tool: tool.into(),
               details: format!("{tool} no disponible"), exploitable: false,
               execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    }
    /// La herramienta fue bloqueada (WAF/rate-limit/auth).
    fn blocked(tool: &str, err: ErrorType) -> Self {
        Self { verified: false, confidence: Confidence::None, tool: tool.into(),
               details: format!("bloqueado: {err:?}"), exploitable: false,
               execution_confirmed: false, error: err, evidence: None, raw: None }
    }

    /// Estado en BD derivado del resultado. Solo la confianza ALTA produce un
    /// veredicto definitivo (VERIFIED/FALSE_POSITIVE); media o baja van a
    /// revisión manual — no se sobre-afirma (directiva 21). Un error reintentable
    /// nunca se marca como falso positivo: pasa por RETRY_PENDING.
    pub fn status(&self) -> &'static str {
        if self.error != ErrorType::None && self.error.is_retryable() {
            "RETRY_PENDING"
        } else if self.confidence == Confidence::High && self.verified {
            "VERIFIED"
        } else if self.confidence == Confidence::High && !self.verified {
            "FALSE_POSITIVE"
        } else {
            "MANUAL_READY"
        }
    }
}

/// Comando sqlmap (sin el binario). Portado de _verify_sqli_with_strategy.
pub fn sqlmap_cmd(url: &str, s: &VerificationStrategy) -> Vec<String> {
    let mut c = vec![
        "-u".into(), url.into(),
        "--batch".into(),
        format!("--level={}", s.level),
        "--risk=1".into(),        // V2: gentil (menos payloads arriesgados)
        "--smart".into(),         // V2: solo prueba params que parecen inyectables (rápido)
        format!("--timeout={}", s.timeout),
        "--retries=2".into(),
        "--threads=4".into(),
        "--random-agent".into(),
        "--answers=crack=N,dict=N,continue=Y".into(),
    ];
    if !s.tamper.is_empty() {
        c.push(format!("--tamper={}", s.tamper.join(",")));
    }
    if s.delay > 0.0 {
        c.push("--delay".into());
        c.push((s.delay as u64).to_string());
    }
    c
}

/// Comando xsstrike. Portado de _verify_xss_with_strategy.
pub fn xsstrike_cmd(url: &str, s: &VerificationStrategy) -> Vec<String> {
    let mut c = vec![
        "-u".into(), url.into(),
        "--skip".into(),
        "-t".into(), "5".into(),
        "--timeout".into(), s.timeout.to_string(),
        "--crawl".into(),
        "-l".into(), "2".into(),
    ];
    if s.delay > 0.0 {
        c.push("--delay".into());
        c.push((s.delay as u64).to_string());
    }
    c
}

/// Comando commix. Portado de _verify_cmdi_with_strategy.
pub fn commix_cmd(url: &str, s: &VerificationStrategy) -> Vec<String> {
    vec![
        "-u".into(), url.into(),
        "--batch".into(),
        format!("--level={}", s.level),
        "--skip-empty".into(),
        "--random-agent".into(),
        format!("--timeout={}", s.timeout),
        "--retries=2".into(),
    ]
}

fn contains_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

/// Interpreta la salida de sqlmap (stdout+stderr en minúsculas). Puro.
pub fn interpret_sqlmap(output: &str) -> Outcome {
    let o = output.to_lowercase();
    let err = diagnose_output(&o);
    if matches!(err, ErrorType::WafBlocked | ErrorType::RateLimited | ErrorType::AuthRequired) {
        return Outcome::blocked("sqlmap", err);
    }
    // sqlmap confirma la inyección con varias frases según sea corrida fresca o
    // reanudada de sesión. Señales robustas: las frases explícitas, "injection
    // point", o el bloque de inyección (Parameter: ... + Type: ...).
    let confirmed = contains_any(&o, &["is vulnerable", "sqlmap identified", "sqlmap resumed", "injection point"])
        || (o.contains("parameter:") && o.contains("type:"));
    if confirmed {
        let injection = if o.contains("boolean-based") { "boolean-based blind" }
            else if o.contains("time-based") { "time-based blind" }
            else if o.contains("union") { "UNION-based" }
            else if o.contains("error-based") { "error-based" }
            else if o.contains("stacked") { "stacked queries" }
            else { "unknown" };
        // sqlmap EXPLOTA la inyección (análisis diferencial), no la adivina: su
        // confirmación de alta confianza ES ejecución probada (directiva 32).
        Outcome { verified: true, confidence: Confidence::High, tool: "sqlmap".into(),
                  details: format!("SQLi confirmada: {injection}"), exploitable: true,
                  execution_confirmed: true, error: ErrorType::None, evidence: Some(injection.into()), raw: None }
    } else if contains_any(&o, &["not injectable", "all tested parameters"]) {
        Outcome { verified: false, confidence: Confidence::High, tool: "sqlmap".into(),
                  details: "sqlmap no halló punto de inyección".into(), exploitable: false,
                  execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    } else {
        Outcome { verified: true, confidence: Confidence::Low, tool: "sqlmap".into(),
                  details: "no concluyente, revisión manual".into(), exploitable: false,
                  execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    }
}

/// Interpreta la salida de xsstrike. Puro.
///
/// **xsstrike es una PISTA, no una confirmación.** Hace análisis heurístico de
/// reflexión; NO ejecuta un navegador. Su "Payload:"/"vulnerable" solo dice que
/// algo se reflejó de forma sospechosa — una reflexión INERTE dispara lo mismo
/// (fue el FP #11: `<injectable>` marcado exploitable con captura de login limpio).
/// Por eso su positivo ya NO marca `exploitable` ni alta confianza: queda como
/// posible-XSS (Medium → MANUAL_READY). Quien PROMUEVE a explotable+confirmado es
/// el gate de ejecución en navegador (`browser::confirm_xss`), que sí cruza la
/// frontera (directivas 28/32). El negativo duro sí es fiable (no había reflejo).
pub fn interpret_xss(output: &str) -> Outcome {
    let o = output.to_lowercase();
    let err = diagnose_output(&o);
    if matches!(err, ErrorType::WafBlocked | ErrorType::RateLimited) {
        return Outcome::blocked("xsstrike", err);
    }
    if contains_any(&o, &["no parameter", "not vulnerable"]) {
        Outcome { verified: false, confidence: Confidence::High, tool: "xsstrike".into(),
                  details: "xsstrike no halló XSS".into(), exploitable: false,
                  execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    } else if output.contains("Payload:") || o.contains("vulnerable") {
        // Pista fuerte, pero SIN ejecución probada: no explotable todavía.
        Outcome { verified: true, confidence: Confidence::Medium, tool: "xsstrike".into(),
                  details: "posible XSS reflejada (pista de xsstrike, pendiente de confirmar ejecución)".into(),
                  exploitable: false, execution_confirmed: false, error: ErrorType::None,
                  evidence: Some("reflexión detectada".into()), raw: None }
    } else {
        Outcome { verified: true, confidence: Confidence::Medium, tool: "xsstrike".into(),
                  details: "posible XSS, revisión manual".into(), exploitable: false,
                  execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    }
}

/// Interpreta la salida de commix. Puro.
pub fn interpret_cmdi(output: &str) -> Outcome {
    let o = output.to_lowercase();
    let err = diagnose_output(&o);
    if matches!(err, ErrorType::WafBlocked | ErrorType::RateLimited) {
        return Outcome::blocked("commix", err);
    }
    if contains_any(&o, &["is vulnerable", "command injection"]) {
        // commix EJECUTA comandos en el objetivo para confirmar: es ejecución probada.
        Outcome { verified: true, confidence: Confidence::High, tool: "commix".into(),
                  details: "inyección de comandos confirmada".into(), exploitable: true,
                  execution_confirmed: true, error: ErrorType::None, evidence: None, raw: None }
    } else if o.contains("not injectable") {
        Outcome { verified: false, confidence: Confidence::High, tool: "commix".into(),
                  details: "commix no halló inyección".into(), exploitable: false,
                  execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    } else {
        Outcome { verified: true, confidence: Confidence::Medium, tool: "commix".into(),
                  details: "no concluyente".into(), exploitable: false,
                  execution_confirmed: false, error: ErrorType::None, evidence: None, raw: None }
    }
}

/// Clasifica el cuerpo de una respuesta HTTP para EXPOSURE (V1, content_check).
/// Indicador FUERTE = secreto real expuesto → explotable/reportable. DÉBIL =
/// podría ser un login benigno → se marca pero no explotable. Puro y testable.
pub fn classify_exposure(body: &str) -> Outcome {
    let low = body[..body.len().min(50_000)].to_lowercase();
    // Substrings de POSIBLE exposición. TODOS son señal DÉBIL: `api_key`,
    // `aws_secret`, `bearer ` casan igual en un NOMBRE DE CAMPO, un placeholder
    // `REDACTED`, un doc o un `.js` que en una fuga real — no discriminan. La
    // CONFIRMACIÓN de secretos reales la hace la capa precisa (`evaluar_secretos`
    // → `detectar` por patrón + verificación viva del proveedor), que corre ANTES
    // y solo cae aquí si no encontró nada. Por eso esta vía NUNCA marca explotable
    // ni alta confianza: queda en Medium → MANUAL_READY (revisión humana).
    //
    // Antes marcaba High + exploitable, y la reproducción P2 del deepscan —que
    // re-corría este clasificador PURO sobre un cuerpo estable, 3/3 determinista—
    // la promovía a execution_confirmed y la AUTO-ENVIABA: un `{"api_key":"REDACTED"}`
    // se enviaba a la plataforma como secreto crítico (revisión de seguridad
    // 2026-08-23, hallazgo H1). directiva 33: el control P2 no fallaba por la vía
    // del fallo real (un substring FP es estable → reproduce perfecto). El fix va
    // en la REGLA: la vía de substrings no confirma, y P2 (gate falso) se retiró.
    let indicadores: [(&str, &str); 8] = [
        ("aws_secret", "aws secret"), ("akia", "aws access key id"),
        ("-----begin", "clave privada"), ("secret_key", "secret key"),
        ("bearer ", "bearer token"), ("api_key", "api key"), ("apikey", "api key"),
        ("password", "campo password"),
    ];
    let mut found: Vec<&str> = indicadores.iter().filter(|(n, _)| low.contains(n)).map(|(_, l)| *l).collect();
    found.dedup();
    let verified = !found.is_empty();
    Outcome {
        verified,
        confidence: if verified { Confidence::Medium } else { Confidence::None },
        tool: "content_check".into(),
        details: if found.is_empty() {
            "sin contenido sensible".into()
        } else {
            format!("posible exposición (señal débil por substring, revisión manual): {}", found.join(", "))
        },
        // NUNCA explotable ni auto-confirmable por esta vía: es fallback heurístico.
        exploitable: false,
        execution_confirmed: false,
        error: ErrorType::None,
        evidence: if found.is_empty() { None } else { Some(found.join(", ")) },
        raw: None,
    }
}

/// Evalúa secretos por PATRÓN + VERIFICACIÓN VIVA (fase 0.1). Devuelve `Some` con
/// un veredicto autoritativo si detecta algún secreto; `None` si no hay ninguno
/// (entonces `content_check` cae al `classify_exposure` de substrings débiles).
/// Un secreto VIVO (confirmado por el proveedor) SÍ es `execution_confirmed`
/// —cruzó la frontera, directiva 28—; un publicable/muerto NO es fuga.
///
/// `secret_verify` gobierna si se TOCA al proveedor con la credencial ajena
/// (`--secret-verify` / NEXUS_SECRET_VERIFY). Por defecto (false) NO se toca a
/// ningún tercero: un secreto detectado se clasifica sin red —publicable si lo es
/// por diseño, si no `NoVerificable` → revisión manual—, nunca "vivo" ni
/// auto-enviable (directivas 21/30). El opt-in existe para el operador que sabe
/// que su alcance lo autoriza.
async fn evaluar_secretos(body: &str, secret_verify: bool) -> Option<Outcome> {
    let dets = crate::secretos::detectar(body);
    if dets.is_empty() {
        return None;
    }
    use crate::secretos::Veredicto;
    let mut vivos: Vec<&str> = Vec::new();
    let mut manuales: Vec<&str> = Vec::new();
    let mut publicables = 0usize;
    for d in &dets {
        // La confirmación VIVA (con red al proveedor) SOLO corre con el opt-in.
        // Apagada, el veredicto se calcula sin tocar a nadie: es puro.
        let ver = if secret_verify {
            crate::secretos::verificar(d).await
        } else if d.clase.publicable() {
            Veredicto::Publicable
        } else {
            Veredicto::NoVerificable
        };
        match ver {
            Veredicto::Vivo => vivos.push(d.clase.nombre()),
            Veredicto::NoVerificable => manuales.push(d.clase.nombre()),
            Veredicto::Publicable => publicables += 1,
            Veredicto::Muerto => {} // credencial rechazada: no es fuga aprovechable
        }
    }
    let base = |verified, confidence, exploitable, execution_confirmed, tool: &str, details: String, ev: Option<String>| Outcome {
        verified,
        confidence,
        tool: tool.into(),
        details,
        exploitable,
        execution_confirmed,
        error: ErrorType::None,
        evidence: ev,
        raw: None,
    };
    if !vivos.is_empty() {
        vivos.sort();
        vivos.dedup();
        return Some(base(true, Confidence::High, true, true, "secret-verify",
            format!("secreto VIVO confirmado por el proveedor: {}", vivos.join(", ")),
            Some(vivos.join(", "))));
    }
    if !manuales.is_empty() {
        manuales.sort();
        manuales.dedup();
        return Some(base(true, Confidence::Medium, true, false, "secret-detect",
            format!("secreto detectado, sin auto-verificación → revisión manual: {}", manuales.join(", ")),
            Some(manuales.join(", "))));
    }
    // Solo publicables y/o revocados: NO es fuga (cortamos el ruido, directiva 23).
    let motivo = if publicables > 0 {
        "solo claves publicables (públicas por diseño), no es fuga"
    } else {
        "credenciales detectadas pero revocadas/no vivas, no es fuga"
    };
    Some(base(false, Confidence::None, false, false, "secret-verify", motivo.into(), None))
}

/// content_check: GET en proceso y clasifica el cuerpo. Sin herramienta externa.
/// `secret_verify` propaga el opt-in de verificación viva a `evaluar_secretos`.
pub async fn content_check(url: &str, secret_verify: bool) -> Outcome {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(crate::evasion::UA_POOL[0])
        .build()
    {
        Ok(c) => c,
        Err(_) => return Outcome::manual(),
    };
    match client.get(url).send().await {
        Ok(resp) => {
            let code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Capa PRECISA primero (patrón + verificación viva); si no hay secreto
            // detectado, cae al clasificador de substrings débiles.
            let mut o = match evaluar_secretos(&body, secret_verify).await {
                Some(o) => o,
                None => classify_exposure(&body),
            };
            if code.as_u16() == 403 || code.as_u16() == 429 {
                o.error = ErrorType::WafBlocked; // señal de bloqueo para la evasión
            }
            o
        }
        Err(_) => {
            let mut o = Outcome::manual();
            o.error = ErrorType::NetworkError;
            o
        }
    }
}

/// Verifica UN hallazgo: clasifica, elige herramienta, la ejecuta como
/// subprocess y interpreta la salida. Cruza la frontera del programa.
pub async fn verify_one(
    cfg: &crate::config::Config,
    evasion: &crate::evasion::Evasion,
    vuln_name: &str,
    url: &str,
    strategy: &VerificationStrategy,
) -> Outcome {
    let vt = classify(vuln_name);
    let (path, mut args): (&str, Vec<String>) = match vt {
        VulnType::Sqli => (&cfg.sqlmap_path, sqlmap_cmd(url, strategy)),
        VulnType::Xss => (&cfg.xsstrike_path, xsstrike_cmd(url, strategy)),
        VulnType::Cmdi => (&cfg.commix_path, commix_cmd(url, strategy)),
        // V1: EXPOSURE se verifica en proceso (sin herramienta externa).
        VulnType::Exposure => {
            let o = content_check(url, cfg.secret_verify).await;
            feed_evasion(evasion, o.error);
            return o;
        }
        _ => return Outcome::manual(),
    };
    // Evasión (P1): proxy + delay adaptativo a las herramientas.
    if let Some(p) = evasion.proxy() {
        args.push("--proxy".into());
        args.push(p.to_string());
    }
    let d = evasion.extra_delay();
    if d > 0.0 && matches!(vt, VulnType::Sqli | VulnType::Cmdi) {
        args.push("--delay".into());
        args.push(format!("{:.0}", d.max(1.0)));
    }

    let timeout = std::time::Duration::from_secs(cfg.deep_timeout);
    match crate::tools::run(path, &args, timeout).await {
        Err(_) => Outcome::tool_missing(vt.tool().unwrap_or("?")),
        Ok(out) => {
            if out.timed_out {
                feed_evasion(evasion, ErrorType::Timeout);
                return Outcome::blocked(vt.tool().unwrap_or("?"), ErrorType::Timeout);
            }
            let combined = format!("{}{}", out.stdout, out.stderr);
            let mut outcome = match vt {
                VulnType::Sqli => interpret_sqlmap(&combined),
                VulnType::Xss => interpret_xss(&combined),
                VulnType::Cmdi => interpret_cmdi(&combined),
                _ => Outcome::manual(),
            };
            feed_evasion(evasion, outcome.error);
            // PUERTA DIFERENCIAL (arreglo de "confía en el stdout de sqlmap", método
            // adaptado de Shannon): una SQLi que sqlmap marca se corrobora por un oráculo
            // booleano independiente antes de darla por confirmada para auto-envío.
            if matches!(vt, VulnType::Sqli) && outcome.verified {
                let corrob = corroborar_sqli_diferencial(url).await;
                aplicar_corroboracion(&mut outcome, corrob);
            }
            // S6: guarda el PoC crudo (últimos ~2000 chars) para el reporte.
            // Antes de guardarlo, REDACTA cualquier credencial que nexus haya puesto
            // en los args y que la herramienta eco en su salida —hoy el `--proxy` con
            // `user:pass@` del .env del operador—, que si no viajaría al advisory
            // (medido 2026-10-18). El corte a 2000 se ajusta a un límite de char UTF-8
            // para no partir un multibyte si la salida de la herramienta trae no-ASCII
            // (el `combined[start..]` anterior podía panicar ahí).
            if outcome.verified {
                let limpio = crate::redaccion::redactar_args_sensibles(&combined, &args);
                let bruto = limpio.len().saturating_sub(2000);
                let start = (bruto..=limpio.len())
                    .find(|&i| limpio.is_char_boundary(i))
                    .unwrap_or(limpio.len());
                outcome.raw = Some(limpio[start..].to_string());
            }
            outcome
        }
    }
}

/// Resultado de la corroboración diferencial de una SQLi que sqlmap marcó.
enum CorrobSqli {
    /// El oráculo diferencial también la reprodujo (ratio, nivel de prueba).
    Confirmado(String, u8),
    /// El oráculo dio `Solido`: el booleano NO reproduce lo que sqlmap afirmó
    /// (posible falso positivo del escáner) → no auto-enviar.
    Contradice,
    /// No se pudo aplicar el diferencial (sin params de query, baseline caído…).
    /// No cambia el veredicto de sqlmap: el oráculo simplemente no opinó.
    NoAplica,
}

/// Aplica el resultado de la corroboración diferencial al veredicto de sqlmap. PURO: separa
/// la DECISIÓN (que un test puede reddenar) del sondeo por red de
/// `corroborar_sqli_diferencial`. Un `Contradice` DEGRADA —quita `execution_confirmed` y baja
/// a `Low`— para que un falso positivo del escáner NO alcance el auto-envío; `Confirmado`
/// solo anota; `NoAplica` no toca nada. Antes esta decisión vivía inline en `verify_one` y
/// ningún test la reddenaba (sin-caso-rojo `verify.rs:730`, 2026-09-24).
fn aplicar_corroboracion(outcome: &mut Outcome, corrob: CorrobSqli) {
    match corrob {
        CorrobSqli::Confirmado(ratio, nivel) => {
            outcome.details = format!(
                "{} · corroborado por oráculo diferencial booleano ({ratio}, nivel-prueba {nivel})",
                outcome.details
            );
        }
        CorrobSqli::Contradice => {
            // sqlmap dijo sí, el diferencial no reproduce → no se auto-envía.
            outcome.execution_confirmed = false;
            outcome.confidence = Confidence::Low;
            outcome.details = format!(
                "{} · ⚠ el oráculo diferencial booleano NO reprodujo la inyección \
                 (posible falso positivo de sqlmap): a revisión manual, sin auto-envío",
                outcome.details
            );
        }
        CorrobSqli::NoAplica => {}
    }
}

/// Corrobora una SQLi de sqlmap con el oráculo diferencial booleano
/// (`oraculo_inyeccion`), independiente del stdout de la herramienta. Reprueba la MISMA
/// URL (ya en scope: la engine la gateó antes de llamar aquí y sqlmap ya la tocó), un
/// parámetro de query a la vez, hasta que uno confirme. Modo por loopback (lab=whitebox).
async fn corroborar_sqli_diferencial(url: &str) -> CorrobSqli {
    use crate::oraculo_diferencial::{Modo, Objetivo};
    use crate::oraculo_inyeccion::{sonda_booleana, CasoInyeccion, Veredicto};

    let Ok(u) = reqwest::Url::parse(url) else { return CorrobSqli::NoAplica };
    let params: Vec<(String, String)> = u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    if params.is_empty() {
        return CorrobSqli::NoAplica; // inyección en cuerpo/ruta: el booleano de query no aplica
    }
    let host = u.host_str().unwrap_or("");
    let modo = if matches!(host, "127.0.0.1" | "localhost" | "::1") { Modo::Whitebox } else { Modo::Blackbox };
    let base = match u.origin().ascii_serialization() {
        s if !s.is_empty() && s != "null" => s,
        _ => return CorrobSqli::NoAplica,
    };
    let obj = Objetivo { base, modo };
    let cli = reqwest::Client::new();
    let mut vio_solido = false;
    for (k, v) in params {
        let caso = CasoInyeccion {
            descripcion: format!("corroboración diferencial SQLi en '{k}'"),
            clase: "sqli".into(),
            ruta: u.path().to_string(),
            param: k,
            valor_base: v,
            cabeceras: vec![],
        };
        match sonda_booleana(&cli, &obj, &caso, 3).await {
            Veredicto::Inyectable(cert, nivel) => {
                return CorrobSqli::Confirmado(cert.repro_ratio.unwrap_or_default(), nivel.nivel());
            }
            Veredicto::Solido => vio_solido = true,
            Veredicto::NoConcluyente(_) => {}
        }
    }
    if vio_solido { CorrobSqli::Contradice } else { CorrobSqli::NoAplica }
}

/// Realimenta el controlador de evasión: bloqueo→baja ritmo, limpio→relaja.
fn feed_evasion(evasion: &crate::evasion::Evasion, err: ErrorType) {
    match err {
        ErrorType::WafBlocked | ErrorType::RateLimited => evasion.note_block(),
        ErrorType::None => evasion.note_ok(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clasifica_por_patron() {
        assert_eq!(classify("SQL Injection detected"), VulnType::Sqli);
        assert_eq!(classify("reflected-xss"), VulnType::Xss);
        assert_eq!(classify("command-injection"), VulnType::Cmdi);
        assert_eq!(classify("algo raro"), VulnType::Other);
    }

    #[test]
    fn herramienta_por_tipo() {
        assert_eq!(VulnType::Sqli.tool(), Some("sqlmap"));
        assert_eq!(VulnType::Ssrf.tool(), None); // manual
    }

    #[test]
    fn diagnostico_y_reintentabilidad() {
        assert_eq!(diagnose_output("Read timed out"), ErrorType::Timeout);
        assert!(diagnose_output("Read timed out").is_retryable());
        assert_eq!(diagnose_output("401 Unauthorized"), ErrorType::AuthRequired);
        assert!(!diagnose_output("401 Unauthorized").is_retryable());
        assert_eq!(diagnose_output("Traceback (most recent call last)"), ErrorType::ToolCrash);
        assert!(!ErrorType::ToolCrash.is_retryable());
    }

    #[test]
    fn plan_de_reintento_discrimina() {
        // permanente: nunca reintenta
        assert_eq!(plan_retry(ErrorType::AuthRequired, 0, 3), None);
        // transitorio: reintenta con backoff creciente
        assert_eq!(plan_retry(ErrorType::Timeout, 0, 3), Some(60));
        assert_eq!(plan_retry(ErrorType::Timeout, 1, 3), Some(120));
        assert_eq!(plan_retry(ErrorType::Timeout, 2, 3), Some(240));
        // agotado
        assert_eq!(plan_retry(ErrorType::Timeout, 3, 3), None);
    }

    #[test]
    fn estrategia_se_adapta_al_waf() {
        let base = VerificationStrategy::default();
        let waf = base.adjusted_for(ErrorType::WafBlocked);
        assert!(!waf.tamper.is_empty());
        assert!(waf.delay >= 2.0);
        let to = base.adjusted_for(ErrorType::Timeout);
        assert_eq!(to.timeout, 240);
    }

    // Handlers de prueba para la PUERTA DIFERENCIAL: reflejan una SQLi booleana simulada
    // (vulnerable) y una parametrizada (segura). Parseo de query a mano (el axum
    // vendorizado no trae la feature `query`).
    fn id_crudo(uri: &axum::http::Uri) -> String {
        let raw = uri.query().unwrap_or("").split('&').find_map(|kv| kv.strip_prefix("id=")).unwrap_or("");
        let b = raw.as_bytes();
        let mut o = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let h = |c: u8| (c as char).to_digit(16);
                if let (Some(x), Some(y)) = (h(b[i + 1]), h(b[i + 2])) {
                    o.push((x * 16 + y) as u8);
                    i += 3;
                    continue;
                }
            }
            o.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
        String::from_utf8_lossy(&o).into_owned()
    }
    async fn vuln_h(uri: axum::http::Uri) -> String {
        let id = id_crudo(&uri);
        let hay = if id.contains("1=2") || id.contains("'1'='2") { false }
            else if id.contains("1=1") || id.contains("'1'='1") { true }
            else { id == "1" };
        if hay { format!("fila ana {}", "x".repeat(300)) } else { "sin resultados".into() }
    }
    async fn safe_h(uri: axum::http::Uri) -> String {
        if id_crudo(&uri) == "1" { format!("fila ana {}", "x".repeat(300)) } else { "sin resultados".into() }
    }
    async fn levantar_v(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let h = tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
        (base, h)
    }

    /// Construye un `Outcome` como el que sqlmap deja al marcar una SQLi VERIFIED y probada.
    fn outcome_sqlmap_confirmado() -> Outcome {
        Outcome {
            verified: true,
            confidence: Confidence::High,
            tool: "sqlmap".into(),
            details: "Type: boolean-based blind".into(),
            exploitable: true,
            execution_confirmed: true,
            error: ErrorType::None,
            evidence: None,
            raw: None,
        }
    }

    #[test]
    fn corroboracion_contradice_degrada_para_no_autoenviar() {
        // CASO ROJO del cableado (verify.rs:730): si el diferencial CONTRADICE lo que sqlmap
        // marcó, el hallazgo pierde `execution_confirmed` (el ÚNICO habilitador del auto-envío)
        // y baja a Low. Revertir esa degradación dejaría auto-enviar un falso positivo.
        let mut o = outcome_sqlmap_confirmado();
        aplicar_corroboracion(&mut o, CorrobSqli::Contradice);
        assert!(!o.execution_confirmed, "Contradice quita el habilitador del auto-envío");
        assert_eq!(o.confidence, Confidence::Low);
        assert!(o.details.contains("NO reprodujo"), "deja rastro auditable (D20)");
    }

    #[test]
    fn corroboracion_confirmado_anota_sin_degradar() {
        // PAREJA: un Confirmado NO degrada — solo anota. Sin este caso, un mutante que
        // degradara siempre pasaría el rojo de arriba.
        let mut o = outcome_sqlmap_confirmado();
        aplicar_corroboracion(&mut o, CorrobSqli::Confirmado("100%".into(), 2));
        assert!(o.execution_confirmed, "Confirmado mantiene el auto-envío");
        assert_eq!(o.confidence, Confidence::High);
        assert!(o.details.contains("corroborado"));
    }

    #[test]
    fn corroboracion_noaplica_no_cambia_el_veredicto() {
        let mut o = outcome_sqlmap_confirmado();
        let antes = format!("{o:?}");
        aplicar_corroboracion(&mut o, CorrobSqli::NoAplica);
        assert_eq!(format!("{o:?}"), antes, "NoAplica es no-op: no opina, no degrada");
    }

    #[tokio::test]
    async fn puerta_diferencial_corrobora_sqli_real() {
        let (base, _h) = levantar_v(axum::Router::new().route("/b", axum::routing::get(vuln_h))).await;
        let r = corroborar_sqli_diferencial(&format!("{base}/b?id=1")).await;
        assert!(matches!(r, CorrobSqli::Confirmado(_, 2)), "app vulnerable debe corroborar a nivel 2");
    }

    #[tokio::test]
    async fn puerta_diferencial_contradice_sqlmap_en_app_segura() {
        // El caso rojo del cableado: si sqlmap marcara SQLi aquí, la puerta lo contradice.
        let (base, _h) = levantar_v(axum::Router::new().route("/b", axum::routing::get(safe_h))).await;
        let r = corroborar_sqli_diferencial(&format!("{base}/b?id=1")).await;
        assert!(matches!(r, CorrobSqli::Contradice), "app segura debe contradecir un falso positivo");
    }

    #[test]
    fn sqlmap_discrimina_confirmado_falso_y_bloqueo() {
        let ok = interpret_sqlmap("Parameter 'id' is vulnerable. Type: UNION-based");
        assert!(ok.verified && ok.exploitable);
        assert_eq!(ok.confidence, Confidence::High);
        assert_eq!(ok.evidence.as_deref(), Some("UNION-based"));
        assert_eq!(ok.status(), "VERIFIED");

        // Sesión reanudada: sqlmap no dice "is vulnerable" sino el bloque de
        // inyección. Debe reconocerse como VERIFIED de alta confianza.
        let resumed = interpret_sqlmap(
            "resuming back-end DBMS 'microsoft sql server'\nParameter: id (GET)\n  Type: boolean-based blind\n  Type: stacked queries\nback-end DBMS: Microsoft SQL Server 2014",
        );
        assert!(resumed.verified && resumed.exploitable);
        assert_eq!(resumed.confidence, Confidence::High);
        assert_eq!(resumed.status(), "VERIFIED");

        let no = interpret_sqlmap("all tested parameters do not appear to be injectable");
        assert!(!no.verified);
        assert_eq!(no.status(), "FALSE_POSITIVE");

        let waf = interpret_sqlmap("403 Forbidden - WAF detected, request blocked");
        assert_eq!(waf.error, ErrorType::WafBlocked);
        assert_eq!(waf.status(), "RETRY_PENDING"); // reintentable, no falso positivo

        let meh = interpret_sqlmap("could not determine anything conclusive");
        assert!(meh.verified && meh.confidence == Confidence::Low);
        assert_eq!(meh.status(), "MANUAL_READY"); // low + verified → manual, no falso positivo
    }

    #[test]
    fn content_check_discrimina_secreto_login_y_nada() {
        // Substrings de exposición → señal DÉBIL: Medium, NO explotable →
        // MANUAL_READY. La confirmación de un secreto REAL la hace evaluar_secretos
        // (detectar+proveedor), no esta vía de fallback (cambio 2026-08-23, H1).
        let s = classify_exposure("app config: AKIA1234ABCD and aws_secret=xxxx");
        assert!(s.verified && !s.exploitable && s.confidence == Confidence::Medium);
        assert_eq!(s.status(), "MANUAL_READY");
        let w = classify_exposure("<form><input type=password></form>");
        assert!(w.verified && !w.exploitable);
        assert_eq!(w.status(), "MANUAL_READY"); // login benigno, no se auto-envía
        let n = classify_exposure("bienvenido a nuestra página");
        assert!(!n.verified);
        assert_eq!(n.status(), "MANUAL_READY");
    }

    #[test]
    fn exposicion_por_substring_nunca_es_auto_enviable() {
        // EL FP QUE HABÍA QUE CERRAR (H1, revisión 2026-08-23): un nombre de campo,
        // un placeholder o un comentario que contiene `api_key`/`secret_key` NO es
        // una fuga. Debe quedar NO explotable y NO alta confianza, para que jamás
        // llegue a execution_confirmed/auto-envío. Antes daba High+exploitable y P2
        // lo promovía por re-lectura determinista.
        for cuerpo in [
            r#"{"api_key":"REDACTED"}"#,
            "// TODO: pon aquí tu api_key",
            r#"{"secret_key": null, "public": true}"#,
            "const AWS_SECRET = process.env.AWS_SECRET; // placeholder",
        ] {
            let o = classify_exposure(cuerpo);
            assert!(!o.exploitable, "substring débil NO es explotable: {cuerpo}");
            assert_ne!(o.confidence, Confidence::High, "nunca alta confianza: {cuerpo}");
            assert!(!o.execution_confirmed, "nunca auto-confirmado: {cuerpo}");
            assert_eq!(o.status(), "MANUAL_READY", "va a revisión humana: {cuerpo}");
        }
    }

    #[tokio::test]
    async fn secretos_sin_opt_in_no_se_auto_confirman() {
        // sk_live detectado, verificación viva APAGADA (defecto): NUNCA se marca
        // execution_confirmed (que es lo único que habilita el auto-envío: db
        // `AND execution_confirmed = 1`), así que jamás llega solo a H1 → va a
        // revisión humana (MANUAL_READY).
        let body = format!("stripe key: sk_live_{}", "a".repeat(30));
        let o = evaluar_secretos(&body, false).await.expect("detecta el secreto");
        assert!(!o.execution_confirmed, "sin opt-in no hay confirmación viva");
        assert_eq!(o.status(), "MANUAL_READY", "va a revisión humana, no a VERIFIED");
        // PAREJA (directiva 33): un publicable se reconoce como NO-fuga aun sin
        // opt-in, porque es puro (no necesita red).
        let pub_body = format!("stripe pub: pk_live_{}", "b".repeat(30));
        let p = evaluar_secretos(&pub_body, false).await.expect("detecta");
        assert!(!p.verified, "publicable no es fuga");
    }
    // LÍMITE HONESTO de la prueba de arriba (directiva 33): NO demuestra que el
    // opt-in apagado no toque la red. Una clave FALSA nunca da `Vivo`, así que con
    // el gate on u off el resultado observable es el mismo (manual); la única
    // diferencia es el efecto de red, invisible a un test sin mock. Que la rama
    // `else` no haga I/O se garantiza por CONSTRUCCIÓN (no tiene `.await` de red) y
    // se ve leyendo `evaluar_secretos`, no ejecutándola. Un mock de proveedor que
    // devuelva `Vivo` cerraría el hueco; no se monta hoy (no hay abstracción de
    // cliente que inyectar, y añadirla es superficie que no paga aún).

    #[test]
    fn xss_y_cmdi_confirman_y_descartan() {
        // xsstrike es PISTA: su positivo NO marca explotable ni confirma ejecución;
        // queda como posible-XSS (MANUAL_READY) a la espera del gate de navegador.
        let pista = interpret_xss("Payload: <script>alert(1)</script>");
        assert!(!pista.exploitable, "xsstrike no marca explotable por sí solo");
        assert!(!pista.execution_confirmed, "sin navegador no hay ejecución confirmada");
        assert_eq!(pista.status(), "MANUAL_READY");
        // El negativo duro sí es fiable.
        assert_eq!(interpret_xss("No parameter found to test").status(), "FALSE_POSITIVE");
        // commix EJECUTA comandos → sí confirma ejecución.
        let ci = interpret_cmdi("The parameter is vulnerable to command injection");
        assert!(ci.exploitable && ci.execution_confirmed);
        assert_eq!(interpret_cmdi("not injectable").status(), "FALSE_POSITIVE");
    }

    #[test]
    fn sqlmap_confirmado_es_ejecucion_probada() {
        let ok = interpret_sqlmap("Parameter 'id' is vulnerable. Type: UNION-based");
        assert!(ok.exploitable && ok.execution_confirmed, "sqlmap explota, no adivina");
        // El no-concluyente NO confirma ejecución.
        assert!(!interpret_sqlmap("could not determine anything conclusive").execution_confirmed);
    }

    #[test]
    fn poda_informativos_y_su_pareja() {
        // Won't-fix por clase de plantilla.
        assert!(is_informational_class("x-backend-server-header-detect", "https://www.sidefx.com/en"));
        assert!(is_informational_class("http-missing-security-headers", "https://x.com"));
        assert!(is_informational_class("tls-sri-not-enforced", "https://x.com"));
        // Debug/RPC en host NO productivo (marcador en su ETIQUETA) → intencional.
        assert!(is_informational_class("blockchain-rpc-debug-exposure", "https://test.xlayer.okx.com"));
        assert!(is_informational_class("actuator-exposure", "https://api-staging.acme.com"));
        assert!(is_informational_class("swagger-ui-exposure", "https://qa.acme.com"));
        // El MISMO endpoint en producción SÍ pasa (no informativo).
        assert!(!is_informational_class("blockchain-rpc-debug-exposure", "https://rpc.okx.com"));
        // FALSO NEGATIVO cerrado (revisión 2026-08-23, Q5): el marcador por
        // SUBSTRING escondía debug/rpc REALES en producción. `latest` contiene
        // «test» y `quates` contiene «uat», pero son PROD → NO se podan.
        assert!(!is_informational_class("blockchain-rpc-debug-exposure", "https://latest.api.okx.com"),
            "`latest` no es testnet: un debug/rpc real en prod no se esconde");
        assert!(!is_informational_class("actuator-exposure", "https://quates.com"),
            "`quates` no es UAT");
        assert!(!is_informational_class("swagger-ui-exposure", "https://greatest-app.com"),
            "`greatest` no es testnet");
        // Vulnerabilidades reales nunca se podan.
        assert!(!is_informational_class("sqli-error-based", "https://x.com/a?id=1"));
        assert!(!is_informational_class("reflected-xss", "https://x.com/q?s=1"));
        assert!(!is_informational_class("CVE-2021-44228", "https://api.prod.com"));
        // El FALSO NEGATIVO que la pareja del prefijo ancho escondía: dns-rebinding
        // y email-*-takeover SON reales y NO deben podarse (antes `dns-`/`email-` los comían).
        assert!(!is_informational_class("dns-rebinding", "https://x.com"), "dns-rebinding es real");
        assert!(!is_informational_class("email-service-takeover", "https://x.com"), "un takeover es real");
        // Pero la higiene específica sí se poda.
        assert!(is_informational_class("spf-record-detect", "https://x.com"));
        assert!(is_informational_class("dmarc-detect", "https://x.com"));
    }

    #[test]
    fn poda_config_ruidosa_y_no_entierra_impacto() {
        // Las 4 clases que inundaban la cola manual —config TLS/cipher/SSH/GraphQL-
        // introspection— ahora son INFORMATIONAL. Son los `vuln_name` REALES del
        // queue medido el 2026-08-26.
        for n in [
            "tls-protocolo-1.0", "tls-protocolo-1.1", "tls-cifrado-3des",
            "ssh-weakkey-exchange-algo", "graphql-introspection-enabled",
        ] {
            assert!(is_informational_class(n, "https://prod.ejemplo.com/"),
                "{n} es config sin impacto → INFORMATIONAL, no cola manual");
        }
        // PAREJA (directiva 33): el desconocido y el impacto NO se podan — van a
        // manual. `hybris-consola-scripting-expuesta` es el RCE crítico que la
        // lista BLANCA enterraba (hallazgo de la revisión): la lista negra NO lo
        // esconde, porque no casa ninguna clase ruidosa conocida.
        for n in [
            "hybris-consola-scripting-expuesta", "hybris-hac-expuesta",
            "hybris-backoffice-expuesto", "hybris-consola-admin-login-alcanzable",
            "control-de-acceso-idor-horizontal", "unauthenticated-varnish-cache-purge",
            "CVE-2020-2096", "ssrf-metadata-aws", "reflected-xss", "subdomain-takeover",
            "ldap-injection", "unrestricted-file-upload", "una-clase-nunca-vista-2027",
        ] {
            assert!(!is_informational_class(n, "https://prod.ejemplo.com/"),
                "{n} no es config ruidosa: debe ir a MANUAL, no esconderse");
        }
    }

    #[test]
    fn todo_nombre_de_higiene_de_cabeceras_y_tls_es_informational() {
        // CANDADO (directiva 33): estos son los `vuln_name` que HOY emiten
        // `cabeceras.rs` y `tls.rs` (verificado contra el artefacto el 2026-08-23).
        // Cada uno DEBE caer en `is_informational_class`, o se colaría a la
        // plataforma como falso positivo (fueron 2 marcados HIGH). Con la lista
        // blanca, ninguno es clase accionable → todos caen a INFORMATIONAL por
        // defecto. El backstop en runtime es la poda P0 de `deepscan` (reclasifica
        // a INFORMATIONAL antes de gastar nada).
        for n in [
            "cookie-sin-httponly", "cookie-sin-samesite", "cookie-sin-secure",
            "header-clickjacking", "header-csp-missing", "header-referrer-missing",
            "header-xcto-missing", "tls-hsts-missing", "tls-no-https-redirect",
            "version-banner-expuesto",
        ] {
            assert!(is_informational_class(n, "https://prod.ejemplo.com/"),
                "{n} debe ser informativo (won't-fix), o se auto-enviaría como FP");
        }
        // PAREJA: una vuln real emitida por OTRO módulo NO se poda por estar cerca.
        assert!(!is_informational_class("subdomain-takeover", "https://prod.ejemplo.com/"));
        assert!(!is_informational_class("ssrf-metadata-aws", "https://prod.ejemplo.com/"));
    }

    #[test]
    fn claves_publicables_son_informational_pero_los_secretos_no() {
        // FP medido #16: el key_id/client-id es PÚBLICO por diseño.
        assert!(is_informational_class("razorpay-clientid-disclosure", "https://www.truecaller.com"));
        assert!(is_informational_class("stripe-publishable-key", "https://x.com"));
        assert!(is_informational_class("recaptcha-site-key-detect", "https://x.com"));
        assert!(is_informational_class("paypal-client-id-disclosure", "https://x.com"));
        // PAREJA (directiva 33): el SECRETO NO se esconde — es fuga real.
        assert!(!is_informational_class("razorpay-key-secret", "https://x.com"), "el key_secret SÍ es fuga");
        assert!(!is_informational_class("stripe-secret-key", "https://x.com"), "sk_live es fuga");
        assert!(!is_informational_class("aws-secret-key-disclosure", "https://x.com"));
        assert!(!is_informational_class("github-personal-access-token", "https://x.com"));
    }

    #[test]
    fn comandos_incluyen_las_palancas_anti_baneo() {
        let s = VerificationStrategy {
            tamper: vec!["space2comment".into()],
            delay: 3.0,
            ..Default::default()
        };
        let cmd = sqlmap_cmd("https://x/y?id=1", &s);
        assert!(cmd.iter().any(|a| a == "--random-agent"));
        assert!(cmd.iter().any(|a| a.starts_with("--tamper=")));
        assert!(cmd.iter().any(|a| a == "--delay"));
        assert!(commix_cmd("https://x", &s).iter().any(|a| a == "--random-agent"));
    }
}
