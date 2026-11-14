// SPDX-License-Identifier: LicenseRef-Propietario
//! Detección y VERIFICACIÓN VIVA de secretos (fase 0.1 del ROADMAP).
//!
//! El estado del arte 2026 (trufflehog `--only-verified`) y la lección de XBOW
//! —«usar algo distinto de un LLM para verificar»— convergen en lo mismo: no se
//! reporta un secreto por match de string, se reporta cuando se **confirma que la
//! credencial está VIVA ahora** con una llamada real al proveedor. Eso distingue
//! una `pk_live` de Stripe (publicable, pública por diseño) de una `sk_live`
//! viva, y arregla de raíz el FP de claves publicables (hoy resuelto con una lista
//! estática en `verify::is_informational_class`).
//!
//! La DETECCIÓN es pura y por PATRÓN (prefijo + charset + longitud), no por
//! substring suelto (`api_key` casa en cualquier doc/JS y era el FP de
//! `classify_exposure`). La VERIFICACIÓN solo se dispara sobre un candidato
//! detectado —rara vez—, así que el coste de red es acotado.

/// Clase de secreto detectada. `verificable()` = hay un endpoint del proveedor
/// para confirmar que está viva.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseSecreto {
    GithubToken,
    SlackToken,
    StripeSecret,
    StripePublicable,
    OpenAiKey,
    AwsAccessKeyId,
    GoogleApiKey,
    ClavePrivada,
}

impl ClaseSecreto {
    pub fn nombre(self) -> &'static str {
        match self {
            ClaseSecreto::GithubToken => "github-token",
            ClaseSecreto::SlackToken => "slack-token",
            ClaseSecreto::StripeSecret => "stripe-secret-key",
            ClaseSecreto::StripePublicable => "stripe-publishable-key",
            ClaseSecreto::OpenAiKey => "openai-key",
            ClaseSecreto::AwsAccessKeyId => "aws-access-key-id",
            ClaseSecreto::GoogleApiKey => "google-api-key",
            ClaseSecreto::ClavePrivada => "private-key",
        }
    }
    /// ¿Hay un handler que confirme si está VIVA?
    pub fn verificable(self) -> bool {
        matches!(
            self,
            ClaseSecreto::GithubToken
                | ClaseSecreto::SlackToken
                | ClaseSecreto::StripeSecret
                | ClaseSecreto::OpenAiKey
        )
    }
    /// ¿Es pública POR DISEÑO? (publicable/cliente: nunca es una fuga).
    pub fn publicable(self) -> bool {
        matches!(self, ClaseSecreto::StripePublicable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretoDetectado {
    pub clase: ClaseSecreto,
    pub valor: String,
}

fn es_base62(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// Extrae el run de `charset` que sigue a `prefijo` en `cuerpo` (todas las
/// apariciones), exigiendo longitud `[min,max]` tras el prefijo.
fn tras_prefijo(
    cuerpo: &str,
    prefijo: &str,
    charset: fn(char) -> bool,
    min: usize,
    max: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = cuerpo.as_bytes();
    let mut i = 0;
    while let Some(pos) = cuerpo[i..].find(prefijo) {
        let inicio = i + pos + prefijo.len();
        let mut j = inicio;
        // charset son predicados ASCII, así que el índice de byte coincide con el
        // límite de carácter y el slice es seguro.
        while j < bytes.len() && charset(bytes[j] as char) && j - inicio < max {
            j += 1;
        }
        if j - inicio >= min {
            out.push(format!("{prefijo}{}", &cuerpo[inicio..j]));
        }
        i = inicio.max(i + pos + 1);
    }
    out
}

/// Detecta secretos por PATRÓN (no substring). Puro y testable.
pub fn detectar(cuerpo: &str) -> Vec<SecretoDetectado> {
    let mut v = Vec::new();
    let mut add = |clase: ClaseSecreto, vals: Vec<String>| {
        for valor in vals {
            v.push(SecretoDetectado { clase, valor });
        }
    };
    // GitHub: ghp_/gho_/ghs_/ghu_/ghr_ + 36 base62; github_pat_ + largo.
    for p in ["ghp_", "gho_", "ghs_", "ghu_", "ghr_"] {
        add(ClaseSecreto::GithubToken, tras_prefijo(cuerpo, p, es_base62, 36, 36));
    }
    add(ClaseSecreto::GithubToken, tras_prefijo(cuerpo, "github_pat_", |c| es_base62(c) || c == '_', 40, 200));
    // Slack: xoxb-/xoxp-/xoxa-/xoxr-/xoxs- + token (dígitos, guiones, base62).
    for p in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
        add(ClaseSecreto::SlackToken, tras_prefijo(cuerpo, p, |c| es_base62(c) || c == '-', 10, 100));
    }
    // Stripe: sk_live_/sk_test_ = SECRETO; pk_live_/pk_test_ = PUBLICABLE.
    for p in ["sk_live_", "sk_test_"] {
        add(ClaseSecreto::StripeSecret, tras_prefijo(cuerpo, p, es_base62, 20, 99));
    }
    for p in ["pk_live_", "pk_test_"] {
        add(ClaseSecreto::StripePublicable, tras_prefijo(cuerpo, p, es_base62, 20, 99));
    }
    // OpenAI: sk-proj- o sk- + largo (exige longitud para no casar «sk-» suelto).
    add(ClaseSecreto::OpenAiKey, tras_prefijo(cuerpo, "sk-proj-", |c| es_base62(c) || c == '-' || c == '_', 40, 200));
    add(ClaseSecreto::OpenAiKey, tras_prefijo(cuerpo, "sk-", es_base62, 44, 60));
    // AWS Access Key ID: AKIA + 16 MAYÚSCULAS/dígitos (no verificable sin el secret).
    add(ClaseSecreto::AwsAccessKeyId, tras_prefijo(cuerpo, "AKIA", |c| c.is_ascii_uppercase() || c.is_ascii_digit(), 16, 16));
    // Google API key: AIza + 35 (ambigua: puede ser browser-key pública → manual).
    add(ClaseSecreto::GoogleApiKey, tras_prefijo(cuerpo, "AIza", |c| es_base62(c) || c == '-' || c == '_', 35, 35));
    // Clave privada PEM: BLOQUE real, no la mera presencia de dos substrings.
    add(ClaseSecreto::ClavePrivada, detectar_pem_privada(cuerpo));
    v
}

/// Detecta BLOQUES PEM de clave privada REALES en `cuerpo`. Discrimina un bloque con
/// cuerpo base64 (fuga) de (a) una función que SERIALIZA PEM —`function s(t){return
/// `-----BEGIN RSA PRIVATE KEY-----${t}…``}`—, y de (b) la mera presencia de
/// `-----BEGIN` (p.ej. de un CERTIFICATE) más las palabras "PRIVATE KEY" sueltas en
/// prosa. Devuelve el HEADER real de cada bloque (nunca el cuerpo de la clave).
fn detectar_pem_privada(cuerpo: &str) -> Vec<String> {
    const HDR_MAX: usize = 40; // "-----BEGIN ENCRYPTED PRIVATE KEY-----" cabe
    const CUERPO_MIN: usize = 100; // una clave real tiene cientos de chars base64
    const BLOQUE_MAX: usize = 20_000;
    const MARCA: &str = "-----BEGIN ";
    const FIN_HDR: &str = "PRIVATE KEY-----";
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = cuerpo[i..].find(MARCA) {
        let ini = i + rel;
        i = ini + MARCA.len(); // avanza SIEMPRE (sin este BEGIN no cualifica → no bucle infinito)
        // El header "-----BEGIN [TIPO ]PRIVATE KEY-----" debe cerrar en ventana corta.
        let ventana = &cuerpo[ini..(ini + HDR_MAX).min(cuerpo.len())];
        let Some(fin_hdr_rel) = ventana.find(FIN_HDR) else { continue };
        // Entre "-----BEGIN " y "PRIVATE KEY" solo el TIPO (letras/espacios): descarta
        // un "-----BEGIN CERTIFICATE…" lejano cuyo "PRIVATE KEY" vive en otra parte.
        let tipo = &cuerpo[ini + MARCA.len()..ini + fin_hdr_rel];
        if !tipo.chars().all(|c| c.is_ascii_uppercase() || c == ' ') {
            continue;
        }
        let fin_hdr = ini + fin_hdr_rel + FIN_HDR.len();
        // Debe cerrar con un "-----END" dentro de una ventana acotada.
        let resto = &cuerpo[fin_hdr..(fin_hdr + BLOQUE_MAX).min(cuerpo.len())];
        let Some(fin_rel) = resto.find("-----END") else { continue };
        let interior = &resto[..fin_rel];
        // Un template de serialización lleva `${`/concatenación; una clave real, no.
        if interior.contains("${") || interior.contains("`+") || interior.contains("\"+") {
            continue;
        }
        // Cuerpo base64 real (ignora separadores \n, \\n, comillas, espacios).
        let base64 = interior
            .chars()
            .filter(|c| es_base62(*c) || *c == '+' || *c == '/' || *c == '=')
            .count();
        if base64 < CUERPO_MIN {
            continue;
        }
        out.push(cuerpo[ini..fin_hdr].to_string()); // el HEADER real, nunca el cuerpo
    }
    out
}

/// Veredicto de verificación viva.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Veredicto {
    /// Confirmada VIVA por el proveedor (200/ok). Fuga real, reportable.
    Vivo,
    /// El proveedor la rechazó (401/revocada/inválida). No es fuga aprovechable.
    Muerto,
    /// Pública por diseño (publicable/cliente). Nunca es fuga.
    Publicable,
    /// Detectada pero sin handler de verificación (AWS id solo, PEM, Google): a
    /// revisión MANUAL, nunca auto-confirmada (directiva 30).
    NoVerificable,
}

/// Verifica un secreto llamando al proveedor. Solo se llama sobre candidatos
/// detectados. Falla al lado seguro: un error de red → `NoVerificable` (no se
/// inventa un «vivo»).
pub async fn verificar(s: &SecretoDetectado) -> Veredicto {
    if s.clase.publicable() {
        return Veredicto::Publicable;
    }
    if !s.clase.verificable() {
        return Veredicto::NoVerificable;
    }
    let cliente = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Veredicto::NoVerificable,
    };
    let resp = match s.clase {
        ClaseSecreto::GithubToken => {
            cliente
                .get("https://api.github.com/user")
                .header("Authorization", format!("token {}", s.valor))
                .header("User-Agent", "nexus-secret-verify")
                .send()
                .await
        }
        ClaseSecreto::OpenAiKey => {
            cliente
                .get("https://api.openai.com/v1/models")
                .header("Authorization", format!("Bearer {}", s.valor))
                .send()
                .await
        }
        ClaseSecreto::StripeSecret => {
            cliente
                .get("https://api.stripe.com/v1/account")
                .basic_auth(&s.valor, Some(""))
                .send()
                .await
        }
        ClaseSecreto::SlackToken => {
            cliente
                .post("https://slack.com/api/auth.test")
                .header("Authorization", format!("Bearer {}", s.valor))
                .send()
                .await
        }
        _ => return Veredicto::NoVerificable,
    };
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            // Slack responde 200 SIEMPRE; la verdad va en el JSON {"ok":bool}.
            if s.clase == ClaseSecreto::SlackToken {
                let txt = r.text().await.unwrap_or_default();
                if txt.contains("\"ok\":true") {
                    Veredicto::Vivo
                } else {
                    Veredicto::Muerto
                }
            } else if (200..300).contains(&status) {
                Veredicto::Vivo
            } else if status == 401 || status == 403 {
                Veredicto::Muerto
            } else {
                // 429/5xx/otros: no concluyente → no inventar vivo.
                Veredicto::NoVerificable
            }
        }
        Err(_) => Veredicto::NoVerificable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_secretos_reales_y_no_texto_benigno() {
        // Un token de GitHub con forma real se detecta.
        let ghp = format!("ghp_{}", "a".repeat(36));
        let d = detectar(&format!("token = {ghp}"));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].clase, ClaseSecreto::GithubToken);
        // PAREJA: el substring benigno «api_key» ya NO dispara nada (era el FP).
        assert!(detectar("const api_key = config.get('apikey');").is_empty());
        assert!(detectar("please set your API_KEY in the env").is_empty());
    }

    #[test]
    fn distingue_publicable_de_secreto_stripe() {
        let sk = format!("sk_live_{}", "b".repeat(30));
        let pk = format!("pk_live_{}", "c".repeat(30));
        let d = detectar(&format!("{sk} y {pk}"));
        let clases: Vec<_> = d.iter().map(|x| x.clase).collect();
        assert!(clases.contains(&ClaseSecreto::StripeSecret));
        assert!(clases.contains(&ClaseSecreto::StripePublicable));
        // El secreto es verificable; el publicable NUNCA es fuga.
        assert!(ClaseSecreto::StripeSecret.verificable());
        assert!(ClaseSecreto::StripePublicable.publicable());
        assert!(!ClaseSecreto::StripePublicable.verificable());
    }

    #[test]
    fn aws_id_y_pem_se_detectan_pero_no_son_verificables() {
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
            "A".repeat(200)
        );
        let d = detectar(&format!("AKIA{} …\n{pem}", "ABCDEF1234567890"));
        let clases: Vec<_> = d.iter().map(|x| x.clase).collect();
        assert!(clases.contains(&ClaseSecreto::AwsAccessKeyId));
        assert!(clases.contains(&ClaseSecreto::ClavePrivada));
        assert!(!ClaseSecreto::AwsAccessKeyId.verificable(), "AKIA solo → manual, no auto-verificable");
        assert!(!ClaseSecreto::ClavePrivada.verificable());
    }

    #[test]
    fn pem_privada_bloque_real_si_template_y_substrings_sueltos_no() {
        let cuerpo = "A".repeat(200); // base64 válido, largo de clave real
        // ROJO: bloque PEM real con cuerpo base64 → fuga, y reporta el header REAL.
        let real = format!("-----BEGIN EC PRIVATE KEY-----\n{cuerpo}\n-----END EC PRIVATE KEY-----");
        let priv_de = |s: &str| {
            detectar(s).into_iter().find(|x| x.clase == ClaseSecreto::ClavePrivada)
        };
        let hit = priv_de(&real).expect("un bloque PEM real debe marcar");
        assert!(hit.valor.contains("EC PRIVATE KEY"), "reporta el header real, no una constante");

        // VERDE (FP viejo #1): función que SERIALIZA PEM (template `${{t}}`), como
        // app.files.com. El viejo `contains && contains` marcaba; ahora NO.
        let template = "function s(t){return`-----BEGIN RSA PRIVATE KEY-----${t}-----END RSA PRIVATE KEY-----`}";
        assert!(priv_de(template).is_none(), "una función de formato PEM NO es fuga");

        // VERDE (FP viejo #2): bloque PÚBLICO + "PRIVATE KEY" suelto en prosa. El viejo
        // marcaba por presencia de dos substrings cualesquiera; ahora NO.
        let pub_prosa = format!("-----BEGIN PUBLIC KEY-----\n{cuerpo}\n-----END PUBLIC KEY-----\n// genera tu PRIVATE KEY");
        assert!(priv_de(&pub_prosa).is_none(), "público + prosa 'PRIVATE KEY' NO es fuga");
    }

    #[tokio::test]
    async fn publicable_no_se_verifica_como_vivo() {
        // No toca la red: un publicable corta antes de cualquier request.
        let s = SecretoDetectado { clase: ClaseSecreto::StripePublicable, valor: "pk_live_x".into() };
        assert_eq!(verificar(&s).await, Veredicto::Publicable);
        // Un AWS id solo tampoco pega a la red (no verificable).
        let a = SecretoDetectado { clase: ClaseSecreto::AwsAccessKeyId, valor: "AKIA…".into() };
        assert_eq!(verificar(&a).await, Veredicto::NoVerificable);
    }
}
