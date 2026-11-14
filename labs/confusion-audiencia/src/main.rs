//! Lab de discriminación — **oráculo de confusión de audiencia** (token
//! sobre-privilegiado / audience confusion, CWE-269/CWE-863).
//!
//! Deriva del caso Hacktron→OpenAI (18-sep-2026): el token de "Sign in with
//! OpenAI" del FORO llevaba scope de API core; con RCE lo reusaron contra ChatGPT/
//! Codex/GitHub porque los endpoints internos NO validaban la audiencia del token.
//!
//! INVARIANTE (la del razonador): *un token emitido para un relying-party de baja
//! confianza NO debe ser aceptado por una audiencia de mayor confianza.*
//!
//! Levanta una API "core" REAL sobre HTTP en dos modos y corre el ORÁCULO
//! DIFERENCIAL sobre cada uno. Único propósito: probar que el oráculo DISCRIMINA
//! (directiva 33) — el MISMO oráculo debe salir `Confirmado` contra el modo
//! Vulnerable y `Limpio` contra el Seguro. Si no los distingue, es ciego.
//!
//! Corre por el socket (directiva 28): HS256 real, verificación real y peticiones
//! HTTP reales — no de estructura a estructura.

use axum::{extract::State, http::HeaderMap, http::StatusCode, routing::get, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

const SECRETO: &[u8] = b"lab-idp-clave-compartida-solo-para-el-banco";
const AUD_CORE: &str = "api-core";
const AUD_FORO: &str = "foro-comunidad";

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: String,
    scope: String,
    exp: u64,
}

/// HMAC-SHA256 (RFC 2104) a mano sobre `sha2` — el crate `hmac` vendorizado choca
/// con la versión de `sha2` (mismo apaño que `nexus/src/autenticacion.rs`, D9).
fn hmac_sha256(clave: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut k = [0u8; 64];
    if clave.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(clave));
    } else {
        k[..clave.len()].copy_from_slice(clave);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = Sha256::new().chain_update(&ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(&opad).chain_update(inner).finalize().into()
}

fn firma(input: &str) -> String {
    B64.encode(hmac_sha256(SECRETO, input.as_bytes()))
}

/// Mint HS256 (header.payload.firma), aud y scope a gusto.
fn mint(aud: &str, scope: &str) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let header = B64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = Claims { sub: "empleado".into(), aud: aud.into(), scope: scope.into(), exp };
    let payload = B64.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{header}.{payload}");
    let f = firma(&input);
    format!("{input}.{f}")
}

/// Verifica firma y expiración. Si `aud_exigida` es Some, exige que coincida
/// (la DEFENSA). Devuelve los claims si el token es válido según esa política.
fn verifica(token: &str, aud_exigida: Option<&str>) -> Option<Claims> {
    let p: Vec<&str> = token.split('.').collect();
    if p.len() != 3 {
        return None;
    }
    // recomputa la firma sobre header.payload y compara con la del token
    let sig = B64.decode(p[2]).ok()?;
    let esperada = hmac_sha256(SECRETO, format!("{}.{}", p[0], p[1]).as_bytes());
    if sig.len() != 32 || sig[..] != esperada[..] {
        return None;
    }
    let claims: Claims = serde_json::from_slice(&B64.decode(p[1]).ok()?).ok()?;
    let ahora = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    if claims.exp < ahora {
        return None;
    }
    if let Some(a) = aud_exigida {
        if claims.aud != a {
            return None; // audiencia equivocada → rechazo (la defensa)
        }
    }
    Some(claims)
}

#[derive(Clone, Copy, PartialEq)]
enum Modo {
    /// Verifica firma pero NO la audiencia → acepta token de cualquier RP (el bug).
    Vulnerable,
    /// Verifica firma Y exige `aud == api-core` (la defensa correcta).
    Seguro,
}

async fn core_data(State(modo): State<Modo>, headers: HeaderMap) -> (StatusCode, &'static str) {
    let tok = match headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None => return (StatusCode::UNAUTHORIZED, "sin token"),
    };
    let aud_exigida = match modo {
        Modo::Seguro => Some(AUD_CORE),
        Modo::Vulnerable => None,
    };
    match verifica(&tok, aud_exigida) {
        Some(_) => (StatusCode::OK, "{\"secreto\":\"datos internos de la API core\"}"),
        None => (StatusCode::UNAUTHORIZED, "token rechazado"),
    }
}

async fn arranca(modo: Modo) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route("/api/core/data", get(core_data)).with_state(modo);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, h)
}

// --- oráculo diferencial (cliente HTTP crudo; localhost, sin dep de cliente) ----

#[derive(Debug, PartialEq)]
enum Veredicto {
    Confirmado,          // token de foro aceptado por la audiencia core → BUG
    Limpio,              // token de foro rechazado, controles OK → limpio
    NoConcluyente(String),
}

fn get_status(addr: SocketAddr, token: Option<&str>) -> u16 {
    let mut s = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = format!("GET /api/core/data HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{auth}\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return 0;
    }
    let mut buf = String::new();
    if s.read_to_string(&mut buf).is_err() {
        return 0;
    }
    // "HTTP/1.1 200 OK" → 200
    buf.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// Sondas: AGUJA = token `aud=foro` contra la API core; CONTROL+ = token
/// `aud=core` correcto (DEBE dar 200: el endpoint vive); CONTROL− = firma inválida
/// (DEBE dar 401: la verificación corre). Sin ambos controles no hay veredicto
/// (directivas 30 y 33).
fn oraculo(addr: SocketAddr) -> Veredicto {
    let aguja = mint(AUD_FORO, "leer:foro");
    let control_pos = mint(AUD_CORE, "leer:core");
    let control_neg = {
        let t = mint(AUD_CORE, "leer:core");
        let mut p: Vec<&str> = t.split('.').collect();
        p[2] = "AAAAAAAAAAAAAAAAAAAAAAAA"; // firma corrupta
        p.join(".")
    };

    let s_pos = get_status(addr, Some(&control_pos));
    if s_pos != 200 {
        return Veredicto::NoConcluyente(format!("control+ = {s_pos}, esperaba 200 (endpoint muerto)"));
    }
    let s_neg = get_status(addr, Some(&control_neg));
    if s_neg != 401 {
        return Veredicto::NoConcluyente(format!("control- = {s_neg}, esperaba 401 (verificación no corre)"));
    }

    match get_status(addr, Some(&aguja)) {
        200 => Veredicto::Confirmado,
        401 | 403 => Veredicto::Limpio,
        otro => Veredicto::NoConcluyente(format!("aguja = {otro}")),
    }
}

fn corre(modo: Modo) -> Veredicto {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (addr, h) = arranca(modo).await;
        // pequeña espera a que el listener acepte
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let v = tokio::task::spawn_blocking(move || oraculo(addr)).await.unwrap();
        h.abort();
        v
    })
}

fn main() {
    let casos = [
        (Modo::Vulnerable, "VULNERABLE (no valida aud)", Veredicto::Confirmado),
        (Modo::Seguro, "SEGURO (exige aud=core)", Veredicto::Limpio),
    ];
    println!("=== Lab confusión de audiencia — discriminación del oráculo ===");
    let mut ok = true;
    for (modo, etiqueta, esperado) in casos {
        let v = corre(modo);
        let bien = v == esperado;
        ok &= bien;
        println!("  {etiqueta:32}  oráculo→ {v:?}   esperado {esperado:?}   {}", if bien { "✓" } else { "✗" });
    }
    if ok {
        println!("\nDISCRIMINA ✓ — el oráculo distingue vulnerable de seguro por EJECUCIÓN.");
    } else {
        println!("\nNO DISCRIMINA ✗ — el oráculo es ciego; no cuenta como hallazgo.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn vulnerable_da_confirmado() {
        assert_eq!(corre(Modo::Vulnerable), Veredicto::Confirmado);
    }

    #[test]
    fn seguro_da_limpio() {
        assert_eq!(corre(Modo::Seguro), Veredicto::Limpio);
    }
}
