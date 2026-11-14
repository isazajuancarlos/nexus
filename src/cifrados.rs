// SPDX-License-Identifier: LicenseRef-Propietario
//! Enumeración EXHAUSTIVA de suites de cifrado vía `sslscan` (tiene pila TLS
//! propia que SÍ ofrece las suites viejas — el openssl del sistema las eliminó de
//! libssl, comprobado 2026-08-21). Herramienta externa apt-firmada, invocada en
//! runtime como nuclei: cero crates nuevos (respeta solo-local). Complementa a
//! `tls` (protocolo + certificado) con las suites DÉBILES que un servidor acepta.
//! Cada hallazgo → Ley 1581 Art. 4(g) (datos en tránsito). Parser CALIBRADO contra
//! sslscan 2.1.5 / badssl.com (null/rc4/3des) con control negativo (github).

use std::process::Stdio;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(60); // sslscan es lento (enumera todo)

/// Extrae, de la salida de sslscan, los nombres de suite ACEPTADOS con sus bits.
/// Líneas `Accepted|Preferred <proto> <N> bits <NOMBRE> [extra]`.
fn suites_aceptadas(salida: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for l in salida.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if !matches!(t.first(), Some(&"Accepted") | Some(&"Preferred")) {
            continue;
        }
        if let Some(i) = t.iter().position(|x| *x == "bits") {
            if i >= 1 {
                let bits = t.get(i - 1).and_then(|b| b.parse::<u32>().ok()).unwrap_or(0);
                if let Some(nombre) = t.get(i + 1) {
                    out.push((nombre.to_ascii_uppercase(), bits));
                }
            }
        }
    }
    out
}

/// Clasifica las suites aceptadas en categorías DÉBILES (una por categoría
/// presente). Es la IP: marcador de suite → obligación. Un catálogo limpio (todo
/// AES-GCM/CHACHA20) devuelve vacío. Directiva 33: discrimina, no marca lo fuerte.
pub fn categorias_debiles(salida: &str) -> Vec<(&'static str, &'static str, String)> {
    let suites = suites_aceptadas(salida);
    let algun = |f: &dyn Fn(&str, u32) -> bool| suites.iter().any(|(n, b)| f(n, *b));
    let es_3des = |n: &str| n.contains("3DES") || n.contains("DES_EDE") || n.contains("DES-CBC3");

    let mut out: Vec<(&'static str, &'static str, String)> = Vec::new();
    if algun(&|n, b| b == 0 || n.contains("NULL")) {
        out.push(("tls-cifrado-null", "critical",
            "el servidor acepta cifrado NULL (sin cifrado): los datos viajan en CLARO".into()));
    }
    if algun(&|n, _| n.contains("ADH") || n.contains("AECDH") || n.contains("ANON")) {
        out.push(("tls-cifrado-anonimo", "high",
            "acepta cifrado anónimo (sin autenticar al servidor): habilita MITM".into()));
    }
    if algun(&|n, _| n.contains("EXP")) {
        out.push(("tls-cifrado-export", "high",
            "acepta cifrado EXPORT (deliberadamente débil): descifrable".into()));
    }
    if algun(&|n, _| n.contains("RC4")) {
        out.push(("tls-cifrado-rc4", "high",
            "acepta RC4 (cifrado roto, sesgos explotables)".into()));
    }
    if algun(&|n, _| es_3des(n)) {
        out.push(("tls-cifrado-3des", "medium",
            "acepta 3DES (Sweet32, CVE-2016-2183)".into()));
    }
    if algun(&|n, _| n.contains("DES") && !es_3des(n)) {
        out.push(("tls-cifrado-des", "high",
            "acepta DES simple (clave de 56 bits, roto)".into()));
    }
    if algun(&|n, _| n.contains("MD5")) {
        out.push(("tls-cifrado-md5", "medium",
            "acepta suites con MAC MD5 (colisiones)".into()));
    }
    out
}

async fn correr_sslscan(host: &str) -> Option<String> {
    // `--` cierra las opciones: aunque `host` empezara por `-` (hoy imposible —
    // viene de host_of() sobre targets.txt filtrado por scope, y una etiqueta DNS
    // no puede empezar por `-`, RFC 1123), sslscan no lo interpretaría como flag.
    // Endurecimiento del sink (revisión 2026-08-23): el argumento no confía en que
    // el filtro de arriba nunca falle (directiva 23: la barandilla va en el sink).
    let fut = tokio::process::Command::new("sslscan")
        .args(["--no-colour", "--", host])
        .stdin(Stdio::null())
        .output();
    match tokio::time::timeout(TIMEOUT, fut).await {
        Ok(Ok(o)) => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        _ => None,
    }
}

/// La fase: por cada HOST vivo (deduplicado, acotado a `max`), corre sslscan y
/// persiste las categorías de cifrado débil que acepta. Lento (~30-40s/host) →
/// cap bajo + gate por deadline.
pub async fn fase_cifrados(
    pool: &sqlx::SqlitePool,
    program: &str,
    corpus: &[String],
    max: usize,
    deadline: Option<Instant>,
) -> crate::error::Result<u64> {
    let program_id = crate::db::upsert_program(pool, program).await?;
    let mut nuevas = 0u64;
    let mut hosts: Vec<String> = Vec::new();

    for url in corpus {
        if hosts.len() >= max {
            break;
        }
        if crate::autz::deadline_vencido(deadline) {
            tracing::info!("cifrados: presupuesto del ciclo agotado — paro ({nuevas} nuevos)");
            break;
        }
        let host = crate::scope::host_of(url);
        if host.is_empty() || hosts.contains(&host) {
            continue;
        }
        hosts.push(host.clone());

        let Some(salida) = correr_sslscan(&host).await else {
            continue;
        };
        let base = format!("https://{host}/");
        for (vuln_name, severity, detalle) in categorias_debiles(&salida) {
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: vuln_name.to_string(),
                severity: severity.to_string(),
                url: base.clone(),
                cwe: None,
                evidencia: Some(detalle),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                nuevas += 1;
            }
        }
    }
    Ok(nuevas)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures REALES capturados de sslscan 2.1.5 / badssl.com (2026-08-21).
    const NULL_HOST: &str = "\
Preferred TLSv1.2  0 bits    ECDHE-RSA-NULL-SHA            Curve P-256 DHE 256
Accepted  TLSv1.2  0 bits    AECDH-NULL-SHA               Curve P-256 DHE 256
Accepted  TLSv1.2  0 bits    NULL-SHA256
Accepted  TLSv1.2  256 bits  ADH-AES256-GCM-SHA384        DHE 1024 bits
";
    const RC4_HOST: &str = "\
Preferred TLSv1.2  128 bits  TLS_ECDHE_RSA_WITH_RC4_128_SHA
Preferred TLSv1.0  128 bits  TLS_RSA_WITH_RC4_128_SHA
";
    const TRESDES_HOST: &str = "\
Preferred TLSv1.2  112 bits  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
Accepted  TLSv1.1  112 bits  TLS_RSA_WITH_3DES_EDE_CBC_SHA
";
    // Control negativo: catálogo moderno y limpio (github).
    const LIMPIO: &str = "\
Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
";

    fn ids(salida: &str) -> Vec<&'static str> {
        categorias_debiles(salida).into_iter().map(|(n, _, _)| n).collect()
    }

    #[test]
    fn detecta_null_y_anonimo() {
        let r = ids(NULL_HOST);
        assert!(r.contains(&"tls-cifrado-null"), "NULL/0 bits");
        assert!(r.contains(&"tls-cifrado-anonimo"), "ADH/AECDH");
    }

    #[test]
    fn detecta_rc4_y_3des_por_separado() {
        assert_eq!(ids(RC4_HOST), vec!["tls-cifrado-rc4"]);
        assert_eq!(ids(TRESDES_HOST), vec!["tls-cifrado-3des"]);
        // 3DES NO se confunde con DES simple (comparten substring "DES")
        assert!(!ids(TRESDES_HOST).contains(&"tls-cifrado-des"));
    }

    // CONTROL (directiva 33): un catálogo moderno no marca NADA. Sin esto, un
    // detector que dijera "sí" a todo pasaría igual.
    #[test]
    fn catalogo_limpio_no_marca_nada() {
        assert!(categorias_debiles(LIMPIO).is_empty(), "AES-GCM/CHACHA20 no es débil");
    }

    #[test]
    fn lineas_no_cipher_se_ignoran() {
        let ruido = "TLSv1.0   enabled\nHeartbleed: not vulnerable\nSubject:  badssl.com\n";
        assert!(categorias_debiles(ruido).is_empty());
    }
}
