// SPDX-License-Identifier: LicenseRef-Propietario
//! Add-on TLS PROFUNDO: protocolos obsoletos (TLS 1.0/1.1) y validez del
//! certificado (vencido, autofirmado, cadena rota, por vencer).
//!
//! Invoca el `openssl` del SISTEMA (ya instalado, apt-firmado) en RUNTIME — NO se
//! linka libssl en el binario: sigue rustls puro. La regla "NUNCA openssl" es
//! sobre el LINK (portabilidad), no sobre el CLI, igual que nexus ya invoca nuclei.
//! Es el ÚNICO camino que detecta TLS 1.0/1.1: rustls se niega a hablarlos por
//! diseño, así que un cliente rustls no puede probar el hallazgo. **Cero crates
//! nuevos** (respeta el protocolo solo-local: no añade superficie de cadena de
//! suministro al build). Cada hallazgo aterriza en Ley 1581 Art. 4(g) — datos en
//! tránsito. Parsers CALIBRADOS contra openssl 3.5 / badssl.com (2026-08-21).

use std::process::Stdio;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(15);

/// ¿El handshake tuvo éxito? Calibrado contra openssl 3.5: éxito imprime
/// "Cipher is <real>"; el rechazo imprime "Cipher is (NONE)". Discrimina limpio.
pub fn handshake_exitoso(salida: &str) -> bool {
    salida.contains("Cipher is ") && !salida.contains("Cipher is (NONE)")
}

/// Extrae "Verify return code: N" de la salida de s_client. None si no aparece.
pub fn codigo_verificacion(salida: &str) -> Option<i64> {
    salida.lines().find_map(|l| {
        l.trim()
            .strip_prefix("Verify return code:")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    })
}

/// Traduce el código de verificación de openssl a un hallazgo. 0 = ok (None).
/// Directiva 20: un código != 0 desconocido NO se asume ok — se reporta inválido.
pub fn diagnostico_cert(codigo: i64) -> Option<(&'static str, &'static str, String)> {
    match codigo {
        0 => None,
        10 => Some((
            "tls-certificado-vencido",
            "high",
            "el certificado del servidor está VENCIDO (openssl verify 10)".into(),
        )),
        18..=19 => Some((
            "tls-certificado-autofirmado",
            "medium",
            "certificado autofirmado, no emitido por una CA de confianza (openssl verify 18/19)".into(),
        )),
        20..=22 => Some((
            "tls-certificado-cadena-rota",
            "medium",
            format!("la cadena del certificado no verifica (openssl verify {codigo})"),
        )),
        c => Some((
            "tls-certificado-invalido",
            "medium",
            format!("el certificado no verifica (openssl verify {c})"),
        )),
    }
}

/// Extrae el primer bloque PEM de certificado de la salida de s_client.
pub fn extraer_pem(salida: &str) -> Option<String> {
    const FIN: &str = "-----END CERTIFICATE-----";
    let ini = salida.find("-----BEGIN CERTIFICATE-----")?;
    let fin = salida.find(FIN)?;
    Some(salida[ini..fin + FIN.len()].to_string())
}

fn combinar(o: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    s
}

/// Corre `openssl s_client` con timeout y stdin cerrado. None si no se pudo
/// ejecutar o venció (inconcluso: NO se confunde "no probado" con "no aceptado").
async fn s_client(args: &[&str]) -> Option<String> {
    let fut = tokio::process::Command::new("openssl")
        .arg("s_client")
        .args(args)
        .stdin(Stdio::null())
        .output();
    match tokio::time::timeout(TIMEOUT, fut).await {
        Ok(Ok(o)) => Some(combinar(&o)),
        _ => None,
    }
}

/// ¿El servidor acepta ese protocolo? None si el probe no pudo correr.
async fn acepta_protocolo(host: &str, flag: &str) -> Option<bool> {
    let conn = format!("{host}:443");
    let salida = s_client(&["-connect", &conn, "-servername", host, flag, "-cipher", "ALL:@SECLEVEL=0"]).await?;
    Some(handshake_exitoso(&salida))
}

/// ¿El cert (PEM) expira en menos de 30 días? `openssl x509 -checkend`: exit 0 =
/// válido más de 30d; exit != 0 = expira dentro de 30d (o ya venció).
async fn por_vencer(pem: &str) -> bool {
    use tokio::io::AsyncWriteExt;
    let segundos = (30 * 24 * 3600).to_string();
    let mut child = match tokio::process::Command::new("openssl")
        .args(["x509", "-checkend", &segundos, "-noout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(pem.as_bytes()).await;
    } // si se cierra aquí (EOF)
    match tokio::time::timeout(TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => !status.success(),
        _ => false,
    }
}

/// La fase: por cada HOST vivo (deduplicado, acotado), prueba TLS 1.0/1.1 y la
/// validez del certificado con `openssl`. Persiste hallazgos con evidencia.
pub async fn fase_tls(
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
            tracing::info!("tls: presupuesto del ciclo agotado — paro ({nuevas} nuevos)");
            break;
        }
        let host = crate::scope::host_of(url);
        if host.is_empty() || hosts.contains(&host) {
            continue;
        }
        hosts.push(host.clone());

        let base = format!("https://{host}/");
        let mut hallazgos: Vec<(&'static str, &'static str, String)> = Vec::new();

        if acepta_protocolo(&host, "-tls1").await == Some(true) {
            hallazgos.push((
                "tls-protocolo-1.0",
                "high",
                format!("{host} acepta TLS 1.0 (obsoleto, prohibido por PCI-DSS; expone datos en tránsito a MITM/downgrade)"),
            ));
        }
        if acepta_protocolo(&host, "-tls1_1").await == Some(true) {
            hallazgos.push((
                "tls-protocolo-1.1",
                "medium",
                format!("{host} acepta TLS 1.1 (obsoleto)"),
            ));
        }

        let conn = format!("{host}:443");
        if let Some(salida) = s_client(&["-connect", &conn, "-servername", &host]).await {
            if let Some(cod) = codigo_verificacion(&salida) {
                if let Some((n, sev, det)) = diagnostico_cert(cod) {
                    hallazgos.push((n, sev, det));
                }
                if cod == 0 {
                    if let Some(pem) = extraer_pem(&salida) {
                        if por_vencer(&pem).await {
                            hallazgos.push((
                                "tls-certificado-por-vencer",
                                "medium",
                                format!("el certificado de {host} expira en menos de 30 días"),
                            ));
                        }
                    }
                }
            }
        }

        for (vuln_name, severity, detalle) in hallazgos {
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

    // Muestras REALES capturadas de openssl 3.5 contra badssl.com (2026-08-21).
    const EXITO: &str = "verify return:1\n-----BEGIN CERTIFICATE-----\nMIIF\n-----END CERTIFICATE-----\nNew, TLSv1.0, Cipher is ECDHE-RSA-AES256-SHA\n    Verify return code: 0 (ok)\n";
    const FALLO: &str = "write:errno=104\nNew, (NONE), Cipher is (NONE)\n";
    const VENCIDO: &str = "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\n    Verify return code: 10 (certificate has expired)\n";

    #[test]
    fn handshake_discrimina_exito_de_fallo() {
        assert!(handshake_exitoso(EXITO), "cipher real = handshake OK");
        assert!(!handshake_exitoso(FALLO), "Cipher is (NONE) = rechazo");
        // sin ninguna línea de cipher (probe no corrió) → no se asume aceptado
        assert!(!handshake_exitoso("errno=111 connection refused"));
    }

    #[test]
    fn codigo_verificacion_parsea() {
        assert_eq!(codigo_verificacion(EXITO), Some(0));
        assert_eq!(codigo_verificacion(VENCIDO), Some(10));
        assert_eq!(codigo_verificacion(FALLO), None);
    }

    #[test]
    fn diagnostico_cert_discrimina_y_no_asume_ok() {
        assert!(diagnostico_cert(0).is_none(), "0 = ok, sin hallazgo");
        assert_eq!(diagnostico_cert(10).unwrap().0, "tls-certificado-vencido");
        assert_eq!(diagnostico_cert(18).unwrap().0, "tls-certificado-autofirmado");
        // código raro != 0 → inválido genérico, NO se asume ok (directiva 20)
        assert_eq!(diagnostico_cert(77).unwrap().0, "tls-certificado-invalido");
    }

    #[test]
    fn extraer_pem_saca_el_bloque() {
        let pem = extraer_pem(EXITO).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
        assert!(extraer_pem(FALLO).is_none());
    }
}
