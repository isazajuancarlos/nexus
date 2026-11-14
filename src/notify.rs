// SPDX-License-Identifier: LicenseRef-Propietario
//! Notificación de hallazgos por webhook (Slack / Discord / genérico).
//!
//! Brecha cerrada el 2026-08-21: nexus corría un ciclo autónomo cada 2 h y NO
//! avisaba de nada —había que mirar la BD o el informe a mano—. La columna
//! `notified` existía desde el principio pero se insertaba siempre en `1` y nadie
//! la consumía: era el gancho vestigial para justo esto. Ahora los hallazgos
//! nacen `notified=0` y este módulo, al cierre de cada ciclo, envía los
//! VERIFIED/MANUAL_READY sin notificar y los marca.
//!
//! **Falla suave** (directiva 20): sin webhook configurado es un no-op silencioso
//! (el comportamiento por defecto no cambia); si el webhook falla, se avisa en el
//! log y el ciclo sigue —una notificación caída no puede tumbar la caza—.
//! **No envía vacío**: si no hay nada que reportar, no toca la red (directiva 20:
//! silencio real, no un webhook con cero hallazgos).

use sqlx::SqlitePool;

/// Un hallazgo reducido a lo que va en la notificación.
pub struct HallazgoBreve {
    pub severity: String,
    pub vuln_type: String,
    pub url: String,
    pub program_name: String,
}

/// Evento notificable. Generalizado (fase 2.0) para que las capacidades de recon
/// —superficie nueva (ASM, 2.2), takeover (2.3)— no le añadan cada una su propio
/// caso a mano al formateador de hallazgos.
pub enum Evento {
    /// Hallazgos VERIFIED/MANUAL_READY nuevos.
    Hallazgos(Vec<HallazgoBreve>),
    /// Superficie NUEVA descubierta desde la última corrida (ASM diffing).
    SuperficieNueva { programa: String, assets: Vec<String> },
    /// Posible subdomain takeover: host colgado sobre un servicio reclamable.
    Takeover { programa: String, host: String, servicio: String },
}

fn rango_severidad(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// Máximo de líneas de detalle en el mensaje; el resto se resume en «… y N más».
const MAX_LINEAS: usize = 15;

/// Construye el mensaje. Devuelve `None` si no hay nada que reportar (para NO
/// enviar un webhook vacío). Ordena por severidad (critical→low) para que lo
/// urgente vaya arriba, y trunca a `MAX_LINEAS` con un resumen del resto.
pub fn construir_mensaje(nuevos: &[HallazgoBreve]) -> Option<String> {
    if nuevos.is_empty() {
        return None;
    }
    let mut v: Vec<&HallazgoBreve> = nuevos.iter().collect();
    v.sort_by_key(|h| rango_severidad(&h.severity));
    let total = v.len();
    let lineas: Vec<String> = v
        .iter()
        .take(MAX_LINEAS)
        .map(|h| {
            format!(
                "• [{}] {} — {} ({})",
                h.severity.to_uppercase(),
                h.vuln_type,
                h.url,
                h.program_name
            )
        })
        .collect();
    let extra = if total > MAX_LINEAS {
        format!("\n… y {} más", total - MAX_LINEAS)
    } else {
        String::new()
    };
    Some(format!(
        "🔔 nexus: {total} hallazgo(s) nuevo(s) (verificados / para revisión)\n{}{}",
        lineas.join("\n"),
        extra
    ))
}

/// Construye el mensaje de un evento cualquiera. `None` = nada que reportar (no
/// se envía webhook vacío). Reutiliza `construir_mensaje` para los hallazgos.
pub fn construir_mensaje_evento(e: &Evento) -> Option<String> {
    match e {
        Evento::Hallazgos(v) => construir_mensaje(v),
        Evento::SuperficieNueva { programa, assets } => {
            if assets.is_empty() {
                return None;
            }
            let total = assets.len();
            let lineas: Vec<String> = assets.iter().take(MAX_LINEAS).map(|a| format!("• {a}")).collect();
            let extra = if total > MAX_LINEAS {
                format!("\n… y {} más", total - MAX_LINEAS)
            } else {
                String::new()
            };
            Some(format!(
                "🛰️ nexus [{programa}]: {total} asset(s) NUEVO(s) en la superficie\n{}{}",
                lineas.join("\n"),
                extra
            ))
        }
        Evento::Takeover { programa, host, servicio } => Some(format!(
            "⚠️ nexus [{programa}]: posible SUBDOMAIN TAKEOVER — {host} (servicio: {servicio})"
        )),
    }
}

/// Notifica UN evento (no-op silencioso sin webhook o sin contenido). Devuelve 1
/// si envió, 0 si no. La puerta genérica para ASM/takeover.
pub async fn notificar(webhook: Option<&str>, evento: &Evento) -> anyhow::Result<usize> {
    let Some(hook) = webhook else {
        return Ok(0);
    };
    let Some(msg) = construir_mensaje_evento(evento) else {
        return Ok(0);
    };
    enviar(hook, &msg)
        .await
        .map_err(|e| anyhow::anyhow!("webhook: {e}"))?;
    Ok(1)
}

/// Envía el mensaje al webhook. Payload `{"text": …}`: el formato que aceptan
/// Slack, Discord y la mayoría de receptores genéricos. Timeout corto para no
/// colgar el cierre del ciclo si el receptor no responde.
pub async fn enviar(webhook: &str, mensaje: &str) -> reqwest::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    client
        .post(webhook)
        .json(&serde_json::json!({ "text": mensaje }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Notifica los hallazgos VERIFIED/MANUAL_READY sin notificar y los marca.
/// No-op silencioso si no hay `webhook` o no hay nada pendiente. Devuelve cuántos
/// se notificaron.
pub async fn notificar_pendientes(
    pool: &SqlitePool,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    let Some(hook) = webhook else {
        return Ok(0);
    };
    let nuevos = crate::db::hallazgos_sin_notificar(pool).await?;
    let Some(msg) = construir_mensaje(&nuevos) else {
        return Ok(0);
    };
    enviar(hook, &msg)
        .await
        .map_err(|e| anyhow::anyhow!("webhook: {e}"))?;
    // Solo se marcan DESPUÉS de un envío exitoso: si el webhook falla, quedan
    // pendientes para el próximo ciclo (directiva 20: no perder el aviso en
    // silencio).
    let marcados = crate::db::marcar_notificados(pool).await?;
    Ok(marcados as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(sev: &str, url: &str) -> HallazgoBreve {
        HallazgoBreve {
            severity: sev.into(),
            vuln_type: "idor".into(),
            url: url.into(),
            program_name: "acme".into(),
        }
    }

    #[test]
    fn vacio_no_produce_mensaje() {
        // Pareja del caso lleno: sin hallazgos NO se arma mensaje → no se envía.
        assert!(construir_mensaje(&[]).is_none());
    }

    #[test]
    fn lleno_arma_mensaje_con_conteo_y_url() {
        let msg = construir_mensaje(&[h("high", "https://a.com/api/x")]).unwrap();
        assert!(msg.contains("1 hallazgo"));
        assert!(msg.contains("https://a.com/api/x"));
        assert!(msg.contains("HIGH"));
    }

    #[test]
    fn ordena_por_severidad_lo_urgente_arriba() {
        let msg = construir_mensaje(&[
            h("low", "https://a.com/low"),
            h("critical", "https://a.com/crit"),
            h("medium", "https://a.com/med"),
        ])
        .unwrap();
        let pc = msg.find("crit").unwrap();
        let pm = msg.find("med").unwrap();
        let pl = msg.find("low").unwrap();
        assert!(pc < pm && pm < pl, "critical antes que medium antes que low");
    }

    #[test]
    fn trunca_y_resume_el_resto() {
        let muchos: Vec<HallazgoBreve> = (0..20)
            .map(|i| h("medium", &format!("https://a.com/{i}")))
            .collect();
        let msg = construir_mensaje(&muchos).unwrap();
        assert!(msg.contains("20 hallazgo"));
        assert!(msg.contains("… y 5 más"), "20 - 15 = 5 resumidos");
    }

    #[test]
    fn evento_superficie_nueva_formatea_y_vacio_es_none() {
        let e = Evento::SuperficieNueva {
            programa: "acme".into(),
            assets: vec!["a.acme.com".into(), "b.acme.com".into()],
        };
        let m = construir_mensaje_evento(&e).unwrap();
        assert!(m.contains("2 asset"));
        assert!(m.contains("a.acme.com"));
        // vacío → None (no se envía webhook vacío).
        let vacio = Evento::SuperficieNueva { programa: "acme".into(), assets: vec![] };
        assert!(construir_mensaje_evento(&vacio).is_none());
    }

    #[test]
    fn evento_takeover_formatea() {
        let e = Evento::Takeover {
            programa: "acme".into(),
            host: "old.acme.com".into(),
            servicio: "GitHub Pages".into(),
        };
        let m = construir_mensaje_evento(&e).unwrap();
        assert!(m.contains("TAKEOVER"));
        assert!(m.contains("old.acme.com"));
        assert!(m.contains("GitHub Pages"));
    }

    #[tokio::test]
    async fn notificar_sin_webhook_es_noop() {
        let e = Evento::Takeover { programa: "x".into(), host: "h".into(), servicio: "s".into() };
        assert_eq!(notificar(None, &e).await.unwrap(), 0);
    }
}
