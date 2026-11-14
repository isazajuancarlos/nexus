// SPDX-License-Identifier: LicenseRef-Propietario
//! Detección de SUBDOMAIN TAKEOVER con lógica propia (fase 2.3), no solo el tag de
//! nuclei. El estado del arte pide confirmar la cadena **CNAME → backend + match de
//! fingerprint** (can-i-take-over-xyz), no un 404 desnudo.
//!
//! Sin dependencia nueva: la resolución de CNAME va por **DNS-over-HTTPS** (reqwest,
//! sin `dig` ni crate de DNS). El matcher es puro y solo dispara con un cuerpo
//! DISTINTIVO del recurso no reclamado (directiva 23: nada de "404 genérico", que
//! haría falsos positivos).

use sqlx::SqlitePool;

/// (servicio, patrón del CNAME, huella DISTINTIVA del recurso no reclamado en el
/// cuerpo HTTP). Curado de can-i-take-over-xyz; solo huellas inequívocas.
pub const FINGERPRINTS: &[(&str, &str, &str)] = &[
    ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
    ("Heroku", "herokuapp.com", "No such app"),
    ("AWS S3", "s3", "NoSuchBucket"),
    // Shopify y Tumblr QUITADOS (2026-08-23, misma razón que Unbounce): sus
    // "huellas" ("Sorry, this shop is currently unavailable" / "Whatever you were
    // looking for doesn't currently exist") aparecen en tiendas/blogs
    // legítimamente PAUSADOS o cerrados, no solo en dominios no reclamados —y
    // Shopify exige poseer ya el dominio en otra cuenta—: casaban un estado que
    // NO es reclamable → falso positivo HIGH a la plataforma. can-i-take-over-xyz
    // los cataloga como no vulnerables/edge. Vuelven con una huella inequívoca.
    ("Fastly", "fastly.net", "Fastly error: unknown domain"),
    ("Surge.sh", "surge.sh", "project not found"),
    ("Bitbucket", "bitbucket.io", "Repository not found"),
    ("Ghost", "ghost.io", "Domain error"),
    ("Pantheon", "pantheonsite.io", "The gods are wise"),
    // Unbounce QUITADO (2026-08-23): su "huella" era `The requested URL was not
    // found` — un 404 GENÉRICO de Apache, no un marcador inequívoco. Casaba con
    // cualquier 404 detrás del CNAME (medido: `try.cloudways.com` da ese cuerpo
    // exacto tras Cloudflare y NO es un takeover confirmable). Una fuente de
    // financiación no puede enviar un falso positivo a la plataforma. Unbounce
    // además no es takeover-able de forma fiable (sin página no reclamada con
    // huella propia). Si algún día tiene un marcador distintivo, vuelve — con él.
    ("Help Scout", "helpscoutdocs.com", "No settings were found for this company"),
    ("Wufoo", "wufoo.com", "Profile not found"),
    ("Cargo", "cargocollective.com", "If you're moving your domain away from Cargo"),
];

/// ¿El par (CNAME, cuerpo) es un takeover? PURO: el CNAME apunta a un servicio
/// conocido Y el cuerpo trae su huella distintiva de recurso no reclamado.
pub fn evaluar_takeover(cname: &str, cuerpo: &str) -> Option<&'static str> {
    let c = cname.to_ascii_lowercase();
    for (servicio, pat, huella) in FINGERPRINTS {
        if c.contains(pat) && cuerpo.contains(huella) {
            return Some(servicio);
        }
    }
    None
}

/// ¿El CNAME apunta a alguno de los servicios reclamables? (pre-filtro barato para
/// no traer el HTTP de hosts que no interesan).
pub fn cname_es_reclamable(cname: &str) -> bool {
    let c = cname.to_ascii_lowercase();
    FINGERPRINTS.iter().any(|(_, pat, _)| c.contains(pat))
}

/// Resuelve el CNAME de `host` por DNS-over-HTTPS (dns.google). `None` si no hay
/// CNAME o falla.
async fn resolver_cname(cliente: &reqwest::Client, host: &str) -> Option<String> {
    let url = format!("https://dns.google/resolve?name={host}&type=CNAME");
    let r = cliente.get(&url).send().await.ok()?;
    let j: serde_json::Value = r.json().await.ok()?;
    j["Answer"].as_array()?.iter().find_map(|a| {
        // type 5 = CNAME.
        if a["type"].as_u64() == Some(5) {
            a["data"].as_str().map(|s| s.trim_end_matches('.').to_string())
        } else {
            None
        }
    })
}

/// Revisa UN host: resuelve CNAME → si apunta a servicio reclamable, trae el HTTP
/// y evalúa la huella. Devuelve el servicio si es un takeover probable.
pub async fn revisar_host(cliente: &reqwest::Client, host: &str) -> Option<(String, &'static str)> {
    let cname = resolver_cname(cliente, host).await?;
    if !cname_es_reclamable(&cname) {
        return None;
    }
    let r = cliente.get(format!("https://{host}")).send().await.ok()?;
    let cuerpo = r.text().await.ok()?;
    let servicio = evaluar_takeover(&cname, &cuerpo)?;
    Some((cname, servicio))
}

/// Revisa una muestra ACOTADA de hosts; por cada takeover probable persiste un
/// finding (high, MANUAL_READY — es explotable pero pide confirmación humana antes
/// de reclamar) y avisa por webhook. Devuelve cuántos halló.
pub async fn fase_takeover(
    pool: &SqlitePool,
    program: &str,
    hosts: &[String],
    max: usize,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    let cliente = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(crate::evasion::UA_POOL[0])
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    // REVALIDAR EL ALCANCE POR HOST, junto al acto de red (directiva 6). `hosts`
    // llega de `recon_subs.txt`, que NO pasa por `filter_to_scope` (solo lo pasa
    // `targets.txt`): para un programa con alcance de host EXACTO, subfinder trae
    // subdominios más profundos que quedan FUERA de alcance, y hacerles un `GET`
    // sería tocar un objetivo no autorizado (baneo/ilegalidad). Con reglas vacías
    // `in_scope` da false → no se toca nada (fail-closed).
    let reglas: Vec<crate::scope::ScopeRule> = crate::db::scope_rules_with_id(pool)
        .await?
        .iter()
        .filter_map(|(_, ident, wild)| crate::scope::ScopeRule::parse(ident, *wild))
        .collect();
    let mut n = 0usize;
    for host in hosts.iter().take(max) {
        if !crate::scope::in_scope(&format!("https://{host}"), &reglas) {
            continue;
        }
        if let Some((cname, servicio)) = revisar_host(&cliente, host).await {
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: "subdomain-takeover".to_string(),
                severity: "high".to_string(),
                url: format!("https://{host}"),
                cwe: Some("CWE-404".to_string()),
                evidencia: Some(format!(
                    "{host} → CNAME {cname} ({servicio}), recurso no reclamado (huella de {servicio} en el cuerpo). Confirmar reclamabilidad en {servicio} antes de reportar."
                )),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                n += 1;
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Takeover {
                        programa: program.to_string(),
                        host: host.clone(),
                        servicio: servicio.to_string(),
                    },
                )
                .await;
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takeover_solo_con_cname_y_huella() {
        // CNAME a GitHub Pages + cuerpo de sitio no reclamado → takeover.
        assert_eq!(
            evaluar_takeover("foo.github.io", "404 There isn't a GitHub Pages site here."),
            Some("GitHub Pages")
        );
        // PAREJA (directiva 33): mismo CNAME pero sitio RECLAMADO (sin la huella) → NO.
        assert_eq!(evaluar_takeover("foo.github.io", "<html>bienvenido</html>"), None);
        // Huella pero CNAME que no es del servicio → NO (evita casar por cuerpo suelto).
        assert_eq!(evaluar_takeover("cdn.propio.com", "No such app"), None);
    }

    /// **EL FALSO POSITIVO REAL QUE HABÍA QUE CERRAR** (2026-08-23): `try.cloudways.com`
    /// apunta a `…unbouncepages.com` y devuelve el 404 genérico exacto de abajo tras
    /// Cloudflare. La entrada de Unbounce (retirada) lo confirmaba como takeover y lo
    /// habría enviado a Intigriti — un FP a una fuente de financiación. Este caso lo
    /// ancla al cuerpo REAL medido: NUNCA debe volver a dar `Some`.
    #[test]
    fn el_404_generico_de_unbounce_no_es_takeover() {
        assert_eq!(
            evaluar_takeover(
                "28820a5a49654f6b85e7216c1a7a1ede.unbouncepages.com",
                "The requested URL was not found on this server."
            ),
            None,
            "un 404 genérico tras un CNAME a un SaaS NO es un takeover confirmado"
        );
    }

    #[test]
    fn prefiltro_de_cname_reclamable() {
        assert!(cname_es_reclamable("x.herokuapp.com"));
        assert!(cname_es_reclamable("bucket.s3.amazonaws.com"));
        assert!(!cname_es_reclamable("edge.cloudfront.net")); // no está en la lista
    }
}
