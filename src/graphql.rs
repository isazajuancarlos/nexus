// SPDX-License-Identifier: LicenseRef-Propietario
//! Detección de GraphQL con introspección EXPUESTA (fase 3.2). Un servidor que
//! deja la introspección abierta entrega su esquema completo a cualquiera —mapa
//! del ataque gratis, y la base para IDOR-de-campo/alias-batching—. Es un hallazgo
//! real (medio) y self-contained.
//!
//! El predicado es PURO (discrimina una respuesta de esquema de un error), y la
//! prueba de red solo se dispara sobre rutas GraphQL conocidas — coste acotado.

use sqlx::SqlitePool;

/// Rutas donde suele vivir un endpoint GraphQL.
pub const RUTAS_GRAPHQL: &[&str] =
    &["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/gql", "/api/gql"];

/// Consulta de introspección mínima (pide el tipo raíz del esquema).
pub const CONSULTA_INTROSPECCION: &str = r#"{"query":"query{__schema{queryType{name}}}"}"#;

/// ¿La respuesta revela el esquema por introspección? PURO. Una introspección
/// exitosa trae `__schema` CON `queryType` en los datos; un servidor que la
/// bloquea responde un error (`"errors":[…"introspection is not allowed"…]`) sin
/// `queryType`. Exigir `queryType` discrimina el esquema real del mensaje de error.
pub fn introspeccion_expuesta(respuesta: &str) -> bool {
    respuesta.contains("\"__schema\"") && respuesta.contains("\"queryType\"")
}

/// Prueba las rutas GraphQL de un origen; devuelve la primera con introspección
/// expuesta.
pub async fn probar(cliente: &reqwest::Client, origen: &str) -> Option<String> {
    let origen = origen.trim_end_matches('/');
    for ruta in RUTAS_GRAPHQL {
        let url = format!("{origen}{ruta}");
        let resp = cliente
            .post(&url)
            .header("Content-Type", "application/json")
            .body(CONSULTA_INTROSPECCION)
            .send()
            .await;
        if let Ok(r) = resp {
            if let Ok(cuerpo) = r.text().await {
                if introspeccion_expuesta(&cuerpo) {
                    return Some(url);
                }
            }
        }
    }
    None
}

/// Revisa una muestra ACOTADA de orígenes; por cada introspección expuesta
/// persiste un finding (medium, MANUAL_READY) y avisa. Devuelve cuántos halló.
pub async fn fase_graphql(
    pool: &SqlitePool,
    program: &str,
    origenes: &[String],
    max: usize,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    let cliente = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(crate::evasion::UA_POOL[0])
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    let mut n = 0usize;
    for origen in origenes.iter().take(max) {
        if let Some(url) = probar(&cliente, origen).await {
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: "graphql-introspection-enabled".to_string(),
                severity: "medium".to_string(),
                url: url.clone(),
                cwe: Some("CWE-200".to_string()),
                evidencia: Some(format!(
                    "introspección GraphQL ABIERTA en {url}: la query __schema devolvió el esquema completo (queryType presente)."
                )),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                n += 1;
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                        severity: "medium".into(),
                        vuln_type: "graphql-introspection".into(),
                        url,
                        program_name: program.to_string(),
                    }]),
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
    fn introspeccion_expuesta_discrimina() {
        // Esquema real (introspección abierta) → true.
        let ok = r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#;
        assert!(introspeccion_expuesta(ok));
        // PAREJA: bloqueada → error SIN queryType → false.
        let bloqueada = r#"{"errors":[{"message":"GraphQL introspection is not allowed"}]}"#;
        assert!(!introspeccion_expuesta(bloqueada));
        // Respuesta normal de datos → false.
        assert!(!introspeccion_expuesta(r#"{"data":{"user":{"id":1}}}"#));
        // Un __schema mencionado en un error, sin queryType → false (no discrimina mal).
        assert!(!introspeccion_expuesta(r#"{"errors":[{"message":"__schema field blocked"}]}"#));
    }
}
