// SPDX-License-Identifier: LicenseRef-Propietario
//! Mass-assignment (fase 1.4): ¿el backend acepta campos privilegiados
//! (`role`, `is_admin`…) que el cliente NO debería poder fijar, al actualizar su
//! PROPIO objeto? Se confirma con re-fetch: el campo inyectado PEGÓ si aparece en
//! la respuesta después y no antes.
//!
//! **Salvaguarda «sin daño» (crítica):**
//!   1. NO toca el motor GET-only de `autz` — es un módulo aparte.
//!   2. Solo escribe sobre el objeto PROPIO del DUEÑO (URLs de `autz_semillas`,
//!      que son sus recursos), NUNCA de un tercero.
//!   3. Valores CENTINELA obvios (`nexusprobe_*`), añade campos, no borra.
//!   4. Es la cuenta de PRUEBA de Juan (como el test de IDOR).
//!   5. **Gateado tras opt-in explícito** (`NEXUS_MASS_ASSIGN`) y requiere una
//!      identidad DUEÑO montada: no-op por defecto, no escribe nada sin permiso.
//!
//! El predicado `campo_pego` es PURO (testeable y simulable a escala).

use crate::autz::{Identidad, Papel};
use sqlx::SqlitePool;

/// Campos privilegiados a intentar inyectar, con su valor CENTINELA. Los string
/// llevan un centinela distintivo (detección inequívoca); los booleanos usan
/// `true` y se discriminan por el diff antes/después.
pub const CAMPOS_SENSIBLES: &[(&str, &str)] = &[
    ("role", "nexusprobe_role"),
    ("account_type", "nexusprobe_type"),
    ("plan", "nexusprobe_plan"),
    ("is_admin", "true"),
    ("isAdmin", "true"),
    ("admin", "true"),
    ("is_verified", "true"),
    ("email_verified", "true"),
    ("verified", "true"),
];

/// ¿`(campo, valor)` está asociado en el cuerpo JSON? (varias formas de espaciado).
fn asociado(cuerpo: &str, campo: &str, valor: &str) -> bool {
    [
        format!("\"{campo}\":\"{valor}\""),
        format!("\"{campo}\": \"{valor}\""),
        format!("\"{campo}\":{valor}"),
        format!("\"{campo}\": {valor}"),
    ]
    .iter()
    .any(|p| cuerpo.contains(p))
}

/// ¿El campo privilegiado PEGÓ? PURO: la asociación `(campo, valor)` aparece
/// DESPUÉS pero no ANTES → la inyección tomó efecto (mass-assignment).
pub fn campo_pego(antes: &str, despues: &str, campo: &str, valor: &str) -> bool {
    asociado(despues, campo, valor) && !asociado(antes, campo, valor)
}

fn con_cabeceras(mut req: reqwest::RequestBuilder, id: &Identidad) -> reqwest::RequestBuilder {
    for (k, v) in &id.cabeceras {
        req = req.header(k.as_str(), v.as_str());
    }
    req
}

async fn obtener(cliente: &reqwest::Client, id: &Identidad, url: &str) -> Option<String> {
    con_cabeceras(cliente.get(url), id).send().await.ok()?.text().await.ok()
}

/// Prueba UN objeto propio del dueño: lee, PATCHea con los campos centinela, relee
/// y comprueba cuál pegó. Un solo PATCH (minimiza la escritura sobre el objeto).
///
/// `extra` son campos DESCUBIERTOS por el sondeo de parámetros ocultos (`parametros`):
/// nombres que el backend acepta pero no documenta, fuera de `CAMPOS_SENSIBLES`. Se
/// inyectan con un centinela string y se comprueban igual — es la superficie que el
/// listado estático no enumera. El `bool` del retorno dice si el campo que pegó fue
/// descubierto (para la evidencia).
pub async fn probar_objeto(
    cliente: &reqwest::Client,
    dueno: &Identidad,
    url: &str,
    extra: &[String],
) -> Option<(String, String, bool)> {
    let antes = obtener(cliente, dueno, url).await?;
    // Campos a inyectar: estáticos (con su valor) + descubiertos (centinela string),
    // marcando cuáles son descubiertos. Un descubierto que YA está en la lista estática
    // no se duplica.
    let mut campos: Vec<(String, String, bool)> = CAMPOS_SENSIBLES
        .iter()
        .map(|(c, v)| ((*c).to_string(), (*v).to_string(), false))
        .collect();
    for c in extra {
        if !CAMPOS_SENSIBLES.iter().any(|(e, _)| e.eq_ignore_ascii_case(c)) {
            campos.push((c.clone(), format!("nexusprobe_{c}"), true));
        }
    }
    // Cuerpo con todos los centinela (bool reales para is_admin, string para role…).
    let mut obj = serde_json::Map::new();
    for (c, v, _) in &campos {
        let val = if v == "true" {
            serde_json::Value::Bool(true)
        } else {
            serde_json::Value::String(v.clone())
        };
        obj.insert(c.clone(), val);
    }
    let body = serde_json::Value::Object(obj).to_string();
    // PATCH sobre el objeto PROPIO (salvaguarda: solo semillas del dueño).
    let _ = con_cabeceras(cliente.patch(url), dueno)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await;
    let despues = obtener(cliente, dueno, url).await?;
    for (c, v, desc) in &campos {
        if campo_pego(&antes, &despues, c, v) {
            return Some((c.clone(), v.clone(), *desc));
        }
    }
    None
}

/// Fase gateada. No-op salvo `opt_in` Y una identidad DUEÑO montada. Recorre las
/// semillas (objetos propios del dueño) y por cada mass-assignment persiste un
/// finding (high) y avisa.
#[allow(clippy::too_many_arguments)]
pub async fn fase_mass_assign(
    pool: &SqlitePool,
    program: &str,
    ids: &[Identidad],
    semillas: &[String],
    opt_in: bool,
    descubrir_ocultos: bool,
    max: usize,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    if !opt_in {
        return Ok(0); // sin daño por defecto: no se escribe nada
    }
    let Some(dueno) = ids.iter().find(|i| i.papel == Papel::Dueno) else {
        return Ok(0);
    };
    let cliente = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;

    // Puente para el descubridor de parámetros ocultos: reusa las cabeceras del DUEÑO.
    let id_desc = crate::oraculo_diferencial::Identidad {
        etiqueta: "dueño".to_string(),
        cabeceras: dueno.cabeceras.clone(),
    };
    let dic: Vec<String> =
        crate::parametros::DICCIONARIO_AUTHZ.iter().map(|s| (*s).to_string()).collect();
    let pcfg = crate::parametros::Config::default();

    let mut n = 0usize;
    for url in semillas.iter().take(max) {
        // Amplía la superficie con los campos que el endpoint acepta pero no documenta
        // (GET benigno). Si el descubrimiento falla (red / objetivo comodín), se sigue con
        // solo el listado estático — falla hacia menos, nunca hacia inventar campos.
        let extra: Vec<String> = if descubrir_ocultos {
            match crate::parametros::descubrir(&cliente, url, &id_desc, &dic, &pcfg).await {
                Ok(ds) => ds.into_iter().map(|d| d.nombre).collect(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        if let Some((campo, _valor, descubierto)) = probar_objeto(&cliente, dueno, url, &extra).await
        {
            let origen = if descubierto {
                " (campo DESCUBIERTO por sondeo de parámetros ocultos, fuera del listado estático)"
            } else {
                ""
            };
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: format!("mass-assignment-{campo}"),
                severity: "high".to_string(),
                url: url.clone(),
                cwe: Some("CWE-915".to_string()),
                evidencia: Some(format!(
                    "mass-assignment en {url}: un PATCH sobre el objeto PROPIO inyectó el campo sensible '{campo}'{origen} y el servidor lo PERSISTIÓ (el valor centinela pegó al releer)."
                )),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                n += 1;
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                        severity: "high".into(),
                        vuln_type: format!("mass-assignment ({campo})"),
                        url: url.clone(),
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
    fn campo_pego_discrimina() {
        let antes = r#"{"id":1,"role":"user","is_admin":false}"#;
        // role cambió a nuestro centinela → pegó.
        let despues = r#"{"id":1,"role":"nexusprobe_role","is_admin":true}"#;
        assert!(campo_pego(antes, despues, "role", "nexusprobe_role"));
        assert!(campo_pego(antes, despues, "is_admin", "true"));
        // PAREJA: un campo que YA valía true antes NO cuenta (no lo pusimos nosotros).
        let antes2 = r#"{"is_verified":true}"#;
        let despues2 = r#"{"is_verified":true}"#;
        assert!(!campo_pego(antes2, despues2, "is_verified", "true"), "ya estaba, no es nuestro");
        // El servidor IGNORÓ el campo (sigue user) → no pegó.
        assert!(!campo_pego(antes, r#"{"id":1,"role":"user"}"#, "role", "nexusprobe_role"));
    }

    #[tokio::test]
    async fn fase_no_escribe_sin_optin() {
        // Salvaguarda: sin opt-in, no-op (0), aunque hubiera semillas.
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::db::open(&dir.path().join("t.db"), 2).await.unwrap();
        let dueno = Identidad { papel: Papel::Dueno, cabeceras: vec![] };
        let n = fase_mass_assign(&pool, "x", &[dueno], &["https://x/1".into()], false, false, 5, None)
            .await
            .unwrap();
        assert_eq!(n, 0, "sin opt-in NO escribe ni reporta");
    }
}
