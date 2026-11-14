//! HACKTIVITY público de HackerOne — reportes ya DIVULGADOS por programa.
//!
//! A diferencia de `h1.rs` (API REST con basic-auth `H1_USER`/`H1_TOKEN` para
//! scope y envío), esto consulta el GraphQL PÚBLICO `https://hackerone.com/graphql`
//! **sin credenciales**: los reportes divulgados son públicos. Es la fuente para el
//! checklist "qué ya se explotó/reportó por programa" — sirve para decidir DÓNDE y a
//! QUIÉN atacar (dedup: no re-cazar lo ya reportado; y mapa de las clases de bug que
//! un programa ya premió, que es donde vuelve a haber tela).
//!
//! Query verificada en vivo (2026-09-06): `reports(handle:$h, state:closed, …)`
//! devuelve, para un no-miembro, solo los reportes divulgados y cerrados del
//! programa, con su CWE (`weakness.external_id`), severidad, substate y URL.

use crate::error::{NexusError, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Duration;

const GRAPHQL_URL: &str = "https://hackerone.com/graphql";

/// Consulta H1 con `state:closed` (cerrados) y `handle` como variable (no
/// interpolada) para no inyectar en el query. Pagina por `after`.
const QUERY: &str = "query($h:String!,$first:Int!,$after:String){ \
    reports(handle:$h, state:closed, first:$first, after:$after){ \
        total_count pageInfo{hasNextPage endCursor} \
        edges{ node{ title url disclosed_at substate votes{total_count} \
            severity{rating} weakness{name external_id} } } } }";

/// Un reporte público divulgado de un programa.
#[derive(Debug, Clone, PartialEq)]
pub struct ReporteDivulgado {
    pub title: String,
    pub url: String,
    /// `external_id` normalizado en minúsculas, p.ej. "cwe-639". `None` si el
    /// reporte se divulgó sin weakness asignada.
    pub cwe: Option<String>,
    pub cwe_name: Option<String>,
    /// none|low|medium|high|critical → aquí "none" se colapsa a `None`.
    pub severity: Option<String>,
    pub substate: String,
    pub disclosed_at: Option<String>,
    pub votes: i64,
}

// ---- Esquema de la respuesta GraphQL (solo los campos que pedimos) ----

#[derive(Deserialize)]
struct Resp {
    data: Option<DataR>,
    errors: Option<serde_json::Value>,
}
#[derive(Deserialize)]
struct DataR {
    reports: Option<ReportsConn>,
}
#[derive(Deserialize)]
struct ReportsConn {
    total_count: i64,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
    edges: Vec<Edge>,
}
#[derive(Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}
#[derive(Deserialize)]
struct Edge {
    node: Node,
}
#[derive(Deserialize)]
struct Node {
    title: String,
    url: String,
    disclosed_at: Option<String>,
    substate: String,
    votes: Votes,
    severity: Option<Severity>,
    weakness: Option<Weakness>,
}
#[derive(Deserialize)]
struct Votes {
    total_count: i64,
}
#[derive(Deserialize)]
struct Severity {
    rating: Option<String>,
}
#[derive(Deserialize)]
struct Weakness {
    name: Option<String>,
    external_id: Option<String>,
}

/// Parsea UNA página. Aislado de la red para poder probarlo con un artefacto
/// capturado (directiva 33). Devuelve (total, hay_siguiente, cursor, reportes).
fn parse_pagina(body: &str) -> Result<(i64, bool, Option<String>, Vec<ReporteDivulgado>)> {
    let resp: Resp = serde_json::from_str(body)?;
    if let Some(errs) = resp.errors {
        return Err(NexusError::Other(format!("GraphQL H1: {errs}")));
    }
    let conn = match resp.data.and_then(|d| d.reports) {
        Some(c) => c,
        // `data.reports == null` sin `errors` = programa sin acceso/sin reportes.
        None => return Ok((0, false, None, Vec::new())),
    };
    let mut out = Vec::with_capacity(conn.edges.len());
    for e in conn.edges {
        let n = e.node;
        let cwe = n
            .weakness
            .as_ref()
            .and_then(|w| w.external_id.as_deref())
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());
        let cwe_name = n.weakness.and_then(|w| w.name);
        let severity = n
            .severity
            .and_then(|s| s.rating)
            .filter(|r| r != "none" && !r.is_empty());
        out.push(ReporteDivulgado {
            title: n.title,
            url: n.url,
            cwe,
            cwe_name,
            severity,
            substate: n.substate,
            disclosed_at: n.disclosed_at,
            votes: n.votes.total_count,
        });
    }
    Ok((
        conn.total_count,
        conn.page_info.has_next_page,
        conn.page_info.end_cursor,
        out,
    ))
}

/// Baja hasta `cap` reportes divulgados de `handle`. Devuelve (total_reportado, reportes).
/// `total_reportado` es el `total_count` de H1 (puede ser mayor que `cap`).
pub async fn fetch(handle: &str, cap: usize, ua: &str) -> Result<(i64, Vec<ReporteDivulgado>)> {
    let http = reqwest::Client::builder()
        .user_agent(ua.to_string())
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut out: Vec<ReporteDivulgado> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut total = 0i64;
    loop {
        let restante = cap.saturating_sub(out.len());
        if restante == 0 {
            break;
        }
        let page = restante.min(50);
        let body = serde_json::json!({
            "query": QUERY,
            "variables": { "h": handle, "first": page, "after": cursor },
        });
        let texto = http
            .post(GRAPHQL_URL)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let (t, hay_mas, cur, mut reportes) = parse_pagina(&texto)?;
        total = t;
        out.append(&mut reportes);
        if !hay_mas || cur.is_none() {
            break;
        }
        cursor = cur;
    }
    Ok((total, out))
}

/// Frecuencia por CWE, de más a menos. El `None` cae en "sin-cwe" (no se pierde).
pub fn por_cwe(reportes: &[ReporteDivulgado]) -> Vec<(String, usize)> {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for r in reportes {
        let k = r.cwe.clone().unwrap_or_else(|| "sin-cwe".to_string());
        *m.entry(k).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// Sección Markdown de un programa: encabezado + tabla CWE + lista de reportes.
pub fn seccion_md(handle: &str, total: i64, reportes: &[ReporteDivulgado]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "### `{handle}` — {total} reporte(s) divulgado(s)\n\n"
    ));
    if reportes.is_empty() {
        s.push_str(
            "_Sin reportes divulgados públicos._ Programa nuevo, privado, o poco cazado — \
             cero prior-art: sin dupes que esquivar, pero también sin pistas ajenas.\n\n",
        );
        return s;
    }
    if total as usize > reportes.len() {
        s.push_str(&format!(
            "> Muestra de {} de {} (subir `--cap` para más).\n\n",
            reportes.len(),
            total
        ));
    }
    s.push_str("**Clases ya premiadas (CWE):**\n\n");
    for (cwe, n) in por_cwe(reportes) {
        s.push_str(&format!("- `{cwe}` ×{n}\n"));
    }
    s.push_str("\n**Reportes:**\n\n");
    for r in reportes {
        let sev = r.severity.as_deref().unwrap_or("—");
        let cwe = r.cwe.as_deref().unwrap_or("sin-cwe");
        let fecha = r.disclosed_at.as_deref().unwrap_or("").chars().take(10).collect::<String>();
        s.push_str(&format!(
            "- [ ] [{sev}] `{cwe}` — {} ({}, {fecha}) <{}>\n",
            r.title.replace('\n', " "),
            r.substate,
            r.url
        ));
    }
    s.push('\n');
    s
}

/// Fila de resumen de un programa (para la tabla-cabecera del checklist consolidado).
pub struct Resumen {
    pub handle: String,
    pub total: i64,
    pub top_cwe: Vec<(String, usize)>,
}

/// Tabla-cabecera del checklist consolidado, ordenada por nº de divulgados desc.
pub fn tabla_resumen(filas: &[Resumen]) -> String {
    let mut fs: Vec<&Resumen> = filas.iter().collect();
    fs.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.handle.cmp(&b.handle)));
    let mut s = String::from("| Programa | Divulgados | Clases top (CWE) |\n|---|---|---|\n");
    for f in fs {
        let top = f
            .top_cwe
            .iter()
            .take(4)
            .map(|(c, n)| format!("{c}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        let top = if top.is_empty() { "—".to_string() } else { top };
        s.push_str(&format!("| `{}` | {} | {} |\n", f.handle, f.total, top));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Artefacto capturado en vivo (discourse, recortado): un nodo COMPLETO y otro
    // con `weakness` y `severity` nulos — el caso rojo que debe caer en "sin-cwe"
    // y no reventar ni inflar otra clase.
    const FIXTURE: &str = r#"{"data":{"reports":{"total_count":20,
      "pageInfo":{"hasNextPage":true,"endCursor":"Mg"},
      "edges":[
        {"node":{"title":"Hidden tags mutated via synonym ID paths","url":"https://hackerone.com/reports/3689633",
          "disclosed_at":"2026-08-26T05:47:28.698Z","substate":"resolved","votes":{"total_count":3},
          "severity":{"rating":"medium"},"weakness":{"name":"IDOR","external_id":"CWE-639"}}},
        {"node":{"title":"Reporte sin weakness ni severidad","url":"https://hackerone.com/reports/1",
          "disclosed_at":null,"substate":"informative","votes":{"total_count":0},
          "severity":null,"weakness":null}},
        {"node":{"title":"Otro IDOR","url":"https://hackerone.com/reports/2",
          "disclosed_at":"2026-01-02T00:00:00.000Z","substate":"resolved","votes":{"total_count":1},
          "severity":{"rating":"none"},"weakness":{"name":"IDOR","external_id":"CWE-639"}}}
      ]}}}"#;

    #[test]
    fn parsea_artefacto_real_y_normaliza() {
        let (total, hay_mas, cursor, reportes) = parse_pagina(FIXTURE).unwrap();
        assert_eq!(total, 20);
        assert!(hay_mas);
        assert_eq!(cursor.as_deref(), Some("Mg"));
        assert_eq!(reportes.len(), 3);
        // CWE normalizado a minúsculas.
        assert_eq!(reportes[0].cwe.as_deref(), Some("cwe-639"));
        assert_eq!(reportes[0].severity.as_deref(), Some("medium"));
        // Caso rojo: nodo sin weakness/severity → None, sin panic.
        assert_eq!(reportes[1].cwe, None);
        assert_eq!(reportes[1].severity, None);
        // "none" se colapsa a None (no queda como severidad "none").
        assert_eq!(reportes[2].severity, None);
    }

    #[test]
    fn agrega_por_cwe_y_discrimina() {
        let (_, _, _, reportes) = parse_pagina(FIXTURE).unwrap();
        let agg = por_cwe(&reportes);
        // Positivo: cwe-639 aparece 2 veces y va primero.
        assert_eq!(agg[0], ("cwe-639".to_string(), 2));
        // El nodo nulo cae en "sin-cwe" = 1 (no se pierde).
        assert!(agg.contains(&("sin-cwe".to_string(), 1)));
        // Discrimina: cwe-639 NO se infló contando el sin-cwe.
        assert_eq!(agg.iter().find(|(k, _)| k == "cwe-639").unwrap().1, 2);
    }

    #[test]
    fn errores_graphql_son_error() {
        let body = r#"{"errors":[{"message":"Field 'x' doesn't exist"}],"data":null}"#;
        assert!(parse_pagina(body).is_err());
    }

    #[test]
    fn data_reports_null_es_vacio_no_error() {
        // Sin `errors` y con reports null = programa sin reportes accesibles.
        let body = r#"{"data":{"reports":null}}"#;
        let (total, hay_mas, _, reportes) = parse_pagina(body).unwrap();
        assert_eq!(total, 0);
        assert!(!hay_mas);
        assert!(reportes.is_empty());
    }
}
