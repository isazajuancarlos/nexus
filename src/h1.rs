//! Cliente de la API de HackerOne. Portado de `recon.py` (HackerOneAuto) y
//! `scope.py` (HackerOneClient). Basic auth con H1_USER/H1_TOKEN del entorno.

use crate::error::{NexusError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

const BASE_URL: &str = "https://api.hackerone.com/v1";

pub struct H1Client {
    http: reqwest::Client,
    user: String,
    token: String,
    /// Caché por handle de {cwe normalizado -> weakness_id} (S4).
    weakness_cache: Mutex<HashMap<String, HashMap<String, String>>>,
}

#[derive(Debug, Deserialize)]
struct ProgramsPage {
    data: Vec<ProgramItem>,
    #[serde(default)]
    links: Links,
}

#[derive(Debug, Deserialize, Default)]
struct Links {
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProgramItem {
    attributes: ProgramAttrs,
}

#[derive(Debug, Deserialize)]
struct ProgramAttrs {
    handle: String,
    /// Estado de envíos del programa: "open" (acepta), "paused"/"disabled" (no).
    /// `default` para no romper los otros usos de este struct (listado de handles),
    /// que no piden este campo.
    #[serde(default)]
    submission_state: Option<String>,
}

/// Respuesta de `GET /hackers/programs/{handle}`: el recurso va en la RAÍZ
/// (`{id,type,attributes}`), SIN envoltorio `data` — a diferencia del LISTADO
/// (`{data:[...]}`), que sí lo lleva. Verificado contra la API real 2026-09-19.
#[derive(Debug, Deserialize)]
struct ProgramDetail {
    attributes: ProgramAttrs,
}

#[derive(Debug, Deserialize)]
struct ScopesPage {
    data: Vec<ScopeItem>,
}

#[derive(Debug, Deserialize)]
struct ScopeItem {
    #[serde(default)]
    id: Option<String>,
    attributes: ScopeAttrs,
}

#[derive(Debug, Deserialize)]
struct ScopeAttrs {
    asset_type: Option<String>,
    asset_identifier: Option<String>,
    #[serde(default)]
    eligible_for_bounty: bool,
}

/// Un dominio raíz elegible para bounty, extraído del scope. `id` es el
/// structured_scope_id de H1 (para asociar el activo al enviar el reporte).
#[derive(Debug, Clone)]
pub struct ScopeDomain {
    pub identifier: String,
    pub is_wildcard: bool,
    pub id: Option<String>,
}

impl H1Client {
    pub fn from_env(user_agent: &str) -> Result<Self> {
        let user = std::env::var("H1_USER").map_err(|_| NexusError::NoCredentials)?;
        let token = std::env::var("H1_TOKEN").map_err(|_| NexusError::NoCredentials)?;
        if user.is_empty() || token.is_empty() {
            return Err(NexusError::NoCredentials);
        }
        let http = reqwest::Client::builder()
            .user_agent(user_agent.to_string())
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { http, user, token, weakness_cache: Mutex::new(HashMap::new()) })
    }

    /// Resuelve un CWE (p.ej. "CWE-89") al weakness_id interno del programa vía
    /// GET /programs/{handle}/weaknesses, cacheado. Fail-safe: None ante cualquier
    /// duda (sin creds, sin match, error) para no enviar un id inválido (422).
    pub async fn resolve_weakness_id(&self, handle: &str, cwe: Option<&str>) -> Option<String> {
        let cwe = cwe?;
        let norm = cwe.trim().to_lowercase().replace('_', "-");
        if norm.is_empty() || norm == "cwe-0" || norm == "cwe-" {
            return None;
        }
        {
            let cache = self.weakness_cache.lock().unwrap();
            if let Some(map) = cache.get(handle) {
                return map.get(&norm).cloned();
            }
        }
        let mut map: HashMap<String, String> = HashMap::new();
        let mut url = Some(format!("{BASE_URL}/hackers/programs/{handle}/weaknesses"));
        while let Some(u) = url {
            let resp = match self
                .http
                .get(&u)
                .basic_auth(&self.user, Some(&self.token))
                .header("Accept", "application/json")
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => r,
                _ => {
                    map.clear();
                    break;
                }
            };
            let j: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            if let Some(data) = j.get("data").and_then(|d| d.as_array()) {
                for w in data {
                    let ext = w
                        .get("attributes")
                        .and_then(|a| a.get("external_id"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let wid = w.get("id").and_then(|i| i.as_str().map(String::from).or_else(|| i.as_i64().map(|n| n.to_string()))).unwrap_or_default();
                    if !ext.is_empty() && !wid.is_empty() {
                        map.insert(ext, wid);
                    }
                }
            }
            url = j.get("links").and_then(|l| l.get("next")).and_then(|n| n.as_str()).map(String::from);
        }
        let result = map.get(&norm).cloned();
        self.weakness_cache.lock().unwrap().insert(handle.to_string(), map);
        result
    }

    /// Lista los handles de todos los programas (paginado).
    pub async fn get_programs(&self) -> Result<Vec<String>> {
        let mut handles = Vec::new();
        let mut page = 1u32;
        loop {
            let resp = self
                .http
                .get(format!("{BASE_URL}/hackers/programs"))
                .basic_auth(&self.user, Some(&self.token))
                .header("Accept", "application/json")
                .query(&[("page[number]", page.to_string()), ("page[size]", "100".into())])
                .send()
                .await?;
            if !resp.status().is_success() {
                break;
            }
            let body: ProgramsPage = resp.json().await?;
            handles.extend(body.data.into_iter().map(|p| p.attributes.handle));
            if body.links.next.is_none() {
                break;
            }
            page += 1;
        }
        Ok(handles)
    }

    /// `submission_state` del programa (`GET /hackers/programs/{handle}`):
    /// "open" = acepta envíos, "paused"/"disabled" = no. `None` si la API no lo
    /// trae. Fuente de verdad para vigilar la reapertura de un programa que está
    /// de pausa (p.ej. `liberapay`), sin depender del HTML renderizado con JS.
    pub async fn submission_state(&self, handle: &str) -> Result<Option<String>> {
        let resp = self
            .http
            .get(format!("{BASE_URL}/hackers/programs/{handle}"))
            .basic_auth(&self.user, Some(&self.token))
            .header("Accept", "application/json")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(NexusError::Other(format!(
                "H1 programa {handle}: HTTP {}",
                resp.status()
            )));
        }
        let detail: ProgramDetail = resp.json().await?;
        Ok(detail.attributes.submission_state)
    }

    /// Dominios elegibles para bounty de un programa. Normaliza `*.dom` y URLs
    /// a netloc, igual que recon.py.
    pub async fn get_scope_domains(&self, handle: &str) -> Result<Vec<ScopeDomain>> {
        let resp = self
            .http
            .get(format!("{BASE_URL}/hackers/programs/{handle}/structured_scopes"))
            .basic_auth(&self.user, Some(&self.token))
            .header("Accept", "application/json")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }
        let body: ScopesPage = resp.json().await?;
        let mut out = Vec::new();
        for item in body.data {
            let a = item.attributes;
            let atype = a.asset_type.as_deref().unwrap_or("");
            if !matches!(atype, "URL" | "WILDCARD" | "DOMAIN") || !a.eligible_for_bounty {
                continue;
            }
            if let Some(ident) = a.asset_identifier {
                if let Some(mut dom) = normalize_asset(&ident) {
                    dom.id = item.id.clone();
                    out.push(dom);
                }
            }
        }
        Ok(out)
    }
}

// ---- Elegibilidad (lectura): datos crudos para el gate de triaje ----

/// Un scope estructurado con los campos que deciden si un hallazgo es elegible.
/// A diferencia de `ScopeDomain` (recon: solo dominios con bounty), aquí van
/// TODOS los scopes con sus banderas de envío/bounty y el tope de severidad.
#[derive(Debug, Clone)]
pub struct ScopeElegible {
    pub asset_type: String,
    pub asset_identifier: String,
    pub eligible_for_submission: bool,
    pub eligible_for_bounty: bool,
    pub max_severity: Option<String>,
}

impl H1Client {
    /// Todos los scopes estructurados de un programa (sin filtrar), con los campos
    /// de elegibilidad. `Ok(vec vacío)` si la respuesta no es 2xx — el llamante lo
    /// trata como «no se pudo juzgar el scope», no como «fuera de scope».
    pub async fn get_structured_scopes(&self, handle: &str) -> Result<Vec<ScopeElegible>> {
        // PAGINA (como `get_weakness_ids`): un programa puede tener los scopes en
        // varias páginas. Sin seguir `links.next`, un host que vive en la página
        // 2+ se vería FUERA de scope → falso descarte bajo enforce.
        let mut out = Vec::new();
        let mut url = Some(format!("{BASE_URL}/hackers/programs/{handle}/structured_scopes"));
        while let Some(u) = url {
            // Reintenta en 429/503 (throttle de la API): tratar un rate-limit como
            // «sin scope» es un FALSO NEGATIVO —marca fuera-de-scope un programa que
            // SÍ lo tiene— y contamina tanto este barrido como `elegibilidad`
            // (directiva 33: el lado ciego que comparte la causa). Honra `Retry-After`;
            // si no lo hay, backoff 2/4/6/8/10 s. En cualquier OTRO fallo (red, 4xx
            // real) se mantiene el fail-open a `[]` (directiva 30), la dirección segura.
            let mut intento: u32 = 0;
            let resp = loop {
                match self
                    .http
                    .get(&u)
                    .basic_auth(&self.user, Some(&self.token))
                    .header("Accept", "application/json")
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => break r,
                    Ok(r) if matches!(r.status().as_u16(), 429 | 503) && intento < 5 => {
                        let espera = r
                            .headers()
                            .get("retry-after")
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(2 * (intento as u64 + 1));
                        tokio::time::sleep(Duration::from_secs(espera.clamp(1, 30))).await;
                        intento += 1;
                        continue;
                    }
                    _ => return Ok(Vec::new()),
                }
            };
            let v: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(_) => return Ok(Vec::new()),
            };
            if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
                for it in data {
                    let Some(a) = it.get("attributes") else { continue };
                    let s = |k: &str| a.get(k).and_then(|x| x.as_str()).map(String::from);
                    let b = |k: &str| a.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
                    out.push(ScopeElegible {
                        asset_type: s("asset_type").unwrap_or_default(),
                        asset_identifier: s("asset_identifier").unwrap_or_default(),
                        eligible_for_submission: b("eligible_for_submission"),
                        eligible_for_bounty: b("eligible_for_bounty"),
                        max_severity: s("max_severity"),
                    });
                }
            }
            url = v
                .get("links")
                .and_then(|l| l.get("next"))
                .and_then(|n| n.as_str())
                .map(String::from);
        }
        Ok(out)
    }

    /// Conjunto de CWEs (external_id normalizado, p.ej. "cwe-79") que el programa
    /// ACEPTA, vía GET /programs/{handle}/weaknesses. `None` = no se pudo obtener
    /// la lista (fallo de red/API): el llamante NO debe descartar sobre un None
    /// —fail-open, directiva 30: un fallo de fetch no es un rechazo—. Es la pareja
    /// de lectura de `resolve_weakness_id` (que resuelve a id para el envío); aquí
    /// interesa la PERTENENCIA, con la distinción vacío-vs-fallo explícita.
    pub async fn get_weakness_ids(&self, handle: &str) -> Option<std::collections::HashSet<String>> {
        use std::collections::HashSet;
        let mut set: HashSet<String> = HashSet::new();
        let mut url = Some(format!("{BASE_URL}/hackers/programs/{handle}/weaknesses"));
        while let Some(u) = url {
            let resp = self
                .http
                .get(&u)
                .basic_auth(&self.user, Some(&self.token))
                .header("Accept", "application/json")
                .send()
                .await
                .ok()?;
            if !resp.status().is_success() {
                return None; // fetch falló → Desconocida, no "lista vacía"
            }
            let j: serde_json::Value = resp.json().await.ok()?;
            if let Some(data) = j.get("data").and_then(|d| d.as_array()) {
                for w in data {
                    if let Some(ext) = w
                        .get("attributes")
                        .and_then(|a| a.get("external_id"))
                        .and_then(|e| e.as_str())
                    {
                        let norm = ext.trim().to_lowercase().replace('_', "-");
                        if !norm.is_empty() {
                            set.insert(norm);
                        }
                    }
                }
            }
            url = j
                .get("links")
                .and_then(|l| l.get("next"))
                .and_then(|n| n.as_str())
                .map(String::from);
        }
        Some(set)
    }
}

// ---- Envío de reportes (POST /v1/hackers/reports) ----

#[derive(Serialize)]
struct ReportEnvelope {
    data: ReportData,
}
#[derive(Serialize)]
struct ReportData {
    #[serde(rename = "type")]
    typ: &'static str,
    attributes: ReportAttrs,
}
#[derive(Serialize)]
struct ReportAttrs {
    team_handle: String,
    title: String,
    vulnerability_information: String,
    impact: String,
    severity_rating: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    structured_scope_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weakness_id: Option<String>,
}

impl H1Client {
    /// Refresca el estado de un reporte enviado y el bounty acumulado.
    /// Devuelve (estado, bounty_total). Portado de hack/ `sync_states`.
    pub async fn report_state(&self, report_id: &str) -> Result<(Option<String>, Option<String>)> {
        let resp = self
            .http
            .get(format!("{BASE_URL}/hackers/reports/{report_id}"))
            .basic_auth(&self.user, Some(&self.token))
            .header("Accept", "application/json")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok((None, None));
        }
        let val: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let data = val.get("data");
        let state = data
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("state"))
            .and_then(|s| s.as_str())
            .map(String::from);
        // Suma los bounties del bloque relationships, si hay.
        let mut total = 0.0f64;
        let mut any = false;
        if let Some(bounties) = data
            .and_then(|d| d.get("relationships"))
            .and_then(|r| r.get("bounties"))
            .and_then(|b| b.get("data"))
            .and_then(|d| d.as_array())
        {
            for b in bounties {
                if let Some(amt) = b.get("attributes").and_then(|a| a.get("amount")) {
                    let v = amt.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| amt.as_f64());
                    if let Some(v) = v {
                        total += v;
                        any = true;
                    }
                }
            }
        }
        let bounty = if any { Some(format!("{total:.2}")) } else { None };
        Ok((state, bounty))
    }
}

/// Lo que hace falta para crear un reporte en HackerOne.
///
/// **Va en un struct y no en siete parámetros sueltos, y no es por el aviso de
/// clippy.** Los siete son cadenas: intercambiar `title` con `impact`, o
/// `severity_rating` con `cwe`, compila perfectamente y manda a HackerOne un
/// reporte con los campos cruzados — y enviarlo es IRREVERSIBLE. Con campos
/// nombrados, ese error no se puede escribir.
#[derive(Debug, Clone, Copy)]
pub struct ReporteNuevo<'a> {
    pub team_handle: &'a str,
    pub title: &'a str,
    pub vulnerability_information: &'a str,
    pub impact: &'a str,
    pub severity_rating: &'a str,
    pub structured_scope_id: Option<&'a str>,
    pub cwe: Option<&'a str>,
}

impl H1Client {
    /// Crea un reporte en HackerOne. Devuelve el id del reporte creado.
    /// Es una acción IRREVERSIBLE (sale al mundo): el llamante debe filtrar bien
    /// qué envía (solo VERIFIED+explotable+alta confianza) y deduplicar.
    pub async fn submit_report(&self, r: &ReporteNuevo<'_>) -> Result<String> {
        let ReporteNuevo {
            team_handle,
            title,
            vulnerability_information,
            impact,
            severity_rating,
            structured_scope_id,
            cwe,
        } = *r;
        // S4: resuelve el weakness_id del CWE (fail-safe: se omite ante duda).
        let weakness_id = self.resolve_weakness_id(team_handle, cwe).await;
        let body = ReportEnvelope {
            data: ReportData {
                typ: "report",
                attributes: ReportAttrs {
                    team_handle: team_handle.to_string(),
                    title: title.to_string(),
                    vulnerability_information: vulnerability_information.to_string(),
                    impact: impact.to_string(),
                    severity_rating: severity_rating.to_string(),
                    structured_scope_id: structured_scope_id.map(String::from),
                    weakness_id,
                },
            },
        };
        let resp = self
            .http
            .post(format!("{BASE_URL}/hackers/reports"))
            .basic_auth(&self.user, Some(&self.token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let val: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            return Err(NexusError::Other(format!("H1 rechazó el envío ({status}): {val}")));
        }
        let id = val
            .get("data")
            .and_then(|d| d.get("id"))
            .map(|i| i.to_string())
            .unwrap_or_else(|| "desconocido".into());
        Ok(id)
    }
}

/// Normaliza un asset_identifier a dominio raíz. Devuelve None si no es un
/// dominio limpio (con path, con espacios, sin punto). Portado de recon.py.
pub fn normalize_asset(raw: &str) -> Option<ScopeDomain> {
    let mut ident = raw.trim().to_string();
    let is_wildcard = ident.starts_with("*.");
    if is_wildcard {
        ident = ident[2..].to_string();
    }
    if ident.contains("://") {
        // quedarnos con el netloc
        ident = ident.split("://").nth(1)?.split('/').next()?.to_string();
    }
    if ident.contains('.') && !ident.contains('/') && !ident.contains(' ') && !ident.is_empty() && !ident.contains('*') {
        Some(ScopeDomain { identifier: ident, is_wildcard, id: None })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normaliza_wildcard_y_url() {
        assert_eq!(normalize_asset("*.example.com").unwrap().identifier, "example.com");
        assert!(normalize_asset("*.example.com").unwrap().is_wildcard);
        assert_eq!(normalize_asset("https://api.example.com/v1").unwrap().identifier, "api.example.com");
        assert_eq!(normalize_asset("plain.example.co").unwrap().identifier, "plain.example.co");
    }

    #[test]
    fn rechaza_basura() {
        assert!(normalize_asset("no-dot").is_none());
        assert!(normalize_asset("has space.com").is_none());
        assert!(normalize_asset("*.*.wild").is_none()); // sigue con *
    }

    /// El parseo de `submission_state` DISCRIMINA (D33): "open" ≠ "paused", y la
    /// ausencia del campo → None (fail-safe). Los fixtures son el JSON REAL de la
    /// API (raíz `{id,type,attributes}`, SIN `data`), verificado contra
    /// `GET /hackers/programs/liberapay` el 2026-09-19 (dio `submission_state:
    /// "paused"`). La primera versión del test usaba un envelope `data.attributes`
    /// inventado y pasaba en verde mientras la corrida real fallaba al decodificar
    /// — cazado por probar contra el VPS (D28/D33).
    #[test]
    fn submission_state_discrimina() {
        let open = r#"{"id":"28411","type":"program","attributes":{"handle":"liberapay","submission_state":"open"}}"#;
        let d: ProgramDetail = serde_json::from_str(open).unwrap();
        assert_eq!(d.attributes.submission_state.as_deref(), Some("open"));

        let paused = r#"{"id":"28411","type":"program","attributes":{"handle":"liberapay","submission_state":"paused"}}"#;
        let d: ProgramDetail = serde_json::from_str(paused).unwrap();
        assert_eq!(d.attributes.submission_state.as_deref(), Some("paused"));

        // Caso rojo: campo ausente → None, sin panic (el watcher lo trata como
        // "no concluyente", no como "abierto").
        let ausente = r#"{"id":"28411","type":"program","attributes":{"handle":"liberapay"}}"#;
        let d: ProgramDetail = serde_json::from_str(ausente).unwrap();
        assert_eq!(d.attributes.submission_state, None);
    }
}
