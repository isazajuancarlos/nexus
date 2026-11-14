// SPDX-License-Identifier: MIT
//! Cliente de la API de INVESTIGADOR de Intigriti (segundo proveedor, camino con
//! token). Da lo que el feed público de arkadiyt NO da: los programas a los que
//! el investigador está UNIDO (incluidos privados) con su scope preciso, y la
//! base para enviar reportes por su API.
//!
//! El token sale del entorno (`NEXUS_INTIGRITI_TOKEN`) y NUNCA se registra —
//! mismo trato que `H1_TOKEN` en h1.rs; Juan lo pone en el `.env` del VPS y el
//! código solo lo usa como `Authorization: Bearer`.
//!
//! FORMA DE LA API: verificada en vivo contra el VPS con el PAT real (el stub
//! prueba la suposición, no la realidad — directiva 30). Endpoints y campos por
//! confirmar en la primera corrida con token.

use crate::error::{NexusError, Result};
use crate::h1::{normalize_asset, ScopeDomain};
use crate::sources::ProgramaIntigriti;
use serde::Deserialize;
use std::time::Duration;

const BASE_URL: &str = "https://api.intigriti.com/external/researcher/v1";

pub struct IntigritiClient {
    http: reqwest::Client,
    token: String,
}

impl IntigritiClient {
    /// Construye el cliente con el token de `NEXUS_INTIGRITI_TOKEN`. Falla con
    /// `NoCredentials` si no está —el llamante decide si eso es fatal o «sáltate
    /// Intigriti y sigue» (directiva 20: falla ruidoso, no inventa)—.
    pub fn from_env(user_agent: &str) -> Result<Self> {
        let token = std::env::var("NEXUS_INTIGRITI_TOKEN").map_err(|_| NexusError::NoCredentials)?;
        if token.trim().is_empty() {
            return Err(NexusError::NoCredentials);
        }
        let http = reqwest::Client::builder()
            .user_agent(user_agent.to_string())
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { http, token })
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<T>().await?)
    }

    /// Programas a los que el investigador está unido, ya con su scope preciso —
    /// listos para `db::seed_intigriti_programs` (mismo tipo que el feed público,
    /// así que reutiliza la siembra). Un fallo al traer el scope de UN programa
    /// no tumba el resto (directiva 20).
    pub async fn programas_con_scope(&self) -> Result<Vec<ProgramaIntigriti>> {
        let handles = self.listar_programas().await?;
        let mut out = Vec::new();
        for p in handles {
            match self.scope_de(&p.guid).await {
                Ok(scope) if !scope.is_empty() => out.push(ProgramaIntigriti {
                    handle: p.handle,
                    guid: p.guid,
                    scope,
                }),
                Ok(_) => tracing::info!("intigriti: {} sin scope web, se salta", p.handle),
                Err(e) => tracing::warn!("intigriti: scope de {}: {e}", p.handle),
            }
        }
        Ok(out)
    }

    /// Lista paginada de los programas del investigador. `following=true` los
    /// acota a los SUYOS (no todo el catálogo); `statusId=3` = «Open». Wrapper
    /// `{ maxCount, records }` (forma verificada en la doc oficial).
    async fn listar_programas(&self) -> Result<Vec<ProgramaMeta>> {
        let mut out = Vec::new();
        let mut offset = 0u32;
        const LIMITE: u32 = 50;
        loop {
            let url = format!(
                "{BASE_URL}/programs?following=true&statusId=3&limit={LIMITE}&offset={offset}"
            );
            let pagina: RespuestaProgramas = self.get_json(&url).await?;
            let n = pagina.records.len() as u32;
            for r in pagina.records {
                if let (Some(guid), Some(handle)) = (r.id, r.handle) {
                    out.push(ProgramaMeta { guid, handle });
                }
            }
            if n < LIMITE {
                break;
            }
            offset += LIMITE;
        }
        Ok(out)
    }

    /// Dominios web in-scope de un programa. Son DOS llamadas (forma verificada):
    /// el detalle da el `versionId` del scope (`domains.id`), y con él se pide la
    /// lista real de activos. Se normalizan igual que el scope de H1 y el del feed
    /// (para que el filtro downstream funcione).
    async fn scope_de(&self, guid: &str) -> Result<Vec<ScopeDomain>> {
        let detalle: DetallePrograma = self.get_json(&format!("{BASE_URL}/programs/{guid}")).await?;
        let version = match detalle.domains.and_then(|d| d.id) {
            Some(v) => v,
            None => return Ok(Vec::new()), // sin versión de scope: nada que traer
        };
        let dom: RespuestaDominios = self
            .get_json(&format!("{BASE_URL}/programs/{guid}/domains/{version}"))
            .await?;
        Ok(activos_web(dom.domains.map(|d| d.content).unwrap_or_default()))
    }
}

/// Filtra los activos a solo dominios WEB y los normaliza. El `type` es un enum
/// {id,value} —"WebApplication", "Url", "Wildcard"…—; el resto (IpRange, Mobile,
/// Device, Other) no son objetivos de recon/nuclei. Puro (testeable sin red).
fn activos_web(content: Vec<ActivoApi>) -> Vec<ScopeDomain> {
    content
        .into_iter()
        .filter(|a| {
            let t = a.tipo.as_ref().map(|e| e.value.to_lowercase()).unwrap_or_default();
            t.contains("web") || t.contains("url") || t.contains("wildcard") || t.contains("domain")
        })
        .filter_map(|a| a.endpoint.as_deref().and_then(normalize_asset))
        .collect()
}

struct ProgramaMeta {
    guid: String,
    handle: String,
}

// ---- Formas de la respuesta (verificadas contra la doc oficial de la API) ----

#[derive(Deserialize)]
struct RespuestaProgramas {
    #[serde(default)]
    records: Vec<ProgramaApi>,
}

#[derive(Deserialize)]
struct ProgramaApi {
    id: Option<String>,
    handle: Option<String>,
}

/// Detalle: `domains` es un objeto-versión con su `id` (el versionId del scope),
/// NO la lista de activos —esa se pide aparte con ese id—.
#[derive(Deserialize)]
struct DetallePrograma {
    #[serde(default)]
    domains: Option<Version>,
}

#[derive(Deserialize)]
struct Version {
    id: Option<String>,
}

/// La respuesta del endpoint de dominios: `{ domains: { content: [...] } }`.
#[derive(Deserialize)]
struct RespuestaDominios {
    #[serde(default)]
    domains: Option<ContenidoDominios>,
}

#[derive(Deserialize)]
struct ContenidoDominios {
    #[serde(default)]
    content: Vec<ActivoApi>,
}

#[derive(Deserialize)]
struct ActivoApi {
    #[serde(rename = "type", default)]
    tipo: Option<Enum>,
    endpoint: Option<String>,
}

/// Los `EnumerationViewModel` de Intigriti: `{ id, value }`.
#[derive(Deserialize)]
struct Enum {
    #[serde(default)]
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **El scope se filtra a WEB y se normaliza** (forma real del endpoint de
    /// dominios). Control (directiva 33): IpRange (CIDR) y MobileApplication NO
    /// entran; WebApplication (URL→netloc) y Wildcard (sin `*.`) sí.
    #[test]
    fn scope_solo_web_normalizado() {
        let json = r#"{"domains":{"id":"v1","createdAt":1672531200000,"content":[
            {"id":"a","type":{"id":1,"value":"WebApplication"},"endpoint":"https://app.example.com/x","tier":{"id":2,"value":"P2"}},
            {"id":"b","type":{"id":9,"value":"Wildcard"},"endpoint":"*.example.org"},
            {"id":"c","type":{"id":5,"value":"IpRange"},"endpoint":"1.2.3.0/24"},
            {"id":"d","type":{"id":7,"value":"MobileApplication"},"endpoint":"com.example.app"}
        ]}}"#;
        let r: RespuestaDominios = serde_json::from_str(json).unwrap();
        let web = activos_web(r.domains.unwrap().content);
        let ids: Vec<&str> = web.iter().map(|d| d.identifier.as_str()).collect();
        assert!(ids.contains(&"app.example.com"), "WebApplication → netloc");
        assert!(web.iter().any(|d| d.identifier == "example.org" && d.is_wildcard), "wildcard sin *.");
        assert!(!ids.iter().any(|i| i.contains("1.2.3") || i.contains("com.example")), "CIDR y móvil fuera");
        assert_eq!(web.len(), 2);
    }

    #[test]
    fn lista_de_programas_lee_el_wrapper_records() {
        let json = r#"{"maxCount":1,"records":[{"id":"550e-guid","handle":"acme","name":"ACME","status":{"id":3,"value":"Open"}}]}"#;
        let r: RespuestaProgramas = serde_json::from_str(json).unwrap();
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.records[0].id.as_deref(), Some("550e-guid"));
        assert_eq!(r.records[0].handle.as_deref(), Some("acme"));
    }

    #[test]
    fn el_detalle_da_el_versionid_del_scope() {
        let json = r#"{"id":"p","handle":"acme","domains":{"id":"ver-guid","content":[]}}"#;
        let d: DetallePrograma = serde_json::from_str(json).unwrap();
        assert_eq!(d.domains.and_then(|v| v.id).as_deref(), Some("ver-guid"));
    }
}
