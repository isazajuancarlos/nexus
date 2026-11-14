//! Fuentes de programas/scope además de la API de HackerOne. Cascada
//! configurable (directiva 19): H1 (preciso, con cuenta) + arkadiyt (ancho, sin
//! cuenta) + Chaos (lista pública). Los parsers son puros y testables; el fetch
//! es una capa fina sobre reqwest.

use crate::error::Result;
use crate::h1::normalize_asset;
use serde::Deserialize;

const ARK_BASE: &str = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data";
// Ruta actual (el repo se reestructuró: la lista compilada vive en dist/data.json).
const CHAOS_URL: &str =
    "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json";

/// Normaliza líneas de dominio (una por línea, admite `*.dom` y URLs). Puro.
pub fn parse_domain_lines(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| normalize_asset(l).map(|d| d.identifier))
        .collect()
}

// ------------------------------------------------------------------------------
// arkadiyt/bounty-targets-data — parseo POR PLATAFORMA con filtro de "solo pagan".
// El domains.txt plano incluye VDPs sin recompensa; estos JSON llevan el importe.
// ------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ArkScope<T> {
    #[serde(default)]
    in_scope: Vec<T>,
}

// HackerOne: paga si offers_bounties; target válido si eligible_for_bounty.
#[derive(Deserialize)]
struct ArkH1 {
    #[serde(default)]
    offers_bounties: bool,
    #[serde(default)]
    targets: ArkScope<ArkH1Target>,
}
#[derive(Deserialize, Default)]
struct ArkH1Target {
    #[serde(default)]
    eligible_for_bounty: bool,
    asset_identifier: Option<String>,
}

// Bugcrowd: paga si max_payout > 0.
#[derive(Deserialize)]
struct ArkBc {
    #[serde(default)]
    max_payout: f64,
    #[serde(default)]
    targets: ArkScope<ArkBcTarget>,
}
#[derive(Deserialize, Default)]
struct ArkBcTarget {
    target: Option<String>,
    uri: Option<String>,
}

// Intigriti: paga si max_bounty.value > 0. Target en `endpoint`, con `type`
// (url|wildcard|device|ios|android|iprange|other). `handle` es el slug del
// programa (identidad); `id` es el GUID nativo (para el envío por API con token).
#[derive(Deserialize)]
struct ArkIn {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    id: Option<String>,
    max_bounty: Option<ArkAmount>,
    #[serde(default)]
    targets: ArkScope<ArkInTarget>,
}
#[derive(Deserialize)]
struct ArkAmount {
    #[serde(default)]
    value: f64,
}
#[derive(Deserialize, Default)]
struct ArkInTarget {
    endpoint: Option<String>,
    #[serde(rename = "type", default)]
    tipo: Option<String>,
}

// YesWeHack: paga si max_bounty > 0. Target en `target`.
#[derive(Deserialize)]
struct ArkYwh {
    #[serde(default)]
    max_bounty: f64,
    #[serde(default)]
    targets: ArkScope<ArkYwhTarget>,
}
#[derive(Deserialize, Default)]
struct ArkYwhTarget {
    target: Option<String>,
}

fn norm_push(out: &mut Vec<String>, raw: Option<&str>) {
    if let Some(r) = raw {
        if let Some(d) = normalize_asset(r) {
            out.push(d.identifier);
        }
    }
}

// Handles de programas H1 que pagan y con submission abierto (para el cazador).
#[derive(Deserialize)]
struct ArkH1Prog {
    handle: Option<String>,
    #[serde(default)]
    offers_bounties: bool,
    #[serde(default)]
    submission_state: Option<String>,
}

/// Handles de programas H1 que pagan y con submission abierto. Puro.
pub fn parse_ark_handles(s: &str) -> Vec<String> {
    let progs: Vec<ArkH1Prog> = serde_json::from_str(s).unwrap_or_default();
    progs
        .into_iter()
        .filter(|p| p.offers_bounties && p.submission_state.as_deref() == Some("open"))
        .filter_map(|p| p.handle)
        .collect()
}

/// Descarga los handles H1 que pagan (para sembrar el cazador por BD).
pub async fn fetch_h1_handles(client: &reqwest::Client) -> Result<Vec<String>> {
    let url = format!("{ARK_BASE}/hackerone_data.json");
    let txt = get_text(client, &url).await?;
    Ok(parse_ark_handles(&txt))
}

/// H1 de arkadiyt, solo programas que pagan y targets elegibles. Puro.
pub fn parse_ark_hackerone(s: &str) -> Vec<String> {
    let progs: Vec<ArkH1> = serde_json::from_str(s).unwrap_or_default();
    let mut out = Vec::new();
    for p in progs {
        if !p.offers_bounties {
            continue;
        }
        for t in p.targets.in_scope {
            if t.eligible_for_bounty {
                norm_push(&mut out, t.asset_identifier.as_deref());
            }
        }
    }
    out
}

/// Bugcrowd de arkadiyt, solo programas con max_payout > 0. Puro.
pub fn parse_ark_bugcrowd(s: &str) -> Vec<String> {
    let progs: Vec<ArkBc> = serde_json::from_str(s).unwrap_or_default();
    let mut out = Vec::new();
    for p in progs {
        if p.max_payout <= 0.0 {
            continue;
        }
        for t in p.targets.in_scope {
            norm_push(&mut out, t.uri.as_deref().or(t.target.as_deref()));
        }
    }
    out
}

/// Intigriti de arkadiyt, solo programas con max_bounty.value > 0. Puro.
pub fn parse_ark_intigriti(s: &str) -> Vec<String> {
    let progs: Vec<ArkIn> = serde_json::from_str(s).unwrap_or_default();
    let mut out = Vec::new();
    for p in progs {
        if p.max_bounty.map(|b| b.value).unwrap_or(0.0) <= 0.0 {
            continue;
        }
        for t in p.targets.in_scope {
            norm_push(&mut out, t.endpoint.as_deref());
        }
    }
    out
}

/// Un programa de Intigriti extraído del feed público de arkadiyt: su slug
/// (identidad), su GUID nativo (para el envío por API con token, hoy sin usar) y
/// su scope web ya normalizado. Solo dominios: `url`/`wildcard`; los tipos
/// device/ios/android/iprange/other no son objetivos de recon.
pub struct ProgramaIntigriti {
    pub handle: String,
    pub guid: String,
    pub scope: Vec<crate::h1::ScopeDomain>,
}

/// Programas de Intigriti que PAGAN, con su scope web, del feed de arkadiyt.
/// Puro. Descarta el que no paga, el que no trae handle/guid, y el que se queda
/// sin un solo dominio web tras normalizar (nada que cazar). Es lo que
/// `parse_ark_intigriti` (que aplana a dominios sueltos) no da: la IDENTIDAD del
/// programa, para meterlo como ciudadano de 1ª en la cola de caza.
pub fn parse_ark_intigriti_programs(s: &str) -> Vec<ProgramaIntigriti> {
    let progs: Vec<ArkIn> = serde_json::from_str(s).unwrap_or_default();
    let mut out = Vec::new();
    for p in progs {
        if p.max_bounty.map(|b| b.value).unwrap_or(0.0) <= 0.0 {
            continue;
        }
        let (Some(handle), Some(guid)) = (p.handle, p.id) else {
            continue;
        };
        if handle.trim().is_empty() {
            continue;
        }
        let mut scope = Vec::new();
        for t in p.targets.in_scope {
            if !matches!(t.tipo.as_deref(), Some("url") | Some("wildcard")) {
                continue;
            }
            if let Some(ep) = t.endpoint.as_deref() {
                if let Some(d) = normalize_asset(ep) {
                    scope.push(d);
                }
            }
        }
        if scope.is_empty() {
            continue;
        }
        out.push(ProgramaIntigriti { handle, guid, scope });
    }
    out
}

/// YesWeHack de arkadiyt, solo programas con max_bounty > 0. Puro.
pub fn parse_ark_yeswehack(s: &str) -> Vec<String> {
    let progs: Vec<ArkYwh> = serde_json::from_str(s).unwrap_or_default();
    let mut out = Vec::new();
    for p in progs {
        if p.max_bounty <= 0.0 {
            continue;
        }
        for t in p.targets.in_scope {
            norm_push(&mut out, t.target.as_deref());
        }
    }
    out
}

#[derive(Deserialize)]
struct ChaosList {
    #[serde(default)]
    programs: Vec<ChaosProgram>,
}
#[derive(Deserialize)]
struct ChaosProgram {
    #[serde(default)]
    bounty: bool,
    #[serde(default)]
    domains: Vec<String>,
}

/// Extrae dominios de la lista Chaos. Si `only_bounty`, solo programas que pagan.
/// Puro.
pub fn parse_chaos_json(s: &str, only_bounty: bool) -> Vec<String> {
    let list: ChaosList = match serde_json::from_str(s) {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for p in list.programs {
        if only_bounty && !p.bounty {
            continue;
        }
        for d in p.domains {
            if let Some(dom) = normalize_asset(&d) {
                out.push(dom.identifier);
            }
        }
    }
    out
}

async fn get_text(client: &reqwest::Client, url: &str) -> Result<String> {
    Ok(client.get(url).send().await?.error_for_status()?.text().await?)
}

/// Descarga arkadiyt/bounty-targets-data por plataforma (H1 + Bugcrowd +
/// Intigriti + YesWeHack) y devuelve SOLO dominios de programas que pagan.
/// Sin cuenta. Cada plataforma que falle se salta (no aborta).
pub async fn fetch_arkadiyt(client: &reqwest::Client) -> Result<Vec<String>> {
    let mut out = Vec::new();
    /// Un archivo del volcado de arkadiyt y el analizador que lo entiende.
    /// Nombrado porque el tipo crudo no se lee: `fn(&str) -> Vec<String>` es
    /// «de este JSON saca dominios», y así lo dice.
    type Plataforma = (&'static str, fn(&str) -> Vec<String>);
    let platforms: [Plataforma; 4] = [
        ("hackerone_data.json", parse_ark_hackerone),
        ("bugcrowd_data.json", parse_ark_bugcrowd),
        ("intigriti_data.json", parse_ark_intigriti),
        ("yeswehack_data.json", parse_ark_yeswehack),
    ];
    for (file, parse) in platforms {
        let url = format!("{ARK_BASE}/{file}");
        match get_text(client, &url).await {
            Ok(txt) => {
                let found = parse(&txt);
                tracing::info!("arkadiyt {file}: +{} dominios que pagan", found.len());
                out.extend(found);
            }
            Err(e) => tracing::warn!("arkadiyt {file}: {e}"),
        }
    }
    Ok(out)
}

/// Descarga los PROGRAMAS de Intigriti (con su identidad y scope) del feed
/// público de arkadiyt. Sin cuenta ni token: es el camino para meter programas
/// de Intigriti en la cola de caza sin el API de investigador.
pub async fn fetch_ark_intigriti_programs(client: &reqwest::Client) -> Result<Vec<ProgramaIntigriti>> {
    let url = format!("{ARK_BASE}/intigriti_data.json");
    let txt = get_text(client, &url).await?;
    Ok(parse_ark_intigriti_programs(&txt))
}

/// Descarga la lista pública de programas con bounty de ProjectDiscovery (Chaos).
pub async fn fetch_chaos(client: &reqwest::Client) -> Result<Vec<String>> {
    let txt = get_text(client, CHAOS_URL).await?;
    Ok(parse_chaos_json(&txt, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsea_lineas_de_dominio() {
        let s = "example.com\n*.wild.com\nhttps://api.foo.com/x\nbasura sin punto\n\n";
        let got = parse_domain_lines(s);
        assert!(got.contains(&"example.com".to_string()));
        assert!(got.contains(&"wild.com".to_string())); // *. quitado
        assert!(got.contains(&"api.foo.com".to_string())); // URL → netloc
        assert!(!got.iter().any(|d| d.contains(' '))); // basura descartada
    }

    /// **`parse_ark_intigriti_programs` — forma REAL del feed (verificada).**
    ///   - VERDE: un programa que paga entra con su handle+guid y SOLO su scope
    ///     web (url/wildcard normalizado).
    ///   - ROJO/control (directiva 33): el no-pagador se descarta; los tipos
    ///     ios/android/iprange/device/other NO entran como scope (mutante = quitar
    ///     el filtro de tipo: aparecería "1519034860"); y un programa cuyo scope
    ///     es SOLO app-móvil se descarta entero (sin dominio web = nada que cazar).
    #[test]
    fn intigriti_programas_solo_pagadores_con_scope_web() {
        let json = r#"[
          {"handle":"aikido","id":"554fc6c5-guid","max_bounty":{"value":2500},
           "targets":{"in_scope":[
             {"type":"url","endpoint":"app.aikido.dev"},
             {"type":"wildcard","endpoint":"*.ad.nl"},
             {"type":"ios","endpoint":"1519034860"},
             {"type":"android","endpoint":"de.bmw.app"}
           ]}},
          {"handle":"nopaga","id":"g2","max_bounty":{"value":0},
           "targets":{"in_scope":[{"type":"url","endpoint":"nopaga.com"}]}},
          {"handle":"soloapp","id":"g3","max_bounty":{"value":100},
           "targets":{"in_scope":[{"type":"ios","endpoint":"999"}]}}
        ]"#;
        let progs = parse_ark_intigriti_programs(json);
        assert_eq!(progs.len(), 1, "solo aikido: paga y tiene scope web");
        let a = &progs[0];
        assert_eq!(a.handle, "aikido");
        assert_eq!(a.guid, "554fc6c5-guid");
        // Solo url + wildcard normalizados (el wildcard pierde el `*.`).
        let idents: Vec<&str> = a.scope.iter().map(|d| d.identifier.as_str()).collect();
        assert!(idents.contains(&"app.aikido.dev"));
        assert!(idents.contains(&"ad.nl"));
        assert!(a.scope.iter().any(|d| d.identifier == "ad.nl" && d.is_wildcard));
        // Los tipos móvil/otros NO entran (el mutante sin filtro dejaría "1519034860").
        assert!(!idents.iter().any(|i| i.contains("1519034860") || i.contains("bmw")));
        assert_eq!(a.scope.len(), 2, "solo los 2 dominios web");
    }

    #[test]
    fn arkadiyt_h1_solo_paga_y_elegible() {
        let j = r#"[
          {"offers_bounties":true,"targets":{"in_scope":[
             {"eligible_for_bounty":true,"asset_identifier":"paga.com"},
             {"eligible_for_bounty":false,"asset_identifier":"noelegible.com"}]}},
          {"offers_bounties":false,"targets":{"in_scope":[
             {"eligible_for_bounty":true,"asset_identifier":"vdp.com"}]}}
        ]"#;
        let got = parse_ark_hackerone(j);
        assert_eq!(got, vec!["paga.com"]); // ni el no-elegible ni el VDP
    }

    #[test]
    fn arkadiyt_bugcrowd_intigriti_ywh_filtran_por_pago() {
        let bc = r#"[
          {"max_payout":7500,"targets":{"in_scope":[{"target":"a.com","uri":"http://a.com/"}]}},
          {"max_payout":0,"targets":{"in_scope":[{"target":"gratis.com","uri":"gratis.com"}]}}]"#;
        assert_eq!(parse_ark_bugcrowd(bc), vec!["a.com"]);

        let intg = r#"[
          {"max_bounty":{"value":2500,"currency":"EUR"},"targets":{"in_scope":[{"endpoint":"app.foo.com"}]}},
          {"max_bounty":{"value":0,"currency":"EUR"},"targets":{"in_scope":[{"endpoint":"gratis.foo"}]}}]"#;
        assert_eq!(parse_ark_intigriti(intg), vec!["app.foo.com"]);

        let ywh = r#"[
          {"max_bounty":5000,"targets":{"in_scope":[{"target":"https://b.com/"}]}},
          {"max_bounty":0,"targets":{"in_scope":[{"target":"gratis.b"}]}}]"#;
        assert_eq!(parse_ark_yeswehack(ywh), vec!["b.com"]);
    }

    #[test]
    fn handles_solo_pagan_y_abiertos() {
        let j = r#"[
          {"handle":"acme","offers_bounties":true,"submission_state":"open"},
          {"handle":"paused","offers_bounties":true,"submission_state":"paused"},
          {"handle":"vdp","offers_bounties":false,"submission_state":"open"}
        ]"#;
        assert_eq!(parse_ark_handles(j), vec!["acme"]);
    }

    #[test]
    fn arkadiyt_json_invalido_no_revienta() {
        assert!(parse_ark_hackerone("no json").is_empty());
        assert!(parse_ark_bugcrowd("{}").is_empty());
    }

    #[test]
    fn parsea_chaos_solo_bounty() {
        let j = r#"{"programs":[
            {"name":"A","bounty":true,"domains":["a.com","*.a.net"]},
            {"name":"B","bounty":false,"domains":["b.com"]}
        ]}"#;
        let paga = parse_chaos_json(j, true);
        assert!(paga.contains(&"a.com".to_string()));
        assert!(paga.contains(&"a.net".to_string()));
        assert!(!paga.contains(&"b.com".to_string())); // B no paga
        // Sin filtro, entra B.
        assert!(parse_chaos_json(j, false).contains(&"b.com".to_string()));
        // JSON inválido → vacío, no pánico.
        assert!(parse_chaos_json("no json", true).is_empty());
    }
}
