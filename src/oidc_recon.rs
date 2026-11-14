//! Recon de RELYING-PARTIES / audiencias OIDC-OAuth — el mapa que alimenta el
//! oráculo de **confusión de audiencia** (token sobre-privilegiado, CWE-269/863).
//!
//! Lo aprendido del caso Hacktron→OpenAI: un token emitido para un RP de baja
//! confianza (el foro) fue aceptado por la API core porque no se validó `aud`.
//! Para razonar eso en un objetivo real hace falta el MAPA: qué IdP hay, qué RPs
//! comparten ese IdP, y qué scope/audiencia pide cada uno. Este módulo lo arma:
//!
//!  - descubre el IdP leyendo `/.well-known/openid-configuration` (metadato
//!    PÚBLICO por diseño; GET no destructivo, vía `impersonate::fetch_evasion`);
//!  - parsea URLs de `authorize` OBSERVADAS (que aporta el analista) → cada RP con
//!    su `client_id`, host de `redirect_uri`, `scope` y `resource`/`audience`.
//!
//! NO dispara nada contra el objetivo más allá de leer el discovery público. La
//! confirmación (reproducir un token de un RP contra otra audiencia) es del
//! ORÁCULO, que necesita blanco autorizado y el go de Juan; aquí solo se MAPEA.

use serde::Serialize;

/// El proveedor de identidad, tal como se anuncia en su discovery.
#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Idp {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub algs: Vec<String>,
    pub claims_supported: Vec<String>,
}

/// Un relying-party observado (de una URL de authorize).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Rp {
    pub client_id: String,
    pub redirect_host: String,
    pub scopes: Vec<String>,
    /// `resource` (RFC 8707) o `audience` que el RP pide explícitamente, si hay.
    pub audiencia_pedida: Option<String>,
}

/// El mapa de audiencias de un objetivo, con los pares candidatos a probar.
#[derive(Debug, Default, Serialize)]
pub struct MapaAudiencias {
    pub idp: Option<Idp>,
    pub rps: Vec<Rp>,
    /// (i, j, motivo): reproducir el token del RP i contra la audiencia del RP j
    /// es un CANDIDATO a confusión de audiencia. Es un LEAD, no un hallazgo: el
    /// razonador lo refuta y el oráculo lo confirma por ejecución.
    pub pares_candidatos: Vec<(usize, usize, String)>,
}

fn lista_str(v: &serde_json::Value, campo: &str) -> Vec<String> {
    v.get(campo)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Parsea un documento de discovery OIDC/OAuth (puro). `None` si no es JSON o no
/// tiene `issuer`.
pub fn parsear_discovery(json: &str) -> Option<Idp> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let issuer = v.get("issuer")?.as_str()?.to_string();
    let s = |c: &str| v.get(c).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(Idp {
        issuer,
        authorization_endpoint: s("authorization_endpoint"),
        token_endpoint: s("token_endpoint"),
        jwks_uri: s("jwks_uri"),
        scopes_supported: lista_str(&v, "scopes_supported"),
        algs: lista_str(&v, "id_token_signing_alg_values_supported"),
        claims_supported: lista_str(&v, "claims_supported"),
    })
}

/// Parsea una URL de `authorize` observada → el RP que la originó (puro). `None`
/// si no trae `client_id`.
pub fn parsear_authorize(url: &str) -> Option<Rp> {
    let u = reqwest::Url::parse(url).ok()?;
    let mut client_id = None;
    let mut redirect = None;
    let mut scope = None;
    let mut resource = None;
    let mut audience = None;
    for (k, val) in u.query_pairs() {
        match k.as_ref() {
            "client_id" => client_id = Some(val.into_owned()),
            "redirect_uri" => redirect = Some(val.into_owned()),
            "scope" => scope = Some(val.into_owned()),
            "resource" => resource = Some(val.into_owned()),
            "audience" | "aud" => audience = Some(val.into_owned()),
            _ => {}
        }
    }
    let client_id = client_id?;
    let redirect_host = redirect
        .as_deref()
        .and_then(|r| reqwest::Url::parse(r).ok())
        .and_then(|r| r.host_str().map(String::from))
        .unwrap_or_default();
    let scopes = scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();
    Some(Rp {
        client_id,
        redirect_host,
        scopes,
        audiencia_pedida: resource.or(audience),
    })
}

/// Arma el mapa: IdP + RPs + pares candidatos. Un par (i,j) es candidato si son
/// RPs DISTINTOS: siempre vale preguntar si el token de i lo acepta la audiencia
/// de j. Se anota el MOTIVO priorizando la asimetría de confianza (j pide scopes
/// que i no) — ahí es donde un token de baja confianza tocaría privilegio mayor.
pub fn construir_mapa(idp: Option<Idp>, rps: Vec<Rp>) -> MapaAudiencias {
    // Cada par dirigido i→j: "el token de i, ¿lo acepta la audiencia de j?".
    // El PELIGRO es cuando j tiene MÁS privilegio que i (baja confianza → alta),
    // que es el caso OpenAI. Prioridad = cuántos scopes tiene j que i no.
    let mut bruto: Vec<(usize, usize, usize, String)> = Vec::new();
    for i in 0..rps.len() {
        for j in 0..rps.len() {
            if i == j || rps[i].client_id == rps[j].client_id {
                continue;
            }
            let extra: Vec<&String> =
                rps[j].scopes.iter().filter(|s| !rps[i].scopes.contains(s)).collect();
            let motivo = if extra.is_empty() {
                "misma superficie de scope; probar aceptación cruzada de todos modos".to_string()
            } else {
                format!(
                    "asimetría: '{}' pide scopes que '{}' no ({})",
                    rps[j].client_id,
                    rps[i].client_id,
                    extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
                )
            };
            bruto.push((i, j, extra.len(), motivo));
        }
    }
    // más privilegio ganado primero (el cruce baja→alta confianza es el peligroso)
    bruto.sort_by_key(|a| std::cmp::Reverse(a.2));
    let pares_candidatos = bruto.into_iter().map(|(i, j, _, m)| (i, j, m)).collect();
    MapaAudiencias { idp, rps, pares_candidatos }
}

/// DESCUBRE el IdP de un origen leyendo su discovery público (GET no destructivo,
/// cruza WAF vía `fetch_evasion`). Prueba openid-configuration y oauth-authorization-server.
pub async fn descubrir_idp(
    cliente: &reqwest::Client,
    origen: &str,
    curl_impersonate_path: &str,
) -> Option<Idp> {
    let base = origen.trim_end_matches('/');
    for disc in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let r = crate::impersonate::fetch_evasion(
            cliente,
            &format!("{base}{disc}"),
            &[],
            curl_impersonate_path,
            12,
        )
        .await;
        if let Some(idp) = parsear_discovery(&r.body) {
            return Some(idp);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVERY: &str = r#"{
        "issuer": "https://auth.ejemplo.com",
        "authorization_endpoint": "https://auth.ejemplo.com/authorize",
        "token_endpoint": "https://auth.ejemplo.com/oauth/token",
        "jwks_uri": "https://auth.ejemplo.com/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "api:core", "foro:leer"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "claims_supported": ["sub", "aud", "email"]
    }"#;

    #[test]
    fn parsea_discovery_completo() {
        let idp = parsear_discovery(DISCOVERY).unwrap();
        assert_eq!(idp.issuer, "https://auth.ejemplo.com");
        assert_eq!(idp.token_endpoint, "https://auth.ejemplo.com/oauth/token");
        assert!(idp.scopes_supported.contains(&"api:core".to_string()));
        assert!(idp.algs.contains(&"HS256".to_string()));
    }

    #[test]
    fn discovery_invalido_es_none() {
        assert!(parsear_discovery("no soy json").is_none());
        assert!(parsear_discovery(r#"{"foo":1}"#).is_none()); // sin issuer
    }

    #[test]
    fn parsea_authorize_con_scope_y_resource() {
        let url = "https://auth.ejemplo.com/authorize?response_type=code&client_id=foro-web&redirect_uri=https%3A%2F%2Fforo.ejemplo.com%2Fcb&scope=openid%20foro%3Aleer&resource=https%3A%2F%2Fforo.ejemplo.com";
        let rp = parsear_authorize(url).unwrap();
        assert_eq!(rp.client_id, "foro-web");
        assert_eq!(rp.redirect_host, "foro.ejemplo.com");
        assert!(rp.scopes.contains(&"foro:leer".to_string()));
        assert_eq!(rp.audiencia_pedida.as_deref(), Some("https://foro.ejemplo.com"));
    }

    #[test]
    fn authorize_sin_client_id_es_none() {
        assert!(parsear_authorize("https://x.com/authorize?scope=openid").is_none());
    }

    #[test]
    fn mapa_marca_par_asimetrico_primero() {
        let foro = Rp { client_id: "foro".into(), redirect_host: "foro.x".into(), scopes: vec!["foro:leer".into()], audiencia_pedida: None };
        let core = Rp { client_id: "core".into(), redirect_host: "api.x".into(), scopes: vec!["api:core".into(), "api:admin".into()], audiencia_pedida: None };
        let mapa = construir_mapa(None, vec![foro, core]);
        // 2 RPs distintos → 2 pares dirigidos (foro→core y core→foro)
        assert_eq!(mapa.pares_candidatos.len(), 2);
        // el primero debe ser el asimétrico foro→core (token de foro contra audiencia core)
        let (i, j, motivo) = &mapa.pares_candidatos[0];
        assert_eq!(mapa.rps[*i].client_id, "foro");
        assert_eq!(mapa.rps[*j].client_id, "core");
        assert!(motivo.contains("asimetría"));
    }
}
