// SPDX-License-Identifier: LicenseRef-Propietario
//! Filtro de OPERABILIDAD IDOR: rankea el pool de programas por qué tan barato y
//! probable es montar un test de IDOR horizontal, con señales que se derivan del
//! SCOPE **sin sondear en vivo**.
//!
//! El motor autz está validado 3 veces (imgur, MercadoLibre, insightly); el
//! cuello nunca fue el motor sino ADQUIRIR dos identidades-par, y eso cuesta
//! según el objetivo (API-key trivial vs OAuth+TOTP caro vs cookie httpOnly). Este
//! filtro dice DÓNDE invertir el montaje de dos cuentas antes de gastar un request.
//!
//! Señales OFFLINE (no tocan la red):
//!   + host de API en scope (`api.*`, `/api`, `.api.`) → REST con id en la ruta.
//!   + paga (`eligible_for_bounty`).
//!   + superficie de API (nº de assets de API).
//!   - el nombre sugiere KYC financiero (banco/inversión/cripto…) → dos cuentas
//!     self-serve son caras o imposibles (medido: fintech pide verificación).
//!
//! Lo que NO se infiere offline —modelo de auth exacto, self-serve real, madurez—
//! queda para un sondeo posterior; este filtro ACOTA el pool a los candidatos
//! baratos. Es una penalización/bonus SUAVE al score, no un filtro duro: un
//! demote injusto baja el candidato, no lo borra (directiva 20/23).

use sqlx::SqlitePool;

#[derive(Debug, Clone)]
pub struct Operabilidad {
    pub programa: String,
    pub puntuacion: i32,
    pub tiene_api: bool,
    pub api_assets: usize,
    pub paga: bool,
    pub kyc_probable: bool,
    pub razones: Vec<String>,
}

/// ¿El asset es un host/ruta de API? (REST con id en la ruta = testeable por autz.)
pub fn es_asset_api(asset: &str) -> bool {
    let a = asset.to_ascii_lowercase();
    a.starts_with("api.")
        || a.starts_with("api-")
        || a.contains(".api.")
        || a.contains("//api.")
        || a.contains("/api/")
        || a.contains("/api.")
}

/// ¿El nombre sugiere un producto con KYC financiero? Entonces dos cuentas
/// self-serve son caras/bloqueadas. Lista ESPECÍFICA (directiva 23): señales
/// FUERTES de finanzas. Penalización SUAVE, no filtro duro.
pub fn kyc_probable(nombre: &str) -> bool {
    let n = nombre.to_ascii_lowercase();
    const SENIALES: &[&str] = &[
        "bank", "banking", "capital", "invest", "trading", "broker", "brokerage",
        "crypto", "securities", "wealth", "lending", "loan", "insurance",
        "fintech", "kyc",
    ];
    SENIALES.iter().any(|s| n.contains(s))
}

/// Puntúa un programa por operabilidad IDOR a partir de su nombre y sus scopes
/// (`asset_identifier`, `eligible_for_bounty`). Puro y testeable.
pub fn puntuar(nombre: &str, scopes: &[(String, bool)]) -> Operabilidad {
    let api_assets = scopes.iter().filter(|(a, _)| es_asset_api(a)).count();
    let tiene_api = api_assets > 0;
    let paga = scopes.iter().any(|(_, e)| *e);
    let kyc = kyc_probable(nombre);

    let mut puntuacion = 0i32;
    let mut razones = Vec::new();
    if tiene_api {
        puntuacion += 30;
        razones.push(format!("+30 API en scope ({api_assets} host/s)"));
    } else {
        razones.push("0 sin host de API en scope (IDOR-REST poco probable)".into());
    }
    let surf = (api_assets.min(6) as i32) * 4;
    if surf > 0 {
        puntuacion += surf;
        razones.push(format!("+{surf} superficie de API"));
    }
    if paga {
        puntuacion += 20;
        razones.push("+20 paga bounty".into());
    }
    if kyc {
        puntuacion -= 30;
        razones.push("-30 nombre sugiere KYC financiero (2 cuentas caras)".into());
    }
    Operabilidad {
        programa: nombre.to_string(),
        puntuacion,
        tiene_api,
        api_assets,
        paga,
        kyc_probable: kyc,
        razones,
    }
}

/// Rankea TODOS los programas del pool por operabilidad IDOR, desc. No toca la
/// red: solo lee `programs` + `program_scopes`.
pub async fn rankear(pool: &SqlitePool) -> anyhow::Result<Vec<Operabilidad>> {
    let filas: Vec<(String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT p.name, s.asset_identifier, s.eligible_for_bounty
         FROM programs p LEFT JOIN program_scopes s ON s.program_id = p.id
         WHERE p.status != 'ScopeBlocked'
         ORDER BY p.name",
    )
    .fetch_all(pool)
    .await?;

    use std::collections::BTreeMap;
    let mut por_prog: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    for (name, asset, elig) in filas {
        let entry = por_prog.entry(name).or_default();
        if let Some(a) = asset {
            entry.push((a, elig.unwrap_or(0) != 0));
        }
    }
    let mut out: Vec<Operabilidad> = por_prog
        .into_iter()
        .map(|(name, scopes)| puntuar(&name, &scopes))
        .collect();
    out.sort_by(|a, b| {
        b.puntuacion
            .cmp(&a.puntuacion)
            .then(a.programa.cmp(&b.programa))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(pairs: &[(&str, bool)]) -> Vec<(String, bool)> {
        pairs.iter().map(|(a, e)| (a.to_string(), *e)).collect()
    }

    #[test]
    fn detecta_asset_api() {
        assert!(es_asset_api("api.insightly.com"));
        assert!(es_asset_api("api-eu.floqast.app"));
        assert!(es_asset_api("foo.api.bar.com"));
        assert!(es_asset_api("https://x.com/api/v3"));
        // Pareja: assets que NO son de API no cuentan.
        assert!(!es_asset_api("www.insightly.com"));
        assert!(!es_asset_api("mercadolibre.com.co"));
        assert!(!es_asset_api("medias.watsons.co.th"));
    }

    #[test]
    fn kyc_por_nombre() {
        assert!(kyc_probable("intigriti:capitalcom"));
        assert!(kyc_probable("some-crypto-wallet"));
        assert!(kyc_probable("BigBank"));
        // Pareja: nombres sin señal financiera NO se penalizan.
        assert!(!kyc_probable("koho"), "koho no lleva señal financiera en el nombre");
        assert!(!kyc_probable("insightly"));
        assert!(!kyc_probable("whatnot"));
    }

    #[test]
    fn consumer_con_api_puntua_mas_que_fintech_con_api() {
        // insightly: API + paga, sin KYC → alto.
        let a = puntuar("insightly", &sc(&[("api.insightly.com", true), ("www.insightly.com", true)]));
        // un fintech con la MISMA superficie pero KYC → penalizado.
        let b = puntuar("acme-capital-invest", &sc(&[("api.acme.com", true)]));
        assert!(a.tiene_api && a.paga && !a.kyc_probable);
        assert!(b.kyc_probable);
        assert!(a.puntuacion > b.puntuacion, "consumer-con-API gana a fintech-con-API");
    }

    #[test]
    fn sin_api_puntua_bajo() {
        let sin = puntuar("solo-web", &sc(&[("www.x.com", true), ("x.com", true)]));
        let con = puntuar("con-api", &sc(&[("api.x.com", true)]));
        assert!(!sin.tiene_api);
        assert!(con.puntuacion > sin.puntuacion, "tener API pesa");
    }
}
