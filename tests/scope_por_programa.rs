//! El filtro de scope del recon debe usar el scope del PROGRAMA DEL CICLO, no el
//! catálogo global. Bug medido el 2026-08-27: un cert de `www.linkedin.com`
//! (in-scope del programa `linkedin`) se atribuyó a `intigriti:intigriti` porque
//! `filter_to_scope` casaba contra TODAS las reglas. Aquí el caso rojo/verde.

use nexus::db;
use nexus::scope::{self, ScopeRule};
use tempfile::TempDir;

async fn insertar_scope(pool: &sqlx::SqlitePool, programa: &str, ident: &str, wildcard: bool) {
    let pid = db::upsert_program(pool, programa).await.unwrap();
    sqlx::query(
        "INSERT INTO program_scopes (program_id, asset_identifier, asset_type, is_wildcard, base_domain)
         VALUES (?1, ?2, 'DOMAIN', ?3, ?2)",
    )
    .bind(pid)
    .bind(ident)
    .bind(wildcard as i64)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn el_scope_se_acota_al_programa_del_ciclo() {
    let dir = TempDir::new().unwrap();
    let pool = db::open(&dir.path().join("s.db"), 4).await.unwrap();

    // Dos programas: intigriti (su dominio) y linkedin (el suyo).
    insertar_scope(&pool, "intigriti:intigriti", "pwn.intigriti.rocks", false).await;
    insertar_scope(&pool, "linkedin", "www.linkedin.com", false).await;

    // El scope del CICLO de intigriti: solo su regla, NO la de linkedin.
    let reglas_raw = db::scope_rules_for_programs(&pool, &["intigriti:intigriti".to_string()])
        .await
        .unwrap();
    let reglas: Vec<ScopeRule> = reglas_raw
        .iter()
        .filter_map(|(_, ident, wild)| ScopeRule::parse(ident, *wild))
        .collect();

    // VERDE: el activo propio de intigriti está en scope.
    assert!(
        scope::in_scope("https://pwn.intigriti.rocks/", &reglas),
        "el activo propio de intigriti debe pasar"
    );
    // ROJO (el bug): linkedin NO está en el scope de intigriti y NO debe pasar.
    assert!(
        !scope::in_scope("https://www.linkedin.com/", &reglas),
        "linkedin es de OTRO programa: no debe pasar el filtro de intigriti (reporte fuera de scope)"
    );

    // PAREJA: el catálogo GLOBAL sí trae las dos reglas (por eso el filtro global
    // dejaba pasar linkedin). Es la causa que el fix acota.
    let global = db::scope_rules_with_id(&pool).await.unwrap();
    assert_eq!(global.len(), 2, "el catálogo global tiene las reglas de AMBOS programas");
    let reglas_g: Vec<ScopeRule> = global
        .iter()
        .filter_map(|(_, ident, wild)| ScopeRule::parse(ident, *wild))
        .collect();
    assert!(
        scope::in_scope("https://www.linkedin.com/", &reglas_g),
        "con el scope GLOBAL linkedin pasaba — exactamente el bug que el fix elimina"
    );
}
