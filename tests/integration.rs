//! Pruebas de integración: arrancan las herramientas REALES (stubs con shebang)
//! como subprocess y comprueban el pipeline de punta a punta. Cruzan la frontera
//! del programa (directiva 28): no van de estructura a estructura, spawnean.

use clap::Parser;
use nexus::config::Config;
use nexus::db::NewFinding;
use nexus::protection::{Guard, ProtectionConfig};
use nexus::{autz, db, deepscan, engine, recon};

fn stub(name: &str) -> String {
    format!("{}/tests/stubs/{}", env!("CARGO_MANIFEST_DIR"), name)
}

/// Construye una Config de test apuntando a los stubs, con cooldowns a 0.
fn test_cfg(dir: &std::path::Path, nuclei_path: &str, extra: &[&str]) -> Config {
    test_cfg_subf(dir, nuclei_path, &stub("subfinder.sh"), extra)
}

/// Igual, pero con un stub de subfinder a elegir (para probar recon con 0
/// subdominios o con distinta salida sin chocar con el `--subfinder-path` fijo).
fn test_cfg_subf(dir: &std::path::Path, nuclei_path: &str, subfinder_path: &str, extra: &[&str]) -> Config {
    let db = dir.join("t.db");
    let scans = dir.join("scans");
    std::fs::create_dir_all(&scans).unwrap();
    let mut args: Vec<String> = vec![
        "nexus".into(),
        "--nuclei-path".into(), nuclei_path.into(),
        "--subfinder-path".into(), subfinder_path.into(),
        "--httpx-path".into(), stub("httpx.sh"),
        "--sqlmap-path".into(), stub("sqlmap.sh"),
        "--deep-workers".into(), "2".into(),
        "--gau-path".into(), stub("gau.sh"),
        "--waybackurls-path".into(), stub("waybackurls.sh"),
        "--katana-path".into(), stub("katana.sh"),
        "--ffuf-path".into(), stub("ffuf.sh"),
        "--arjun-path".into(), stub("arjun.sh"),
        "--wordlist".into(), dir.join("wl.txt").display().to_string(),
        "--chromium-path".into(), stub("chromium.sh"),
        "--evidence-dir".into(), dir.join("ev").display().to_string(),
        "--reports-dir".into(), dir.join("reports").display().to_string(),
        "--phase-cooldown".into(), "0".into(),
        "--db".into(), db.display().to_string(),
        "--scans-dir".into(), scans.display().to_string(),
    ];
    for e in extra {
        args.push((*e).into());
    }
    args.push("scan".into()); // subcomando (sus args son opcionales)
    Config::parse_from(args)
}

#[tokio::test]
async fn scan_inserta_y_deduplica() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();

    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://a.example.com\nhttps://b.example.com\n").unwrap();

    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = || 0.5_f64;

    // Primera pasada: fase CRITICAL emite 2 CVE, fase HIGH emite 1 XSS → 3.
    let n1 = engine::scan_program(&cfg, &pool, &mut guard, None, "acme", &targets, 2, &mut rng)
        .await
        .unwrap();
    assert_eq!(n1, 3, "esperados 3 hallazgos nuevos, obtenidos {n1}");

    // Segunda pasada: el dedup por (url,vuln_name) debe rechazar TODO.
    let n2 = engine::scan_program(&cfg, &pool, &mut guard, None, "acme", &targets, 2, &mut rng)
        .await
        .unwrap();
    assert_eq!(n2, 0, "el dedup debe discriminar: 0 nuevos en la segunda pasada");

    assert_eq!(db::count_findings(&pool).await.unwrap(), 3);
}

#[tokio::test]
async fn una_pasada_sin_prioridad() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &["--no-priority-scan"]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://a.example.com\n").unwrap();
    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = || 0.5_f64;
    // Modo ALL: tags con cve y xss → el stub emite los 3 de una vez.
    let n = engine::scan_program(&cfg, &pool, &mut guard, None, "acme", &targets, 1, &mut rng)
        .await
        .unwrap();
    assert_eq!(n, 3);
}

#[tokio::test]
async fn herramienta_ausente_activa_backoff_sin_reventar() {
    let dir = tempfile::tempdir().unwrap();
    // nuclei apunta a un binario que no existe → tools::run devuelve Err.
    let cfg = test_cfg(dir.path(), "/nonexistent/nuclei_xyz", &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://a.example.com\n").unwrap();
    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = || 0.5_f64;

    // No debe entrar en pánico; termina con 0 hallazgos y fallos registrados.
    let n = engine::scan_program(&cfg, &pool, &mut guard, None, "acme", &targets, 1, &mut rng)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(
        guard.consecutive_failures() >= 1,
        "un fallo de herramienta debe registrar backoff (anti-baneo), no pasar como éxito"
    );
}

#[tokio::test]
async fn recon_subfinder_y_httpx_encadenados() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);

    let roots_file = cfg.scans_dir.join("roots.txt");
    std::fs::write(&roots_file, "example.com\n").unwrap();
    let roots = vec!["example.com".to_string()];

    let subs_file = cfg.scans_dir.join("subs.txt");
    let n_subs = recon::enumerate(&cfg, &roots, &subs_file).await.unwrap();
    // El activo (example.com) se SIEMBRA además de sus 2 subdominios → 3.
    assert_eq!(n_subs, 3, "example.com sembrado + www.+api. = 3 objetivos");

    let targets_file = cfg.scans_dir.join("targets.txt");
    let n_live = recon::live_hosts(&cfg, &subs_file, &targets_file).await.unwrap();
    assert_eq!(n_live, 3, "httpx marca vivos el activo y sus 2 subdominios");

    let content = std::fs::read_to_string(&targets_file).unwrap();
    assert!(content.contains("https://example.com"), "el activo del scope se escanea, no solo sus subdominios");
    assert!(content.contains("https://www.example.com"));
    assert!(content.contains("https://api.example.com"));
}

/// FILTRO DE SCOPE ANTES DE SONDEAR (revisión 2026-08-23, obs 2): la lista de
/// subdominios de subfinder son hosts PELADOS (sin esquema); se recortan a
/// in-scope ANTES de que httpx los toque, para no sondear un objetivo fuera de
/// alcance. Prueba que `filter_to_scope` discrimina sobre esa forma de entrada.
#[tokio::test]
async fn scope_recorta_subdominios_pelados_antes_de_sondear() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();
    db::insert_scope(&pool, pid, "example.com", true, Some("SCOPE-1")).await.unwrap(); // *.example.com
    let subs = cfg.scans_dir.join("recon_subs.txt");
    std::fs::write(&subs, "api.example.com\nadmin.example.com\nevil.attacker.com\n").unwrap();
    let (before, after) = recon::filter_to_scope(&cfg, &pool, &subs).await.unwrap();
    assert_eq!((before, after), (3, 2), "el host fuera de scope se recorta antes de httpx");
    let content = std::fs::read_to_string(&subs).unwrap();
    assert!(content.contains("api.example.com") && content.contains("admin.example.com"));
    // PAREJA (directiva 33): el fuera-de-scope NO sobrevive → httpx no lo toca.
    assert!(!content.contains("evil.attacker.com"), "un subdominio fuera de scope no llega al sondeo");
}

/// **Fix C — un host hoja del scope se SIEMBRA como objetivo aunque no tenga
/// subdominios.** Es el caso de meesho medido en producción: el scope son hosts
/// concretos (supplier.meesho.com…), subfinder no encuentra nada por debajo, y
/// antes el programa daba 0 objetivos → ScopeBlocked → 0 hallazgos SIEMPRE.
///
/// Mutante = git HEAD:src/recon.rs (no sembraba): con subfinder vacío escribía 0.
#[tokio::test]
async fn recon_siembra_el_host_del_scope_sin_subdominios() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg_subf(dir.path(), &stub("nuclei.sh"), &stub("subfinder_vacio.sh"), &[]);

    let subs_file = cfg.scans_dir.join("subs.txt");
    let n = recon::enumerate(&cfg, &["supplier.example.com".to_string()], &subs_file).await.unwrap();
    assert_eq!(n, 1, "el host hoja se siembra como objetivo aunque subfinder no dé nada");

    let content = std::fs::read_to_string(&subs_file).unwrap();
    assert!(content.contains("supplier.example.com"), "el activo del scope tiene que estar en la lista");
}

/// **Fix C — un activo wildcard se normaliza a su dominio base para enumerar.**
/// `*.example.com` no es un dominio válido para subfinder (is_valid_domain lo
/// rechaza por el `*`); antes se caía en silencio y el wildcard no aportaba nada.
/// Ahora se enumera `example.com` y se siembra la base.
///
/// Mutante = git HEAD: is_valid_domain("*.example.com") es false → 0 objetivos.
#[tokio::test]
async fn recon_normaliza_el_wildcard_a_su_base() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]); // subfinder emite www.+api.<d>

    let subs_file = cfg.scans_dir.join("subs.txt");
    let n = recon::enumerate(&cfg, &["*.example.com".to_string()], &subs_file).await.unwrap();
    assert_eq!(n, 3, "base example.com sembrada + www.+api.example.com = 3");

    let content = std::fs::read_to_string(&subs_file).unwrap();
    assert!(!content.contains('*'), "el asterisco del wildcard no debe llegar a subfinder ni a los objetivos");
    assert!(content.contains("example.com"));
    assert!(content.contains("www.example.com"));
}

/// **Fix A — una fase que EXPIRA conserva los hallazgos ya emitidos.**
///
/// Cruza la frontera del proceso (directiva 28): arranca un nuclei real (stub)
/// que emite un hallazgo y LUEGO se cuelga más que el techo de la fase. Con el
/// bug anterior (`wait_with_output` cancelado al expirar), stdout salía vacío y
/// el hallazgo se perdía → 0. Con el arreglo, la línea ya emitida sobrevive al
/// SIGKILL y se ingiere.
///
/// Su PAREJA está justo debajo (`una_fase_que_completa_no_se_marca_timeout`):
/// el mismo `run_phase` con un nuclei que termina rápido no debe marcar timeout
/// y trae sus 2 hallazgos. Sin la pareja, un `run_phase` que dijera «timeout» a
/// todo pasaría igual.
#[tokio::test]
async fn una_fase_que_expira_conserva_lo_ya_emitido() {
    use nexus::config::HIGH_PRIORITY_TAGS;
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei_lento.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();
    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://a.example.com\n").unwrap();

    // tope de 2s: el stub emite en t=0 y duerme 30s → lo mata el timeout a los 2s.
    let (found, _bad) = engine::run_phase(
        &cfg, &pool, "acme", pid, "CRITICAL", HIGH_PRIORITY_TAGS, &targets, 1, 2,
    )
    .await
    .unwrap();
    assert_eq!(found, 1, "el hallazgo emitido antes del timeout debe ingerirse, no perderse");

    // Falló por la VÍA REAL: la fase se registró como 'timeout', no 'completed'.
    let status: String = sqlx::query_scalar("SELECT status FROM scan_logs ORDER BY id DESC LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "timeout", "la fase tiene que haber EXPIRADO (si no, no prueba el rescate)");
}

/// **Filtro por severidad — el ruido `info` no se almacena, el pagable sí.**
/// Es el caso de los 7 'info' de braze que saturaban la cola manual: el stub
/// emite un info y un critical, y solo el critical debe quedar en la BD.
///
/// Mutante = git HEAD (sin filtro): guardaría los 2. La pareja (que el critical
/// SÍ pasa) distingue esto de un filtro que rechazara todo.
#[tokio::test]
async fn el_filtro_de_severidad_descarta_info_y_guarda_lo_pagable() {
    use nexus::config::HIGH_PRIORITY_TAGS;
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei_info_y_critico.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();
    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://a.example.com\n").unwrap();

    let (found, _bad) = engine::run_phase(
        &cfg, &pool, "acme", pid, "CRITICAL", HIGH_PRIORITY_TAGS, &targets, 1, 30,
    )
    .await
    .unwrap();
    assert_eq!(found, 1, "solo el critical se almacena; el info se descarta");

    let sev: String = sqlx::query_scalar("SELECT severity FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sev, "critical", "lo guardado es el pagable, no el ruido info");
    assert_eq!(db::count_findings(&pool).await.unwrap(), 1);
}

/// Pareja de la anterior: un nuclei que termina rápido NO se marca timeout y trae
/// todo. Es el control que distingue «rescató lo emitido» de «marca timeout a todo».
#[tokio::test]
async fn una_fase_que_completa_no_se_marca_timeout() {
    use nexus::config::HIGH_PRIORITY_TAGS;
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();
    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://a.example.com\n").unwrap();

    let (found, _bad) = engine::run_phase(
        &cfg, &pool, "acme", pid, "CRITICAL", HIGH_PRIORITY_TAGS, &targets, 1, 30,
    )
    .await
    .unwrap();
    assert_eq!(found, 2, "el stub cve emite 2 críticos y termina");

    let status: String = sqlx::query_scalar("SELECT status FROM scan_logs ORDER BY id DESC LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "completed", "terminó limpio: no es timeout");
}

/// **Fix B — el recon RESETEA los subdominios entre ciclos.**
///
/// Siembra `subs_file` con un host RANCIO de un «programa anterior», corre
/// `enumerate` (que enumera el programa actual) y exige que el rancio DESAPAREZCA
/// y solo queden los subdominios frescos. Con el bug (`append`), el rancio
/// sobrevivía y `live_hosts` lo escaneaba fuera de scope.
///
/// El mutante es la versión anterior de la regla: `git show HEAD:src/recon.rs`
/// abría en `.append(true)` — contra ella este test falla (el rancio persiste).
#[tokio::test]
async fn recon_resetea_subdominios_entre_ciclos() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let subs_file = cfg.scans_dir.join("recon_subs.txt");

    // Ciclo anterior dejó este subdominio de OTRO programa.
    std::fs::write(&subs_file, "rancio.programa-anterior.com\n").unwrap();

    // Ciclo actual: enumera example.com → el stub emite www.+api.example.com.
    let n = recon::enumerate(&cfg, &["example.com".to_string()], &subs_file).await.unwrap();
    assert_eq!(n, 3, "example.com sembrado + www.+api. frescos = 3");

    let content = std::fs::read_to_string(&subs_file).unwrap();
    assert!(
        !content.contains("rancio.programa-anterior.com"),
        "el subdominio del ciclo anterior NO debe seguir en el archivo (contaminación entre programas)"
    );
    assert!(content.contains("www.example.com") && content.contains("api.example.com"));
}

#[tokio::test]
async fn deep_verify_confirma_descarta_y_reintenta() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();

    // Tres hallazgos SQLi con URLs que dirigen al stub por cada camino.
    for url in [
        "https://vuln.example.com/?id=1", // → confirmado
        "https://clean.example.com/?id=1", // → falso positivo
        "https://waf.example.com/?id=1",   // → bloqueado por WAF → reintento
    ] {
        let f = NewFinding {
            program_name: "acme".into(),
            vuln_name: "sqli-injection".into(),
            severity: "high".into(),
            url: url.into(),
            cwe: None,
            evidencia: None,
        };
        assert!(db::insert_finding_dedup(&pool, &f, pid).await.unwrap());
    }

    let s = deepscan::run(&cfg, &pool, 100).await.unwrap();
    assert_eq!(s.verified, 1, "la URL 'vuln' debe confirmarse");
    assert_eq!(s.false_positive, 1, "la URL 'clean' debe descartarse");
    assert_eq!(s.retry, 1, "la URL 'waf' es reintentable, no falso positivo");

    // El WAF quedó en RETRY_PENDING con el contador incrementado.
    let verifiable_again = db::fetch_verifiable(&pool, 100).await.unwrap();
    // 'clean' y 'vuln' ya no son verificables; 'waf' sí (retry vencido: next_retry futuro
    // → NO debería reaparecer aún). Comprobamos que los 2 resueltos no reaparecen.
    assert!(
        verifiable_again.len() <= 1,
        "solo el reintento pendiente podría reaparecer, no los resueltos"
    );
}

#[tokio::test]
async fn enhanced_recon_amplia_superficie() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);

    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://live.example.com\n").unwrap();

    let s = nexus::enhanced::enhance(&cfg, &targets, None).await.unwrap();
    assert!(s.added > 0, "enhanced recon debe añadir URLs nuevas");

    let content = std::fs::read_to_string(&targets).unwrap();
    assert!(content.contains("/archived1"), "gau (pasivo) aporta URLs de archivo");
    assert!(content.contains("/crawled"), "katana aporta URLs rastreadas");
    assert!(content.contains("/admin"), "ffuf aporta rutas descubiertas");
    assert!(content.contains("hidden=1"), "arjun aporta parámetros ocultos");

    // Invariante de nexus: nunca escribe una URL ya conocida → el archivo no
    // contiene líneas duplicadas, ni siquiera tras una segunda pasada.
    let _ = nexus::enhanced::enhance(&cfg, &targets, None).await.unwrap();
    let lines: Vec<String> = std::fs::read_to_string(&targets).unwrap().lines().map(String::from).collect();
    let unique: std::collections::BTreeSet<&String> = lines.iter().collect();
    assert_eq!(lines.len(), unique.len(), "el archivo de objetivos no debe tener duplicados");
}

/// Siembra un hallazgo VERIFIED explotable y devuelve (cfg, pool).
async fn seed_verified(dir: &std::path::Path) -> (Config, sqlx::SqlitePool) {
    let cfg = test_cfg(dir, &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();
    let f = NewFinding {
        program_name: "acme".into(),
        vuln_name: "sql-injection".into(),
        severity: "critical".into(),
        url: "https://vuln.example.com/?id=1".into(),
        cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &f, pid).await.unwrap();
    let id = db::fetch_verifiable(&pool, 10).await.unwrap()[0].id;
    db::apply_verification(&pool, id, "VERIFIED", true, "sqlmap", "high", true, Some("UNION-based"), "sqli", Some("[sqlmap PoC]"), true, Some("3/3"))
        .await
        .unwrap();
    (cfg, pool)
}

#[tokio::test]
async fn submitter_genera_informe_con_cvss() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, pool) = seed_verified(dir.path()).await;

    let n = nexus::submitter::generate_all(&cfg, &pool).await.unwrap();
    assert_eq!(n, 1, "un grupo (acme, sql-injection) → un informe");

    let path = cfg.reports_dir.join("acme_sql-injection.md");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("9.8 (Critical)"), "CVSS de sqli");
    assert!(content.contains("Fuga de datos"), "impacto de sqli");
    assert!(content.contains("Explotable: SÍ"));
    assert!(content.contains("sqlmap"));
}

/// El reporte que va a H1 CERCA el PoC con una valla más larga que cualquier
/// racha de backticks del contenido (directiva 28: se prueba el PRODUCTO —el
/// markdown emitido—, no solo el helper `cercar_poc`). El `raw` puede traer
/// cuerpo controlado por el objetivo; una línea ``` no debe cerrar la valla e
/// inyectar markdown en el informe publicado. Cierra el hunk sin-caso-rojo de la
/// LLAMADA a cercar_poc en build_submission.
#[tokio::test]
async fn el_reporte_cerca_el_poc_ante_backticks_del_objetivo() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();
    let f = NewFinding {
        program_name: "acme".into(), vuln_name: "sql-injection".into(),
        severity: "critical".into(), url: "https://vuln.example.com/?id=1".into(),
        cwe: None, evidencia: None,
    };
    db::insert_finding_dedup(&pool, &f, pid).await.unwrap();
    let id = db::fetch_verifiable(&pool, 10).await.unwrap()[0].id;
    // El objetivo mete una línea ``` seguida de markdown inyectado en el cuerpo
    // que sqlmap captura como PoC.
    let raw_malicioso = "sqlmap: id inyectable\n```\n# TÍTULO INYECTADO\n[click](http://malo)";
    db::apply_verification(&pool, id, "VERIFIED", true, "sqlmap", "critical", true, Some("UNION"), "sqli", Some(raw_malicioso), true, Some("3/3")).await.unwrap();

    nexus::submitter::generate_all(&cfg, &pool).await.unwrap();
    let content = std::fs::read_to_string(cfg.reports_dir.join("acme_sql-injection.md")).unwrap();

    // La sección del PoC abre con valla de 4 backticks (más larga que el ``` interno).
    assert!(content.contains("## Prueba (PoC)\n````\n"),
        "el PoC se cerca con una valla de 4 backticks ante un ``` del objetivo");
    // El contenido íntegro se preserva (no se mutila la evidencia).
    assert!(content.contains("# TÍTULO INYECTADO"), "la evidencia se conserva entera");
    // Y el PoC cierra con la MISMA valla de 4 (no con la de 3 que el objetivo metió).
    assert!(content.contains("[click](http://malo)\n````\n"),
        "el bloque cierra con la valla de 4, tras el contenido íntegro");
}

#[tokio::test]
async fn autosubmit_dry_run_atribuye_y_discrimina() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, pool) = seed_verified(dir.path()).await;

    // Programa 'acme' con scope *.example.com → cubre el hallazgo sembrado
    // (host vuln.example.com), que es VERIFIED+explotable+alta confianza.
    let pid = db::upsert_program_handle(&pool, "acme", "acme").await.unwrap();
    db::insert_scope(&pool, pid, "example.com", true, Some("SCOPE-123")).await.unwrap();

    // Un segundo hallazgo de alta señal PERO fuera de cualquier scope → manual.
    let orphan = NewFinding {
        program_name: "acme".into(),
        vuln_name: "cmdi-shell".into(),
        severity: "critical".into(),
        url: "https://orphan.otradominio.com/x".into(),
        cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &orphan, pid).await.unwrap();
    let oid = db::fetch_verifiable(&pool, 10).await.unwrap()
        .into_iter().find(|f| f.url.contains("orphan")).unwrap().id;
    db::apply_verification(&pool, oid, "VERIFIED", true, "commix", "high", true, None, "cmdi", Some("[commix PoC] Parameter: id (GET) is injectable; command output captured"), true, Some("3/3")).await.unwrap();

    let s = nexus::autosubmit::run(&cfg, &pool, true).await.unwrap();
    assert_eq!(s.sent, 0, "dry-run no envía nada a H1");
    assert_eq!(s.dry_run, 1, "el atribuible (example.com) se enviaría");
    assert_eq!(s.skipped_no_program, 1, "el huérfano sin scope queda para manual (directiva 20)");
}

/// EL GATE del auto-envío y su pareja (directiva 33): sin `execution_confirmed`
/// NO se auto-envía, aunque sea VERIFIED+explotable+alta — que es EXACTAMENTE el
/// FP #11 (reflexión inerte marcada "verified" por xsstrike). Con ejecución
/// confirmada, sí. El caso rojo falla por la vía real: la cláusula de la BD.
#[tokio::test]
async fn autosubmit_exige_ejecucion_confirmada() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program_handle(&pool, "acme", "acme").await.unwrap();
    db::insert_scope(&pool, pid, "example.com", true, Some("SCOPE-1")).await.unwrap();
    let f = NewFinding {
        program_name: "acme".into(),
        vuln_name: "reflected-xss".into(),
        severity: "high".into(),
        url: "https://app.example.com/?q=1".into(),
        cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &f, pid).await.unwrap();
    let id = db::fetch_verifiable(&pool, 10).await.unwrap()[0].id;

    // ROJO: VERIFIED + explotable + alta, pero SIN ejecución confirmada (el FP #11).
    db::apply_verification(&pool, id, "VERIFIED", true, "xsstrike", "high", true, None, "xss", None, false, Some("0/3")).await.unwrap();
    assert!(db::fetch_autosubmit(&pool).await.unwrap().is_empty(),
        "sin execution_confirmed NO es candidato a auto-envío");

    // VERDE: el gate de navegador confirmó ejecución reproducible → sí candidato.
    db::apply_verification(&pool, id, "VERIFIED", true, "browser", "high", true, Some("ejecución 3/3"), "xss", Some("[browser PoC] GET /?q=<script>alert(1)</script> → alert() ejecutó (captura adjunta)"), true, Some("3/3")).await.unwrap();
    assert_eq!(db::fetch_autosubmit(&pool).await.unwrap().len(), 1,
        "con execution_confirmed sí es candidato");
}

/// LA PUERTA DE EVIDENCIA (transversal, 2026-08-24) y su pareja (directiva 33):
/// un hallazgo VERIFIED + execution_confirmed + explotable + ALTA pero SIN
/// `raw_evidence` capturada NO se auto-envía — es el hueco del FP medido (46
/// "IDOR" con evidencia vacía). Con PoC capturado, sí. El rojo falla por la vía
/// real: la cláusula `LENGTH(TRIM(raw_evidence)) > 0` de `fetch_autosubmit`.
#[tokio::test]
async fn autosubmit_exige_evidencia_capturada() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program_handle(&pool, "acme", "acme").await.unwrap();
    db::insert_scope(&pool, pid, "example.com", true, Some("SCOPE-1")).await.unwrap();
    let f = NewFinding {
        program_name: "acme".into(),
        vuln_name: "sql-injection".into(),
        severity: "critical".into(),
        url: "https://app.example.com/?id=1".into(),
        cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &f, pid).await.unwrap();
    let id = db::fetch_verifiable(&pool, 10).await.unwrap()[0].id;

    // ROJO: confirmado y explotable, pero raw_evidence VACÍA (None) → no candidato.
    db::apply_verification(&pool, id, "VERIFIED", true, "sqlmap", "critical", true, Some("union-based"), "sqli", None, true, Some("3/3")).await.unwrap();
    assert!(db::fetch_autosubmit(&pool).await.unwrap().is_empty(),
        "sin raw_evidence capturada NO es candidato a auto-envío");

    // VERDE: el verificador capturó el PoC crudo → sí candidato.
    db::apply_verification(&pool, id, "VERIFIED", true, "sqlmap", "critical", true, Some("union-based"), "sqli", Some("[sqlmap] Parameter: id (GET); payload: 1 UNION SELECT ... ; 3 columnas"), true, Some("3/3")).await.unwrap();
    assert_eq!(db::fetch_autosubmit(&pool).await.unwrap().len(), 1,
        "con raw_evidence capturada sí es candidato");
}

/// Dedup entre ciclos: un (programa, vuln) ya REPORTED no se reenvía, aunque
/// aparezca un nuevo hallazgo confirmado del mismo tipo (H1 lo cerraría duplicate).
#[tokio::test]
async fn autosubmit_no_reenvia_lo_ya_reportado() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, pool) = seed_verified(dir.path()).await; // sqli VERIFIED+confirmado en acme
    let pid = db::upsert_program_handle(&pool, "acme", "acme").await.unwrap();
    db::insert_scope(&pool, pid, "example.com", true, Some("SCOPE-1")).await.unwrap();

    // Primera vuelta: hay un candidato atribuible.
    assert!(!db::already_reported(&pool, "acme", "sql-injection").await.unwrap());
    let s1 = nexus::autosubmit::run(&cfg, &pool, true).await.unwrap();
    assert_eq!(s1.dry_run, 1, "primera vez: se enviaría");

    // Marca ese hallazgo como REPORTED (como si el POST hubiera ocurrido).
    let cand = db::fetch_autosubmit(&pool).await.unwrap();
    db::mark_reported(&pool, cand[0].id, "REPORT-1").await.unwrap();

    // Aparece un NUEVO hallazgo confirmado del mismo (programa, vuln) en otra URL.
    let f2 = NewFinding {
        program_name: "acme".into(), vuln_name: "sql-injection".into(),
        severity: "critical".into(), url: "https://otro.example.com/?id=9".into(), cwe: None,
        evidencia: None,
    };
    db::insert_finding_dedup(&pool, &f2, pid).await.unwrap();
    let id2 = db::fetch_verifiable(&pool, 10).await.unwrap().into_iter().find(|f| f.url.contains("otro")).unwrap().id;
    db::apply_verification(&pool, id2, "VERIFIED", true, "sqlmap", "critical", true, Some("UNION-based"), "sqli", Some("poc"), true, Some("3/3")).await.unwrap();

    // Segunda vuelta: el dedup lo salta, NO lo reenvía.
    assert!(db::already_reported(&pool, "acme", "sql-injection").await.unwrap());
    let s2 = nexus::autosubmit::run(&cfg, &pool, true).await.unwrap();
    assert_eq!(s2.dry_run, 0, "no reenvía un (programa, vuln) ya reportado");
    assert_eq!(s2.skipped_duplicate, 1, "lo cuenta como duplicado saltado");
}

/// PAYABILITY: una XSS confirmada por ejecución NO se auto-envía (queda manual);
/// una SQLi sí. Es lo que hace el auto-envío efectivo y sin baneo.
#[tokio::test]
async fn autosubmit_payability_deja_xss_en_manual() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program_handle(&pool, "acme", "acme").await.unwrap();
    db::insert_scope(&pool, pid, "example.com", true, Some("SCOPE-1")).await.unwrap();

    // XSS confirmada por navegador, alta severidad, atribuible.
    let fx = NewFinding { program_name: "acme".into(), vuln_name: "reflected-xss".into(),
        severity: "high".into(), url: "https://app.example.com/?q=1".into(), cwe: None, evidencia: None };
    db::insert_finding_dedup(&pool, &fx, pid).await.unwrap();
    let xid = db::fetch_verifiable(&pool, 10).await.unwrap()[0].id;
    db::apply_verification(&pool, xid, "VERIFIED", true, "browser", "high", true, Some("ejecución 3/3"), "xss", Some("[browser PoC] GET /?q=<script>alert(1)</script> → alert() ejecutó (captura adjunta)"), true, Some("3/3")).await.unwrap();

    let s = nexus::autosubmit::run(&cfg, &pool, true).await.unwrap();
    assert_eq!(s.dry_run, 0, "la XSS confirmada NO se auto-envía");
    assert_eq!(s.skipped_not_payable, 1, "queda para revisión manual por payability");
}

/// CORTACIRCUITOS anti-baneo: si H1 cerró reportes propios como duplicate/
/// informative por encima del umbral, el auto-envío REAL se pausa sin tocar H1.
#[tokio::test]
async fn autosubmit_cortacircuitos_por_signal() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &["--autosubmit-signal-floor", "2"]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let pid = db::upsert_program(&pool, "acme").await.unwrap();

    // Dos reportes propios ya cerrados por H1 como mala señal (umbral = 2).
    for (u, st) in [("https://a.example.com/?id=1", "duplicate"), ("https://b.example.com/?id=1", "informative")] {
        let f = NewFinding { program_name: "acme".into(), vuln_name: "sql-injection".into(),
            severity: "critical".into(), url: u.into(), cwe: None, evidencia: None };
        db::insert_finding_dedup(&pool, &f, pid).await.unwrap();
        let id = db::fetch_verifiable(&pool, 10).await.unwrap().into_iter().find(|x| x.url == u).unwrap().id;
        db::mark_reported(&pool, id, &format!("R-{u}")).await.unwrap();
        db::update_h1_state(&pool, id, st, None).await.unwrap();
    }
    assert_eq!(db::count_bad_signal(&pool).await.unwrap(), 2);

    // En modo REAL, el cortacircuitos devuelve pausa ANTES de tocar H1 (sin creds).
    let s = nexus::autosubmit::run(&cfg, &pool, false).await.unwrap();
    assert!(s.paused_signal, "el auto-envío debe pausarse por Signal bajo");
    assert_eq!(s.sent, 0, "no envía nada estando pausado");
}

#[tokio::test]
async fn evidencia_captura_verificados() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, pool) = seed_verified(dir.path()).await;

    let n = nexus::evidence::capture_all(&cfg, &pool).await.unwrap();
    assert_eq!(n, 1, "un hallazgo verificado → una captura");

    // La captura existe y la BD guarda su ruta.
    let rows = db::verified_findings(&pool).await.unwrap();
    let ev = rows[0].verification_evidence.as_deref().unwrap();
    assert!(ev.ends_with(".png"));
    assert!(std::path::Path::new(ev).exists(), "el png debe existir");

    // Idempotencia: una segunda pasada no vuelve a capturar (ya tiene .png).
    let n2 = nexus::evidence::capture_all(&cfg, &pool).await.unwrap();
    assert_eq!(n2, 0, "no recaptura lo que ya tiene evidencia");
}

/// **Reconciliación de escaneos huérfanos, con su pareja (directiva 33).**
///
/// Un ciclo de caza que muere a mitad de nuclei (SIGKILL de systemd, OOM) deja
/// su fila en `'running'` para siempre. `reconcile_orphaned_scans` la cierra a
/// `'interrupted'` — pero SOLO si es vieja de verdad. Tres filas, no una:
///   - ROJO: `'running'` vieja → DEBE reconciliarse (el fallo real).
///   - VERDE: `'running'` reciente (escaneo VIVO) → NO se toca. Es el control
///     que distingue el barrido bueno de uno ciego que marque todo `'running'`
///     —sin el guard de `started_at` este caso se pondría en rojo—.
///   - CONTROL: `'completed'` vieja → intacta (solo se tocan las `'running'`).
#[tokio::test]
async fn reconcilia_huerfanos_sin_tocar_lo_vivo_ni_lo_cerrado() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    // Inserta las tres con started_at controlado (aritmética de SQLite).
    let ins = |program: &'static str, status: &'static str, age_secs: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO scan_logs (program_name, scan_type, phase, status, started_at)
                 VALUES (?1, 'nuclei', 'HIGH', ?2, datetime(CURRENT_TIMESTAMP, '-' || ?3 || ' seconds'))",
            )
            .bind(program)
            .bind(status)
            .bind(age_secs)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    ins("huerfano_viejo", "running", 7200).await; // 2 h → muerto
    ins("vivo_reciente", "running", 60).await; //   1 min → escaneo en curso
    ins("cerrado_viejo", "completed", 7200).await; // viejo pero ya cerrado

    // Umbral de 3600 s: > que el vivo (60 s), < que los viejos (7200 s).
    let n = db::reconcile_orphaned_scans(&pool, 3600).await.unwrap();
    assert_eq!(n, 1, "solo la 'running' vieja se reconcilia");

    let estado = |program: &'static str| {
        let pool = pool.clone();
        async move {
            let row: (String, Option<String>) = sqlx::query_as(
                "SELECT status, completed_at FROM scan_logs WHERE program_name = ?1",
            )
            .bind(program)
            .fetch_one(&pool)
            .await
            .unwrap();
            row
        }
    };

    let (s, c) = estado("huerfano_viejo").await;
    assert_eq!(s, "interrupted", "el huérfano viejo DEBE cerrarse");
    assert!(c.is_some(), "reconciliar fija completed_at");

    let (s, _) = estado("vivo_reciente").await;
    assert_eq!(s, "running", "el escaneo VIVO no se toca (control verde)");

    let (s, _) = estado("cerrado_viejo").await;
    assert_eq!(s, "completed", "una fila ya cerrada no se reabre");

    // Idempotencia: una segunda pasada no reconcilia nada más.
    let n2 = db::reconcile_orphaned_scans(&pool, 3600).await.unwrap();
    assert_eq!(n2, 0, "sin huérfanos nuevos, no reconcilia de más");
}

/// **Cuarentena de programas estériles, con su pareja (directiva 33).**
///
/// SESGO A BLANDOS (2026-08-25): un programa que PAGA y tiene superficie amplia
/// (scope wildcard) gana al round-robin por antigüedad — ahí es donde una clase
/// commodity tiene chance de un rincón sin endurecer. El sesgo es un TIER: dentro de
/// él, sigue el round-robin (no re-caza el mismo).
#[tokio::test]
async fn sesgo_prioriza_blandos_que_pagan_con_wildcard() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    let prog = |name: &'static str, dias: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query("INSERT INTO programs (name, h1_handle, status, last_scanned) VALUES (?1, ?1, 'scanned', datetime(CURRENT_TIMESTAMP, '-' || ?2 || ' days'))")
                .bind(name).bind(dias).execute(&pool).await.unwrap();
        }
    };
    let scope = |program: &'static str, bounty: i64, wildcard: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query("INSERT INTO program_scopes (program_id, asset_identifier, asset_type, eligible_for_bounty, is_wildcard) SELECT id, '*.x.com', 'WILDCARD', ?2, ?3 FROM programs WHERE name = ?1")
                .bind(program).bind(bounty).bind(wildcard).execute(&pool).await.unwrap();
        }
    };

    // duro: el MÁS antiguo (el round-robin viejo lo elegiría), pero NO paga / sin wildcard.
    prog("duro", 100).await;
    scope("duro", 0, 0).await;
    // blando: más NUEVO, pero paga + wildcard → el tier lo sube por encima.
    prog("blando", 10).await;
    scope("blando", 1, 1).await;

    let pick = db::next_program_to_hunt(&pool, 8, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(pick.as_deref(), Some("blando"), "el blando (paga+wildcard) gana al duro más antiguo");

    // Dentro del tier blando, round-robin por antigüedad: un blando MÁS viejo va primero.
    prog("blando_viejo", 200).await;
    scope("blando_viejo", 1, 1).await;
    let pick2 = db::next_program_to_hunt(&pool, 8, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(pick2.as_deref(), Some("blando_viejo"), "dentro del tier, round-robin por antigüedad");
}

/// `next_program_to_hunt` elige el menos-reciente, pero deprioritiza el que
/// acumula timeouts sin completar jamás (coupang_tw: 59 escaneos, 0 completados).
///   - ROJO: un estéril MÁS ANTIGUO no debe ganarle a uno productivo más nuevo
///     —la regla vieja (solo `last_scanned ASC`) elegiría el estéril—.
///   - VERDE: un nunca-escaneado va primero (comportamiento preservado); y un
///     programa productivo antiguo SÍ se elige (no se deprioritiza al sano).
///   - AUTO-SANA: en cuanto el estéril completa un escaneo, vuelve a la cola.
#[tokio::test]
async fn cuarentena_deprioritiza_esteriles_pero_se_autosana() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    let prog = |name: &'static str, dias: Option<i64>| {
        let pool = pool.clone();
        async move {
            match dias {
                Some(d) => {
                    sqlx::query(
                        "INSERT INTO programs (name, h1_handle, status, last_scanned)
                         VALUES (?1, ?1, 'scanned', datetime(CURRENT_TIMESTAMP, '-' || ?2 || ' days'))",
                    )
                    .bind(name)
                    .bind(d)
                    .execute(&pool)
                    .await
                    .unwrap();
                }
                None => {
                    sqlx::query("INSERT INTO programs (name, h1_handle, status) VALUES (?1, ?1, 'scanned')")
                        .bind(name)
                        .execute(&pool)
                        .await
                        .unwrap();
                }
            }
        }
    };
    let log = |program: &'static str, status: &'static str, veces: i64| {
        let pool = pool.clone();
        async move {
            for _ in 0..veces {
                sqlx::query(
                    "INSERT INTO scan_logs (program_name, scan_type, phase, status)
                     VALUES (?1, 'nuclei', 'HIGH', ?2)",
                )
                .bind(program)
                .bind(status)
                .execute(&pool)
                .await
                .unwrap();
            }
        }
    };

    // barren_vieja: la más antigua, 10 timeouts, 0 completados → estéril.
    prog("barren_vieja", Some(100)).await;
    log("barren_vieja", "timeout", 10).await;
    // productiva_media: más nueva que la estéril, pero con 1 completado → sana.
    prog("productiva_media", Some(50)).await;
    log("productiva_media", "completed", 1).await;

    // ROJO: pese a ser MÁS ANTIGUA, la estéril NO gana. La regla vieja
    // (last_scanned ASC) habría devuelto barren_vieja.
    let pick = db::next_program_to_hunt(&pool, 8, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(pick.as_deref(), Some("productiva_media"),
        "el estéril viejo se deprioritiza frente al productivo más nuevo");

    // VERDE: un nunca-escaneado va por delante de todo.
    prog("nunca", None).await;
    let pick = db::next_program_to_hunt(&pool, 8, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(pick.as_deref(), Some("nunca"), "nunca-escaneado va primero");

    // AUTO-SANA: la estéril completa UN escaneo → deja de estar en cuarentena.
    // Quitamos a los que le ganarían para aislar la señal: marcamos 'nunca' y
    // 'productiva_media' como recién escaneados, y damos a barren_vieja un
    // 'completed'. Ahora barren_vieja (last_scanned más antiguo) debe ganar.
    db::mark_program_scanned(&pool, "nunca", "scanned").await.unwrap();
    db::mark_program_scanned(&pool, "productiva_media", "scanned").await.unwrap();
    log("barren_vieja", "completed", 1).await;
    let pick = db::next_program_to_hunt(&pool, 8, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(pick.as_deref(), Some("barren_vieja"),
        "tras completar uno, el ex-estéril vuelve a la prioridad normal (auto-sana)");
}

/// **`sin_hosts_vivos` se REINTENTA; `ScopeBlocked` no (directiva 32/22).**
///
/// La contraparte de selección del fix de `estado_tras_recon`: un programa con
/// scope pero 0 host vivo se marca `sin_hosts_vivos` y DEBE seguir en la cola;
/// uno sin scope se marca `ScopeBlocked` y se excluye. Y `no_live` repetido
/// deprioritiza igual que timeout/failed (la cuarentena ya lo cuenta).
///   - ROJO (regla vieja): el transitorio se marcaba ScopeBlocked → la cola lo
///     excluía y devolvía otra cosa (o None). Aquí lo exigimos seleccionable.
///   - CONTROL: el ScopeBlocked de verdad no aparece jamás.
#[tokio::test]
async fn sin_hosts_vivos_sigue_en_la_cola_scopeblocked_no() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    // transitorio: con scope, 0 host vivo ahora. Es el ÚNICO no-bloqueado.
    sqlx::query(
        "INSERT INTO programs (name, h1_handle, status, last_scanned)
         VALUES ('transitorio','transitorio','sin_hosts_vivos', CURRENT_TIMESTAMP)",
    ).execute(&pool).await.unwrap();
    // sin_scope: ScopeBlocked, y MÁS ANTIGUO (last_scanned -100d) → si no se
    // excluyera, ganaría por round-robin. Es el control (directiva 33).
    sqlx::query(
        "INSERT INTO programs (name, h1_handle, status, last_scanned)
         VALUES ('sin_scope','sin_scope','ScopeBlocked', datetime(CURRENT_TIMESTAMP,'-100 days'))",
    ).execute(&pool).await.unwrap();

    let pick = db::next_program_to_hunt(&pool, 8, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(pick.as_deref(), Some("transitorio"),
        "el transitorio se reintenta; el ScopeBlocked (más antiguo) se excluye");

    // CUARENTENA: 8 `no_live` sin completar → estéril. Un productivo más nuevo
    // debe ganarle, igual que con timeout/failed. Sin el 'no_live' en el IN de
    // la cuarentena, el transitorio (más antiguo) ganaría.
    for _ in 0..8 {
        let id = db::scan_log_start(&pool, "transitorio", "recon", "live").await.unwrap();
        db::scan_log_finish(&pool, id, "no_live", 0, None).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO programs (name, h1_handle, status, last_scanned)
         VALUES ('productivo','productivo','scanned', CURRENT_TIMESTAMP)",
    ).execute(&pool).await.unwrap();
    let id = db::scan_log_start(&pool, "productivo", "recon", "HIGH").await.unwrap();
    db::scan_log_finish(&pool, id, "completed", 0, None).await.unwrap();
    // envejecer el transitorio para que SOLO la cuarentena pueda bajarlo.
    sqlx::query("UPDATE programs SET last_scanned=datetime(CURRENT_TIMESTAMP,'-50 days') WHERE name='transitorio'")
        .execute(&pool).await.unwrap();

    let pick = db::next_program_to_hunt(&pool, 8, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(pick.as_deref(), Some("productivo"),
        "no_live repetido deprioritiza como timeout/failed (cuarentena lo cuenta)");
}

/// **Un programa de Intigriti es ciudadano de 1ª en la cola de caza (#4).**
/// Sembrado del feed público (sin token): identidad `intigriti:{slug}`, scope en
/// program_scopes, y el cazador lo selecciona y lo marca por NAME.
///   - ROJO/filtro (directiva 33): con la regla vieja `h1_handle IS NOT NULL` un
///     Intigriti (h1_handle NULL) NO se seleccionaría → pick sería None.
///   - ROJO/mark: con `mark_program_scanned` clavando por h1_handle, marcar un
///     Intigriti NO tocaría ninguna fila → seguiría seleccionable tras marcarlo.
///   - VERDE: seleccionable, scope legible, idempotente, y excluible.
#[tokio::test]
async fn intigriti_es_ciudadano_de_primera_en_la_cola() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("t.db"), 4).await.unwrap();

    // Sembrar vía el parser real (forma del feed): un programa con scope web.
    let json = r#"[{"handle":"aikido","id":"guid-x","max_bounty":{"value":500},
        "targets":{"in_scope":[
            {"type":"url","endpoint":"app.aikido.dev"},
            {"type":"wildcard","endpoint":"*.ad.nl"}]}}]"#;
    let progs = nexus::sources::parse_ark_intigriti_programs(json);
    assert_eq!(db::seed_intigriti_programs(&pool, &progs).await.unwrap(), 1);

    // Seleccionable, con nombre namespaced y plataforma 'intigriti' (FILTRO).
    let pick = db::next_program_to_hunt(&pool, 8, 0).await.unwrap();
    assert_eq!(
        pick.as_ref().map(|(n, p)| (n.as_str(), p.as_str())),
        Some(("intigriti:aikido", "intigriti")),
        "un Intigriti (h1_handle NULL) tiene que ser seleccionable"
    );

    // Su scope está en program_scopes y se lee por NAME (fuente Almacenado).
    let roots = db::scope_roots_for_program(&pool, "intigriti:aikido").await.unwrap();
    assert!(roots.contains(&"app.aikido.dev".to_string()));
    assert!(roots.contains(&"ad.nl".to_string()), "el wildcard perdió el *.");

    // Idempotente: re-sembrar el mismo no cuenta como nuevo.
    assert_eq!(db::seed_intigriti_programs(&pool, &progs).await.unwrap(), 0);

    // mark_program_scanned clavea por NAME (h1_handle es NULL) — con la vieja
    // versión no tocaría fila y el programa seguiría en la cola.
    db::mark_program_scanned(&pool, "intigriti:aikido", "ScopeBlocked").await.unwrap();
    let pick2 = db::next_program_to_hunt(&pool, 8, 0).await.unwrap();
    assert!(pick2.is_none(), "un Intigriti ScopeBlocked se excluye igual que un H1");
}

/// **Modo pasivo del enhanced recon, con su pareja (directiva 33/28).**
///
/// La caza de 2 h usa `--recon-passive-only`: gana superficie de endpoints SIN
/// la fuerza bruta de ffuf (la parte agresiva que arriesga baneo de IP y viola
/// políticas anti-scanner). Cruza la frontera (D28): corre los stubs reales.
///   - VERDE: pasivo/crawl SÍ aportan (gau `/archived1`, katana `/crawled`).
///   - ROJO de control: ffuf (`/admin`) y arjun (`hidden=1`) NO aparecen, y sus
///     contadores son 0 — el stub de ffuf produce `/admin` si se le llama, así
///     que su ausencia prueba que NO se ejecutó, no que no encontró nada.
#[tokio::test]
async fn recon_pasivo_omite_la_fuerza_bruta() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &["--recon-passive-only"]);

    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://live.example.com\n").unwrap();

    let s = nexus::enhanced::enhance(&cfg, &targets, None).await.unwrap();
    let content = std::fs::read_to_string(&targets).unwrap();

    // VERDE: lo pasivo y el crawl siguen aportando.
    assert!(content.contains("/archived1"), "gau (pasivo) sigue corriendo");
    assert!(content.contains("/crawled"), "katana (crawl) sigue corriendo");

    // ROJO de control: la fase activa NO corre.
    assert!(!content.contains("/admin"), "ffuf (fuerza bruta) NO debe ejecutarse en modo pasivo");
    assert!(!content.contains("hidden=1"), "arjun (fuzzing de params) NO debe ejecutarse en modo pasivo");
    assert_eq!(s.discovered, 0, "cero descubrimientos por ffuf en modo pasivo");
    assert_eq!(s.params, 0, "cero params por arjun en modo pasivo");
}

/// El deadline de recon corta las fases que faltan: con un deadline YA vencido,
/// ni siquiera el crawl ni la fase activa corren (solo el pasivo inicial). Es lo
/// que impide que enhanced recon se coma el tiempo de escaneo en la caza de 2 h.
#[tokio::test]
async fn recon_respeta_el_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let targets = cfg.scans_dir.join("targets.txt");
    std::fs::write(&targets, "https://live.example.com\n").unwrap();

    // Deadline en el pasado → todo lo que se comprueba entre fases se salta.
    let ya = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let s = nexus::enhanced::enhance(&cfg, &targets, Some(ya)).await.unwrap();
    let content = std::fs::read_to_string(&targets).unwrap();

    assert!(!content.contains("/crawled"), "katana no corre tras el deadline");
    assert!(!content.contains("/admin"), "ffuf no corre tras el deadline");
    assert_eq!(s.crawled, 0);
    assert_eq!(s.discovered, 0);
    // La fase PASIVA (gau/wayback) también respeta el deadline. Sin este
    // aserto el test daba verde mientras la pasiva se comía el ciclo entero
    // en producción (directiva 33: la sonda no miraba la vía de fallo real).
    // El stub de gau aporta "/archived1"; con el bug, aparece pese al deadline.
    assert!(!content.contains("/archived1"), "gau (pasivo) no corre tras el deadline");
    assert_eq!(s.passive, 0, "la fase pasiva respeta el deadline");
}

/// **La selección por frescura, con su pareja (directiva 33).**
///
/// El caso ROJO tiene que fallar por la vía real: un programa FRESCO ya
/// escaneado gana a un VETERANO ya escaneado *solo* porque cae dentro de la
/// ventana. Y el caso que descarta un instrumento que diga siempre que sí: con
/// la ventana en 0, la frescura se apaga y manda el round-robin por antigüedad.
///
/// Se controla `created_at` a mano (los helpers normales lo ponen a `now`),
/// porque frescura ES una función de esa columna: sin escribirla no se prueba
/// nada. `last_scanned` se fija para que el desempate por antigüedad EMPUJE en
/// contra de la frescura — así, si el fresco gana, es por la frescura y no por
/// el desempate.
#[tokio::test]
async fn frescura_prioriza_lo_nuevo_y_se_apaga_con_ventana_cero() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();

    // VETERANO: apareció hace 100 días, escaneado hace mucho (last_scanned viejo
    // → el desempate por antigüedad lo pondría PRIMERO).
    sqlx::query(
        "INSERT INTO programs (name, h1_handle, created_at, last_scanned)
         VALUES ('veterano','veterano', datetime('now','-100 days'), datetime('now','-30 days'))",
    ).execute(&pool).await.unwrap();

    // FRESCO: apareció hace 2 días, escaneado AYER (last_scanned más reciente →
    // el desempate por antigüedad lo pondría SEGUNDO). Solo la frescura puede
    // hacerlo ganar.
    sqlx::query(
        "INSERT INTO programs (name, h1_handle, created_at, last_scanned)
         VALUES ('fresco','fresco', datetime('now','-2 days'), datetime('now','-1 days'))",
    ).execute(&pool).await.unwrap();

    // ROJO→VERDE: con ventana de 14 días, el fresco gana pese a ser el más
    // reciente en escanearse.
    let elegido = db::next_program_to_hunt(&pool, 3, 14).await.unwrap().map(|(n, _)| n);
    assert_eq!(
        elegido.as_deref(),
        Some("fresco"),
        "dentro de la ventana, el programa nuevo tiene que ir primero aunque se \
         acabe de escanear"
    );

    // EL DISCRIMINANTE: con la ventana en 0 la frescura se apaga y vuelve a
    // mandar la antigüedad de escaneo → el veterano (last_scanned más viejo).
    // Si esta mitad no cambiara, la prueba pasaría con una frescura cableada a
    // 'siempre'.
    let sin_frescura = db::next_program_to_hunt(&pool, 3, 0).await.unwrap().map(|(n, _)| n);
    assert_eq!(
        sin_frescura.as_deref(),
        Some("veterano"),
        "con ventana 0, el orden vuelve a ser el de antes: manda last_scanned"
    );

    // Y el borde: un programa que aparece HOY pero ya envejeció fuera de la
    // ventana (created_at a 20 días) NO es fresco con ventana 14.
    sqlx::query(
        "INSERT INTO programs (name, h1_handle, created_at, last_scanned)
         VALUES ('casi','casi', datetime('now','-20 days'), datetime('now','-40 days'))",
    ).execute(&pool).await.unwrap();
    // 'casi' tiene el last_scanned más viejo de los tres: sin frescura iría
    // primero. Pero 'fresco' sigue ganando por la ventana.
    let con_borde = db::next_program_to_hunt(&pool, 3, 14).await.unwrap().map(|(n, _)| n);
    assert_eq!(
        con_borde.as_deref(),
        Some("fresco"),
        "un programa a 20 días queda fuera de la ventana de 14 y no compite por frescura"
    );
}

/// **El re-sembrado cuenta solo los NUEVOS (directiva 20/33).** El sync loguea
/// este número como "programas nuevos"; si contara también los que ya existían,
/// gritaría el catálogo entero cada día y enterraría la señal de que uno nuevo
/// llegó de verdad.
///
/// Mutante = `ON CONFLICT(name) DO UPDATE ...`: en SQLite un DO UPDATE cuenta
/// como fila afectada aunque la fila ya existiera → la segunda siembra devolvería
/// 2 en vez de 1. El caso rojo falla por esa vía real.
#[tokio::test]
async fn seed_cuenta_solo_los_programas_nuevos() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();

    let n1 = db::seed_programs_pending(&pool, &["a".into(), "b".into()]).await.unwrap();
    assert_eq!(n1, 2, "dos handles nuevos → 2 sembrados");

    // Segunda siembra con SOLAPE: "b" ya existe, solo "c" es nuevo.
    let n2 = db::seed_programs_pending(&pool, &["b".into(), "c".into()]).await.unwrap();
    assert_eq!(n2, 1, "solo 'c' es nuevo; con DO UPDATE 'b' contaría y daría 2");

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM programs")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(total, 3, "a, b, c — sin duplicar 'b'");
}

/// **El almacén de identidades del motor autz (incremento 2).** Se cargan de la
/// tabla real, las cabeceras se parsean, `juego_listo` exige dueño + otro, y un
/// papel desconocido falla RUIDOSO (directiva 20: la config a mano no se degrada
/// en silencio a un juego incompleto).
#[tokio::test]
async fn identidades_se_cargan_y_papel_malo_falla_ruidoso() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();

    // Solo dueño → carga pero NO permite diffear.
    sqlx::query("INSERT INTO identidades (program_name, papel, cabeceras) VALUES ('acme','dueno','[[\"Cookie\",\"s=A\"]]')")
        .execute(&pool).await.unwrap();
    let ids = db::cargar_identidades(&pool, "acme").await.unwrap();
    assert_eq!(ids.len(), 1);
    assert!(!autz::juego_listo(&ids), "solo dueño no permite diffear");

    // + un par → listo, y las cabeceras se parsean bien.
    sqlx::query("INSERT INTO identidades (program_name, papel, cabeceras) VALUES ('acme','par','[[\"Cookie\",\"s=B\"]]')")
        .execute(&pool).await.unwrap();
    let ids = db::cargar_identidades(&pool, "acme").await.unwrap();
    assert_eq!(ids.len(), 2);
    assert!(autz::juego_listo(&ids));
    let par = ids.iter().find(|i| i.papel == autz::Papel::Par).unwrap();
    assert_eq!(par.cabeceras, vec![("Cookie".to_string(), "s=B".to_string())]);

    // Programa sin identidades → vacío (el motor lo salta), NO error.
    assert!(db::cargar_identidades(&pool, "inexistente").await.unwrap().is_empty());

    // Papel desconocido → error RUIDOSO.
    sqlx::query("INSERT INTO identidades (program_name, papel, cabeceras) VALUES ('bad','xyz','[]')")
        .execute(&pool).await.unwrap();
    assert!(db::cargar_identidades(&pool, "bad").await.is_err(), "papel desconocido debe fallar ruidoso");
}

// --- Stub HTTP para el motor autz (incremento 2b): tres endpoints que modelan
//     los tres desenlaces. Cuerpos > 64 bytes (MIN_LEN del clasificador). ---
const CUERPO_ALICE: &str = "SECRETO-DE-ALICE-0123456789abcdef0123456789abcdef0123456789abcdef-fin";

async fn stub_vulnerable(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    // IDOR HORIZONTAL real: exige estar AUTENTICADO (cualquier cookie de sesión),
    // pero NO comprueba la PROPIEDAD → alice y bob reciben el dato de alice. El
    // anónimo (sin cookie) es DENEGADO: hay control, y por eso es una costura y no
    // un recurso público (la distinción que el guardia de recurso público exige).
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    if cookie.contains("s=") {
        (axum::http::StatusCode::OK, CUERPO_ALICE).into_response()
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "").into_response()
    }
}
async fn stub_publico() -> &'static str {
    // Recurso PÚBLICO (una fuente, un SVG, .well-known): lo recibe CUALQUIERA,
    // incluido el anónimo. El par ve el mismo cuerpo que el dueño, pero NO es IDOR
    // —no hay control que saltar—. Es el falso positivo medido el 2026-08-24.
    CUERPO_ALICE
}
async fn stub_seguro(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    if cookie.contains("s=alice") {
        (axum::http::StatusCode::OK, CUERPO_ALICE).into_response()
    } else {
        // El control CORRECTO: 404 al recurso ajeno, no 403 (la señal de medico).
        (axum::http::StatusCode::NOT_FOUND, "").into_response()
    }
}
async fn stub_perfil(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    // Cada identidad ve LO SUYO: cuerpos y longitudes distintos → NO es fuga.
    if cookie.contains("s=alice") {
        (axum::http::StatusCode::OK, "PERFIL-DE-ALICE-nombre-email-telefono-direccion-corto-0").into_response()
    } else {
        (axum::http::StatusCode::OK, "perfil-de-bob-mucho-mas-largo-con-otros-campos-y-una-longitud-claramente-diferente-9999").into_response()
    }
}

/// **El driver autz contra un servidor REAL (directiva 28: se cruza la frontera
/// HTTP, no de estructura a estructura).** Los tres desenlaces: vulnerable marca
/// IDOR con confianza Alta; seguro (404 al ajeno) no marca; perfil (cada uno ve
/// lo suyo) no marca —el falso positivo grande, ahora probado end-to-end—.
#[tokio::test]
async fn autz_diffea_contra_un_servidor_real() {
    let app = axum::Router::new()
        .route("/vulnerable", axum::routing::get(stub_vulnerable))
        .route("/publico", axum::routing::get(stub_publico))
        .route("/seguro", axum::routing::get(stub_seguro))
        .route("/perfil", axum::routing::get(stub_perfil));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = autz::cliente("nexus-autz-test").unwrap();
    let base = format!("http://{addr}");
    let ids = vec![
        autz::Identidad { papel: autz::Papel::Dueno, cabeceras: vec![("Cookie".into(), "s=alice".into())] },
        autz::Identidad { papel: autz::Papel::Par, cabeceras: vec![("Cookie".into(), "s=bob".into())] },
    ];

    let (vuln, _) = autz::diffear(&client, &autz::Solicitud { url: format!("{base}/vulnerable") }, &ids, autz::UMBRAL_DEFECTO).await.unwrap();
    assert_eq!(vuln.len(), 1, "el endpoint vulnerable debe marcar una costura");
    assert_eq!(vuln[0].veredicto.costura, autz::Costura::IdorHorizontal);
    assert_eq!(vuln[0].veredicto.confianza, autz::Confianza::Alta);
    // La evidencia REAL lleva el diferencial de los tres (dueño/par/anónimo), no
    // una etiqueta: prueba que el anónimo quedó DENEGADO (la costura es real).
    assert!(vuln[0].evidencia.contains("anónimo"), "la evidencia incluye la línea base anónima");
    assert!(vuln[0].evidencia.contains("HTTP 401"), "el anónimo denegado consta en la evidencia");

    // El FALSO POSITIVO medido: recurso público (anónimo también lo obtiene) NO
    // debe marcar, aunque el par vea lo mismo que el dueño (mata los 46 FP de
    // fuentes/SVG del 2026-08-24), end-to-end sobre HTTP real.
    let (publico, _) = autz::diffear(&client, &autz::Solicitud { url: format!("{base}/publico") }, &ids, autz::UMBRAL_DEFECTO).await.unwrap();
    assert!(publico.is_empty(), "recurso público (anónimo accede) NO es IDOR");

    let (seguro, _) = autz::diffear(&client, &autz::Solicitud { url: format!("{base}/seguro") }, &ids, autz::UMBRAL_DEFECTO).await.unwrap();
    assert!(seguro.is_empty(), "seguro (404 al ajeno) no debe marcar");

    let (perfil, _) = autz::diffear(&client, &autz::Solicitud { url: format!("{base}/perfil") }, &ids, autz::UMBRAL_DEFECTO).await.unwrap();
    assert!(perfil.is_empty(), "cada identidad ve su propio dato: no es IDOR");
}

/// **La FASE autz completa (incremento 2c): corpus → diffing → findings en la
/// base REAL.** Reusa el stub de tres endpoints; con dueño+par montados, corre
/// sobre las tres URLs y debe persistir UNA costura (la vulnerable) con su
/// vuln_type, saltando seguro y perfil. Verifica el enganche de punta a punta.
#[tokio::test]
async fn fase_autz_persiste_solo_la_costura_real() {
    let app = axum::Router::new()
        .route("/vulnerable", axum::routing::get(stub_vulnerable))
        .route("/seguro", axum::routing::get(stub_seguro))
        .route("/perfil", axum::routing::get(stub_perfil));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();

    // Montar identidades (dueño + par).
    for (papel, ck) in [("dueno", "s=alice"), ("par", "s=bob")] {
        sqlx::query("INSERT INTO identidades (program_name, papel, cabeceras) VALUES ('acme', ?1, ?2)")
            .bind(papel).bind(format!("[[\"Cookie\",\"{ck}\"]]")).execute(&pool).await.unwrap();
    }
    let ids = db::cargar_identidades(&pool, "acme").await.unwrap();

    let base = format!("http://{addr}");
    let corpus = vec![format!("{base}/vulnerable"), format!("{base}/seguro"), format!("{base}/perfil")];
    let mut guard = Guard::new(ProtectionConfig::default());
    let ca = autz::ConfigAutz { user_agent: "nexus-test".into(), umbral: autz::UMBRAL_DEFECTO, cap: 100, cooldown_secs: 0, pausa_tecnica_secs: 0 };

    let n = autz::fase_autz(&pool, "acme", &corpus, &ids, &mut guard, &ca, None, || 0.5).await.unwrap();
    assert_eq!(n, 1, "solo la URL vulnerable debe producir una costura");

    // El finding quedó con su vuln_type. Confianza ALTA (firma exacta) = bypass
    // PROBADO por diferencial → se CONFIRMA sin esperar a un humano (VERIFIED +
    // execution_confirmed). NO se auto-envía igual: control de acceso no es clase
    // pagable — la garantía de «no envío» se movió de execution_confirmed a
    // payability, no a quedarse en revisión manual eterna.
    let (vt, url, ec, st): (String, String, i64, String) = sqlx::query_as(
        "SELECT vuln_type, url, execution_confirmed, status FROM findings WHERE vuln_name='control-de-acceso-idor-horizontal'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(vt, "idor");
    assert!(url.ends_with("/vulnerable"));
    assert_eq!(ec, 1, "una ALTA de autz es bypass probado por diferencial → execution_confirmed");
    assert_eq!(st, "VERIFIED", "confirmada deja de esperar a un humano");

    // Sin juego (solo dueño) → 0, se salta.
    let solo = vec![ids.iter().find(|i| i.papel == autz::Papel::Dueno).unwrap().clone()];
    let n2 = autz::fase_autz(&pool, "acme", &corpus, &solo, &mut guard, &ca, None, || 0.5).await.unwrap();
    assert_eq!(n2, 0, "sin par/anónimo no hay con qué diffear: se salta");
}

/// Las URLs semilla (recursos propios del dueño) se cargan por programa.
#[tokio::test]
async fn semillas_autz_se_cargan_por_programa() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    for u in ["https://acme.test/account/albums/PRIV1", "https://acme.test/account/settings"] {
        sqlx::query("INSERT INTO autz_semillas (program_name, url) VALUES ('acme', ?1)").bind(u).execute(&pool).await.unwrap();
    }
    let s = db::cargar_semillas(&pool, "acme").await.unwrap();
    assert_eq!(s.len(), 2);
    assert!(s.iter().any(|u| u.ends_with("/PRIV1")));
    assert!(db::cargar_semillas(&pool, "otro").await.unwrap().is_empty());
}

// --- Stubs para la fase de EVASIÓN (bypass 403), sin login ---
async fn stub_bypass_vulnerable(h: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Protegido para el plano; se salta con X-Forwarded-For (ACL por IP mal hecha).
    if h.contains_key("x-forwarded-for") {
        (axum::http::StatusCode::OK, CUERPO_ALICE).into_response()
    } else {
        (axum::http::StatusCode::FORBIDDEN, "acceso denegado").into_response()
    }
}
async fn stub_bypass_seguro() -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::FORBIDDEN, "acceso denegado").into_response()
}
async fn stub_bypass_publico() -> &'static str {
    CUERPO_ALICE
}

/// **La fase de EVASIÓN sin login (bypass 403), de punta a punta.** El endpoint
/// vulnerable (403 plano, 200 con X-Forwarded-For) debe marcarse; el siempre-403
/// y el público, no. Sin identidades: es la vía account-free.
#[tokio::test]
async fn fase_bypass_detecta_evasion_sin_login() {
    let app = axum::Router::new()
        .route("/vuln", axum::routing::get(stub_bypass_vulnerable))
        .route("/seguro", axum::routing::get(stub_bypass_seguro))
        .route("/publico", axum::routing::get(stub_bypass_publico));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let base = format!("http://{addr}");
    let corpus = vec![format!("{base}/vuln"), format!("{base}/seguro"), format!("{base}/publico")];
    let mut guard = Guard::new(ProtectionConfig::default());
    let ca = autz::ConfigAutz { user_agent: "nexus-bypass-test".into(), umbral: autz::UMBRAL_DEFECTO, cap: 100, cooldown_secs: 0, pausa_tecnica_secs: 0 };

    let n = autz::fase_bypass(&pool, "acme", &corpus, &mut guard, &ca, None, || 0.5).await.unwrap();
    assert_eq!(n, 1, "solo el endpoint con bypass real debe marcarse");
    let (vt, url): (String, String) = sqlx::query_as(
        "SELECT vuln_type, url FROM findings WHERE vuln_name='control-de-acceso-evasion-403'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(vt, "bac");
    assert!(url.ends_with("/vuln"));
}

/// **El cortacircuitos anti-baneo (VPS compartido).** Un objetivo que responde
/// SIEMPRE 429 debe hacer que la fase de evasión PARE tras pocas peticiones
/// (should_pause a los 3 fallos), no que martille los 10 endpoints × 14 técnicas.
/// Directiva 33: el caso rojo (objetivo enojado) tiene que frenar, no seguir.
#[tokio::test]
async fn cortacircuitos_para_ante_429_repetido() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    async fn stub_429(
        axum::extract::State(cnt): axum::extract::State<Arc<AtomicUsize>>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        cnt.fetch_add(1, Ordering::SeqCst);
        (axum::http::StatusCode::TOO_MANY_REQUESTS, "slow down").into_response()
    }
    let cnt = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route("/e/{id}", axum::routing::get(stub_429))
        .with_state(cnt.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let base = format!("http://{addr}");
    let corpus: Vec<String> = (0..10).map(|i| format!("{base}/e/{i}")).collect();
    // Guard con backoff CERO para que el test no duerma 120s, pero cortacircuitos
    // a los 3 fallos (el default real).
    let pcfg = ProtectionConfig { failure_backoff_base: 0, failure_backoff_max: 0, ..ProtectionConfig::default() };
    let mut guard = Guard::new(pcfg);
    let ca = autz::ConfigAutz { user_agent: "t".into(), umbral: autz::UMBRAL_DEFECTO, cap: 100, cooldown_secs: 0, pausa_tecnica_secs: 0 };

    let n = autz::fase_bypass(&pool, "acme", &corpus, &mut guard, &ca, None, || 0.5).await.unwrap();
    let peticiones = cnt.load(Ordering::SeqCst);
    assert_eq!(n, 0, "un 429 nunca es un bypass");
    assert!(peticiones <= 4, "el cortacircuitos debe parar tras ~3 fallos, no martillar; hizo {peticiones} peticiones");
}

/// **El muro-403 detiene la fase (protección de la IP compartida).** Un WAF que
/// devuelve 403 a TODO no es protección por-endpoint: es nuestra IP bloqueada.
/// El código VIEJO trataba cada 403 como endpoint protegido y lanzaba las 14
/// técnicas de evasión en CADA uno → se volvía MÁS agresivo justo al ser
/// frenado. Ahora, un run de 403 seguidos PARA la fase.
///   - ROJO (mutante = sin muro_403): procesaría los 12 endpoints × (1 base + 14
///     técnicas) = 180 peticiones. La cota lo mata.
///   - VERDE: para tras ~MURO_403_MAX baselines, evadiendo solo el 1er 403 del
///     run; n=0 (un muro nunca es un bypass).
///   - CONTROL (directiva 33): `fase_bypass_detecta_evasion_sin_login` prueba
///     que un objetivo VARIADO (200 intercalado) NO dispara el muro y sí halla
///     el bypass real — el mismo detector no se ciega en lo legítimo.
#[tokio::test]
async fn muro_403_detiene_la_fase_y_protege_la_ip() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    async fn stub_403_todo(
        axum::extract::State(cnt): axum::extract::State<Arc<AtomicUsize>>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        cnt.fetch_add(1, Ordering::SeqCst);
        (axum::http::StatusCode::FORBIDDEN, "denegado").into_response()
    }
    let cnt = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route("/e/{id}", axum::routing::get(stub_403_todo))
        .with_state(cnt.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let cfg = test_cfg(dir.path(), &stub("nuclei.sh"), &[]);
    let pool = db::open(&cfg.db_path, 4).await.unwrap();
    let base = format!("http://{addr}");
    // 12 endpoints, TODOS 403: es un muro, no 12 recursos protegidos.
    let corpus: Vec<String> = (0..12).map(|i| format!("{base}/e/{i}")).collect();
    let mut guard = Guard::new(ProtectionConfig::default());
    let ca = autz::ConfigAutz { user_agent: "t".into(), umbral: autz::UMBRAL_DEFECTO, cap: 100, cooldown_secs: 0, pausa_tecnica_secs: 0 };

    let n = autz::fase_bypass(&pool, "acme", &corpus, &mut guard, &ca, None, || 0.5).await.unwrap();
    let peticiones = cnt.load(Ordering::SeqCst);
    assert_eq!(n, 0, "un muro-403 nunca es un bypass");
    // Sin el muro: 12×(1+14)=180. Con él: ~5 baselines + 14 técnicas del 1er 403.
    assert!(peticiones <= 25,
        "el muro-403 debe PARAR la fase, no martillar los 12 endpoints; hizo {peticiones} peticiones (mutante haría 180)");
}
