//! NEXUS — orquestador de bug bounty en Rust. Unifica hacker/ (sniper) y bounty/
//! (pipeline con protección). El motor son binarios externos (nuclei, subfinder,
//! httpx, sqlmap...); Rust dirige, protege la IP y persiste.

use clap::Parser;
use anyhow::Context as _;
use nexus::config::{Command, Config};
use nexus::protection::{Guard, ProtectionConfig};
use nexus::{autz, db, deepscan, engine, h1, recon, report};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Carga .env si existe (sin dependencia: parseo mínimo).
    load_dotenv();

    let mut cfg = Config::parse();
    cfg.apply_safe_mode();
    // NEXUS_AUTO_SUBMIT (1/true/yes/on) enciende el auto-envío desde el entorno,
    // además del flag --auto-submit. Parseo tolerante (evita el fallo de clap con "1").
    if !cfg.auto_submit && env_truthy("NEXUS_AUTO_SUBMIT") {
        cfg.auto_submit = true;
    }
    // NEXUS_H1_GATE_ENFORCE (1/true/yes/on) activa el enforce del gate de
    // elegibilidad en el ciclo, igual que arriba. En `false` el gate solo mide.
    if !cfg.h1_gate_enforce && env_truthy("NEXUS_H1_GATE_ENFORCE") {
        cfg.h1_gate_enforce = true;
    }
    // NEXUS_AUTZ_PAYABLE (1/true/yes/on) hace auto-enviables las clases de control
    // de acceso (idor/bac) confirmadas por autz. Irreversible + Signal: opt-in.
    if !cfg.autz_payable && env_truthy("NEXUS_AUTZ_PAYABLE") {
        cfg.autz_payable = true;
    }
    // NEXUS_SECRET_VERIFY (1/true/yes/on) enciende la verificación VIVA de secretos
    // (usa la credencial ajena contra el proveedor). Opt-in: por defecto NO se toca
    // al tercero y un secreto detectado va a revisión manual.
    if !cfg.secret_verify && env_truthy("NEXUS_SECRET_VERIFY") {
        cfg.secret_verify = true;
    }

    init_tracing(cfg.verbose);
    tokio::fs::create_dir_all(&cfg.scans_dir).await.ok();

    // El colector OOB es PÚBLICO y sin autenticar: NO abre la BD principal
    // (findings/programas, en un VPS con datos clínicos), solo su BD aislada.
    // Se despacha ANTES de abrir la principal, para que este proceso jamás la toque.
    if matches!(cfg.command, Command::OobServer) {
        return cmd_oob_server(&cfg).await;
    }

    // FP-lab: se despacha ANTES de abrir la BD principal — es un lab autocontenido
    // (app-trampa en loopback), no toca findings/programas.
    if let Command::FpEval { port, xss_tries } = &cfg.command {
        return cmd_fp_eval(&cfg, *port, *xss_tries).await;
    }

    // Oráculo diferencial (whitebox/blackbox): autocontenido, no toca findings.
    if let Command::Oraculo { black, base, caso, scope, intentos, lab, realtime } = &cfg.command {
        return cmd_oraculo(*black, base, caso, scope, *intentos, lab.as_deref(), *realtime).await;
    }

    // Hacktivity: GraphQL público de H1, SIN credenciales y sin BD. Se despacha
    // antes de abrir la BD principal (adyacente a datos clínicos): no la necesita.
    if let Command::Hacktivity { programas, lista, cap, salida } = &cfg.command {
        return cmd_hacktivity(&cfg, programas, lista.as_deref(), *cap, salida.as_deref()).await;
    }

    // Recon OIDC de RPs/audiencias: autocontenido (solo lee discovery público y
    // parsea URLs de authorize). No toca la BD principal.
    if let Command::OidcRecon { base, authorize, json } = &cfg.command {
        return cmd_oidc_recon(&cfg, base, authorize, *json).await;
    }

    // Candidatos: search API + advisories de GitHub, SIN credenciales y sin BD. Selección
    // para el carril whitebox; se despacha antes de abrir la BD principal.
    if let Command::Candidatos { dominios, lang, anios, max, salida } = &cfg.command {
        return cmd_candidatos(&cfg, dominios, lang.as_deref(), *anios, *max, salida.as_deref()).await;
    }

    let pool = db::open(&cfg.db_path, cfg.workers as u32 + 2).await?;

    match cfg.command.clone() {
        Command::VigilarPrograma { handle } => cmd_vigilar_programa(&cfg, &handle).await?,
        Command::Recon { scope_only } => cmd_recon(&cfg, &pool, None, scope_only).await?,
        Command::Scan { targets, program } => {
            let targets = targets.unwrap_or_else(|| cfg.scans_dir.join("targets.txt"));
            cmd_scan(&cfg, &pool, &targets, &program, None).await?;
        }
        Command::Buckets { bases, program, max } => {
            let n = nexus::buckets::fase_buckets(
                &pool,
                &program,
                &bases,
                max,
                cfg.notify_webhook.as_deref(),
            )
            .await?;
            println!("buckets expuestos persistidos: {n}");
        }
        Command::Parametros { url, metodo, cabeceras, sensible_longitud } => {
            cmd_parametros(&url, &metodo, &cabeceras, sensible_longitud).await?;
        }
        Command::SecretosJs { url, max_js, verificar } => {
            cmd_secretos_js(&cfg, &url, max_js, verificar).await?;
        }
        Command::TokenSinAuth { url, protegido } => {
            cmd_token_sin_auth(&cfg, &url, protegido.as_deref()).await?;
        }
        Command::RedteamLlm { url, campo, plantilla_cuerpo, ruta_respuesta, cabeceras, categorias } => {
            cmd_redteam_llm(&url, &campo, plantilla_cuerpo, ruta_respuesta, &cabeceras, &categorias)
                .await?;
        }
        Command::Verify { limit } => cmd_verify(&cfg, &pool, limit).await?,
        Command::Evidence => {
            let n = nexus::evidence::capture_all(&cfg, &pool).await?;
            tracing::info!("{n} capturas de evidencia");
        }
        Command::Sync => cmd_sync(&pool).await?,
        Command::Hunt { program } => cmd_hunt(&cfg, &pool, program).await?,
        Command::Submit { auto, dry_run } => {
            let n = nexus::submitter::generate_all(&cfg, &pool).await?;
            tracing::info!("{n} informes generados en {}", cfg.reports_dir.display());
            if auto {
                let s = nexus::autosubmit::run(&cfg, &pool, dry_run).await?;
                tracing::info!(
                    "auto-envío: {} enviados, {} dry-run, {} sin programa, {} duplicados, {} fallidos",
                    s.sent, s.dry_run, s.skipped_no_program, s.skipped_duplicate, s.failed
                );
            }
        }
        Command::Report => cmd_report(&cfg, &pool).await?,
        Command::Serve => cmd_serve(&cfg, &pool).await?,
        Command::OobServer => unreachable!("OobServer se despacha antes de abrir la BD principal"),
        Command::FpEval { .. } => unreachable!("FpEval se despacha antes de abrir la BD principal"),
        Command::Oraculo { .. } => unreachable!("Oraculo se despacha antes de abrir la BD principal"),
        Command::OidcRecon { .. } => unreachable!("OidcRecon se despacha antes de abrir la BD principal"),
        Command::Elegibilidad { aplicar } => {
            cmd_elegibilidad(&pool, aplicar, cfg.manual_ready_max_dias).await?
        }
        Command::Operabilidad { top } => cmd_operabilidad(&pool, top).await?,
        Command::ScopesRefresh { todos, limite } => cmd_scopes_refresh(&pool, todos, limite).await?,
        Command::Dictamen { programa, cumplimiento } => {
            cmd_dictamen(&pool, &programa, cumplimiento.as_deref()).await?
        }
        Command::Cbom { ruta, salida, dictamen, perito, tarjeta, cliente, nit } => {
            let enc = nexus::cbom::Encargo {
                perito: perito.as_deref(), tarjeta: tarjeta.as_deref(),
                cliente: cliente.as_deref(), nit: nit.as_deref(),
            };
            cmd_cbom(&ruta, salida.as_deref(), dictamen, &enc);
        }
        Command::Cumplimiento { catalogo } => cmd_cumplimiento(catalogo),
        Command::Identidad { programa, papel, cabeceras, listar, borrar } => {
            cmd_identidad(&pool, &programa, papel.as_deref(), &cabeceras, listar, borrar.as_deref()).await?
        }
        Command::Semilla { programa, urls, listar } => {
            cmd_semilla(&pool, &programa, &urls, listar).await?
        }
        Command::Hacktivity { .. } => {
            unreachable!("Hacktivity se despacha antes de abrir la BD principal")
        }
        Command::Candidatos { .. } => {
            unreachable!("Candidatos se despacha antes de abrir la BD principal")
        }
    }
    Ok(())
}

/// Selección de OSS joven para el carril whitebox de código-fuente. Por cada dominio busca
/// repos jóvenes (search API keyless), cuenta avisos de seguridad por repo (clase authz vs total),
/// cruza la LISTA-NEGRA y los puntúa como EMBUDO (prioridad de lectura puerta-0, NO predicción de
/// hallazgo — el discriminador real solo se ve leyendo el código). Emite markdown para el razonador.
async fn cmd_candidatos(
    cfg: &Config,
    dominios: &[String],
    lang: Option<&str>,
    anios: i64,
    max: usize,
    salida: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use nexus::candidatos;
    use std::time::Duration;

    let ua = cfg
        .user_agent
        .clone()
        .unwrap_or_else(|| nexus::evasion::UA_POOL[0].to_string());
    let client = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(Duration::from_secs(20))
        .build()
        .context("construyendo el cliente HTTP")?;

    // Lista negra (si existe): cruce para no re-ofrecer lo ya descartado. Ausente = cadena vacía
    // (no falla el barrido; solo deja de cruzar — se dice en el encabezado).
    let ruta_negra = std::path::Path::new("/mnt/data/conocimiento/objetivos/LISTA-NEGRA.md");
    let negra = tokio::fs::read_to_string(ruta_negra).await.unwrap_or_default();
    if negra.is_empty() {
        eprintln!("candidatos: ⚠ LISTA-NEGRA no encontrada en {} — sin cruce de exclusión", ruta_negra.display());
    }

    let anio_hoy: i64 = chrono::Utc::now().format("%Y").to_string().parse().unwrap_or(2026);

    // Reúne repos de todos los dominios, dedup por full_name.
    let mut repos = Vec::new();
    let mut vistos = std::collections::HashSet::new();
    for dom in dominios {
        eprintln!("candidatos: buscando `{dom}`…");
        match candidatos::buscar(&client, dom, lang, anios, anio_hoy, max).await {
            Ok(rs) => {
                for r in rs {
                    if vistos.insert(r.full_name.clone()) {
                        repos.push(r);
                    }
                }
            }
            // Un dominio que falla (rate-limit, red) NO tumba el barrido (D30: se DICE por qué).
            Err(e) => eprintln!("  ⚠ `{dom}`: {e}"),
        }
        // Rate-limit search keyless = 10/min: espera entre dominios.
        tokio::time::sleep(Duration::from_secs(7)).await;
    }

    if repos.is_empty() {
        anyhow::bail!("sin repos: ¿rate-limit de GitHub, o dominios sin resultados jóvenes?");
    }

    eprintln!("candidatos: triando {} repos (avisos por repo, ~1s c/u)…", repos.len());
    // Jitter entre llamadas a advisories (API core keyless = 60/h): 1s basta para una tanda chica.
    let candidatos = candidatos::triar(&client, repos, &negra, anios, anio_hoy, Duration::from_secs(1)).await;

    let doc = candidatos::informe_md(&candidatos);
    match salida {
        Some(ruta) => {
            tokio::fs::write(ruta, &doc)
                .await
                .with_context(|| format!("escribiendo {}", ruta.display()))?;
            let persigue = candidatos.iter().filter(|c| c.veredicto == candidatos::Veredicto::Perseguir).count();
            eprintln!("candidatos: {} triados, {persigue} PERSEGUIR → {}", candidatos.len(), ruta.display());
        }
        None => print!("{doc}"),
    }
    Ok(())
}

/// Checklist "qué ya se explotó/reportó por programa" desde el hacktivity público
/// de H1. Reúne los handles de `--programa` y del archivo `--lista`, baja los
/// reportes divulgados de cada uno y emite un Markdown: tabla-resumen (ordenada por
/// nº de divulgados) + una sección por programa con las clases CWE ya premiadas y
/// la lista de reportes. Solo lectura hacia H1; no toca la BD.
async fn cmd_hacktivity(
    cfg: &Config,
    programas: &[String],
    lista: Option<&std::path::Path>,
    cap: usize,
    salida: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use nexus::hacktivity;

    // Reúne handles: los de --programa más los del archivo, en orden y sin duplicar.
    let mut handles: Vec<String> = Vec::new();
    let mut vistos = std::collections::HashSet::new();
    let agregar = |h: &str, handles: &mut Vec<String>, vistos: &mut std::collections::HashSet<String>| {
        let h = h.trim();
        if h.is_empty() || h.starts_with('#') {
            return;
        }
        if vistos.insert(h.to_string()) {
            handles.push(h.to_string());
        }
    };
    for p in programas {
        agregar(p, &mut handles, &mut vistos);
    }
    if let Some(ruta) = lista {
        let txt = tokio::fs::read_to_string(ruta)
            .await
            .with_context(|| format!("leyendo la lista de programas {}", ruta.display()))?;
        for linea in txt.lines() {
            agregar(linea, &mut handles, &mut vistos);
        }
    }
    if handles.is_empty() {
        anyhow::bail!("sin programas: da --programa <handle> (repetible) y/o --lista <archivo>");
    }

    let ua = cfg
        .user_agent
        .clone()
        .unwrap_or_else(|| nexus::evasion::UA_POOL[0].to_string());

    let mut resumenes: Vec<hacktivity::Resumen> = Vec::new();
    let mut secciones = String::new();
    let mut errores: Vec<String> = Vec::new();
    for h in &handles {
        eprintln!("hacktivity: consultando `{h}`…");
        match hacktivity::fetch(h, cap, &ua).await {
            Ok((total, reportes)) => {
                resumenes.push(hacktivity::Resumen {
                    handle: h.clone(),
                    total,
                    top_cwe: hacktivity::por_cwe(&reportes),
                });
                secciones.push_str(&hacktivity::seccion_md(h, total, &reportes));
            }
            // Un programa que falla (red, handle inexistente) NO tumba el barrido:
            // se registra y sigue (directiva 30: se DICE por qué no salió, no se calla).
            Err(e) => {
                eprintln!("  ⚠ `{h}`: {e}");
                errores.push(format!("`{h}`: {e}"));
            }
        }
    }

    let mut doc = String::new();
    doc.push_str("# Checklist H1 — vulnerabilidades ya divulgadas por programa\n\n");
    doc.push_str(&format!(
        "Fuente: hacktivity público de HackerOne (reportes divulgados, `state:closed`). \
         {} programa(s), cap {} por programa. Generado por `nexus hacktivity`.\n\n\
         > **Qué NO dice un `0`.** Es 0 reportes *divulgados públicamente*, no 0 bugs \
         encontrados ni «programa sin cazar»: muchos programas no divulgan nada. Un 0 \
         significa «sin prior-art público» (sin dupes visibles, pero tampoco pistas \
         ajenas), no «terreno virgen». Las `Clases top (CWE)` son donde el programa ya \
         PREMIÓ — ahí suele haber más tela y a la vez más riesgo de dupe.\n\n",
        handles.len(),
        cap
    ));
    doc.push_str("## Resumen\n\n");
    doc.push_str(&hacktivity::tabla_resumen(&resumenes));
    if !errores.is_empty() {
        doc.push_str("\n**No consultados** (error): ");
        doc.push_str(&errores.join("; "));
        doc.push('\n');
    }
    doc.push_str("\n## Detalle por programa\n\n");
    doc.push_str(&secciones);

    match salida {
        Some(ruta) => {
            tokio::fs::write(ruta, doc.as_bytes())
                .await
                .with_context(|| format!("escribiendo {}", ruta.display()))?;
            eprintln!("checklist escrito en {}", ruta.display());
        }
        None => print!("{doc}"),
    }
    Ok(())
}

/// Parsea una cabecera "Clave: Valor" a `(clave, valor)`. Falla RUIDOSO
/// (directiva 20) ante una cabecera sin `:`: montar una credencial mal formada en
/// silencio dejaría el juego "listo" pero ciego. El valor puede contener `:`
/// (los Bearer y las cookies los llevan), así que se parte SOLO en el primero.
fn parsear_cabecera(s: &str) -> anyhow::Result<(String, String)> {
    let (k, v) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("cabecera sin ':' — usa \"Clave: Valor\" (recibí: {s:?})"))?;
    let k = k.trim();
    let v = v.trim();
    if k.is_empty() {
        anyhow::bail!("cabecera con clave vacía (recibí: {s:?})");
    }
    // Validez HTTP real, no solo sintaxis: una clave con espacios o un valor con
    // un control (CRLF interior) los rechaza `HeaderName`/`HeaderValue` DESPUÉS,
    // en plena caza, dejando el juego "listo" pero con esa identidad muerta y en
    // silencio (observación de la revisión 2026-08-23; directiva 20). Se falla
    // aquí, al montar, que es cuando el operador puede corregirlo.
    reqwest::header::HeaderName::from_bytes(k.as_bytes())
        .map_err(|e| anyhow::anyhow!("clave de cabecera inválida {k:?}: {e}"))?;
    reqwest::header::HeaderValue::from_str(v)
        .map_err(|e| anyhow::anyhow!("valor de cabecera inválido para {k:?} (¿CRLF o control?): {e}"))?;
    Ok((k.to_string(), v.to_string()))
}

async fn cmd_identidad(
    pool: &sqlx::SqlitePool,
    programa: &str,
    papel: Option<&str>,
    cabeceras: &[String],
    listar: bool,
    borrar: Option<&str>,
) -> anyhow::Result<()> {
    use nexus::autz::Papel;

    if listar {
        let papeles = db::listar_identidades(pool, programa).await?;
        if papeles.is_empty() {
            println!("{programa}: sin identidades montadas");
        } else {
            println!("{programa}: {} identidad(es) → {}", papeles.len(), papeles.join(", "));
            let ids = db::cargar_identidades(pool, programa).await?;
            println!(
                "juego listo para diffear (dueño + otra): {}",
                if nexus::autz::juego_listo(&ids) { "SÍ" } else { "NO — falta el dueño o un par/menor/anónimo" }
            );
        }
        return Ok(());
    }

    if let Some(p) = borrar {
        let papel = Papel::desde_str(p)
            .ok_or_else(|| anyhow::anyhow!("papel desconocido '{p}' (usa dueno|par|menor|anonimo)"))?;
        let borrado = db::borrar_identidad(pool, programa, papel).await?;
        println!(
            "{}",
            if borrado { format!("borrada la identidad '{p}' de {programa}") } else { format!("{programa} no tenía identidad '{p}'") }
        );
        return Ok(());
    }

    // Alta/rotación. `papel` está garantizado por clap (required_unless listar/borrar).
    let papel_s = papel.expect("clap garantiza --papel salvo con --listar/--borrar");
    let papel = Papel::desde_str(papel_s)
        .ok_or_else(|| anyhow::anyhow!("papel desconocido '{papel_s}' (usa dueno|par|menor|anonimo)"))?;

    let cabs: Vec<(String, String)> = cabeceras
        .iter()
        .map(|c| parsear_cabecera(c))
        .collect::<anyhow::Result<_>>()?;

    // Un papel autenticado SIN cabeceras es casi siempre un olvido: se montaría
    // una identidad idéntica al anónimo y el diff no vería nada. Se avisa y se
    // rechaza (directiva 20) salvo que sea el papel anónimo, que va vacío a propósito.
    if cabs.is_empty() && papel != Papel::Anonimo {
        anyhow::bail!(
            "el papel '{papel_s}' no lleva cabeceras: una identidad autenticada sin credencial es igual al anónimo. \
             Pasa al menos una --cabecera, o usa --papel anonimo si de verdad quieres el acceso sin autenticar."
        );
    }
    if !cabs.is_empty() && papel == Papel::Anonimo {
        anyhow::bail!("el papel anónimo va SIN cabeceras (recibí {} )", cabs.len());
    }

    let rotada = db::guardar_identidad(pool, programa, papel, &cabs).await?;
    println!(
        "{} la identidad '{papel_s}' de {programa} ({} cabecera[s])",
        if rotada { "ROTADA" } else { "montada" },
        cabs.len()
    );
    let ids = db::cargar_identidades(pool, programa).await?;
    println!(
        "juego listo para diffear: {}",
        if nexus::autz::juego_listo(&ids) { "SÍ" } else { "NO — falta el dueño o una segunda identidad" }
    );
    Ok(())
}

async fn cmd_semilla(
    pool: &sqlx::SqlitePool,
    programa: &str,
    urls: &[String],
    listar: bool,
) -> anyhow::Result<()> {
    if listar {
        let semillas = db::cargar_semillas(pool, programa).await?;
        if semillas.is_empty() {
            println!("{programa}: sin semillas");
        } else {
            println!("{programa}: {} semilla(s)", semillas.len());
            for u in &semillas {
                println!("  {u}");
            }
        }
        return Ok(());
    }
    let mut nuevas = 0usize;
    for u in urls {
        if db::guardar_semilla(pool, programa, u).await? {
            nuevas += 1;
        }
    }
    println!(
        "{programa}: {nuevas} semilla(s) nueva(s) de {} (el resto ya estaban)",
        urls.len()
    );
    Ok(())
}

/// Imprime el pool rankeado por operabilidad IDOR (dónde montar dos cuentas
/// cuesta menos). No toca la red.
async fn cmd_operabilidad(pool: &sqlx::SqlitePool, top: usize) -> anyhow::Result<()> {
    let rank = nexus::operabilidad::rankear(pool).await?;
    let con_api = rank.iter().filter(|o| o.tiene_api).count();
    println!(
        "# Operabilidad IDOR — {} programas ({} con API en scope). Top {top}:",
        rank.len(),
        con_api
    );
    println!("{:>5}  {:<30} {:>4} {:>5} {:>4}", "pts", "programa", "API", "paga", "KYC");
    for o in rank.iter().take(top) {
        println!(
            "{:>5}  {:<30} {:>4} {:>5} {:>4}",
            o.puntuacion,
            o.programa,
            o.api_assets,
            if o.paga { "sí" } else { "no" },
            if o.kyc_probable { "sí" } else { "-" }
        );
    }
    Ok(())
}

/// Baja el HTML/JS servido de un objetivo y lo pasa por el detector de secretos; imprime
/// los hallazgos con el valor ENMASCARADO y, con `--verificar`, su veredicto de vida.
async fn cmd_secretos_js(
    cfg: &Config,
    url: &str,
    max_js: usize,
    verificar: bool,
) -> anyhow::Result<()> {
    // Cliente que SIGUE redirects: el apex de muchas apps (console.*, app.*)
    // 302-redirige a la SPA real donde vive el JS; sin seguirlo, 0 recursos.
    let cli = nexus::autz::cliente_redirigible(cfg.user_agent.as_deref().unwrap_or(nexus::evasion::UA_POOL[0]))?;
    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = make_rng();
    let (hallazgos, diag) = nexus::secretos_js::escanear_objetivo(
        &cli,
        url,
        &cfg.curl_impersonate_path,
        max_js,
        15,
        &mut guard,
        &mut rng,
        verificar,
    )
    .await;
    // Positivo de control (D30): SIEMPRE se dice qué se bajó, antes del veredicto —
    // así un "0 hallazgos" con 0 recursos NO se confunde con un objetivo limpio.
    println!(
        "secretos-js: raíz={} · {} recurso(s) · {} B escaneados · {} hallazgo(s) en {url}",
        diag.root_status, diag.recursos, diag.bytes, hallazgos.len()
    );
    if hallazgos.is_empty() {
        if diag.recursos == 0 {
            println!(
                "  AVISO: 0 recursos bajados (raíz={}) — redirect no resuelto, muro WAF o host caído; NO es un limpio fiable",
                diag.root_status
            );
        }
        return Ok(());
    }
    for h in &hallazgos {
        let ver = match h.veredicto {
            Some(v) => format!(" [{v:?}]"),
            None => String::new(),
        };
        let nota = if h.clase.publicable() { "  (publicable, NO es fuga)" } else { "" };
        println!("  {} · {} · {}{}{}", h.clase.nombre(), h.valor_enmascarado, h.url, nota, ver);
    }
    Ok(())
}

/// Sondea endpoints de emisión de token sin credencial y confirma por oráculo diferencial.
async fn cmd_token_sin_auth(
    cfg: &Config,
    url: &str,
    protegido: Option<&str>,
) -> anyhow::Result<()> {
    let cli = nexus::autz::cliente(cfg.user_agent.as_deref().unwrap_or(nexus::evasion::UA_POOL[0]))?;
    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = make_rng();
    let hallazgos = nexus::token_sin_auth::sondear(
        &cli,
        url,
        nexus::token_sin_auth::RUTAS_EMISION,
        protegido,
        12,
        &mut guard,
        &mut rng,
    )
    .await;
    if hallazgos.is_empty() {
        println!("token-sin-auth: sin hallazgos en {url}");
        return Ok(());
    }
    println!("token-sin-auth: {} hallazgo(s) en {url}", hallazgos.len());
    for h in &hallazgos {
        println!(
            "  {} {} · {} · {:?}",
            h.metodo, h.ruta, h.token_enmascarado, h.veredicto
        );
    }
    if protegido.is_none() {
        println!("  (sin --protegido: usabilidad SIN confirmar; da un endpoint protegido para el oráculo)");
    }
    Ok(())
}

/// Descubre parámetros ocultos de un endpoint por anomalía (`nexus::parametros`) e imprime
/// los efectivos con su señal — la superficie nueva que alimenta a autz/mass_assign/graphql.
async fn cmd_parametros(
    url: &str,
    metodo: &str,
    cabeceras: &[String],
    sensible_longitud: bool,
) -> anyhow::Result<()> {
    use nexus::oraculo_diferencial::Identidad;
    use nexus::parametros::{self, Config as PConfig, Metodo};

    let metodo = match metodo.to_ascii_lowercase().as_str() {
        "get" => Metodo::Get,
        "post-form" | "postform" | "form" => Metodo::PostForm,
        "post-json" | "postjson" | "json" => Metodo::PostJson,
        otro => anyhow::bail!("método desconocido «{otro}» (usa get | post-form | post-json)"),
    };
    // Identidad a partir de las cabeceras `Nombre: valor` (falla ruidosamente si falta el
    // separador, D20 — no se adivina).
    let mut pares: Vec<(&str, &str)> = Vec::new();
    for c in cabeceras {
        let (k, v) = c
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("cabecera sin ':' → «{c}» (formato: `Nombre: valor`)"))?;
        pares.push((k.trim(), v.trim()));
    }
    let identidad =
        if pares.is_empty() { Identidad::anonimo() } else { Identidad::con("cli", pares) };

    let cliente = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(nexus::evasion::UA_POOL[0])
        .build()?;

    let diccionario: Vec<String> =
        parametros::DICCIONARIO_AUTHZ.iter().map(|s| s.to_string()).collect();
    let pcfg = PConfig { metodo, sensible_longitud, ..PConfig::default() };

    let hallados = parametros::descubrir(&cliente, url, &identidad, &diccionario, &pcfg).await?;
    if hallados.is_empty() {
        println!("sin parámetros ocultos detectados en {url} ({} candidatos)", diccionario.len());
    } else {
        println!("parámetros ocultos en {url}:");
        for d in &hallados {
            println!("  {} — {}", d.nombre, d.senal.nombre());
        }
    }
    Ok(())
}

/// Red-team de seguridad de LLM (`nexus::redteam_llm`) contra un endpoint de chat
/// AUTORIZADO: dispara el corpus categorizado e imprime los payloads que pegaron (oráculo
/// de canario). Operator-directed, opt-in.
async fn cmd_redteam_llm(
    url: &str,
    campo: &str,
    plantilla_cuerpo: Option<String>,
    ruta_respuesta: Option<String>,
    cabeceras: &[String],
    categorias: &[String],
) -> anyhow::Result<()> {
    use nexus::oraculo_diferencial::Identidad;
    use nexus::redteam_llm::{self, Categoria, Config as RConfig};

    let mut pares: Vec<(&str, &str)> = Vec::new();
    for c in cabeceras {
        let (k, v) = c
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("cabecera sin ':' → «{c}» (formato: `Nombre: valor`)"))?;
        pares.push((k.trim(), v.trim()));
    }
    let identidad =
        if pares.is_empty() { Identidad::anonimo() } else { Identidad::con("cli", pares) };

    // Categorías: falla ruidosamente ante un nombre desconocido (D20).
    let mut cats = Vec::new();
    for c in categorias {
        cats.push(
            Categoria::desde_nombre(c)
                .ok_or_else(|| anyhow::anyhow!("categoría desconocida «{c}»"))?,
        );
    }

    // Sin ruta a la salida del modelo, el canario se busca en el cuerpo entero y el eco del
    // request puede dar un falso positivo — se avisa (la exactitud del reporte es del operador).
    if ruta_respuesta.is_none() {
        eprintln!(
            "aviso: sin --ruta-respuesta el canario se busca en el cuerpo ENTERO; si el endpoint \
             hace eco del request, puede dar falso positivo. Pásala (p.ej. choices.0.message.content)."
        );
    }

    // `--plantilla-cuerpo` y `--campo` son excluyentes; si hay plantilla, el campo (que tiene
    // default) se ignora.
    let cfg = RConfig {
        url: url.to_string(),
        campo: if plantilla_cuerpo.is_some() { None } else { Some(campo.to_string()) },
        plantilla_cuerpo,
        ruta_respuesta,
        categorias: cats,
    };

    let cliente = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(nexus::evasion::UA_POOL[0])
        .build()?;

    let hallazgos = redteam_llm::redteam(&cliente, &cfg, &identidad).await?;
    if hallazgos.is_empty() {
        println!("sin pegos: el endpoint resistió el corpus de red-team LLM ({url})");
    } else {
        println!("red-team LLM — {} payload(s) PEGARON en {url}:", hallazgos.len());
        for h in &hallazgos {
            println!("  [{}] {}", h.categoria.nombre(), h.categoria.owasp());
            println!("    payload: {}", h.payload);
        }
    }
    Ok(())
}

/// ENSAMBLA el dictamen técnico-jurídico de un programa desde sus findings y lo
/// imprime (Markdown). Solo lectura: la mitad técnica sale de la BD; el §5
/// organizacional y la firma (§8) los pone la persona. Se redirige a un archivo.
async fn cmd_dictamen(
    pool: &sqlx::SqlitePool,
    programa: &str,
    cumplimiento: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use nexus::{cumplimiento as cmp, dictamen};
    let filas = dictamen::fetch(pool, programa).await?;
    // §5: si se pasó el archivo de respuestas se evalúa y se genera; si no, None
    // (el dictamen deja el checklist en blanco). Directiva 20: si el archivo se
    // pidió pero no se puede leer, FALLA ruidoso — no se sigue como si no existiera.
    let resultados = match cumplimiento {
        Some(p) => {
            let texto = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("no pude leer el checklist §5 {}: {e}", p.display()))?;
            Some(cmp::evaluar(&texto))
        }
        None => None,
    };
    let fecha = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let meta = dictamen::Meta {
        programa,
        fecha: &fecha,
        binario: env!("CARGO_PKG_VERSION"),
    };
    print!("{}", dictamen::generar(&meta, &filas, resultados.as_deref()));
    Ok(())
}

/// Emite la plantilla del checklist §5 (o el catálogo con `--catalogo`). No usa BD.
fn cmd_cbom(ruta: &std::path::Path, salida: Option<&std::path::Path>, dictamen: bool, enc: &nexus::cbom::Encargo) {
    let d = match nexus::cbom::detectar(ruta) {
        Ok(d) => d,
        Err(e) => { eprintln!("no pude escanear {}: {e}", ruta.display()); std::process::exit(1); }
    };
    let contenido = if dictamen {
        let fecha = chrono::Utc::now().format("%Y-%m-%d").to_string();
        nexus::cbom::dictamen(&d, enc, &fecha, env!("CARGO_PKG_VERSION"))
    } else {
        print!("{}", nexus::cbom::resumen(&d));
        nexus::cbom::emitir(&d)
    };
    match salida {
        Some(p) => {
            if let Err(e) = std::fs::write(p, &contenido) { eprintln!("no pude escribir {}: {e}", p.display()); std::process::exit(1); }
            eprintln!("{} escrito en {}", if dictamen { "Dictamen" } else { "CBOM" }, p.display());
        }
        None => print!("{contenido}"),
    }
}

fn cmd_cumplimiento(catalogo: bool) {
    use nexus::cumplimiento as cmp;
    if catalogo {
        println!("# Catálogo del §5 — ítem → obligación legal (Ley 1581 / Decreto 1377)\n");
        let corpus = nexus::oraculo::corpus_proteccion_datos();
        for item in cmp::CATALOGO {
            println!(
                "- **{}** ({}) — `{}`\n  {}",
                item.pregunta, item.severidad, item.id, item.obligacion_cotejada(&corpus)
            );
        }
    } else {
        print!("{}", cmp::plantilla());
    }
}

/// MIDE (solo lectura) la elegibilidad de los hallazgos MANUAL_READY contra las
/// reglas publicadas de su programa en H1: ¿el host cae en un scope submittable?
/// ¿el programa acepta este CWE? No descarta ni envía nada — imprime el veredicto.
/// Es la medida que responde «¿cuáles sirven?» sin dejarlo al ojo humano (que
/// tampoco puede: la validez la decide H1) y sin arriesgar un descarte automático.
/// Vigila si un programa H1 volvió a aceptar envíos (`submission_state == "open"`).
/// Salidas, distinguidas a propósito (D30 — "cerrado sano" ≠ "no corrió"):
/// **10** = reabrió (imprime y avisa por `--notify-webhook` si hay), **0** = sigue
/// cerrado, **2** = no concluyente (sin credenciales, red caída, o la API no trae
/// el campo). Pensado para cron: `nexus vigilar-programa --handle liberapay`.
async fn cmd_vigilar_programa(cfg: &Config, handle: &str) -> anyhow::Result<()> {
    let pcfg = ProtectionConfig::default();
    let client = match h1::H1Client::from_env(&pcfg.user_agent) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{handle}: sin credenciales H1 ({e}) — no concluyente");
            std::process::exit(2);
        }
    };
    match client.submission_state(handle).await {
        Ok(Some(estado)) if estado == "open" => {
            let msg = format!(
                "🔓 HackerOne `{handle}` ACEPTA envíos de nuevo (submission_state=open). Radicar el reporte pendiente."
            );
            println!("{msg}");
            if let Some(hook) = cfg.notify_webhook.as_deref() {
                if let Err(e) = nexus::notify::enviar(hook, &msg).await {
                    eprintln!("aviso: el webhook falló: {e}");
                }
            }
            std::process::exit(10);
        }
        Ok(Some(estado)) => {
            println!("{handle}: submission_state={estado} (sigue sin aceptar envíos)");
        }
        Ok(None) => {
            eprintln!("{handle}: la API no devolvió submission_state — no concluyente");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("{handle}: no se pudo consultar ({e}) — no concluyente");
            std::process::exit(2);
        }
    }
    Ok(())
}

async fn cmd_elegibilidad(pool: &sqlx::SqlitePool, aplicar: bool, max_dias: u64) -> anyhow::Result<()> {
    use nexus::elegibilidad::{self, Veredicto};

    let pcfg = ProtectionConfig::default();
    let client = h1::H1Client::from_env(&pcfg.user_agent)?;
    // MISMA evaluación que usa el enforce del ciclo (directiva 9): aquí solo se
    // imprime; allí se descarta. No pueden divergir.
    let resultados = elegibilidad::evaluar_manual(pool, &client).await?;
    if resultados.is_empty() {
        println!("no hay hallazgos en MANUAL_READY");
        return Ok(());
    }
    println!(
        "== Elegibilidad de {} hallazgos MANUAL_READY (solo H1; MEDIDA, no descarta) ==\n",
        resultados.len()
    );
    let (mut elegibles, mut fuera, mut clase_rech, mut informativas, mut otras) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut ultimo_prog = String::new();
    for r in &resultados {
        if r.otra_plataforma {
            otras += 1;
            println!(
                "  [otra-plataforma ] {} · {} ({}) — no juzgado",
                r.program, r.vuln, r.severity
            );
            continue;
        }
        // Contexto por programa (primera aparición): distingue «juzgado» de «no se
        // pudo» (directiva 30). Los resultados vienen ordenados por programa.
        if r.program != ultimo_prog {
            ultimo_prog = r.program.clone();
            let clases_txt = match r.clases_leidas {
                Some(n) => format!("{n} clases aceptadas"),
                None => "clases NO OBTENIDAS (gate de clase inactivo, fail-open)".into(),
            };
            println!(
                "  · programa {}: {} scopes submittable, {clases_txt}",
                r.program, r.scopes_submittable
            );
        }
        let etq = match &r.veredicto {
            Veredicto::Elegible => {
                elegibles += 1;
                "ELEGIBLE       "
            }
            Veredicto::FueraDeScope => {
                fuera += 1;
                "FUERA-DE-SCOPE "
            }
            Veredicto::ClaseRechazada(_) => {
                clase_rech += 1;
                "CLASE-RECHAZADA"
            }
            Veredicto::Informativa => {
                informativas += 1;
                "INFORMATIVA    "
            }
        };
        println!(
            "  [{etq}] {} · {} ({}, cwe={}) — {}",
            r.program,
            r.vuln,
            r.severity,
            r.cwe.as_deref().unwrap_or("-"),
            r.veredicto.motivo()
        );
    }
    println!(
        "\nResumen: {elegibles} elegibles · {fuera} fuera-de-scope · {clase_rech} clase-rechazada · {informativas} informativa · {otras} otra-plataforma"
    );
    println!(
        "(Descartables = fuera-de-scope + clase-rechazada + informativa. Con NEXUS_H1_GATE_ENFORCE=1 el ciclo los resuelve a INFORMATIONAL; sin él, esto solo mide.)"
    );

    // Con --aplicar, reclasifica los descartables ya evaluados (no re-consulta H1).
    // Es el mismo efecto que el enforce del ciclo, a demanda: reversible y visible.
    if aplicar {
        let mut aplicados = 0u32;
        for r in &resultados {
            if r.veredicto.descartable() {
                db::descartar_por_elegibilidad(pool, r.id, &r.veredicto.motivo()).await?;
                println!(
                    "  APLICADO: {} · {} → INFORMATIONAL ({})",
                    r.program,
                    r.vuln,
                    r.veredicto.motivo()
                );
                aplicados += 1;
            }
        }
        println!("\nENFORCE aplicado a demanda: {aplicados} reclasificado(s) a INFORMATIONAL (reversible).");
        // Reloj terminal, si hay ventana configurada (NEXUS_MANUAL_READY_MAX_DIAS).
        let cerrados = elegibilidad::reloj_terminal(pool, max_dias).await?;
        if cerrados > 0 {
            println!("RELOJ TERMINAL: {cerrados} cerrado(s) a INFORMATIONAL tras {max_dias} días sin resolver.");
        }
    }
    Ok(())
}

/// Baja las structured scopes de H1 para TODOS los programas y las persiste con su
/// `asset_type` real (incl. SOURCE_CODE), marcando `scope_status='fetched'`. Es la base
/// de la clasificación blanca/negra. Resumable: salta los ya 'fetched' salvo `--todos`.
/// Solo lectura hacia H1 (GET paginado); no envía ni descarta nada. Cortés con la API
/// (~3 req/s). Positivo de control (directiva 30): un programa solo se marca 'fetched'
/// si LLEGARON scopes; un vacío (fail-open del cliente o sin scopes) NO se marca.
async fn cmd_scopes_refresh(pool: &sqlx::SqlitePool, todos: bool, limite: usize) -> anyhow::Result<()> {
    let pcfg = ProtectionConfig::default();
    let client = h1::H1Client::from_env(&pcfg.user_agent)?;
    let programas = db::all_h1_programs(pool).await?;
    let total = programas.len();
    tracing::info!("scopes-refresh: {total} programas H1 en la BD (todos={todos}, limite={limite})");
    let (mut hechos, mut con_source, mut con_bounty, mut vacios) = (0usize, 0usize, 0usize, 0usize);
    for (pid, _name, handle) in programas {
        let Some(handle) = handle else { continue };
        if !todos {
            let st: Option<String> = sqlx::query_scalar("SELECT scope_status FROM programs WHERE id = ?1")
                .bind(pid)
                .fetch_one(pool)
                .await
                .ok();
            if st.as_deref() == Some("fetched") {
                continue;
            }
        }
        let scopes = client.get_structured_scopes(&handle).await.unwrap_or_default();
        if scopes.is_empty() {
            // Vacío = no se pudo juzgar (fail-open del cliente) o programa sin scopes.
            // NO se marca 'fetched': solo registramos lo que de verdad llegó.
            vacios += 1;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            continue;
        }
        // Se persisten solo los scopes SUBMITTABLE (lo que de verdad se puede reportar);
        // se reemplaza el scope viejo del programa (feed de dominios) por el autoritativo.
        db::clear_scopes_for_program(pool, pid).await?;
        let (mut hay_source, mut hay_bounty) = (false, false);
        for s in &scopes {
            if !s.eligible_for_submission {
                continue;
            }
            let is_wc = s.asset_type == "WILDCARD";
            db::insert_structured_scope(pool, pid, &s.asset_identifier, &s.asset_type, s.eligible_for_bounty, is_wc, None).await?;
            if s.asset_type == "SOURCE_CODE" {
                hay_source = true;
            }
            if s.eligible_for_bounty {
                hay_bounty = true;
            }
        }
        db::set_scope_status(pool, pid, "fetched").await?;
        hechos += 1;
        con_source += hay_source as usize;
        con_bounty += hay_bounty as usize;
        if hechos % 25 == 0 {
            tracing::info!("scopes-refresh: {hechos} hechos · {con_source} con SOURCE_CODE · {con_bounty} con bounty · {vacios} vacíos");
        }
        if limite != 0 && hechos >= limite {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    tracing::info!(
        "scopes-refresh TERMINADO: {hechos} programas fetched · {con_source} con SOURCE_CODE en scope · {con_bounty} con bounty · {vacios} vacíos/no-juzgables"
    );
    Ok(())
}

/// Recon completo: fuentes (H1/arkadiyt/Chaos) → subfinder → httpx → enhanced.
async fn cmd_recon(
    cfg: &Config,
    pool: &sqlx::SqlitePool,
    recon_deadline: Option<std::time::Instant>,
    scope_only: bool,
) -> anyhow::Result<()> {
    use nexus::config::Source;
    use nexus::sources;
    let pcfg = ProtectionConfig::default();
    let mut roots: std::collections::BTreeSet<String> = Default::default();

    // Fuente H1 (precisa, con cuenta). Guarda el scope por programa para poder
    // atribuir hallazgos a su team_handle en el auto-envío.
    if cfg.sources.contains(&Source::H1) {
        let client = h1::H1Client::from_env(&pcfg.user_agent)?;
        tracing::info!("H1: descargando programas...");
        let mut programs = client.get_programs().await?;
        if !cfg.only.is_empty() {
            programs.retain(|h| cfg.only.contains(h));
            tracing::info!("H1: acotado a {} programa(s): {}", programs.len(), programs.join(", "));
        } else {
            tracing::info!("H1: {} programas", programs.len());
        }
        // Recon completo regenera todo el scope; recon acotado (--only) refresca
        // solo esos programas y conserva el scope de los demás (directiva 22).
        if cfg.only.is_empty() {
            db::clear_scopes(pool).await?;
        }
        for handle in &programs {
            if let Ok(domains) = client.get_scope_domains(handle).await {
                if domains.is_empty() {
                    continue;
                }
                let pid = db::upsert_program_handle(pool, handle, handle).await?;
                if !cfg.only.is_empty() {
                    db::clear_scopes_for_program(pool, pid).await?;
                }
                for d in &domains {
                    db::insert_scope(pool, pid, &d.identifier, d.is_wildcard, d.id.as_deref()).await?;
                }
                roots.extend(domains.into_iter().map(|d| d.identifier));
            }
        }
    }

    // Fuentes públicas (sin cuenta) vía HTTP.
    if cfg.sources.contains(&Source::Arkadiyt) || cfg.sources.contains(&Source::Chaos) {
        let http = reqwest::Client::builder()
            .user_agent(pcfg.user_agent.clone())
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        if cfg.sources.contains(&Source::Arkadiyt) {
            let n = roots.len();
            roots.extend(sources::fetch_arkadiyt(&http).await.unwrap_or_default());
            tracing::info!("arkadiyt: +{} dominios", roots.len() - n);
        }
        if cfg.sources.contains(&Source::Chaos) {
            let n = roots.len();
            roots.extend(sources::fetch_chaos(&http).await.unwrap_or_default());
            tracing::info!("Chaos: +{} dominios", roots.len() - n);
        }
    }

    // Fuente ALMACENADA: el scope ya está en program_scopes (feed de Intigriti,
    // sembrado por el sync). No se llama a ninguna API; se leen las raíces
    // guardadas de los programas acotados por --only y se enumeran como el resto.
    if cfg.sources.contains(&Source::Almacenado) {
        for name in &cfg.only {
            let n = roots.len();
            roots.extend(db::scope_roots_for_program(pool, name).await?);
            tracing::info!("almacenado {name}: +{} dominios de scope", roots.len() - n);
        }
    }

    let roots: Vec<String> = roots.into_iter().collect();
    tracing::info!("{} dominios raíz únicos (tras dedup)", roots.len());

    // SCOPE-ONLY: el scope ya quedó PERSISTIDO en `program_scopes` por el bucle H1 de
    // arriba (`insert_scope`, con su structured_scope_id para atribuir el envío). Paramos
    // ANTES del subfinder/httpx: esto es la SINCRONIZACIÓN del catálogo autorizado vivo,
    // ligera para la IP compartida, que un timer refresca cada tanto. Sobre esa base
    // corre después toda la maquinaria (bespoke/arnm/autz/…).
    if scope_only {
        let (progs, scopes): (i64, i64) = {
            let p = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM programs").fetch_one(pool).await.unwrap_or(0);
            let s = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM program_scopes").fetch_one(pool).await.unwrap_or(0);
            (p, s)
        };
        tracing::info!("scope-sync: catálogo persistido — {progs} programas, {scopes} activos de scope en la BD");
        return Ok(());
    }

    let roots_file = cfg.scans_dir.join("recon_roots.txt");
    tokio::fs::write(&roots_file, roots.join("\n")).await?;

    let subs_file = cfg.scans_dir.join("recon_subs.txt");
    // RESERVA para la fase PASIVA: subfinder escala para llenar cualquier deadline (medido
    // 2026-08-25 en producción: con 11 min y con 30 min de budget se lo come ENTERO y deja a
    // gau a 0 → `pasivo 0` → sin superficie para nuclei/XSS/SSRF). Se le da un SUB-deadline
    // (55% del budget de recon), reservando el resto para enhanced/pasiva —gau sobre archivos
    // es barato y da la superficie parametrizada que el resto necesita—. Sin deadline (hunt
    // dirigido) no se divide.
    let subfinder_deadline = recon_deadline.map(|fin| {
        let ahora = std::time::Instant::now();
        ahora + fin.saturating_duration_since(ahora).mul_f64(0.55)
    });
    let subs = recon::enumerate_hasta(cfg, &roots, &subs_file, subfinder_deadline).await?;
    tracing::info!("{subs} subdominios");

    // ALCANCE ANTES DE TOCAR (revisión 2026-08-23, obs 2): filtrar los subdominios
    // a in-scope ANTES de que httpx los sondee y enhanced los toque. subfinder
    // enumera TODO lo que cuelga de un dominio; para un scope de host EXACTO eso
    // incluye subdominios FUERA de alcance, y sondearlos (httpx) o traerles el .js
    // (enhanced) sería tocar un objetivo no autorizado — la misma clase que
    // `takeover` ya cierra por host. Fail-closed (scope vacío + validación ON → 0).
    // El filtro posterior sobre targets.txt se queda como red: enhanced puede
    // DESCUBRIR URLs de otros hosts al crawl-ear, y ahí se recortan.
    let (sb, sa) = recon::filter_to_scope(cfg, pool, &subs_file).await?;
    if sb != sa {
        tracing::info!("scope (pre-sondeo): {sb}→{sa} subdominios in-scope (recortados {} ANTES de tocarlos)", sb - sa);
    }

    let targets_file = cfg.scans_dir.join("targets.txt");
    let live = recon::live_hosts(cfg, &subs_file, &targets_file).await?;
    tracing::info!("{live} hosts vivos → {}", targets_file.display());

    // Enhanced recon (F4): amplía la superficie antes de escanear. Respeta el
    // presupuesto de recon (deadline) y, en modo pasivo, omite la fuerza bruta.
    if !cfg.no_enhanced_recon {
        let s = nexus::enhanced::enhance(cfg, &targets_file, recon_deadline).await?;
        tracing::info!(
            "enhanced recon{}: +{} URLs (pasivo {}, crawl {}, ffuf {}, params {})",
            if cfg.recon_passive_only { " [pasivo]" } else { "" },
            s.added, s.passive, s.crawled, s.discovered, s.params
        );
    }

    // RASTREO CON EVASIÓN (la llave maestra, validada en unico 2026-08-24): baja el
    // HTML/JS de los hosts vivos CRUZANDO el WAF que frena a katana (medido: idcash-uat
    // pasó de 403 a 200/45KB vía impersonate), extrae la API con js_extract y sondea
    // endpoints de descubrimiento (openid/swagger). Es lo que rompe el `params 0`. Solo
    // corre si hay curl-impersonate configurado. GET, no destructivo. Se filtra a scope
    // justo después (fail-closed).
    if !cfg.curl_impersonate_path.is_empty() {
        let vivos: Vec<String> = tokio::fs::read_to_string(&targets_file)
            .await
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if !vivos.is_empty() {
            match nexus::autz::cliente(cfg.user_agent.as_deref().unwrap_or(nexus::evasion::UA_POOL[0])) {
                Ok(cli) => {
                    let mut guard = Guard::new(ProtectionConfig::default());
                    let mut rng = make_rng();
                    // LLAVERO MAESTRO: cada host se fingerprintea y va a su estrategia de
                    // extracción (SPA→js, Flutter→dart agresivo, API→wordlist, server→enlaces).
                    let mut desc: std::collections::BTreeSet<String> = Default::default();
                    let mut tipos: std::collections::BTreeMap<String, usize> = Default::default();
                    for host in vivos.iter().take(40) {
                        if nexus::autz::deadline_vencido(recon_deadline) || guard.should_pause() {
                            break;
                        }
                        // TIMEOUT POR-HOST (fix del hang, 2026-08-26): aunque cada
                        // petición de `despachar` va bounded (fetch_evasion, 15-20s),
                        // un subproceso externo (curl-impersonate) que deja NIETOS con
                        // la tubería stdout abierta cuelga `tools::run` en su `.await`
                        // de drenaje pese al SIGKILL — y el loop se atasca (medido:
                        // eurid y sidefx, 0% CPU, futex_wait, el recon nunca llega a la
                        // fase SSRF). Un tope duro por host convierte el cuelgue en
                        // "salta este host y sigue" (dir. 39: toda espera con tope).
                        let disp = tokio::time::timeout(
                            std::time::Duration::from_secs(90),
                            nexus::llavero::despachar(
                                &cli, host, &cfg.curl_impersonate_path, 15, &mut guard, recon_deadline, &mut rng,
                            ),
                        )
                        .await;
                        let (tipo, eps) = match disp {
                            Ok(r) => r,
                            Err(_) => {
                                tracing::warn!("llavero: {host} excedió 90s — se salta (anti-hang)");
                                continue;
                            }
                        };
                        *tipos.entry(format!("{tipo:?}")).or_default() += 1;
                        desc.extend(eps);
                    }
                    if !desc.is_empty() {
                        use tokio::io::AsyncWriteExt;
                        let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(&targets_file).await?;
                        for u in &desc {
                            f.write_all(format!("{u}\n").as_bytes()).await?;
                        }
                        f.flush().await?;
                    }
                    let resumen: Vec<String> = tipos.iter().map(|(t, n)| format!("{n} {t}")).collect();
                    tracing::info!("llavero: +{} endpoints descubiertos [{}]", desc.len(), resumen.join(", "));
                }
                Err(e) => tracing::warn!("llavero: cliente HTTP: {e}"),
            }
        }
    }

    // P2: filtrar a in-scope (fail-closed). Nunca escanear fuera de scope.
    let (b, a) = recon::filter_to_scope(cfg, pool, &targets_file).await?;
    if b != a {
        tracing::info!("scope: {b}→{a} objetivos in-scope (filtrados {} fuera de scope)", b - a);
    }

    // Característica #10 (contrato recon→hunt): ordena el set final in-scope por valor
    // —P1 (api/auth/admin, no-prod) antes que P2 (app genérica), KILL (estático) al final—
    // para que la fase cara (nuclei/oráculos, con presupuesto anti-baneo) gaste primero
    // donde más vale. REORDEN, no filtro: KILL se conserva (D21-invertido, no perder hits).
    let (p1, p2, kill) = recon::ordenar_por_superficie(&targets_file).await?;
    if p1 + p2 + kill > 0 {
        tracing::info!("superficie: objetivos ordenados por valor — P1={p1} P2={p2} KILL={kill} (P1 primero)");
    }
    Ok(())
}

/// Escaneo por fases sobre un archivo de objetivos.
async fn cmd_scan(
    cfg: &Config,
    pool: &sqlx::SqlitePool,
    targets: &PathBuf,
    program: &str,
    scan_deadline: Option<std::time::Instant>,
) -> anyhow::Result<()> {
    // `--no-scan` omite nuclei pero SÍ corre la fase de control de acceso: así se
    // pueden probar identidades/semillas sin el coste de cargar 13.510 plantillas.
    if !cfg.no_scan && !targets.exists() {
        anyhow::bail!("no existe el archivo de objetivos: {}", targets.display());
    }

    let mut guard = Guard::new(ProtectionConfig::default());
    let mut rng = make_rng();

    if cfg.no_scan {
        tracing::info!("--no-scan: se omite nuclei; solo control de acceso");
    } else {
        let host_count = tokio::fs::read_to_string(targets).await?.lines().filter(|l| !l.trim().is_empty()).count();
        tracing::info!("escaneando {host_count} objetivos (programa {program})");
        // RESERVA para las fases POST-ESCANEO (auth, XSS…): nuclei sobre miles de URLs escala
        // para llenar el deadline y deja a la fase XSS —que corre DESPUÉS— con 0 presupuesto,
        // así que rompe en `deadline_vencido` sin procesar un endpoint (medido rivian
        // 2026-08-25: XSS 0 con 1951 params disponibles, mientras SSRF —antes del deadline—
        // atacó 27). Es la MISMA cascada que ya se capó en subfinder→recon. nuclei recibe un
        // SUB-deadline (60% del budget de escaneo), reservando el resto para lo que va después.
        // Sin deadline (hunt dirigido) no se divide.
        let nuclei_deadline = scan_deadline.map(|fin| {
            let ahora = std::time::Instant::now();
            ahora + fin.saturating_duration_since(ahora).mul_f64(0.6)
        });
        let found = engine::scan_program(cfg, pool, &mut guard, nuclei_deadline, program, targets, host_count, &mut rng).await?;
        tracing::info!("{found} hallazgos nuevos");
    }

    // Fase KEYLESS de IDOR/BOLA sin auth (fuga sin auth): opt-in por --fuga-sin-auth, e
    // INDEPENDIENTE del bloque de identidades — es la forma operable de autz "sin crear
    // cuentas" (Juan 2026-08-25). Corpus propio (lee targets + semillas) y guard FRESCO.
    //
    // VA ANTES DEL BLOQUE DE BYPASS a propósito (medido 2026-08-26): el bypass hace hasta
    // 14 técnicas por endpoint protegido, machaca el objetivo hasta el 429 y pausa; la
    // keyless, corriendo 1s después, HEREDABA ese estrangulamiento y pausaba sin atacar
    // nada (0 falso). El transporte de evasión NO lo arregla —solo cruza muros 403 de
    // borde (Akamai/CF), no el 429 de rate-limit—. Corriendo PRIMERA recibe el objetivo
    // fresco. En un programa sin identidades el bloque de abajo solo pega con bypass, así
    // que basta con adelantar esta fase. GET de solo lectura, MANUAL_READY, auto-envío OFF.
    if cfg.fuga_sin_auth && targets.exists() {
        let mut corpus_fsa: Vec<String> = tokio::fs::read_to_string(targets)
            .await?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        corpus_fsa.extend(db::cargar_semillas(pool, program).await.unwrap_or_default());
        if !corpus_fsa.is_empty() {
            let ca = autz::ConfigAutz {
                user_agent: cfg.user_agent.clone().unwrap_or_else(|| nexus::evasion::UA_POOL[0].to_string()),
                umbral: autz::UMBRAL_DEFECTO,
                cap: cfg.autz_cap,
                cooldown_secs: cfg.autz_cooldown_secs,
                pausa_tecnica_secs: autz::PAUSA_TECNICA_SECS,
            };
            let mut guard_fsa = Guard::new(ProtectionConfig::default()); // guard FRESCO propio
            match autz::fase_fuga_sin_auth(pool, program, &corpus_fsa, &mut guard_fsa, &ca, scan_deadline, &mut rng).await {
                Ok(n) => tracing::info!("fuga sin auth: {n} IDOR keyless nueva(s) a revisión manual"),
                Err(e) => tracing::warn!("fuga sin auth: {e}"),
            }
        }
    }

    // Fase de CONTROL DE ACCESO (autz): lo que nuclei no ve (IDOR/BAC). Solo corre
    // si el programa tiene un juego de identidades montado (config manual por
    // programa); no-op para los que no lo tienen. Reusa el `guard` (anti-baneo).
    let ids = db::cargar_identidades(pool, program).await?;
    let corre_autz = autz::juego_listo(&ids); // IDOR horizontal: necesita identidades
    // JWT de MUESTRA observados en las cabeceras de las identidades (Authorization: Bearer
    // <jwt>): son la base para el ataque a autenticación (forjar alg:none, etc.).
    let jwt_muestra: Vec<String> = ids
        .iter()
        .flat_map(|id| id.cabeceras.iter())
        .filter_map(|(k, v)| {
            if k.eq_ignore_ascii_case("authorization") {
                let t = v.trim().strip_prefix("Bearer ").unwrap_or(v.trim()).to_string();
                nexus::autenticacion::parse_jwt(&t).map(|_| t)
            } else {
                None
            }
        })
        .collect();
    if corre_autz || cfg.bypass || !jwt_muestra.is_empty() {
        let mut corpus: Vec<String> = if targets.exists() {
            tokio::fs::read_to_string(targets)
                .await?
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        } else {
            Vec::new()
        };
        // Las URLs SEMILLA (recursos propios del dueño, privados) que el recon no
        // ve: son el corpus REAL del IDOR horizontal. Se añaden al corpus público.
        corpus.extend(db::cargar_semillas(pool, program).await?);
        let ca = autz::ConfigAutz {
            user_agent: cfg
                .user_agent
                .clone()
                .unwrap_or_else(|| nexus::evasion::UA_POOL[0].to_string()),
            umbral: autz::UMBRAL_DEFECTO,
            cap: cfg.autz_cap,
            cooldown_secs: cfg.autz_cooldown_secs,
            pausa_tecnica_secs: autz::PAUSA_TECNICA_SECS,
        };
        if corre_autz {
            match autz::fase_autz(pool, program, &corpus, &ids, &mut guard, &ca, scan_deadline, &mut rng).await {
                Ok(n) => tracing::info!("control de acceso: {n} costuras nuevas ({} identidades)", ids.len()),
                Err(e) => tracing::warn!("control de acceso: {e}"),
            }
        }
        // 1.4 Mass-assignment: GATEADO por `--mass-assign` + identidad dueño. ESCRIBE
        // (PATCH) solo sobre el objeto PROPIO del dueño (semillas). No-op por defecto
        // (sin daño): sin el flag no toca nada.
        if cfg.mass_assign {
            let semillas = db::cargar_semillas(pool, program).await.unwrap_or_default();
            match nexus::mass_assign::fase_mass_assign(
                pool, program, &ids, &semillas, cfg.mass_assign, cfg.mass_assign_descubrir, 20,
                cfg.notify_webhook.as_deref(),
            )
            .await
            {
                Ok(0) => {}
                Ok(k) => tracing::info!("mass-assignment: {k} campo(s) privilegiado(s) aceptado(s) en {program}"),
                Err(e) => tracing::warn!("mass-assignment: {e}"),
            }
        }
        // Evasión SIN login (bypass 403/401): account-free, opt-in por --bypass.
        if cfg.bypass {
            // Forced browsing (1.2): añade rutas protegidas de alto valor al corpus
            // de bypass —SOLO aquí, no al de autz para no FP—, acotado a 48 para
            // proteger la IP compartida. fase_bypass solo evade las que dan 401/403.
            let mut corpus_fb = corpus.clone();
            corpus_fb.extend(autz::semillas_forced_browsing(&corpus, 48));
            match autz::fase_bypass(pool, program, &corpus_fb, &mut guard, &ca, scan_deadline, &mut rng).await {
                Ok(n) => tracing::info!("evasión sin login: {n} bypass nuevos"),
                Err(e) => tracing::warn!("evasión sin login: {e}"),
            }
        }
        // Fase de ATAQUE A AUTENTICACIÓN (JWT alg:none): si observamos un JWT de muestra,
        // forja identidades y prueba el bypass sobre el corpus (capado, para proteger la IP),
        // vía el transporte de EVASIÓN TLS (cruza WAF). No destructivo (PoC de solo lectura,
        // token de prueba propio); nunca auto-envío. Estatuto nexus-detector.
        if !jwt_muestra.is_empty() && !corpus.is_empty() {
            match autz::cliente(&ca.user_agent) {
                Ok(cli) => {
                    let program_id = db::upsert_program(pool, program).await?;
                    let cap = corpus.len().min(cfg.autz_cap);
                    match nexus::autenticacion::fase_autenticacion(
                        pool, program, program_id, &corpus[..cap], &jwt_muestra, &cli,
                        &cfg.curl_impersonate_path, &mut guard, scan_deadline,
                        cfg.notify_webhook.as_deref(), &mut rng,
                    )
                    .await
                    {
                        Ok(n) => tracing::info!("ataque a auth: {n} bypass de autenticación confirmado(s) ({} JWT de muestra)", jwt_muestra.len()),
                        Err(e) => tracing::warn!("ataque a auth: {e}"),
                    }
                }
                Err(e) => tracing::warn!("ataque a auth: cliente HTTP: {e}"),
            }
        }

        // Fase JWT OUT-OF-BAND (jku): confirma los moldes JkuSsrf/JkuAtacante por CALLBACK al
        // colector —su oráculo es que el server TRAIGA el `jku`, no la aceptación, así que va
        // aparte del bloque de forja de arriba—. Solo con colector configurado (NEXUS_OOB_BASE)
        // y muestras+corpus. El colector debe estar desplegado y sirviendo /…/jwks.json.
        if let Some(base) = cfg.oob_base.as_deref() {
            if !jwt_muestra.is_empty() && !corpus.is_empty() {
                match db::open_oob(&cfg.oob_db_path(), 2).await {
                    Ok(oob_pool) => {
                        let cap = corpus.len().min(cfg.autz_cap);
                        match nexus::oob::fase_jwt_oob(
                            pool, &oob_pool, program, &corpus[..cap], &jwt_muestra, 30, base,
                            cfg.oob_wait, cfg.notify_webhook.as_deref(),
                        )
                        .await
                        {
                            Ok(n) => tracing::info!("jwt-oob: {n} hallazgo(s) jku confirmado(s) por callback"),
                            Err(e) => tracing::warn!("jwt-oob: {e}"),
                        }
                    }
                    Err(e) => tracing::warn!("jwt-oob: no se pudo abrir la BD del colector: {e}"),
                }
            }
        }
    }

    // Fase de XSS ADAPTATIVA (arnm): opt-in por --xss, e INDEPENDIENTE del bloque de identidades
    // de arriba. Antes estaba anidada dentro de `corre_autz||bypass||jwt`, así que para un
    // programa SIN identidad solo corría con `bypass` on — y compartía el `guard` que el bypass
    // AGOTABA por rate-limit, rompiendo XSS en `should_pause` sin atacar un endpoint (medido
    // rivian/sbbglobal 2026-08-25: 0 endpoints parametrizados con 1000+ params disponibles). Con
    // su PROPIO corpus (lee targets) y un `guard` FRESCO, arnm por fin tiene un turno limpio.
    // No destructivo (el payload solo pone un atributo-testigo); nunca auto-envío.
    if cfg.xss && targets.exists() {
        let mut corpus_xss: Vec<String> = tokio::fs::read_to_string(targets)
            .await?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        corpus_xss.extend(db::cargar_semillas(pool, program).await.unwrap_or_default());
        if !corpus_xss.is_empty() {
            let ua = cfg.user_agent.clone().unwrap_or_else(|| nexus::evasion::UA_POOL[0].to_string());
            match autz::cliente(&ua) {
                Ok(cli) => {
                    let program_id = db::upsert_program(pool, program).await?;
                    let guard_xss = Guard::new(ProtectionConfig::default()); // guard FRESCO propio
                    match nexus::xss::fase_xss_adaptativa(
                        pool, program, program_id, &corpus_xss, &cli, cfg,
                        &cfg.curl_impersonate_path, &guard_xss, scan_deadline,
                        cfg.notify_webhook.as_deref(), cfg.xss_confirm_tries,
                    )
                    .await
                    {
                        Ok(n) => tracing::info!("xss adaptativa: {n} XSS confirmada(s) por ejecución"),
                        Err(e) => tracing::warn!("xss adaptativa: {e}"),
                    }
                }
                Err(e) => tracing::warn!("xss adaptativa: cliente HTTP: {e}"),
            }
        }
    }

    // Add-on "datos en tránsito": cabeceras de seguridad, flags de cookies y
    // forzado de HTTPS/HSTS sobre los hosts vivos. Ligero (2 GET/host, capado a
    // 40) y general (todo programa lo quiere); alimenta el dictamen (§4/§6).
    // Gateado por el mismo deadline del ciclo.
    if targets.exists() {
        let hosts: Vec<String> = tokio::fs::read_to_string(targets)
            .await
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if !hosts.is_empty() {
            let ua = cfg
                .user_agent
                .clone()
                .unwrap_or_else(|| nexus::evasion::UA_POOL[0].to_string());
            match nexus::cabeceras::fase_cabeceras(pool, program, &hosts, &ua, 40, scan_deadline).await {
                Ok(0) => {}
                Ok(n) => tracing::info!("cabeceras: {n} hallazgos de datos en tránsito"),
                Err(e) => tracing::warn!("cabeceras: {e}"),
            }
            // TLS profundo (protocolo obsoleto + validez del certificado) vía el
            // openssl del sistema. Más pesado (varios s_client/host) → cap 20.
            match nexus::tls::fase_tls(pool, program, &hosts, 20, scan_deadline).await {
                Ok(0) => {}
                Ok(n) => tracing::info!("tls profundo: {n} hallazgos (protocolo/certificado)"),
                Err(e) => tracing::warn!("tls profundo: {e}"),
            }
            // Enumeración exhaustiva de suites de cifrado vía sslscan. Muy lenta
            // (~30-40s/host) → cap 8 + gate por deadline.
            match nexus::cifrados::fase_cifrados(pool, program, &hosts, 8, scan_deadline).await {
                Ok(0) => {}
                Ok(n) => tracing::info!("cifrados débiles: {n} hallazgos"),
                Err(e) => tracing::warn!("cifrados débiles: {e}"),
            }
        }
    }

    // Verificación profunda encadenada (como bounty/: broad scan → deep verify).
    // Bajo `--no-scan` se omite: no hay hallazgos de nuclei que verificar.
    if !cfg.no_scan && !cfg.no_deep_scan {
        let s = deepscan::run(cfg, pool, 500).await?;
        tracing::info!(
            "verificación: {} confirmados, {} falsos positivos, {} en reintento, {} manual, {} informativos, {} fallidos",
            s.verified, s.false_positive, s.retry, s.manual, s.informational, s.failed
        );

        // Evidencia (screenshots) de los verificados, para el cuerpo del reporte.
        match nexus::evidence::capture_all(cfg, pool).await {
            Ok(n) if n > 0 => tracing::info!("{n} capturas de evidencia"),
            Ok(_) => {}
            Err(e) => tracing::warn!("evidencia: {e}"),
        }

        // Auto-envío a H1 del tramo de máxima señal (opt-in explícito). El primero
        // que reporta se lleva el bounty: por eso se hace aquí, sin esperar a un humano.
        if cfg.auto_submit {
            let a = nexus::autosubmit::run(cfg, pool, false).await?;
            tracing::info!(
                "auto-envío: {} enviados, {} sin programa, {} duplicados, {} no-payable, {} por tope, {} fallidos{}",
                a.sent, a.skipped_no_program, a.skipped_duplicate, a.skipped_not_payable,
                a.skipped_cap, a.failed, if a.paused_signal { " [PAUSADO por Signal]" } else { "" }
            );
        }
    }

    cmd_report(cfg, pool).await?;
    Ok(())
}

async fn cmd_verify(cfg: &Config, pool: &sqlx::SqlitePool, limit: i64) -> anyhow::Result<()> {
    let s = deepscan::run(cfg, pool, limit).await?;
    tracing::info!(
        "verificación: {} confirmados, {} falsos positivos, {} en reintento, {} manual, {} fallidos",
        s.verified, s.false_positive, s.retry, s.manual, s.failed
    );
    Ok(())
}

/// Antigüedad mínima (segundos) para dar por MUERTO un escaneo que sigue en
/// `'running'`. Debe ser `>= TimeoutStartSec` del `.service` (hoy 3600): pasado
/// ese techo systemd ya mató el proceso, así que ninguna fila más vieja puede
/// ser un escaneo vivo. Con la cadencia del timer a 2 h (7200 s), 3600 deja un
/// margen cómodo por ambos lados: no toca lo vivo, alcanza lo huérfano.
const RECONCILE_STALE_SECS: i64 = 3600;

/// Cuántos escaneos no-completados (timeout/interrupted/failed) SIN un solo
/// `completed` bastan para deprioritizar un programa como "estéril". coupang_tw
/// llevaba 59; 8 es holgado para no castigar un mal día de red y firme para
/// cortar el desperdicio crónico. Es deprioritización auto-sanable, no exclusión.
const QUARANTINE_TIMEOUTS: i64 = 8;

/// Sc1: un ciclo del cazador con scheduling por BD. Elige el programa
/// menos-reciente, hace recon acotado + scan, y lo marca escaneado.
async fn cmd_hunt(cfg: &Config, pool: &sqlx::SqlitePool, program_override: Option<String>) -> anyhow::Result<()> {
    use nexus::config::Source;
    // El reloj del ciclo arranca AQUÍ: el presupuesto (`NEXUS_SCAN_DEADLINE_SECS`)
    // cuenta desde este punto, así que incluye el recon. `0` = sin límite.
    let started = std::time::Instant::now();
    // Un hunt DIRIGIDO (--program) va a fondo sobre UN objetivo elegido: sin deadline, para
    // que el recon profundo (subfinder+katana+gau) y la extracción (enhance+llavero) no se
    // estrangulen. Medido en unico: con deadline de 11min, recon daba +0 (subfinder se lo
    // comía); sin deadline, +150K URLs → +1947 endpoints → 21 sondas SSRF. El timer pasivo
    // (sin --program) conserva su deadline para repartir el cupo entre muchos programas.
    let scan_deadline = (cfg.scan_deadline_secs > 0 && program_override.is_none())
        .then(|| started + std::time::Duration::from_secs(cfg.scan_deadline_secs));

    // Reconcilia escaneos huérfanos de un ciclo anterior que murió a mitad de
    // nuclei (SIGKILL de systemd, OOM) sin cerrar su fila. Se hace al arrancar
    // el ciclo —los `hunt` no solapan (oneshot + timer) y `serve` no escribe
    // scan_logs— y solo toca filas más viejas que `RECONCILE_STALE_SECS`, que
    // nunca es un escaneo en curso (ver la función). Log solo si limpió algo.
    match db::reconcile_orphaned_scans(pool, RECONCILE_STALE_SECS).await {
        Ok(0) => {}
        Ok(n) => tracing::info!("cazador: {n} escaneo(s) huérfano(s) reconciliado(s) → 'interrupted'"),
        Err(e) => tracing::warn!("cazador: reconciliación de huérfanos falló: {e}"),
    }
    // Siembra la BD con handles que pagan si el pool es escaso (una vez; luego
    // count sube a ~225 y no se vuelve a bajar arkadiyt).
    if db::count_programs(pool).await? < 20 {
        let pcfg = ProtectionConfig::default();
        let http = reqwest::Client::builder().user_agent(pcfg.user_agent).timeout(std::time::Duration::from_secs(120)).build()?;
        let handles = nexus::sources::fetch_h1_handles(&http).await.unwrap_or_default();
        let n = db::seed_programs_pending(pool, &handles).await?;
        tracing::info!("cazador: sembrados {n} programas que pagan");
    }

    let (name, platform) = match &program_override {
        // Campaña dirigida: un programa concreto elegido (no la lotería del planificador).
        Some(p) => {
            let plat: Option<String> = sqlx::query_scalar("SELECT platform FROM programs WHERE name = ?")
                .bind(p)
                .fetch_optional(pool)
                .await?;
            match plat {
                Some(platform) => (p.clone(), platform),
                None => {
                    tracing::error!("cazador: programa '{p}' no existe en la BD (¿nombre exacto? ¿scope cargado?)");
                    return Ok(());
                }
            }
        }
        None => match db::next_program_to_hunt(pool, QUARANTINE_TIMEOUTS, cfg.fresh_window_days).await? {
            Some(p) => p,
            None => {
                tracing::info!("cazador: no hay programas para escanear");
                return Ok(());
            }
        },
    };
    tracing::info!("cazador: programa {name} [{platform}]{}", if program_override.is_some() { " (DIRIGIDO)" } else { " (menos reciente)" });

    // Recon+scan acotados a ese programa. La FUENTE del scope depende del
    // proveedor: H1 lo trae de su API (y atribuye); Intigriti (sembrado del feed)
    // lo tiene ya en program_scopes → Source::Almacenado, sin API.
    let mut c = cfg.clone();
    c.only = vec![name.clone()];
    c.sources = match platform.as_str() {
        "intigriti" => vec![Source::Almacenado],
        _ => vec![Source::H1],
    };

    // El recon no puede comerse más que su fracción del presupuesto (medido:
    // se comía casi la mitad y encontraba 0). `NEXUS_RECON_FRAC` = 0.25 por
    // defecto: una cuarta parte para enumerar, el resto para escanear.
    let recon_deadline = scan_deadline.map(|_| {
        started + std::time::Duration::from_secs_f64(
            cfg.scan_deadline_secs as f64 * cfg.recon_frac,
        )
    });
    cmd_recon(&c, pool, recon_deadline, false).await?;

    // Conteo de líneas no vacías de un archivo (0 si falta): mismo criterio para
    // el scope y para los objetivos vivos.
    let contar = |p: std::path::PathBuf| async move {
        match tokio::fs::read_to_string(&p).await {
            Ok(s) => s.lines().filter(|l| !l.trim().is_empty()).count(),
            Err(_) => 0,
        }
    };
    // `recon_roots.txt` = el scope que H1 entregó para ESTE programa (lo escribe
    // cmd_recon truncándolo por ciclo). Es el discriminador que separa las dos
    // causas que `live == 0` confundía (directiva 32): sin scope = permanente;
    // con scope pero sin host vivo = transitorio, y hoy se perdía para siempre.
    let scope_count = contar(c.scans_dir.join("recon_roots.txt")).await;

    // 2.2 ASM: diffea la superficie. Registra los subdominios de esta corrida y
    // avisa SOLO de los NUEVOS (no en la primera corrida del programa: ahí toda la
    // superficie es «nueva» y sería ruido — se toma como línea base). El aviso va
    // por el webhook si está configurado; falla suave.
    if let Ok(subs) = tokio::fs::read_to_string(c.scans_dir.join("recon_subs.txt")).await {
        let lista: Vec<String> = subs
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        match db::registrar_assets(pool, &name, &lista).await {
            Ok((nuevos, primera)) if !primera && !nuevos.is_empty() => {
                tracing::info!("ASM: {} asset(s) NUEVO(s) en la superficie de {name}", nuevos.len());
                if let Err(e) = nexus::notify::notificar(
                    cfg.notify_webhook.as_deref(),
                    &nexus::notify::Evento::SuperficieNueva { programa: name.clone(), assets: nuevos },
                )
                .await
                {
                    tracing::warn!("ASM: aviso falló: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("ASM: registrar assets falló: {e}"),
        }
        // 2.3 Subdomain takeover: revisa una muestra ACOTADA de subdominios
        // (CNAME→huella distintiva), reusando la lista de subs. Persiste high +
        // avisa por webhook; falla suave.
        match nexus::takeover::fase_takeover(pool, &name, &lista, 25, cfg.notify_webhook.as_deref()).await {
            Ok(0) => {}
            Ok(k) => tracing::info!("takeover: {k} posible(s) subdomain takeover en {name}"),
            Err(e) => tracing::warn!("takeover: {e}"),
        }
    }

    // 3.2 GraphQL: introspección expuesta en una muestra ACOTADA de hosts vivos.
    if let Ok(t) = tokio::fs::read_to_string(c.scans_dir.join("targets.txt")).await {
        let mut origenes: Vec<String> = t
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        match nexus::graphql::fase_graphql(pool, &name, &origenes, 20, cfg.notify_webhook.as_deref()).await {
            Ok(0) => {}
            Ok(k) => tracing::info!("graphql: {k} endpoint(s) con introspección expuesta en {name}"),
            Err(e) => tracing::warn!("graphql: {e}"),
        }

        // 3.0b DESCUBRIMIENTO BESPOKE (Hybris/SAP Commerce): fingerprint de los
        // hosts y, para los que confirman el stack, la superficie OCC conocida que
        // el crawler genérico NO enumera (el cuello `params 0` medido el
        // 2026-08-24). Se FUNDE en `origenes` para que fluya al `param` de abajo y
        // las fases de inyección/IDOR la ataquen. Falla suave; superficie vacía si
        // no hay Hybris (lo normal). El motor es GRAMÁTICA estructural, no LLM.
        let ua_bespoke = cfg.user_agent.as_deref().unwrap_or(nexus::evasion::UA_POOL[0]);
        match nexus::bespoke::fase_bespoke(pool, &name, &origenes, 40, ua_bespoke, scan_deadline, cfg.notify_webhook.as_deref()).await {
            Ok(urls) if !urls.is_empty() => {
                let n = nexus::bespoke::fundir_superficie(&mut origenes, urls);
                tracing::info!("bespoke: +{n} URLs de superficie OCC fundidas al corpus");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("bespoke: {e}"),
        }

        // 3.1 SSRF→metadata: inyecta payloads de metadata en las URLs PARAMETRIZADAS
        // (muestra acotada) y confirma por exfiltración real en la respuesta. GET,
        // sin daño. Reusa las URLs vivas del mismo fichero.
        let param: Vec<String> = origenes
            .iter()
            .filter(|l| nexus::enhanced::is_parameterizable(l))
            .cloned()
            .collect();
        // ADAPTATIVO (arnm): cuando el filtro bloquea la IP literal, VARÍA
        // (codifica la IP, host alterno, confusión de parser) en vez de salir
        // seco. `tope=16` son sondas LÓGICAS por endpoint, y solo se expande
        // contra objetivos que FILTRAN (un target limpio para tras ~4 sondas
        // literales). OJO: cada sonda hace UNA petición por parámetro de la URL,
        // así que un endpoint con N params que filtra puede costar hasta 16×N
        // peticiones a ESE endpoint (en scope, nunca a un tercero: el destino
        // mutado viaja como valor de parámetro y lo resuelve el servidor víctima).
        match nexus::arnm::fase_ssrf_adaptativa(pool, &name, &param, 30, 16, cfg.notify_webhook.as_deref(), scan_deadline,
            if cfg.exclusiones_enforce { Some(cfg.exclusiones_ttl_dias * 86_400) } else { None },
            &cfg.nuclei_templates_dir).await {
            Ok(0) => {}
            Ok(k) => tracing::info!("ssrf: {k} exfiltración(es) de metadata cloud en {name} (adaptativo)"),
            Err(e) => tracing::warn!("ssrf: {e}"),
        }

        // 3.1b SSRF OUT-OF-BAND: caza el SSRF CIEGO (el que no refleja la metadata)
        // inyectando un callback al colector auto-hospedado y confirmando por hit.
        // Solo si hay colector configurado (NEXUS_OOB_BASE); si no, no-op. Los hits
        // se consultan en la BD AISLADA del colector (open_oob), no en la principal.
        if let Some(base) = cfg.oob_base.as_deref() {
            let oob_pool = db::open_oob(&cfg.oob_db_path(), 2).await?;
            match nexus::oob::fase_ssrf_oob(pool, &oob_pool, &name, &param, 30, base, cfg.oob_wait, cfg.notify_webhook.as_deref()).await {
                Ok(0) => {}
                Ok(k) => tracing::info!("ssrf-oob: {k} SSRF ciego(s) confirmado(s) por callback en {name}"),
                Err(e) => tracing::warn!("ssrf-oob: {e}"),
            }
        }

        // 3.1c DAST / fuzzing (GATEADO por --dast): fuzzea los parámetros de las
        // MISMAS URLs (SQLi/XSS/SSTI/cmdi en el código del objetivo) — lo que las
        // plantillas-CVE no ven. Tráfico activo → opt-in. Siempre -no-interactsh.
        if cfg.dast {
            match engine::fase_dast(cfg, pool, &name, &param, scan_deadline).await {
                Ok(0) => {}
                Ok(k) => tracing::info!("dast: {k} candidato(s) de inyección por fuzzing en {name}"),
                Err(e) => tracing::warn!("dast: {e}"),
            }
        }

        // 3.3 Request smuggling (GATEADO por --smuggling): sondas de desync por
        // timing, auto-contenidas. No-op por defecto (sin daño); la clase más
        // sensible se activa a conciencia.
        match nexus::smuggling::fase_smuggling(pool, &name, &origenes, cfg.smuggling, 15, cfg.notify_webhook.as_deref()).await {
            Ok(0) => {}
            Ok(k) => tracing::info!("smuggling: {k} posible(s) desync por timing en {name}"),
            Err(e) => tracing::warn!("smuggling: {e}"),
        }
    }
    let targets = c.scans_dir.join("targets.txt");
    let live = contar(targets.clone()).await;

    // La DECISIÓN vive en recon::estado_tras_recon (pura, probada con su pareja);
    // aquí solo se despachan los efectos de cada desenlace.
    let status = recon::estado_tras_recon(scope_count, live);
    match status {
        "scanned" => {
            cmd_scan(&c, pool, &targets, &name, scan_deadline).await?;
        }
        "sin_hosts_vivos" => {
            // Registrar el intento estéril para que la cuarentena lo cuente si se
            // repite (directiva 22). El programa NO se excluye de la cola.
            let log_id = db::scan_log_start(pool, &name, "recon", "live").await?;
            db::scan_log_finish(pool, log_id, "no_live", 0, None).await?;
        }
        _ => {} // ScopeBlocked: sin efecto, solo se marca abajo y se excluye.
    }
    // Gate de elegibilidad (ENFORCE, opt-in `NEXUS_H1_GATE_ENFORCE`): descarta a
    // INFORMATIONAL lo que las reglas del programa en H1 excluyen (fuera de scope /
    // clase rechazada). Solo tras un scan real (hay hallazgos nuevos). Falla SUAVE
    // (directiva 20): si H1 no responde, se avisa y el ciclo sigue — no se descarta
    // a ciegas. En `false` (defecto) este bloque no corre y el gate solo mide.
    if cfg.h1_gate_enforce && status == "scanned" {
        match h1::H1Client::from_env(&ProtectionConfig::default().user_agent) {
            Ok(client) => match nexus::elegibilidad::enforce(pool, &client).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    "gate H1: {n} hallazgo(s) descartado(s) a INFORMATIONAL por inelegibilidad"
                ),
                Err(e) => tracing::warn!("gate H1: enforce falló: {e}"),
            },
            Err(e) => tracing::warn!("gate H1: sin cliente H1 ({e}); enforce omitido"),
        }
    }

    // Reloj terminal (opt-in `NEXUS_MANUAL_READY_MAX_DIAS>0`): nada espera para
    // siempre. Independiente del enforce H1 —es tiempo, no scope—; corre siempre.
    if cfg.manual_ready_max_dias > 0 {
        match nexus::elegibilidad::reloj_terminal(pool, cfg.manual_ready_max_dias).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(
                "reloj terminal: {n} hallazgo(s) cerrado(s) a INFORMATIONAL tras {} días sin resolver",
                cfg.manual_ready_max_dias
            ),
            Err(e) => tracing::warn!("reloj terminal falló: {e}"),
        }
    }

    db::mark_program_scanned(pool, &name, status).await?;
    tracing::info!("cazador: {name} → {status} (scope {scope_count}, {live} vivos)");

    // Notifica los hallazgos nuevos del ciclo (no-op si no hay webhook). Falla
    // SUAVE: un webhook caído avisa en el log pero no tumba la caza (directiva 20).
    match nexus::notify::notificar_pendientes(pool, cfg.notify_webhook.as_deref()).await {
        Ok(0) => {}
        Ok(n) => tracing::info!("notificación: {n} hallazgo(s) avisado(s) por webhook"),
        Err(e) => tracing::warn!("notificación: {e}"),
    }
    Ok(())
}

/// Refresca estado + bounty de los reportes enviados a H1.
async fn cmd_sync(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    let pcfg = ProtectionConfig::default();
    let client = h1::H1Client::from_env(&pcfg.user_agent)?;

    // 1) DESCUBRIR programas nuevos de H1 — la materia prima de la frescura.
    //
    // Hasta hoy el sync solo actualizaba estados de reportes, y los programas se
    // sembraban UNA vez (el lote inicial). Medido el 2026-08-19: 225 programas,
    // todos con `created_at` del 3-4 de agosto, cero nuevos en 16 días — así que
    // la cola envejecía entera y la selección por frescura no tenía nada fresco
    // que priorizar. `get_programs` ya lista todo el catálogo (paginado);
    // `seed_programs_pending` es idempotente e inserta SOLO los que faltan, con
    // `created_at = ahora`. Ese `created_at` es el reloj de la ventana de
    // frescura: un programa que aparece hoy en H1 se siembra hoy y se caza con
    // prioridad durante `NEXUS_FRESH_WINDOW_DAYS`.
    //
    // Falla SUAVE (directiva 20): si H1 no responde, se avisa y se sigue con el
    // sync de reportes; no se inventa nada ni se tumba el resto.
    match client.get_programs().await {
        Ok(handles) => match db::seed_programs_pending(pool, &handles).await {
            Ok(nuevos) => tracing::info!(
                "sync: {} programas en H1, {nuevos} nuevos sembrados",
                handles.len()
            ),
            Err(e) => tracing::warn!("sync: no se pudieron sembrar programas nuevos: {e}"),
        },
        Err(e) => tracing::warn!("sync: no se pudo listar el catálogo de H1: {e}"),
    }

    // 1b) SEGUNDO PROVEEDOR: programas PÚBLICOS de Intigriti del feed de arkadiyt
    // (sin token). Ciudadanos de 1ª en la cola; su scope va a program_scopes y el
    // recon lo lee de ahí. Falla SUAVE igual que H1 (directiva 20).
    match reqwest::Client::builder()
        .user_agent(pcfg.user_agent.clone())
        .timeout(std::time::Duration::from_secs(60))
        .build()
    {
        Ok(http) => match nexus::sources::fetch_ark_intigriti_programs(&http).await {
            Ok(progs) => match db::seed_intigriti_programs(pool, &progs).await {
                Ok(nuevos) => tracing::info!(
                    "sync: {} programas Intigriti que pagan, {nuevos} nuevos sembrados",
                    progs.len()
                ),
                Err(e) => tracing::warn!("sync: no se pudieron sembrar programas Intigriti: {e}"),
            },
            Err(e) => tracing::warn!("sync: no se pudo bajar el feed de Intigriti: {e}"),
        },
        Err(e) => tracing::warn!("sync: no se pudo crear el cliente HTTP para Intigriti: {e}"),
    }

    // 1c) API de INVESTIGADOR de Intigriti (con token): programas UNIDOS (incl.
    // privados) con scope PRECISO. Falla SUAVE: sin NEXUS_INTIGRITI_TOKEN se
    // omite y el feed público sigue sirviendo (directiva 20).
    match nexus::intigriti::IntigritiClient::from_env(&pcfg.user_agent) {
        Ok(cli) => match cli.programas_con_scope().await {
            Ok(progs) => match db::seed_intigriti_programs(pool, &progs).await {
                Ok(nuevos) => tracing::info!(
                    "sync: {} programas Intigriti UNIDOS (API), {nuevos} nuevos sembrados",
                    progs.len()
                ),
                Err(e) => tracing::warn!("sync: no se sembraron los unidos de Intigriti: {e}"),
            },
            Err(e) => tracing::warn!("sync: API de investigador de Intigriti: {e}"),
        },
        Err(_) => tracing::info!(
            "sync: sin NEXUS_INTIGRITI_TOKEN — se omite la API de investigador (el feed público sigue)"
        ),
    }

    // 2) ACTUALIZAR estados de los reportes ya enviados.
    let rows = db::submitted_findings(pool).await?;
    if rows.is_empty() {
        tracing::info!("sync: no hay reportes enviados");
        return Ok(());
    }
    let mut updated = 0u64;
    for (id, report_id) in rows {
        match client.report_state(&report_id).await {
            Ok((Some(state), bounty)) => {
                db::update_h1_state(pool, id, &state, bounty.as_deref()).await?;
                updated += 1;
            }
            Ok((None, _)) => {}
            Err(e) => tracing::warn!("sync {report_id}: {e}"),
        }
    }
    tracing::info!("sync: {updated} reportes actualizados");
    Ok(())
}

async fn cmd_report(cfg: &Config, pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    let findings = db::all_findings(pool).await?;
    let total = db::count_findings(pool).await?;
    let md = report::build_markdown(&findings, &total.to_string());
    let path = cfg.scans_dir.join("scan_report.md");
    tokio::fs::write(&path, md).await?;
    tracing::info!("informe → {}", path.display());
    Ok(())
}

async fn cmd_serve(cfg: &Config, pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    let app = nexus::web::router(pool.clone());
    let addr = format!("{}:{}", cfg.host, cfg.port);
    tracing::info!("panel en http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Colector SSRF out-of-band: escucha en 0.0.0.0:oob_port (público) y registra
/// los callbacks en la BD. Necesita `ConnectInfo` para la IP de origen, así que
/// se sirve con `into_make_service_with_connect_info`.
/// Recon de RPs/audiencias OIDC: lee el discovery público del origen y parsea las
/// URLs de authorize observadas, e imprime el mapa de audiencias con los pares
/// candidatos a confusión (leads para el razonador/oráculo, no hallazgos).
async fn cmd_oidc_recon(
    cfg: &nexus::config::Config,
    base: &str,
    authorize: &[String],
    json: bool,
) -> anyhow::Result<()> {
    use nexus::{jwks, oidc_recon};
    let ua = cfg.user_agent.as_deref().unwrap_or(nexus::evasion::UA_POOL[0]);
    let cli = nexus::autz::cliente(ua)?;
    let origen = jwks::origen_de(base);
    let idp = oidc_recon::descubrir_idp(&cli, &origen, &cfg.curl_impersonate_path).await;
    let rps: Vec<oidc_recon::Rp> = authorize.iter().filter_map(|u| oidc_recon::parsear_authorize(u)).collect();
    let mapa = oidc_recon::construir_mapa(idp, rps);

    if json {
        println!("{}", serde_json::to_string_pretty(&mapa)?);
        return Ok(());
    }
    println!("=== Recon de audiencias OIDC — {origen} ===");
    match &mapa.idp {
        Some(i) => {
            println!("IdP: issuer={}  token={}", i.issuer, i.token_endpoint);
            println!("     algs=[{}]  scopes=[{}]", i.algs.join(","), i.scopes_supported.join(","));
        }
        None => println!("IdP: (sin discovery público en el origen)"),
    }
    println!("RPs observados: {}", mapa.rps.len());
    for r in &mapa.rps {
        println!("  - {} → host {} scopes=[{}] aud={:?}", r.client_id, r.redirect_host, r.scopes.join(" "), r.audiencia_pedida);
    }
    println!("Pares candidatos a confusión de audiencia (LEAD, no hallazgo): {}", mapa.pares_candidatos.len());
    for (i, j, motivo) in &mapa.pares_candidatos {
        println!("  · token de '{}' → audiencia de '{}'  [{}]", mapa.rps[*i].client_id, mapa.rps[*j].client_id, motivo);
    }
    println!("\nSiguiente: el oráculo confirma por ejecución (blanco autorizado + go de Juan);");
    println!("el banco `labs/confusion-audiencia` prueba que el oráculo discrimina.");
    Ok(())
}

async fn cmd_oob_server(cfg: &Config) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    // Abre SOLO la BD aislada del colector (nunca la principal).
    let oob_pool = db::open_oob(&cfg.oob_db_path(), 4).await?;
    // Housekeeping: purga inicial + tarea periódica (cada hora) que borra los
    // callbacks de más de 24h. La tabla la puede engordar cualquiera en internet;
    // la ventana `since_id` da la corrección, esto acota el disco (dir. 22/37).
    match db::purge_oob_hits_older_than(&oob_pool, 24).await {
        Ok(n) if n > 0 => tracing::info!("oob: purga inicial, {n} callbacks viejos borrados"),
        Ok(_) => {}
        Err(e) => tracing::warn!("oob: purga inicial falló: {e}"),
    }
    {
        let p = oob_pool.clone();
        tokio::spawn(async move {
            let mut tic = tokio::time::interval(std::time::Duration::from_secs(3600));
            tic.tick().await; // consume el primer tick inmediato
            loop {
                tic.tick().await;
                if let Err(e) = db::purge_oob_hits_older_than(&p, 24).await {
                    tracing::warn!("oob: purga periódica falló: {e}");
                }
            }
        });
    }
    let app = nexus::oob::router(oob_pool);
    let addr = format!("0.0.0.0:{}", cfg.oob_port);
    tracing::info!(
        "colector OOB en http://{addr} (público; registra callbacks SSRF en {})",
        cfg.oob_db_path().display()
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// Generador de aleatorio [0,1) para el jitter. Aislado para poder sustituirlo
/// por uno determinista en tests.
fn make_rng() -> impl FnMut() -> f64 {
    use rand::Rng;
    let mut r = rand::rng();
    move || r.random::<f64>()
}

fn init_tracing(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("nexus={level}")));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
}

/// ¿La variable de entorno está en un valor "verdadero"? Tolerante: 1/true/yes/on.
fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => false,
    }
}

/// Carga mínima de .env (KEY=VALUE por línea) sin dependencia externa.
fn load_dotenv() {
    if let Ok(content) = std::fs::read_to_string(".env") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim().trim_matches('"').trim_matches('\'');
                if std::env::var(k.trim()).is_err() {
                    std::env::set_var(k.trim(), v);
                }
            }
        }
    }
}

/// FP-LAB de extremo a extremo: levanta la app-trampa LOCAL (bind 127.0.0.1) y mide
/// FPR/TPR del SISTEMA de deteccion contra HTTP real (directiva 28). No abre la BD
/// principal ni sale a la red externa. Imprime la tabla por clase y el total.
async fn cmd_fp_eval(cfg: &Config, port: u16, xss_tries: usize) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let real_port = listener.local_addr()?.port();
    let base = format!("http://127.0.0.1:{real_port}");
    let app = nexus::fp_app::router();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    println!("# FP-lab: app trampa LOCAL en {base}");
    println!("# Midiendo el sistema de deteccion contra HTTP real (directiva 28)...\n");
    let res = nexus::fp_lab::evaluar_sistema(&base, cfg, xss_tries).await;
    nexus::fp_lab::imprimir(&res);
    server.abort();
    Ok(())
}

/// Oráculo diferencial unificado. Carga un `CasoDiferencial` de JSON, aplica la barandilla
/// por modo (whitebox=loopback / blackbox=scope), opcionalmente levanta un lab, corre la
/// sonda y emite el certificado. Mismo camino para lab (white) y objetivo vivo (black).
async fn cmd_oraculo(
    black: bool,
    base: &str,
    caso_path: &std::path::Path,
    scope: &[String],
    intentos: usize,
    lab_dir: Option<&std::path::Path>,
    realtime: bool,
) -> anyhow::Result<()> {
    use nexus::oraculo_diferencial::{guardia, sonda, CasoDiferencial, Modo, Objetivo};

    let modo = if black { Modo::Blackbox } else { Modo::Whitebox };
    let objetivo = Objetivo { base: base.to_string(), modo };

    // Barandilla ANTES de tocar nada (directiva 18 / estatuto sin daño). host_de() sirve
    // igual para http:// y ws://.
    if let Err(e) = guardia(&objetivo, scope) {
        eprintln!("barandilla {}: {e}", modo.nombre());
        std::process::exit(2);
    }

    // Camino de TIEMPO REAL (websocket/DDP): --base es la ws_url, --caso un CasoRealtime.
    if realtime {
        let texto = std::fs::read_to_string(caso_path)
            .map_err(|e| anyhow::anyhow!("no pude leer el caso {}: {e}", caso_path.display()))?;
        let caso: nexus::oraculo_realtime::CasoRealtime =
            serde_json::from_str(&texto).map_err(|e| anyhow::anyhow!("caso realtime JSON inválido: {e}"))?;
        if let Some(dir) = lab_dir {
            if !black {
                println!("# levantando lab en {} …", dir.display());
                nexus::lab::levantar(dir).map_err(|e| anyhow::anyhow!(e))?;
            }
        }
        println!("# oráculo realtime [{}] contra {base}", modo.nombre());
        println!("# caso: {} ({})\n", caso.descripcion, caso.clase);
        let cli = autz::cliente("nexus-oraculo/1.0").map_err(|e| anyhow::anyhow!(e))?;
        let v = nexus::oraculo_realtime::sonda_realtime(&cli, modo, &caso).await;
        if let Some(dir) = lab_dir { if !black { nexus::lab::bajar(dir); } }
        return emitir_veredicto(v);
    }

    let texto = std::fs::read_to_string(caso_path)
        .map_err(|e| anyhow::anyhow!("no pude leer el caso {}: {e}", caso_path.display()))?;
    let caso: CasoDiferencial =
        serde_json::from_str(&texto).map_err(|e| anyhow::anyhow!("caso JSON inválido: {e}"))?;

    // Lab opcional (solo whitebox): levantar antes, bajar SIEMPRE al terminar.
    if let Some(dir) = lab_dir {
        if black {
            eprintln!("--lab es solo para whitebox (un objetivo vivo no se levanta); ignorado");
        } else {
            println!("# levantando lab en {} …", dir.display());
            nexus::lab::levantar(dir).map_err(|e| anyhow::anyhow!(e))?;
            if !nexus::lab::esperar_http(base, 300).await {
                nexus::lab::bajar(dir);
                anyhow::bail!("el lab no respondió en {base} a tiempo");
            }
        }
    }

    println!("# oráculo diferencial [{}] contra {base}", modo.nombre());
    println!("# caso: {} ({})\n", caso.descripcion, caso.clase);
    let cli = autz::cliente("nexus-oraculo/1.0").map_err(|e| anyhow::anyhow!(e))?;
    let veredicto = sonda(&cli, &objetivo, &caso, intentos).await;

    if let Some(dir) = lab_dir {
        if !black {
            println!("# bajando lab …");
            nexus::lab::bajar(dir);
        }
    }

    emitir_veredicto(veredicto)
}

/// Imprime el veredicto + certificado y sale con el código convenido (0=hallazgo, 1=sólido,
/// 2=no concluyente). Compartido por el camino HTTP y el de tiempo real.
fn emitir_veredicto(v: nexus::oraculo_diferencial::Veredicto) -> anyhow::Result<()> {
    use nexus::oraculo_diferencial::Veredicto;
    match v {
        Veredicto::Fuga(cert) => {
            println!("VEREDICTO: HALLAZGO — el no-autorizado ve el recurso.\n");
            print!("{}", cert.render());
            std::process::exit(0);
        }
        Veredicto::Solido => {
            println!("VEREDICTO: SÓLIDO — el invariante se sostiene (no-autorizado denegado).");
            std::process::exit(1);
        }
        Veredicto::NoConcluyente(por_que) => {
            println!("VEREDICTO: NO CONCLUYENTE — {por_que}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parsear_cabecera;

    /// `parsear_cabecera` parte SOLO en el primer ':' — un Bearer o una cookie
    /// llevan ':' en el valor y no deben romperse — y trima. Su pareja roja
    /// (directiva 33): sin ':' o con clave vacía FALLA, que es lo que impide
    /// montar una credencial muda (directiva 20).
    #[test]
    fn cabecera_valida_parte_en_el_primer_dospuntos() {
        assert_eq!(
            parsear_cabecera("Authorization: Bearer eyJ:abc.def").unwrap(),
            ("Authorization".to_string(), "Bearer eyJ:abc.def".to_string())
        );
        assert_eq!(
            parsear_cabecera("Cookie:sid=123").unwrap(),
            ("Cookie".to_string(), "sid=123".to_string())
        );
    }

    #[test]
    fn cabecera_sin_dospuntos_o_clave_vacia_falla() {
        assert!(parsear_cabecera("malformada").is_err(), "sin ':' debe fallar");
        assert!(parsear_cabecera(": valor").is_err(), "clave vacía debe fallar");
    }

    /// Validez HTTP, no solo sintaxis: una clave con espacio (token inválido) y un
    /// valor con CRLF interior (inyección de cabecera) deben fallar AL MONTAR, no
    /// morir mudos en la caza (directiva 20/33).
    #[test]
    fn cabecera_invalida_para_http_falla_al_montar() {
        assert!(parsear_cabecera("X Cabecera Mala: v").is_err(), "clave con espacio no es token HTTP");
        assert!(parsear_cabecera("X-Inj: a\r\nEvil: b").is_err(), "CRLF en el valor debe fallar");
    }
}
