//! Reconocimiento: subfinder (enumeración de subdominios) + httpx (hosts vivos).
//! Portado de `recon.py`. Streaming a disco: en el VPS sin swap no se acumulan
//! los subdominios en memoria.

use crate::config::Config;
use crate::error::Result;
use crate::scope::{self, ScopeRule};
use crate::tools;
use sqlx::SqlitePool;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Clasifica el desenlace del recon de UN ciclo de caza en el estado del
/// programa, separando dos causas que un solo `live == 0` confundía (directiva
/// 32) — y que hacían PERDER para siempre un programa unido cuyo scope estaba
/// vivo pero cuyos hosts no respondieron en ese instante:
///
///   - `scope == 0` → **ScopeBlocked**: H1 no entregó scope (no unido, o sin
///     activos elegibles para bounty). No hay nada que cazar aquí nunca → la
///     cola lo EXCLUYE permanentemente.
///   - `scope > 0` y `live == 0` → **sin_hosts_vivos**: hay scope pero 0 host
///     vivo AHORA (DNS caído, httpx sin respuesta, pico transitorio). El
///     programa NO se pierde: sigue seleccionable y se reintenta en la vuelta
///     del round-robin; si se REPITE, la cuarentena (que ya cuenta `no_live`) lo
///     deprioritiza — auto-sanable (directiva 22).
///   - `live > 0` → **scanned**: hay objetivos; el llamante corre el scan.
///
/// Pura: es la MISMA función que usa `cmd_hunt`, así que su pareja de pruebas
/// falla por la vía real (directiva 33), no por un arnés paralelo.
pub fn estado_tras_recon(scope: usize, live: usize) -> &'static str {
    if scope == 0 {
        "ScopeBlocked"
    } else if live == 0 {
        "sin_hosts_vivos"
    } else {
        "scanned"
    }
}

/// Filtra `targets_file` a solo hosts in-scope (P2, protección anti-baneo/legal).
/// FAIL-CLOSED: si la validación de scope está ON y no hay scope guardado, deja
/// el archivo VACÍO (no escanear fuera de scope). Devuelve (antes, después).
pub async fn filter_to_scope(cfg: &Config, pool: &SqlitePool, targets_file: &Path) -> Result<(usize, usize)> {
    if !targets_file.exists() {
        return Ok((0, 0));
    }
    let content = tokio::fs::read_to_string(targets_file).await?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let before = lines.len();

    // ALCANCE POR PROGRAMA (fix 2026-08-27): el ciclo caza UN programa (`cfg.only`),
    // así que el filtro usa el scope de ESE programa, no el catálogo global. Con el
    // global, un host in-scope de OTRO programa (linkedin durante intigriti) pasaba
    // y se atribuía mal → riesgo de reporte fuera de scope. Sin `only` (recon
    // global manual), se conserva el comportamiento anterior.
    let rules_raw = if cfg.only.is_empty() {
        crate::db::scope_rules_with_id(pool).await?
    } else {
        crate::db::scope_rules_for_programs(pool, &cfg.only).await?
    };
    if rules_raw.is_empty() {
        if !cfg.no_scope_validation {
            tracing::warn!("scope vacío y validación ON → 0 objetivos (fail-closed; usa --no-scope-validation para forzar)");
            tokio::fs::write(targets_file, "").await?;
            return Ok((before, 0));
        }
        return Ok((before, before)); // validación off: se deja tal cual
    }

    let rules: Vec<ScopeRule> = rules_raw
        .iter()
        .filter_map(|(_, ident, wild)| ScopeRule::parse(ident, *wild))
        .collect();
    let kept: Vec<&str> = lines.into_iter().filter(|u| scope::in_scope(u, &rules)).collect();
    tokio::fs::write(targets_file, kept.join("\n")).await?;
    Ok((before, kept.len()))
}

/// Reordena `targets_file` por la superficie RANKEADA (característica #10): pone los
/// objetivos de alto valor (`P1` — api/auth/admin, no-prod) ANTES que la app genérica
/// (`P2`), y lo provablemente estático (`KILL` — cdn/assets/.css) al final. La fase cara
/// (nuclei/oráculos, con presupuesto anti-baneo) gasta primero donde más vale.
///
/// **Es un reorden, NO un filtro (D21-invertido, igual que `superficie`):** `KILL` se
/// CONSERVA al final, nunca se descarta — demotar un objetivo real es un falso negativo
/// (un hit perdido). Rankea solo por la URL (lo único que captura el recon hoy); el
/// discriminador real lo pone el oráculo por ejecución, no esta capa (D16). El orden
/// dentro de cada banda se preserva (sort estable), respetando el orden de descubrimiento.
///
/// Devuelve el conteo `(p1, p2, kill)`. Archivo inexistente o vacío → `(0,0,0)`, sin tocar.
pub async fn ordenar_por_superficie(targets_file: &Path) -> Result<(usize, usize, usize)> {
    if !targets_file.exists() {
        return Ok((0, 0, 0));
    }
    let content = tokio::fs::read_to_string(targets_file).await?;
    let lineas: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    if lineas.is_empty() {
        return Ok((0, 0, 0));
    }
    let activos: Vec<crate::superficie::Activo> = lineas
        .iter()
        .map(|u| crate::superficie::Activo::de_url(u.clone()))
        .collect();
    let rankeados = crate::superficie::superficie_rankeada(&activos); // ya ordena P1<P2<KILL (D9)
    let (mut p1, mut p2, mut kill) = (0usize, 0usize, 0usize);
    for r in &rankeados {
        match r.prioridad {
            crate::superficie::Prioridad::P1 => p1 += 1,
            crate::superficie::Prioridad::P2 => p2 += 1,
            crate::superficie::Prioridad::Kill => kill += 1,
        }
    }
    let ordenadas: Vec<String> = rankeados.into_iter().map(|r| r.activo.url).collect();
    tokio::fs::write(targets_file, ordenadas.join("\n")).await?;
    Ok((p1, p2, kill))
}

/// Valida un dominio para subfinder (rechaza wildcards y basura). Portado de
/// is_valid_domain de recon.py.
pub fn is_valid_domain(d: &str) -> bool {
    let d = d.trim();
    !d.is_empty()
        && d.contains('.')
        && !d.contains('*')
        && !d.contains('/')
        && !d.contains(' ')
        && !d.starts_with('-')
        && !d.starts_with('.')
}

/// Corre subfinder sobre un dominio; devuelve los subdominios encontrados.
pub async fn subfinder_one(cfg: &Config, domain: &str) -> Result<Vec<String>> {
    if !is_valid_domain(domain) {
        return Ok(Vec::new());
    }
    let args: Vec<String> = vec![
        "-d".into(), domain.into(),
        "-silent".into(),
        "-t".into(), "5".into(),
        "-timeout".into(), "60".into(),
        "-nW".into(),
        "-r".into(), "8.8.8.8,1.1.1.1,9.9.9.9".into(),
    ];
    let out = tools::run(&cfg.subfinder_path, &args, Duration::from_secs(70)).await?;
    if out.timed_out {
        return Ok(Vec::new());
    }
    Ok(out.stdout.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

/// Reúne los objetivos de recon de todos los activos del scope y los escribe en
/// `subs_file`. Devuelve el total (hosts sembrados + subdominios), deduplicado.
/// Con jitter entre dominios para no crear un patrón (anti-baneo).
///
/// **SIEMBRA el propio activo del scope, no solo sus subdominios.** subfinder
/// solo busca subdominios POR DEBAJO de lo que se le da; los activos de H1 llegan
/// como host concreto (`supplier.meesho.com`) o wildcard (`*.meesho.com`). Un
/// host hoja no tiene subdominios, así que enumerarlo daba 0 — y el activo, que
/// ES el objetivo válido y está vivo, nunca entraba en la lista. Resultado
/// medido: programas con scope de hosts concretos producían 0 objetivos →
/// ScopeBlocked → 0 hallazgos, pasara lo que pasara aguas abajo. Ahora, por cada
/// activo se siembra su host base (quitando el `*.` del wildcard) Y se enumeran
/// sus subdominios; el filtro de scope posterior recorta lo que no esté en scope.
/// ¿Hay que cortar el recon ANTES de pedir el siguiente subfinder?
///
/// Pura y por eso testeable: la decisión no depende del reloj real sino de dos
/// instantes que se le pasan. `None` = sin tope, nunca corta.
fn recon_vencido(ahora: std::time::Instant, deadline: Option<std::time::Instant>) -> bool {
    matches!(deadline, Some(d) if ahora >= d)
}

pub async fn enumerate(cfg: &Config, roots: &[String], subs_file: &Path) -> Result<usize> {
    enumerate_hasta(cfg, roots, subs_file, None).await
}

/// Igual, pero con un TOPE PROPIO: `recon_deadline` es el instante en que la
/// enumeración debe haber terminado. Al cruzarlo, deja de pedir subdominios
/// nuevos y escribe lo que ya tiene.
///
/// POR QUÉ EXISTE (medido en el VPS el 2026-08-06): `subfinder_one` corre por
/// dominio, en SERIE, 70 s de tope cada uno más 300 ms de jitter. Con 25
/// dominios eso es hasta ~29 min ANTES de escanear una sola URL, y el
/// presupuesto del ciclo (`NEXUS_SCAN_DEADLINE_SECS`) ya está corriendo — así
/// que el recon se comía casi la mitad y encontraba 0. Un tope propio hace que
/// el recon no pueda robarle al scan más que su parte.
///
/// Los activos YA sembrados no se pierden al vencer: el host base de cada uno se
/// inserta ANTES de llamar a subfinder, así que un recon cortado a la mitad
/// sigue entregando todos los objetivos válidos, solo con menos subdominios
/// enumerados. Eso es degradación, no fallo.
/// Carga el diccionario del bruteforce: el archivo de `cfg.bruteforce_wordlist` si se
/// dio (y FALLA si no existe — dir. 20, nada de defaults silenciosos), o el curado
/// embebido en el binario. Filtra vacíos y comentarios `#`.
async fn cargar_palabras(wordlist: Option<&Path>) -> Result<Vec<String>> {
    match wordlist {
        Some(ruta) => {
            // Un error de lectura convierte a NexusError::Io por el `?` (fail loud).
            let txt = tokio::fs::read_to_string(ruta).await?;
            let v: Vec<String> = txt
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if v.is_empty() {
                return Err(crate::error::NexusError::Other(format!("wordlist {ruta:?} está vacía")));
            }
            Ok(v)
        }
        None => Ok(crate::bruteforce::PALABRAS_DEFECTO.iter().map(|s| s.to_string()).collect()),
    }
}

pub async fn enumerate_hasta(
    cfg: &Config,
    roots: &[String],
    subs_file: &Path,
    recon_deadline: Option<std::time::Instant>,
) -> Result<usize> {
    // TRUNCA al abrir: cada ciclo del cazador enumera UN programa, y el archivo
    // se reabre una vez por ciclo. En `append` (como estaba) los subdominios se
    // acumulaban entre programas, así que `live_hosts` escaneaba el montón de
    // TODOS los programas previos — objetivos fuera del scope del actual y ~17
    // min de httpx malgastados por ciclo.
    let mut file = tokio::fs::OpenOptions::new().create(true).write(true).truncate(true).open(subs_file).await?;
    // Dedup: un wildcard y un host concreto del mismo programa pueden solaparse
    // (subfinder de la base reencuentra el host concreto). Sin dedup, httpx lo
    // probaría dos veces y gastaría presupuesto de scan en duplicados. Un ciclo
    // cubre UN programa, así que el conjunto está acotado (cientos, no miles).
    let mut objetivos: std::collections::BTreeSet<String> = Default::default();
    let mut bases: std::collections::BTreeSet<String> = Default::default();
    let mut cortado = false;
    for asset in roots {
        // `*.meesho.com` → `meesho.com`: el activo del wildcard es su dominio base.
        let base = asset.trim().trim_start_matches("*.");
        if is_valid_domain(base) {
            objetivos.insert(base.to_string()); // el activo en sí es un objetivo
            bases.insert(base.to_string());
        }
        // EL TOPE se mira ANTES de llamar a subfinder —que tarda hasta 70 s— y
        // DESPUÉS de sembrar el host base, para que vencer no pierda el objetivo
        // válido que sí teníamos.
        if recon_vencido(std::time::Instant::now(), recon_deadline) {
            cortado = true;
            break;
        }
        for s in subfinder_one(cfg, base).await? {
            objetivos.insert(s);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // BRUTEFORCE DNS PROPIO (keyless): sobre cada dominio base, resolver el diccionario
    // y añadir los subdominios que lo pasivo no vio. Falla suave: un error de wordlist
    // no tumba el recon (subfinder ya dio lo suyo). Respeta el tope del recon.
    // SCOPE: genera subs de las bases igual que subfinder encuentra hermanos; el gate
    // es `filter_to_scope` AGUAS ABAJO (main.rs, antes de httpx), que descarta lo que
    // no esté en scope (para un programa de host EXACTO, todos estos caen). Solo se
    // resuelve DNS aquí (una consulta, no se toca el host); nada se sondea sin filtrar.
    if cfg.bruteforce_dns && !cortado {
        // M3: si se dio una wordlist por config y falla (ruta mala / vacía), es un ERROR
        // de configuración → propaga y ABORTA el recon (dir. 20, nada de degradar en
        // silencio). Con la lista embebida `cargar_palabras` no puede fallar.
        let palabras = cargar_palabras(cfg.bruteforce_wordlist.as_deref()).await?;
        let refs: Vec<&str> = palabras.iter().map(|s| s.as_str()).collect();
        let antes = objetivos.len();
        for base in &bases {
            if recon_vencido(std::time::Instant::now(), recon_deadline) {
                break;
            }
            let hits = crate::bruteforce::bruteforce(
                base, &refs, cfg.bruteforce_concurrencia, recon_deadline,
                |h| Box::pin(crate::bruteforce::resolver_sistema_owned(h)),
            ).await;
            for h in hits {
                objetivos.insert(h);
            }
        }
        tracing::info!("bruteforce DNS: +{} subdominios sobre {} base(s)", objetivos.len() - antes, bases.len());
    }
    if cortado {
        tracing::warn!(
            "recon cortado por su tope: {} de {} activos enumerados, {} objetivos",
            objetivos.len().min(roots.len()), roots.len(), objetivos.len()
        );
    }
    for h in &objetivos {
        file.write_all(h.as_bytes()).await?;
        file.write_all(b"\n").await?;
    }
    file.flush().await?;
    Ok(objetivos.len())
}

/// Corre httpx sobre el archivo de subdominios y escribe los hosts vivos en
/// `targets_file` (streaming). Devuelve el número de hosts vivos. `-fc 404`
/// filtra los 404 como en recon.py.
pub async fn live_hosts(cfg: &Config, subs_file: &Path, targets_file: &Path) -> Result<usize> {
    let mut file = tokio::fs::File::create(targets_file).await?;
    let mut count = 0usize;
    let args: Vec<String> = vec![
        "-l".into(), subs_file.display().to_string(),
        "-silent".into(),
        "-t".into(), "50".into(),
        "-fc".into(), "404".into(),
        "-follow-redirects".into(),
    ];
    // Recogemos en un buffer local por líneas y las volcamos; run_streaming no es
    // async-friendly con el File aquí, así que juntamos las líneas y escribimos al final
    // por lotes pequeños para no crecer sin límite.
    let mut batch: Vec<String> = Vec::with_capacity(256);
    let mut lines_buf: Vec<String> = Vec::new();
    // Timeout duro: httpx sobre la lista de subdominios; si cuelga (nieto con la
    // tubería abierta) no debe bloquear el ciclo — 5 min es holgado para el sondeo
    // de liveness y corta el cuelgue (fix del hang de recon, 2026-08-26).
    tools::run_streaming(&cfg.httpx_path, &args, std::time::Duration::from_secs(300), |line| {
        let l = line.trim();
        if l.starts_with("http") {
            lines_buf.push(l.to_string());
        }
    })
    .await?;
    for l in lines_buf {
        batch.push(l);
        count += 1;
        if batch.len() >= 256 {
            file.write_all(batch.join("\n").as_bytes()).await?;
            file.write_all(b"\n").await?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        file.write_all(batch.join("\n").as_bytes()).await?;
        file.write_all(b"\n").await?;
    }
    file.flush().await?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cargar_palabras_defecto_y_fail_loud() {
        // Sin archivo → diccionario embebido, no vacío.
        let def = cargar_palabras(None).await.unwrap();
        assert!(def.len() > 50 && def.iter().any(|w| w == "admin"));

        // Archivo válido: filtra vacíos y comentarios `#`.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("w.txt");
        tokio::fs::write(&f, "api\n\n# comentario\nadmin\n  staging  \n").await.unwrap();
        let v = cargar_palabras(Some(&f)).await.unwrap();
        assert_eq!(v, vec!["api", "admin", "staging"]);

        // M3 — FAIL LOUD: ruta dada pero inexistente → Err (no defecto silencioso).
        assert!(cargar_palabras(Some(&dir.path().join("no-existe.txt"))).await.is_err());
        // M3 — archivo vacío (solo comentarios/blancos) → Err.
        let vac = dir.path().join("vacia.txt");
        tokio::fs::write(&vac, "# solo comentario\n\n").await.unwrap();
        assert!(cargar_palabras(Some(&vac)).await.is_err());
    }

    #[tokio::test]
    async fn ordenar_por_superficie_pone_p1_primero_y_conserva_kill() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("targets.txt");
        // Orden de llegada del recon: estático (KILL), app genérica (P2), api (P1).
        tokio::fs::write(
            &f,
            "https://cdn.acme.com/assets/app.css\nhttps://www.acme.com/contacto\nhttps://api.acme.com/v1/users\n",
        )
        .await
        .unwrap();

        let (p1, p2, kill) = ordenar_por_superficie(&f).await.unwrap();
        assert_eq!((p1, p2, kill), (1, 1, 1), "un objetivo por banda");

        let out: Vec<String> = tokio::fs::read_to_string(&f)
            .await
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        // Discrimina (D33): sin el reorden, `api` (P1) seguiría DETRÁS de `cdn`/`www`.
        assert!(out[0].contains("api.acme.com"), "P1 primero, fue: {out:?}");
        // El estático NO se pierde: se conserva al final (D21-invertido).
        assert_eq!(out.len(), 3, "KILL se conserva, no se descarta");
        assert!(out[2].contains("cdn.acme.com"), "KILL al final, fue: {out:?}");

        // Vacío / inexistente → (0,0,0) sin panic.
        let vacio = dir.path().join("vacio.txt");
        tokio::fs::write(&vacio, "\n  \n").await.unwrap();
        assert_eq!(ordenar_por_superficie(&vacio).await.unwrap(), (0, 0, 0));
        assert_eq!(
            ordenar_por_superficie(&dir.path().join("no-existe.txt")).await.unwrap(),
            (0, 0, 0)
        );
    }

    #[test]
    fn valida_dominios() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("api.sub.example.co"));
        assert!(!is_valid_domain("*.example.com"));
        assert!(!is_valid_domain("nodot"));
        assert!(!is_valid_domain("has/slash.com"));
        assert!(!is_valid_domain("-bad.com"));
    }

    #[test]
    fn el_tope_del_recon_corta_cuando_vence_y_no_antes() {
        use std::time::{Duration, Instant};
        let ahora = Instant::now();
        // SIN tope: nunca corta, por muy tarde que sea (comportamiento de
        // siempre, intacto cuando no hay presupuesto).
        assert!(!recon_vencido(ahora, None), "sin tope no debe cortar nunca");
        // Deadline en el FUTURO: aún no corta —el control que evita que el tope
        // mate el recon el primer segundo—.
        let futuro = ahora + Duration::from_secs(60);
        assert!(!recon_vencido(ahora, Some(futuro)), "con margen no debe cortar");
        // Deadline en el PASADO: corta.
        let pasado = ahora.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(recon_vencido(ahora, Some(pasado)), "vencido debe cortar");
        // Justo en el instante: cortar (>=, no >).
        assert!(recon_vencido(ahora, Some(ahora)), "en el borde debe cortar");
    }

    /// **`live == 0` deja de significar "perdido para siempre" (directiva 32).**
    /// Es la MISMA función que `cmd_hunt` usa para decidir el estado, así que el
    /// caso rojo falla por la vía real (directiva 33).
    ///
    /// Mutante = la regla vieja `if live == 0 { "ScopeBlocked" }`: marcaba el
    /// caso transitorio (scope > 0, live == 0) como ScopeBlocked y lo excluía de
    /// la cola para siempre. La aserción central lo mata.
    #[test]
    fn estado_tras_recon_separa_sin_scope_de_sin_hosts_vivos() {
        // ROJO (el bug): hay scope pero 0 host vivo → transitorio, NO ScopeBlocked.
        assert_eq!(estado_tras_recon(5, 0), "sin_hosts_vivos",
            "con scope y 0 vivos el programa se REINTENTA, no se pierde");
        // CONTROL sin scope: bloqueo permanente de verdad.
        assert_eq!(estado_tras_recon(0, 0), "ScopeBlocked",
            "sin scope de H1 sí es bloqueo permanente");
        // CONTROL productivo: hay objetivos → se escanea.
        assert_eq!(estado_tras_recon(5, 3), "scanned");
        // Borde: 0 scope aunque hubiera vivos (imposible en la práctica, pero la
        // ausencia de scope MANDA — nunca se escanea fuera de un scope conocido).
        assert_eq!(estado_tras_recon(0, 9), "ScopeBlocked",
            "sin scope conocido no se escana aunque haya hosts");
    }
}
