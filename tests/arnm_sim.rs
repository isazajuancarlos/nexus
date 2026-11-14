//! Simulación del bucle adaptativo (`arnm`) a nivel de FASE, sobre BD real, con
//! perfiles de filtro variados y concurrencia (directiva 8: 100+ operaciones;
//! directiva 28: cruza la frontera de la BD; directiva 33: cada perfil es un
//! discriminador — el vulnerable DEBE confirmar, el muro/reflexión/abierto NO).

use std::sync::Arc;

use nexus::arnm::{self, Sonda};
use nexus::db;
use nexus::protection::{Guard, ProtectionConfig};

/// Guard permisivo para la simulación (sin señales de baneo → nunca frena),
/// pausa 0 y rng fijo → sin sleeps reales.
fn g() -> Guard {
    Guard::new(ProtectionConfig::default())
}

/// Objetivo sintético con una postura de filtro conocida. Emula lo que el
/// endpoint vulnerable respondería al buscar la URL de metadata inyectada.
#[derive(Clone, Copy)]
enum Perfil {
    /// Sin filtro: la IP literal ya exfiltra (el caso fácil, también debe cazarse).
    LiteralAbierto,
    /// Filtra la cadena literal; cede a la IP codificada (el caso que el estático
    /// NO resuelve y el adaptativo sí).
    FiltraLiteral,
    /// Filtra literal Y codificaciones numéricas; cede solo a host alterno.
    SoloHostAlterno,
    /// Muro: bloquea todo. No debe confirmar.
    Muro,
    /// Refleja el payload en un error. FP clásico; no debe confirmar.
    Reflexion,
    /// Responde 200 sin metadata: no es SSRF. No debe confirmar.
    Abierto,
}

struct SondaSintetica(Perfil);

const CUERPO_AWS: &str =
    r#"{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret","ami-launch-index":0}"#;

impl Sonda for SondaSintetica {
    async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
        let literal = payload.contains("169.254.169.254");
        let numerica = payload.contains("2852039166")
            || payload.contains("0xa9fea9fe")
            || payload.contains("0251.0376")
            || payload.contains("::ffff:");
        let host_alt = payload.contains("nip.io") || payload.contains("metadata.google.internal");
        match self.0 {
            Perfil::LiteralAbierto => Some((200, CUERPO_AWS.to_string())),
            Perfil::FiltraLiteral => {
                if literal {
                    Some((403, "Blocked host: internal address not allowed".into()))
                } else if numerica || host_alt {
                    Some((200, CUERPO_AWS.to_string()))
                } else {
                    Some((200, "<html>ok</html>".into()))
                }
            }
            Perfil::SoloHostAlterno => {
                if host_alt {
                    Some((200, CUERPO_AWS.to_string()))
                } else {
                    Some((403, "Blocked host: private ip".into()))
                }
            }
            Perfil::Muro => Some((403, "Forbidden host".into())),
            Perfil::Reflexion => Some((200, format!("Error fetching {payload}: refused"))),
            Perfil::Abierto => Some((200, "<html>ok</html>".into())),
        }
    }
}

fn debe_confirmar(p: Perfil) -> bool {
    matches!(p, Perfil::LiteralAbierto | Perfil::FiltraLiteral | Perfil::SoloHostAlterno)
}

/// 120 endpoints, perfiles rotando. Cada uno discrimina: el vulnerable confirma y
/// recuerda; el muro/reflexión/abierto no dejan rastro.
#[tokio::test]
async fn fase_sobre_120_endpoints_discrimina() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("sim.db"), 8).await.unwrap();
    let program_id = db::upsert_program(&pool, "prog").await.unwrap();

    let perfiles = [
        Perfil::LiteralAbierto,
        Perfil::FiltraLiteral,
        Perfil::SoloHostAlterno,
        Perfil::Muro,
        Perfil::Reflexion,
        Perfil::Abierto,
    ];

    let mut esperados_confirmados = 0;
    for i in 0..120 {
        let p = perfiles[i % perfiles.len()];
        let host = format!("h{i}.example.com");
        let url = format!("https://{host}/fetch?url=x");
        let confirmado = arnm::procesar_url(
            &pool, "prog", program_id, &url, &SondaSintetica(p), 100, None,
            &mut g(), 0, &mut || 0.5, None, &arnm::objetivos_base()[..4],
        )
        .await
        .unwrap();
        assert_eq!(
            confirmado,
            debe_confirmar(p),
            "endpoint {i} (perfil {:?}) discrimina mal",
            p as u8
        );
        if debe_confirmar(p) {
            esperados_confirmados += 1;
            // El acierto se recordó como secuencia CONFIRMADA, llaveada al host
            // víctima. Camino A (2026-08-26): la adaptación previa puede dejar además
            // variantes amuralladas/refutadas, así que se cuenta la CONFIRMADA (una
            // por host víctima), no toda fila viva.
            let n = nexus::secuencias::contar_confirmadas(&pool, &host).await.unwrap();
            assert_eq!(n, 1, "endpoint {i}: acierto recordado");
        }
    }

    // 120/6 = 20 de cada perfil; 3 perfiles confirman → 60.
    assert_eq!(esperados_confirmados, 60);
    let hallazgos: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(hallazgos, 60, "solo los vulnerables persisten hallazgo");

    // La reforma BIBLIOTECA (2026-08-26): la memoria ya no guarda SOLO aciertos.
    // Los CONFIRMADOS por oráculo siguen siendo exactamente 60 (un finding = una
    // secuencia confirmada), el invariante de selección intacto...
    let confirmadas: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM secuencias WHERE caducada = 0 AND veces_confirmada > 0",
    )
    .fetch_one(&pool).await.unwrap();
    assert_eq!(confirmadas, 60, "solo los confirmados por oráculo se recuerdan como ACIERTO");

    // ...pero ahora las variantes SERVIDAS-sin-fuga (perfiles Reflexion/Abierto,
    // 200 sin exfiltrar) también se acumulan como REFUTADAS reciclables — la mitad
    // que faltaba, la que hace que el motor se nutra del fracaso (Juan 2026-08-26).
    let refutadas: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM secuencias WHERE veces_confirmada = 0 AND veces_refutada > 0",
    )
    .fetch_one(&pool).await.unwrap();
    assert!(refutadas > 0, "los fracasos servidos se acumulan como variantes reciclables");
}

/// Concurrencia: 60 endpoints vulnerables procesados a la vez. Sin pánico, sin
/// conteo inconsistente. Cada uno su host → sin colisión lógica; la carrera que
/// se prueba es la de la BD.
#[tokio::test]
async fn sesenta_endpoints_concurrentes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(db::open(&dir.path().join("conc.db"), 8).await.unwrap());
    let program_id = db::upsert_program(&pool, "prog").await.unwrap();

    let mut handles = Vec::new();
    for i in 0..60 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            let url = format!("https://c{i}.example.com/fetch?url=x");
            arnm::procesar_url(
                &pool, "prog", program_id, &url,
                &SondaSintetica(Perfil::FiltraLiteral), 100, None,
                &mut g(), 0, &mut || 0.5, None, &arnm::objetivos_base()[..4],
            )
            .await
            .unwrap()
        }));
    }
    let mut confirmados = 0;
    for h in handles {
        if h.await.unwrap() {
            confirmados += 1;
        }
    }
    assert_eq!(confirmados, 60);
    let secuencias: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secuencias WHERE caducada = 0")
        .fetch_one(&*pool).await.unwrap();
    assert_eq!(secuencias, 60);
}

/// procesar_url alimenta la memoria NEGATIVA por causa (directiva 28: cruza la BD;
/// directiva 33: cierra el hunk sin-caso-rojo del registro en arnm). Un muro total
/// agota el arsenal → MetodosAgotados; un confirmado sobre un host antes excluido
/// borra la exclusión (ya no está agotado).
#[tokio::test]
async fn procesar_url_alimenta_la_memoria_negativa() {
    use nexus::exclusiones::{self, Causa};
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("neg.db"), 4).await.unwrap();
    let pid = db::upsert_program(&pool, "prog").await.unwrap();

    // MURO (403 a todo): el arsenal estático se agota → registra MetodosAgotados,
    // cuya política es GENERAR método nuevo, no repetir el arsenal.
    let host_muro = "muro.example.com";
    let url_muro = format!("https://{host_muro}/fetch?url=x");
    arnm::procesar_url(&pool, "prog", pid, &url_muro, &SondaSintetica(Perfil::Muro), 50, None, &mut g(), 0, &mut || 0.5, None, &arnm::objetivos_base()[..4])
        .await.unwrap();
    assert_eq!(
        exclusiones::consultar(&pool, host_muro, "ssrf").await.unwrap().map(|(c, _)| c),
        Some(Causa::MetodosAgotados),
        "un muro total registra métodos agotados"
    );

    // CONFIRMADO sobre un host con exclusión previa → la borra (ya no está agotado).
    let host_ok = "vuln.example.com";
    exclusiones::registrar(&pool, host_ok, "ssrf", Causa::MetodosAgotados, "vieja").await.unwrap();
    let url_ok = format!("https://{host_ok}/fetch?url=x");
    let confirmado = arnm::procesar_url(&pool, "prog", pid, &url_ok, &SondaSintetica(Perfil::LiteralAbierto), 50, None, &mut g(), 0, &mut || 0.5, None, &arnm::objetivos_base()[..4])
        .await.unwrap();
    assert!(confirmado, "el perfil abierto confirma SSRF");
    assert!(
        exclusiones::consultar(&pool, host_ok, "ssrf").await.unwrap().is_none(),
        "un confirmado borra la exclusión previa del host"
    );
}

/// ENFORCEMENT de la memoria negativa (directiva 33, par rojo/verde): con
/// enforce=true y un veredicto MetodosAgotados vigente bajo la MISMA huella, la
/// caza SALTA la búsqueda cara (Resultado::Saltado). Si la huella no coincide, o
/// si enforce=false, NO salta y corre la fase (MuroTotal → registra y sale seco).
#[tokio::test]
async fn enforcement_salta_bajo_huella_vigente_y_no_bajo_otra() {
    use nexus::arnm::{cazar_ssrf, huella_filtro, ClaseBloqueo, Memoria, Resultado};
    use nexus::exclusiones::{self, Causa};
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("enf.db"), 4).await.unwrap();
    let host = "muro.example.com";

    // Un MuroTotal produce ClaseBloqueo::FiltroDestino tras el literal → esta es la
    // huella que el enforcement comparará (misma función que el writer).
    let huella_muro = huella_filtro(ClaseBloqueo::FiltroDestino);
    exclusiones::registrar(&pool, host, "ssrf", Causa::MetodosAgotados, &huella_muro).await.unwrap();

    // enforce=false: NO salta aunque haya veredicto → corre y sale Seco.
    let r = cazar_ssrf(&SondaSintetica(Perfil::Muro), 100, Some(Memoria { pool: &pool, host, program_name: "prog-sim", enforce_ttl: None }), &mut g(), 0, &mut || 0.5, &arnm::objetivos_base()[..4]).await;
    assert!(matches!(r, Resultado::Seco { .. }), "sin enforce corre la fase (Seco), no salta");

    // enforce=true y huella vigente: SALTA (no gasta la búsqueda cara).
    let r = cazar_ssrf(&SondaSintetica(Perfil::Muro), 100, Some(Memoria { pool: &pool, host, program_name: "prog-sim", enforce_ttl: Some(86_400) }), &mut g(), 0, &mut || 0.5, &arnm::objetivos_base()[..4]).await;
    match r {
        Resultado::Saltado { causa, intentos, .. } => {
            assert_eq!(causa, Causa::MetodosAgotados);
            assert!(intentos <= 4, "solo el sondeo literal, no la fase 2");
        }
        otro => panic!("con enforce y huella vigente debe SALTAR, no {otro:?}"),
    }

    // enforce=true pero veredicto bajo OTRA huella: caduca → NO salta, corre la fase.
    let otro_host = "cambia.example.com";
    exclusiones::registrar(&pool, otro_host, "ssrf", Causa::MetodosAgotados, "s=999;waf=inexistente").await.unwrap();
    let r = cazar_ssrf(&SondaSintetica(Perfil::Muro), 100, Some(Memoria { pool: &pool, host: otro_host, program_name: "prog-sim", enforce_ttl: Some(86_400) }), &mut g(), 0, &mut || 0.5, &arnm::objetivos_base()[..4]).await;
    assert!(matches!(r, Resultado::Seco { .. }), "huella distinta caduca el veredicto → corre la fase, no salta");
}
