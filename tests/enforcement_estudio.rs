//! ESTUDIO del enforcement de la memoria negativa (pedido por Juan, 2026-08-24).
//!
//! No es un ciclo en vivo: un ciclo en vivo con la tabla `exclusiones` vacía
//! mostraría CERO saltos (no hay veredicto que casar), es lento y no determinista
//! (WAF/rate-limit), y la rotación por frescura hace que el mismo host casi no
//! recurra. Este experimento SIEMBRA el estado y MIDE el mecanismo con números,
//! deterministamente — y demuestra empíricamente el riesgo residual (el falso
//! negativo) para que la decisión de encender el flag se tome con datos.
//!
//! Correr con:  cargo test --test enforcement_estudio -- --nocapture

use nexus::arnm::{cazar_ssrf, Memoria, Resultado, Sonda};
use nexus::db;
use nexus::exclusiones::{self, Causa};
use nexus::protection::{Guard, ProtectionConfig};
use sqlx::SqlitePool;

fn g() -> Guard {
    Guard::new(ProtectionConfig::default())
}

/// Corre una caza contra un perfil sintético y devuelve (sondas gastadas, resultado).
/// Sonda contada: cada petición es tráfico a la IP compartida en producción.
/// `enforce_ttl`: `None` apagado, `Some(secs)` enforce con ese TTL.
async fn contar(pool: &SqlitePool, perfil: Perfil, enforce_ttl: Option<i64>, host: &str) -> (u32, Resultado) {
    let n = std::cell::Cell::new(0u32);
    let sonda = SondaContada { n: &n, perfil };
    let r = cazar_ssrf(
        &sonda, 100,
        Some(Memoria { pool, host, program_name: "prog-est", enforce_ttl }),
        &mut g(), 0, &mut || 0.5,
        &nexus::arnm::objetivos_base()[..4],
    )
    .await;
    (n.get(), r)
}

/// TTL amplio para las fases donde el veredicto es fresco (no debe caducar por
/// antigüedad): 30 días en segundos.
const TTL: i64 = 30 * 86_400;

const CUERPO_AWS: &str =
    r#"{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret","x":0}"#;

/// Sonda que CUENTA cuántas peticiones reales recibe (la métrica de coste: cada
/// petición es tráfico a la IP compartida). El comportamiento se elige por perfil.
struct SondaContada<'a> {
    n: &'a std::cell::Cell<u32>,
    perfil: Perfil,
}
#[derive(Clone, Copy)]
enum Perfil {
    /// 403 a todo: arsenal se agota → Seco → MetodosAgotados.
    Muro,
    /// 403 al literal (MISMA huella que el muro), pero exfiltra con IP codificada:
    /// se volvió VULNERABLE sin cambiar su postura observable. Es el caso del
    /// riesgo residual.
    MuroPeroAhoraVulnerable,
}

impl Sonda for SondaContada<'_> {
    async fn pedir(&self, payload: &str) -> Option<(u16, String)> {
        self.n.set(self.n.get() + 1);
        let literal = payload.contains("169.254.169.254");
        let codificada = payload.contains("2852039166")
            || payload.contains("0xa9fea9fe")
            || payload.contains("0251.0376")
            || payload.contains("::ffff:");
        match self.perfil {
            Perfil::Muro => Some((403, "Forbidden host".into())),
            Perfil::MuroPeroAhoraVulnerable => {
                if !literal && codificada {
                    Some((200, CUERPO_AWS.into()))
                } else {
                    Some((403, "Forbidden host".into()))
                }
            }
        }
    }
}

#[tokio::test]
async fn estudio_enforcement_ahorro_y_riesgo_residual() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open(&dir.path().join("estudio.db"), 4).await.unwrap();

    eprintln!("\n════════ ESTUDIO: enforcement de la memoria negativa ════════\n");

    // ── FASE FRÍA (enforce=off): 10 hosts muro. Corren el arsenal ENTERO y cada
    //    uno registra MetodosAgotados. Es el estado "sin memoria negativa".
    let mut sondas_frio = 0u32;
    for i in 0..10 {
        let host = format!("muro{i}.example.com");
        let (n, r) = contar(&pool, Perfil::Muro, None, &host).await;
        sondas_frio += n;
        // Registrar como lo haría procesar_url en el brazo Seco (huella estable).
        if let Resultado::Seco { huella, .. } = &r {
            exclusiones::registrar(&pool, &host, "ssrf", Causa::MetodosAgotados, huella).await.unwrap();
        }
    }
    let excluidos: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM exclusiones WHERE causa='metodos_agotados'")
        .fetch_one(&pool).await.unwrap();
    eprintln!("FASE FRÍA  (enforce=off): 10 hosts muro");
    eprintln!("  · sondas totales gastadas : {sondas_frio}");
    eprintln!("  · veredictos registrados  : {excluidos} MetodosAgotados\n");

    // ── FASE CALIENTE (enforce=on): los MISMOS 10 hosts, misma huella. Deben
    //    SALTAR: solo el sondeo literal, no la búsqueda cara.
    let mut sondas_caliente = 0u32;
    let mut saltados = 0u32;
    for i in 0..10 {
        let host = format!("muro{i}.example.com");
        let (n, r) = contar(&pool, Perfil::Muro, Some(TTL), &host).await;
        sondas_caliente += n;
        if matches!(r, Resultado::Saltado { .. }) {
            saltados += 1;
        }
    }
    eprintln!("FASE CALIENTE (enforce=on): los mismos 10 hosts, misma huella");
    eprintln!("  · sondas totales gastadas : {sondas_caliente}");
    eprintln!("  · hosts SALTADOS          : {saltados}/10");
    let ahorro = 100.0 * (sondas_frio - sondas_caliente) as f64 / sondas_frio as f64;
    eprintln!("  · AHORRO de tráfico       : {ahorro:.0}%  ({sondas_frio} → {sondas_caliente} sondas)\n");

    // ── CONTROL 1 (caducidad): un host cuya huella CAMBIÓ (bajó el WAF). Aunque
    //    tenga veredicto, NO debe saltar — el entorno ya no es el que lo produjo.
    let host_cambiado = "abrio.example.com";
    exclusiones::registrar(&pool, host_cambiado, "ssrf", Causa::MetodosAgotados, "s=999;waf=viejo").await.unwrap();
    let (_, r) = contar(&pool, Perfil::Muro, Some(TTL), host_cambiado).await;
    let control_caducidad_ok = matches!(r, Resultado::Seco { .. });
    eprintln!("CONTROL 1 (caducidad por huella): veredicto bajo huella VIEJA distinta");
    eprintln!("  · ¿corrió la fase (NO saltó)? {control_caducidad_ok}  → la caducidad protege\n");

    // ── CONTROL 2 (RIESGO RESIDUAL, el importante): un host que se volvió
    //    VULNERABLE pero conserva la MISMA huella (403 al literal). Con enforce=on
    //    se SALTA y se PIERDE el hallazgo. Esto es lo que se está decidiendo.
    let host_fn = "muro0.example.com"; // ya tiene MetodosAgotados bajo huella muro
    let (_, r) = contar(&pool, Perfil::MuroPeroAhoraVulnerable, Some(TTL), host_fn).await;
    let se_perdio = matches!(r, Resultado::Saltado { .. });
    // Y sin enforce, el MISMO host vulnerable SÍ se caza (prueba que el hallazgo existía):
    let (_, r2) = contar(&pool, Perfil::MuroPeroAhoraVulnerable, None, host_fn).await;
    let se_caza_sin_enforce = matches!(r2, Resultado::Confirmado { .. });
    eprintln!("CONTROL 2 (RIESGO RESIDUAL — falso negativo):");
    eprintln!("  · host se volvió vulnerable, MISMA huella (403 al literal)");
    eprintln!("  · con enforce=on  → ¿se SALTÓ y se perdió?  {se_perdio}");
    eprintln!("  · con enforce=off → ¿se habría cazado?      {se_caza_sin_enforce}");
    eprintln!("  → dentro de la ventana TTL se salta; el CONTROL 3 muestra el cierre\n");

    // ── CONTROL 3 (el TTL CIERRA el riesgo residual): el mismo host, mismo
    //    veredicto y misma huella, pero ENVEJECIDO más allá del TTL. Ahora el
    //    enforcement NO salta → re-caza el arsenal → encuentra la vuln que antes
    //    perdía. Se envejece retrocediendo `registrado_en` en la BD (simula el paso
    //    del tiempo sin dormir el test).
    sqlx::query("UPDATE exclusiones SET registrado_en = datetime('now', '-10 days') WHERE host = ?1")
        .bind(host_fn).execute(&pool).await.unwrap();
    let ttl_corto = 7 * 86_400; // 7 días < 10 días de antigüedad → caduca
    let (_, r) = contar(&pool, Perfil::MuroPeroAhoraVulnerable, Some(ttl_corto), host_fn).await;
    let recuperado = matches!(r, Resultado::Confirmado { .. });
    eprintln!("CONTROL 3 (el TTL cierra el falso negativo):");
    eprintln!("  · mismo host/huella, veredicto envejecido 10 días, TTL 7 días");
    eprintln!("  · con enforce=on → ¿re-cazó y RECUPERÓ el hallazgo? {recuperado}");
    eprintln!("  → el TTL acota la ceguera a la ventana; pasada, se vuelve a probar\n");

    eprintln!("═════════════════════════════════════════════════════════════\n");

    // Aserciones: el estudio también es una prueba que discrimina (directiva 33).
    assert_eq!(saltados, 10, "con enforce y huella vigente, los 10 muros saltan");
    assert!(sondas_caliente < sondas_frio, "el enforcement AHORRA sondas");
    assert!(sondas_caliente <= 40, "un salto gasta solo el sondeo literal (<=4/host)");
    assert!(control_caducidad_ok, "huella cambiada NO salta (caducidad)");
    assert!(se_perdio, "riesgo residual DENTRO del TTL: misma huella + ahora vulnerable = saltado");
    assert!(se_caza_sin_enforce, "sin enforce el hallazgo SÍ existía (el FN es real)");
    assert!(recuperado, "el TTL caduca el veredicto viejo → re-caza y recupera el hallazgo");
}
