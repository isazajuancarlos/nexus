//! Constructor de lab genérico para el modo WHITEBOX.
//!
//! Generaliza lo que se hizo ad-hoc para los labs de Rocket.Chat/Zabbix: levantar un
//! `docker compose` en un directorio, esperar a que el servicio responda, y bajarlo al
//! terminar (norma permanente de Juan: [[bajar-el-lab-al-terminar]]). La siembra de
//! identidades es específica de cada objetivo (se hace por REST/DDP tras `levantar`); esto
//! cubre la orquestación común.
//!
//! Requiere que el usuario esté en el grupo `docker`. No unit-testeado el `docker compose`
//! (necesita Docker), sí la espera HTTP (contra un servidor en proceso).

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Espera hasta `timeout_secs` a que `url` responda (cualquier respuesta HTTP cuenta como
/// "arriba"; un 000/conexión rechazada, no). Devuelve true si respondió a tiempo. Tope de
/// tiempo real (directiva 39): quien la hace verdadera es el servicio arrancando.
pub async fn esperar_http(url: &str, timeout_secs: u64) -> bool {
    let cli = match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let fin = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if cli.get(url).send().await.is_ok() {
            return true;
        }
        if Instant::now() >= fin {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Levanta el `docker compose` del directorio dado (`up -d --wait`). Devuelve error con la
/// salida si falla. NO siembra identidades — eso es específico del objetivo.
pub fn levantar(dir: &Path) -> Result<(), String> {
    correr(dir, &["compose", "up", "-d", "--wait"])
}

/// Baja el lab y borra volúmenes (`down -v`). Best-effort: se llama SIEMPRE al terminar.
pub fn bajar(dir: &Path) {
    let _ = correr(dir, &["compose", "down", "-v"]);
}

fn correr(dir: &Path, args: &[&str]) -> Result<(), String> {
    let salida = Command::new("docker")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("no pude ejecutar docker (¿instalado? ¿grupo docker?): {e}"))?;
    if salida.status.success() {
        Ok(())
    } else {
        Err(format!(
            "docker {} falló: {}",
            args.join(" "),
            String::from_utf8_lossy(&salida.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn esperar_http_ve_un_servicio_vivo() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(l, Router::new().route("/", get(|| async { "ok" }))).await.unwrap();
        });
        assert!(esperar_http(&base, 10).await, "un servicio vivo debe verse");
    }

    #[tokio::test]
    async fn esperar_http_se_rinde_con_tope() {
        // Puerto muerto: debe rendirse por el tope, no colgarse (directiva 39).
        let t0 = Instant::now();
        assert!(!esperar_http("http://127.0.0.1:1", 1).await, "puerto muerto → false");
        assert!(t0.elapsed() < Duration::from_secs(20), "respetó el tope");
    }
}
