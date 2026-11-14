//! Oráculo diferencial de TIEMPO REAL (websocket/DDP) — el transporte que le faltaba.
//!
//! Contexto (2026-09-05): el hallazgo de Rocket.Chat era por el stream DDP (websocket): el
//! gate HTTP cierra, pero el broadcast en vivo filtra a un no-miembro. El oráculo HTTP
//! (`oraculo_diferencial`) correctamente decía SÓLIDO en REST — la fuga estaba en el tiempo
//! real, fuera de su transporte. Esta pieza cubre ese transporte con la MISMA lógica: un
//! sujeto AUTORIZADO recibe `marca` por su suscripción (control positivo), un NO-autorizado
//! no debe recibirla; si la recibe → hallazgo. Devuelve el mismo [`Veredicto`]/[`Certificado`]
//! que el oráculo HTTP. Usa el cliente WS propio [`crate::ws_min`] (sin dependencia nueva).

use crate::certificado::Certificado;
use crate::oraculo_diferencial::{Modo, Veredicto};
use crate::ws_min::Ws;
use std::time::{Duration, Instant};

/// Una identidad para el stream: sus frames de apertura (connect/login/subscribe), ya con el
/// token puesto.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentidadWs {
    pub etiqueta: String,
    pub aperturas: Vec<String>,
}

/// El disparo que produce el evento (opcional): una petición HTTP (postear un mensaje).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Disparo {
    pub metodo: String,
    pub url: String,
    #[serde(default)]
    pub cabeceras: Vec<(String, String)>,
    #[serde(default)]
    pub cuerpo: Option<String>,
}

/// El caso de tiempo real: "solo el autorizado recibe `marca` por el stream".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CasoRealtime {
    pub descripcion: String,
    pub clase: String,
    pub ws_url: String,
    pub autorizado: IdentidadWs,
    pub no_autorizado: IdentidadWs,
    #[serde(default)]
    pub disparo: Option<Disparo>,
    pub marca: String,
    /// Segundos a escuchar tras el disparo.
    pub ventana_secs: u64,
}

/// Conecta un websocket, envía las aperturas, y escucha `duracion`: devuelve si algún frame
/// contuvo `marca`. `ws_min` ya responde `ping` con `pong`. Tope de tiempo (directiva 39).
async fn escuchar(ws_url: &str, aperturas: &[String], marca: &str, duracion: Duration) -> Result<bool, String> {
    let mut ws = Ws::conectar(ws_url).await?;
    for a in aperturas {
        ws.enviar_texto(a).await?;
    }
    let fin = Instant::now() + duracion;
    let mut visto = false;
    loop {
        let restante = fin.saturating_duration_since(Instant::now());
        if restante.is_zero() {
            break;
        }
        // ventana de lectura acotada al tiempo restante
        match ws.leer_texto(restante.min(Duration::from_secs(2))).await? {
            Some(t) => {
                if t.contains(marca) {
                    visto = true; // seguimos hasta el tope, no cortamos
                }
            }
            None => {
                // timeout de esta lectura o cierre: si aún queda ventana, reintenta; si el
                // socket cerró, el próximo leer_texto devolverá None de inmediato y saldremos.
                if Instant::now() >= fin {
                    break;
                }
            }
        }
    }
    Ok(visto)
}

/// Dispara la petición HTTP que produce el evento (si la hay).
async fn disparar(cli: &reqwest::Client, d: &Disparo) -> Result<(), String> {
    let m = reqwest::Method::from_bytes(d.metodo.to_uppercase().as_bytes()).map_err(|e| e.to_string())?;
    let mut req = cli.request(m, &d.url);
    for (k, v) in &d.cabeceras {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(b) = &d.cuerpo {
        req = req.header("Content-Type", "application/json").body(b.clone());
    }
    req.send().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// EL RUNNER de tiempo real. Suscribe al autorizado y al no-autorizado, dispara el evento y
/// observa quién recibe `marca`. Mismo veredicto/certificado que el oráculo HTTP; el control
/// es el DIFERENCIAL de identidad sobre el stream (no la repetición).
pub async fn sonda_realtime(cli: &reqwest::Client, objetivo_modo: Modo, caso: &CasoRealtime) -> Veredicto {
    let establecer = Duration::from_secs(2);
    let duracion = establecer + Duration::from_secs(caso.ventana_secs.max(1));

    let (u1, ap1, m1) = (caso.ws_url.clone(), caso.autorizado.aperturas.clone(), caso.marca.clone());
    let t_aut = tokio::spawn(async move { escuchar(&u1, &ap1, &m1, duracion).await });
    let (u2, ap2, m2) = (caso.ws_url.clone(), caso.no_autorizado.aperturas.clone(), caso.marca.clone());
    let t_noaut = tokio::spawn(async move { escuchar(&u2, &ap2, &m2, duracion).await });

    // Establecer suscripciones antes del disparo.
    tokio::time::sleep(establecer).await;
    if let Some(d) = &caso.disparo {
        if let Err(e) = disparar(cli, d).await {
            return Veredicto::NoConcluyente(format!("el disparo falló: {e}"));
        }
    }

    let aut = match t_aut.await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Veredicto::NoConcluyente(format!("suscripción del autorizado falló: {e}")),
        Err(e) => return Veredicto::NoConcluyente(format!("tarea del autorizado: {e}")),
    };
    let noaut = match t_noaut.await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Veredicto::NoConcluyente(format!("suscripción del no-autorizado falló: {e}")),
        Err(e) => return Veredicto::NoConcluyente(format!("tarea del no-autorizado: {e}")),
    };

    if !aut {
        return Veredicto::NoConcluyente(
            "el AUTORIZADO no recibió la marca por el stream: el arnés/disparo no discrimina \
             (control positivo falló)".into(),
        );
    }
    if !noaut {
        return Veredicto::Solido;
    }

    let cert = Certificado {
        execution_confirmed: true,
        repro_ratio: None, // el control es el diferencial de identidad, no la repetición…
        diferencial: true, // …y `control_valido` lo acepta por esa vía
        evidencia_presente: true,
        herramienta: Some(format!("oraculo-realtime:{}", objetivo_modo.nombre())),
        confianza: Some("high".into()),
        clase: caso.clase.clone(),
        ancla: format!("nexus v{} · realtime · {}", env!("CARGO_PKG_VERSION"), objetivo_modo.nombre()),
    };
    Veredicto::Fuga(cert)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use base64::Engine;
    use sha1::{Digest, Sha1};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // Server WS mínimo (accept side) hecho a mano para el test: handshake, lee la apertura
    // (frame enmascarado del cliente), y difunde `marca` según `fuga`/owner.
    async fn atender(mut s: TcpStream, fuga: bool) {
        // 1) leer request hasta \r\n\r\n, extraer Sec-WebSocket-Key
        let mut req = Vec::new();
        let mut b = [0u8; 1];
        while !req.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).await.unwrap_or(0) == 0 { return; }
            req.push(b[0]);
        }
        let txt = String::from_utf8_lossy(&req);
        let key = txt.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap_or("").trim();
        let mut h = Sha1::new();
        h.update(key.as_bytes());
        h.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11".as_bytes());
        let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
        let resp = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n");
        s.write_all(resp.as_bytes()).await.unwrap();

        // 2) leer UN frame del cliente (enmascarado) = la apertura
        let apertura = leer_frame_cliente(&mut s).await;
        let es_owner = apertura.contains("owner");

        // 3) difundir marca (frame de texto del server, SIN máscara) según la regla
        tokio::time::sleep(Duration::from_millis(400)).await;
        if fuga || es_owner {
            let payload = b"{\"msg\":\"changed\",\"args\":[\"SECRETO-rt\"]}";
            let mut frame = vec![0x81u8, payload.len() as u8]; // FIN+texto, sin máscara
            frame.extend_from_slice(payload);
            let _ = s.write_all(&frame).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    async fn leer_frame_cliente(s: &mut TcpStream) -> String {
        let mut cab = [0u8; 2];
        if s.read_exact(&mut cab).await.is_err() { return String::new(); }
        let mut len = (cab[1] & 0x7F) as usize;
        if len == 126 {
            let mut e = [0u8; 2]; let _ = s.read_exact(&mut e).await; len = u16::from_be_bytes(e) as usize;
        }
        let mut mask = [0u8; 4];
        if cab[1] & 0x80 != 0 { let _ = s.read_exact(&mut mask).await; }
        let mut payload = vec![0u8; len];
        if s.read_exact(&mut payload).await.is_err() { return String::new(); }
        if cab[1] & 0x80 != 0 {
            for (i, x) in payload.iter_mut().enumerate() { *x ^= mask[i % 4]; }
        }
        String::from_utf8_lossy(&payload).into_owned()
    }

    async fn servidor(fuga: bool) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("ws://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { break };
                tokio::spawn(atender(s, fuga));
            }
        });
        base
    }

    fn caso(ws_url: &str) -> CasoRealtime {
        CasoRealtime {
            descripcion: "no-miembro recibe mensajes de sala privada por el stream".into(),
            clase: "bac".into(),
            ws_url: ws_url.into(),
            autorizado: IdentidadWs { etiqueta: "owner".into(), aperturas: vec!["{\"sub\":\"room1\",\"user\":\"owner\"}".into()] },
            no_autorizado: IdentidadWs { etiqueta: "eve".into(), aperturas: vec!["{\"sub\":\"room1\",\"user\":\"eve\"}".into()] },
            disparo: None,
            marca: "SECRETO-rt".into(),
            ventana_secs: 2,
        }
    }

    #[tokio::test]
    async fn stream_que_filtra_a_todos_da_hallazgo() {
        let base = servidor(true).await;
        let cli = reqwest::Client::new();
        let v = sonda_realtime(&cli, Modo::Whitebox, &caso(&base)).await;
        match v {
            Veredicto::Fuga(c) => { assert!(c.es_valido()); assert!(c.diferencial); }
            otro => panic!("esperaba Fuga, fue {otro:?}"),
        }
    }

    #[tokio::test]
    async fn stream_que_respeta_al_dueno_da_solido() {
        // Pareja (directiva 33): server que solo emite al owner → el no-autorizado no recibe.
        let base = servidor(false).await;
        let cli = reqwest::Client::new();
        let v = sonda_realtime(&cli, Modo::Whitebox, &caso(&base)).await;
        assert!(matches!(v, Veredicto::Solido), "stream que respeta al dueño = sólido, fue {v:?}");
    }
}
