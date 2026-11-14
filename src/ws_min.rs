//! Cliente WebSocket MÍNIMO (RFC 6455, `ws://`), hecho a mano.
//!
//! nexus compila solo desde `vendor/` (protocolo solo-local) y no hay un crate WS
//! vendorizado; pero `base64` y `sha1` sí lo están, que es todo lo que el handshake
//! necesita. Esto da al `oraculo_realtime` su transporte sin dependencia nueva. Solo lo que
//! el oráculo usa: conectar, enviar texto (frames enmascarados del cliente), y leer frames
//! de texto (respondiendo `ping`). `wss://` (TLS) queda pendiente —el lab es `ws://`—.

use base64::Engine;
use sha1::{Digest, Sha1};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub struct Ws {
    stream: TcpStream,
    buf: Vec<u8>,
    mask_ctr: u32,
}

fn parse_ws_url(url: &str) -> Result<(String, u16, String), String> {
    let resto = url.strip_prefix("ws://").ok_or_else(|| format!("solo ws:// (no {url})"))?;
    let (hostport, path) = match resto.find('/') {
        Some(i) => (&resto[..i], &resto[i..]),
        None => (resto, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "puerto inválido".to_string())?),
        None => (hostport.to_string(), 80u16),
    };
    Ok((host, port, path.to_string()))
}

impl Ws {
    /// Conecta y hace el handshake HTTP/Upgrade. Devuelve error si no hay 101.
    pub async fn conectar(url: &str) -> Result<Ws, String> {
        let (host, port, path) = parse_ws_url(url)?;
        let mut stream = TcpStream::connect((host.as_str(), port)).await.map_err(|e| e.to_string())?;

        // Sec-WebSocket-Key: 16 bytes en base64 (no necesita ser cripto-aleatorio en cliente).
        let semilla = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let key_bytes = semilla.to_le_bytes(); // 16 bytes
        let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;

        // Leer hasta el fin de cabeceras (\r\n\r\n).
        let mut resp = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = stream.read(&mut b).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("el server cerró durante el handshake".into());
            }
            resp.push(b[0]);
            if resp.ends_with(b"\r\n\r\n") {
                break;
            }
            if resp.len() > 8192 {
                return Err("respuesta de handshake demasiado larga".into());
            }
        }
        let texto = String::from_utf8_lossy(&resp);
        if !texto.starts_with("HTTP/1.1 101") {
            return Err(format!("handshake sin 101: {}", texto.lines().next().unwrap_or("")));
        }
        // Verificar Sec-WebSocket-Accept (sanidad; no seguridad).
        let esperado = {
            let mut h = Sha1::new();
            h.update(key.as_bytes());
            h.update(GUID.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(h.finalize())
        };
        if !texto.to_ascii_lowercase().contains(&esperado.to_ascii_lowercase()) {
            return Err("Sec-WebSocket-Accept no coincide".into());
        }
        Ok(Ws { stream, buf: Vec::new(), mask_ctr: 0 })
    }

    /// Envía un frame de texto (FIN=1, opcode=0x1), enmascarado como exige el cliente.
    pub async fn enviar_texto(&mut self, s: &str) -> Result<(), String> {
        self.enviar_frame(0x1, s.as_bytes()).await
    }

    async fn enviar_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut frame = vec![0x80 | opcode]; // FIN + opcode
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8); // MASK + len
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        self.mask_ctr = self.mask_ctr.wrapping_add(0x9E3779B1);
        let mask = self.mask_ctr.to_le_bytes();
        frame.extend_from_slice(&mask);
        for (i, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }
        self.stream.write_all(&frame).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Lee el siguiente frame de texto del server (los frames del server NO van
    /// enmascarados). Responde `pong` a un `ping` y sigue. Devuelve `Ok(None)` al cerrarse.
    /// `timeout` acota la espera (directiva 39).
    pub async fn leer_texto(&mut self, timeout: Duration) -> Result<Option<String>, String> {
        loop {
            let frame = match tokio::time::timeout(timeout, self.leer_frame()).await {
                Err(_) => return Ok(None), // se acabó el tiempo
                Ok(r) => r?,
            };
            let Some((opcode, payload)) = frame else { return Ok(None) };
            match opcode {
                0x1 => return Ok(Some(String::from_utf8_lossy(&payload).into_owned())),
                0x9 => { self.enviar_frame(0xA, &payload).await?; } // ping → pong, seguir
                0x8 => return Ok(None),                             // close
                _ => {} // otros (binario/pong/continuación): ignorar y seguir
            }
        }
    }

    async fn leer_n(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.buf.len() < n {
            let mut tmp = [0u8; 4096];
            let leidos = self.stream.read(&mut tmp).await.map_err(|e| e.to_string())?;
            if leidos == 0 {
                return Err("cerrado".into());
            }
            self.buf.extend_from_slice(&tmp[..leidos]);
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// Lee UN frame → (opcode, payload). None si se cierra limpio.
    async fn leer_frame(&mut self) -> Result<Option<(u8, Vec<u8>)>, String> {
        let cab = match self.leer_n(2).await {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        let opcode = cab[0] & 0x0F;
        let masked = cab[1] & 0x80 != 0;
        let mut len = (cab[1] & 0x7F) as usize;
        if len == 126 {
            let ext = self.leer_n(2).await?;
            len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        } else if len == 127 {
            let ext = self.leer_n(8).await?;
            len = u64::from_be_bytes(ext.try_into().unwrap()) as usize;
        }
        let mask = if masked { self.leer_n(4).await? } else { vec![] };
        let mut payload = self.leer_n(len).await?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Ok(Some((opcode, payload)))
    }
}

#[cfg(test)]
mod pruebas {
    #[test]
    fn parsea_ws_url() {
        assert_eq!(super::parse_ws_url("ws://host:3000/websocket").unwrap(), ("host".into(), 3000, "/websocket".into()));
        assert_eq!(super::parse_ws_url("ws://127.0.0.1/x").unwrap(), ("127.0.0.1".into(), 80, "/x".into()));
        assert!(super::parse_ws_url("wss://host/x").is_err(), "wss:// no soportado aún");
    }
}
