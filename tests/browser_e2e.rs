//! E2E del gate de ejecución de XSS con Chromium REAL (directiva 28: cruza la
//! frontera —arranca el navegador de verdad— en vez de ir de estructura a
//! estructura). Y su pareja (directiva 33): una página que EJECUTA el script pone
//! el marcador computado; una que solo REFLEJA el texto del payload, no. El caso
//! rojo falla por la vía real: el navegador no ejecuta, luego el marcador no está.
//!
//! Si no hay Chromium en el sistema, el test lo DICE y no falla en falso (directiva
//! 30: un negativo silencioso es indistinguible de un negativo real).

use nexus::browser;
use nexus::config::Config;

fn find_chromium() -> Option<String> {
    for p in [
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

fn cfg_chromium(path: &str) -> Config {
    use clap::Parser;
    Config::parse_from(["nexus", "--chromium-path", path, "scan"])
}

#[tokio::test]
async fn gate_de_ejecucion_discrimina_con_chromium_real() {
    let Some(chromium) = find_chromium() else {
        eprintln!("SKIP gate_de_ejecucion_discrimina_con_chromium_real: no hay chromium en el sistema");
        return;
    };
    let cfg = cfg_chromium(&chromium);
    let dir = tempfile::tempdir().unwrap();
    let (_payload, marker) = browser::build_canary(124);
    assert_eq!(marker, "data-nxproof=\"248\"");

    // VERDE: la página EJECUTA el script que pone el marcador COMPUTADO (124*2=248).
    let green = dir.path().join("green.html");
    std::fs::write(
        &green,
        "<!doctype html><html><head><meta charset=utf-8></head><body>\
         <script>document.documentElement.setAttribute('data-nxproof', String(124*2));</script>\
         </body></html>",
    )
    .unwrap();
    let dom_green = browser::dump_dom(&cfg, &format!("file://{}", green.display())).await.unwrap();
    assert!(
        browser::executed(&dom_green, &marker),
        "chromium real debe EJECUTAR el script y poner data-nxproof=\"248\". DOM: {dom_green}"
    );

    // ROJO: la página REFLEJA el texto del payload (con '124*2' y 'data-nxproof'
    // como TEXTO), pero no ejecuta. El marcador serializado no debe aparecer.
    let red = dir.path().join("red.html");
    std::fs::write(
        &red,
        "<!doctype html><html><head><meta charset=utf-8></head><body>\
         <pre>reflejo inerte: &lt;script&gt;document.documentElement.setAttribute('data-nxproof',String(124*2))&lt;/script&gt; resultado 248</pre>\
         </body></html>",
    )
    .unwrap();
    let dom_red = browser::dump_dom(&cfg, &format!("file://{}", red.display())).await.unwrap();
    assert!(
        !browser::executed(&dom_red, &marker),
        "una reflexión inerte NO debe traer el atributo serializado data-nxproof=\"248\". DOM: {dom_red}"
    );
}

// --- Lazo completo: inject_canary → servidor que REFLEJA → Chromium ejecuta ---
//
// El test de arriba cruza la frontera (Chromium real) pero SIRVE a mano la página
// que ejecuta. No prueba el lazo que corre en producción: `confirm_xss(url)` toma
// una URL objetivo, le INYECTA el canary con `inject_canary`, y depende de que un
// endpoint vulnerable REFLEJE ese canary inyectado como HTML ejecutable. Esa
// composición —inyección + reflejo del servidor + ejecución— es la que nunca se
// había probado, y es justo donde podría fallar en silencio (un breakout que no
// rompe el contexto real, o el parámetro equivocado). Aquí se levanta un servidor
// que refleja de verdad y se apunta `confirm_xss` a él.

/// Percent-decodifica un valor de query (inverso de `browser::percent_encode_all`,
/// que codifica todo lo no-unreserved como %XX). `+`→espacio por si acaso.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16);
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                }
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Escapa el reflejo para el endpoint SEGURO: lo que hace un servidor bien
/// escrito, y lo que vuelve inerte al canary.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Levanta un servidor HTTP mínimo con dos rutas que reflejan el parámetro `q`:
///
/// - `/reflejo` lo refleja SIN escapar (vulnerable: el canary ejecuta)
/// - cualquier otra (`/seguro`) lo refleja ESCAPADO (inerte)
///
/// Devuelve la dirección; la tarea vive hasta que termina el test.
async fn spawn_reflectors() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let n = match sock.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                // Primera línea: "GET /ruta?query HTTP/1.1".
                let path_q = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (path, query) = path_q.split_once('?').unwrap_or((path_q, ""));
                let qval = query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("q="))
                    .unwrap_or("");
                let decoded = percent_decode(qval);
                let reflejo = if path.starts_with("/reflejo") {
                    decoded // vulnerable: sin escapar
                } else {
                    html_escape(&decoded) // seguro: escapado
                };
                let body = format!(
                    "<!doctype html><html><head><meta charset=utf-8></head>\
                     <body>busqueda: {reflejo}</body></html>"
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn confirm_xss_lazo_completo_contra_servidor_que_refleja() {
    let Some(chromium) = find_chromium() else {
        eprintln!(
            "SKIP confirm_xss_lazo_completo_contra_servidor_que_refleja: no hay chromium en el sistema"
        );
        return;
    };
    let cfg = cfg_chromium(&chromium);
    let addr = spawn_reflectors().await;

    // VERDE: el endpoint refleja el canary SIN escapar → ejecuta. Se exige 2 de 2
    // (reproducible), que es lo que `confirm_xss` pide para lo auto-enviable.
    let vuln = format!("http://{addr}/reflejo?q=inicial");
    let green = browser::confirm_xss(&cfg, &vuln, 2, 2, 1000).await;
    assert!(
        green.confirmed,
        "un endpoint que refleja sin escapar DEBE confirmar por ejecución (lazo completo); ratio {}",
        green.ratio
    );

    // ROJO, por la vía real: el MISMO canary, el MISMO lazo, pero el servidor
    // ESCAPA el reflejo → inerte → no ejecuta → no confirma. Falla por donde
    // fallaría de verdad (reflexión escapada), no por un mock. Un `executed()` o
    // un `inject_canary` rotos que confirmaran siempre pondrían esto en verde y
    // el test en rojo.
    let safe = format!("http://{addr}/seguro?q=inicial");
    let red = browser::confirm_xss(&cfg, &safe, 2, 2, 1000).await;
    assert!(
        !red.confirmed,
        "un endpoint que escapa el reflejo NO debe confirmar (inerte); ratio {}",
        red.ratio
    );
}
