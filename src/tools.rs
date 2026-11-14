//! Ejecutor de herramientas externas. TODO el motor real (subfinder, httpx,
//! nuclei, y luego sqlmap/gau/katana/...) se invoca aquí como subprocess.
//! Rust nunca reimplementa el motor; lo dirige.
//!
//! Seguridad: SIEMPRE argumentos como lista (nunca `sh -c`), para que no haya
//! inyección de comandos por un dominio malicioso del scope (portado del patrón
//! de bounty/: "no shell=True").

use crate::error::{NexusError, Result};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Comprueba que un binario existe y es ejecutable (o resoluble por PATH).
pub async fn ensure_tool(path: &str) -> Result<()> {
    // Si es una ruta absoluta/relativa existente, vale.
    if tokio::fs::metadata(path).await.is_ok() {
        return Ok(());
    }
    // Si no, intentamos resolver por PATH ejecutando `--version` de forma barata.
    match Command::new(path).arg("-version").stdout(Stdio::null()).stderr(Stdio::null()).status().await {
        Ok(_) => Ok(()),
        Err(_) => Err(NexusError::ToolMissing(path.to_string())),
    }
}

/// Resultado de correr una herramienta.
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Corre `program args...` con timeout, capturando stdout/stderr. Si expira, mata
/// el proceso y marca `timed_out`. No usa shell.
///
/// **Conserva lo YA emitido si el proceso expira.** nuclei (y httpx, gau…)
/// transmiten resultados según los encuentran: se drena stdout/stderr en tareas
/// concurrentes, así que al matar el proceso por timeout se devuelve todo lo que
/// alcanzó a escribir. La versión anterior usaba `wait_with_output()`, cuyo
/// futuro se cancelaba al expirar y descartaba TODA la salida — y como el
/// acotado por presupuesto hace que la fase expire en el caso NORMAL (el propio
/// diseño dice «nuclei sale con lo que haya reunido»), eso tiraba a la basura
/// los hallazgos de cada ciclo (0 hallazgos en 73 ciclos, medido en el VPS).
pub async fn run(program: &str, args: &[String], timeout: Duration) -> Result<Output> {
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Err(NexusError::ToolMissing(program.to_string())),
    };

    // Drenar ambas tuberías en paralelo con la espera evita dos cosas: (1) el
    // interbloqueo clásico si el proceso llena el buffer de la tubería (64 KB) y
    // se bloquea al escribir mientras nosotros esperamos; (2) perder la salida
    // al matarlo. Los lectores terminan solos al cerrarse la tubería (EOF), sea
    // por salida limpia o por muerte del proceso.
    // Los drenajes escriben en un BUFFER COMPARTIDO (no devuelven al final): así,
    // aunque la tarea se abandone por el tope de abajo, lo YA drenado se conserva
    // (directiva 28: el hallazgo emitido antes del timeout NO se pierde).
    let out_buf = Arc::new(Mutex::new(String::new()));
    let err_buf = Arc::new(Mutex::new(String::new()));
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let out_task = tokio::spawn(drain(BufReader::new(stdout).lines(), out_buf.clone()));
    let err_task = tokio::spawn(drain(BufReader::new(stderr).lines(), err_buf.clone()));

    let (code, timed_out) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => (status.code(), false),
        Ok(Err(e)) => return Err(NexusError::Io(e)),
        Err(_) => {
            let _ = child.start_kill(); // SIGKILL; cierra las tuberías → los lectores drenan y acaban
            (None, true)
        }
    };

    // Espera acotada a que los drenajes cierren por EOF. Normalmente llega en
    // microsegundos (salida limpia o SIGKILL cierra la tubería). PERO un NIETO que
    // heredó la tubería stdout la mantiene abierta pese a matar al hijo → el drenaje
    // colgaría PARA SIEMPRE (la raíz del hang de recon medido en eurid/sidefx:
    // curl-impersonate via este runner). El tope de 5s convierte el cuelgue en
    // "abandona y sigue"; y como el buffer es COMPARTIDO, lo drenado hasta ese
    // instante ya está a salvo (fix 2026-08-26).
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = out_task.await;
        let _ = err_task.await;
    })
    .await;

    let stdout = std::mem::take(&mut *out_buf.lock().unwrap());
    let stderr = std::mem::take(&mut *err_buf.lock().unwrap());
    Ok(Output { code, stdout, stderr, timed_out })
}

/// Acumula todas las líneas de un lector en una cadena (con `\n` final por línea).
/// Termina al EOF de la tubería. Errores de lectura se tratan como fin.
async fn drain<R>(mut lines: tokio::io::Lines<R>, buf: Arc<Mutex<String>>)
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    // El lock se toma SOLO para el push (sin `.await` dentro): nunca se retiene un
    // Mutex de std a través de un await. Lo emitido se acumula en el buffer
    // compartido, así el llamante lo lee aunque esta tarea se abandone por timeout.
    while let Ok(Some(line)) = lines.next_line().await {
        let mut b = buf.lock().unwrap();
        b.push_str(&line);
        b.push('\n');
    }
}

/// Corre una herramienta y llama a `on_line` por cada línea de stdout, en
/// streaming, sin cargar toda la salida en memoria. Clave en el VPS sin swap:
/// nuclei/httpx sobre miles de hosts producen mucha salida — se procesa al vuelo.
/// Devuelve el código de salida.
pub async fn run_streaming<F>(
    program: &str,
    args: &[String],
    timeout: Duration,
    mut on_line: F,
) -> Result<Option<i32>>
where
    F: FnMut(&str),
{
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| NexusError::ToolMissing(program.to_string()))?;

    let stdout = child.stdout.take().expect("stdout piped");
    let mut lines = BufReader::new(stdout).lines();
    // TIMEOUT DURO (fix del hang de recon, 2026-08-26): sin él, una herramienta
    // que cuelga —no emite otra línea ni sale, o deja un NIETO con la tubería
    // stdout abierta— bloquea `next_line().await`/`child.wait().await` PARA
    // SIEMPRE (0% CPU, futex_wait; medido en eurid y sidefx, el recon nunca
    // llegaba a la fase SSRF). Al vencer, se dropea el futuro → `child` se dropea
    // → `kill_on_drop` lo mata → se devuelve `None` (colgó, no un código de salida).
    let leer = async {
        while let Some(line) = lines.next_line().await? {
            on_line(&line);
        }
        let status = child.wait().await?;
        Ok::<Option<i32>, NexusError>(status.code())
    };
    match tokio::time::timeout(timeout, leer).await {
        Ok(r) => r,
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El timeout de `run_streaming` CORTA un cuelgue (fix del hang de recon,
    /// 2026-08-26). Pareja discriminante: `sleep` no emite línea ni sale, así que
    /// SIN el timeout `next_line().await`/`wait().await` bloquearían el tiempo del
    /// sleep entero; CON él, se corta y devuelve `None`. Mata al mutante que
    /// ignora el timeout (bloquearía 30s y el test excedería su propio límite).
    #[tokio::test]
    async fn run_streaming_corta_el_cuelgue_con_timeout() {
        let inicio = std::time::Instant::now();
        let r = run_streaming("sleep", &["30".into()], Duration::from_millis(300), |_| {}).await;
        assert!(
            inicio.elapsed() < Duration::from_secs(5),
            "el timeout debe cortar el cuelgue, no esperar los 30s"
        );
        assert!(matches!(r, Ok(None)), "un cuelgue vencido devuelve None, no un código de salida");
    }

    /// Y el camino feliz sigue: un comando que emite líneas y termina rápido
    /// devuelve su código y todas las líneas (el timeout no lo estrangula).
    #[tokio::test]
    async fn run_streaming_camino_feliz_emite_lineas_y_termina() {
        let mut vistas = Vec::new();
        let r = run_streaming("printf", &["a\\nb\\nc\\n".into()], Duration::from_secs(10), |l| {
            vistas.push(l.to_string());
        })
        .await;
        assert_eq!(vistas, vec!["a", "b", "c"]);
        assert!(matches!(r, Ok(Some(0))), "salida limpia devuelve su código 0");
    }
}
