// SPDX-License-Identifier: LicenseRef-Propietario
//! Exposición de datos en almacenamiento en la nube por ACCESO ANÓNIMO (S3, GCS).
//!
//! Distinto del `takeover` de un bucket huérfano (reclamar un `NoSuchBucket` al que
//! apunta un CNAME): aquí se busca un bucket que EXISTE y es **públicamente legible o
//! listable** sin credenciales — la fuga de datos clásica de S3/GCS mal configurado
//! (CWE-200). Es la única veta *pagable* que el `storage_explorer` de Raccoon tocaba y
//! nexus no tenía; se reimplementa en Rust, **keyless y soberano** (REST anónimo, sin
//! SDK ni llave), y con mejor descubrimiento (permutaciones del nombre del objetivo, no
//! solo `<img src>`).
//!
//! **Read-only y dentro del estatuto** (`[[nexus-detector-ataca-para-encontrar]]`): solo
//! `GET` anónimo, nunca escribe, lista ni descarga en masa. El espacio de nombres de S3
//! es GLOBAL, así que un candidato derivado del objetivo **puede no pertenecerle**: por
//! eso todo hallazgo sale marcado `TITULARIDAD SIN CONFIRMAR` y NO se auto-envía —un
//! humano confirma que el bucket es del programa y está en alcance antes de reportar,
//! igual que el `takeover` exige confirmar la reclamabilidad.

use sqlx::SqlitePool;

/// Proveedor de almacenamiento con REST anónimo y respuesta `ListBucketResult` (XML).
/// Azure Blob queda fuera a propósito: su modelo es cuenta + contenedor (dos incógnitas)
/// y no responde con `ListBucketResult`; entra cuando haya un descubrimiento de cuentas
/// que lo alimente, no como stub (Raccoon lo dejó vacío).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proveedor {
    S3,
    Gcs,
}

impl Proveedor {
    fn etiqueta(self) -> &'static str {
        match self {
            Proveedor::S3 => "AWS S3",
            Proveedor::Gcs => "Google Cloud Storage",
        }
    }
}

/// Qué dice el proveedor sobre un nombre de bucket. El orden de gravedad es
/// `Publico` (fuga) > `ExistePrivado` (existe, no lista) > `OtraRegion` (existe en otra
/// región, hay que re-probar) > `NoExiste`/`Desconocido`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// 200 + `ListBucketResult`: el bucket LISTA su contenido sin credenciales.
    Publico,
    /// 403 `AccessDenied`: el bucket EXISTE pero no lista (puede tener objetos públicos
    /// sueltos; se reporta como informativo, no como fuga).
    ExistePrivado,
    /// 301 `PermanentRedirect`: existe en otra región; el `<Endpoint>` dice dónde.
    OtraRegion(String),
    /// 404 `NoSuchBucket` (o `NoSuchKey`): no existe.
    NoExiste,
    /// Nada reconocible (un 200 que NO es un `ListBucketResult` —p. ej. un sitio web
    /// estático servido desde el bucket— NO es «listable»: es el control anti-falso
    /// positivo, D23).
    Desconocido,
}

/// Clasifica la respuesta (código + cuerpo) SIN tocar la red: es la aguja que se valida
/// contra artefactos reales en las pruebas (D33). No se fía del código a secas —un 403
/// puede ser de un WAF— ni del cuerpo a secas: exige la señal INEQUÍVOCA del proveedor.
#[must_use]
pub fn clasificar(status: u16, cuerpo: &str) -> Estado {
    let tiene = |s: &str| cuerpo.contains(s);
    match status {
        200 if tiene("<ListBucketResult") => Estado::Publico,
        403 if tiene("<Code>AccessDenied</Code>") || tiene("AccessDenied") => Estado::ExistePrivado,
        301 | 302 if tiene("PermanentRedirect") => match endpoint_de(cuerpo) {
            Some(e) => Estado::OtraRegion(e),
            None => Estado::Desconocido,
        },
        404 if tiene("NoSuchBucket") || tiene("NoSuchKey") => Estado::NoExiste,
        // GCS devuelve 404 con `<Code>NoSuchBucket</Code>` o un cuerpo JSON/HTML;
        // 400 `InvalidBucketName` es «no existe con ese nombre».
        400 if tiene("InvalidBucketName") => Estado::NoExiste,
        _ => Estado::Desconocido,
    }
}

/// Extrae el host de `<Endpoint>…</Endpoint>` de un `PermanentRedirect` de S3.
fn endpoint_de(cuerpo: &str) -> Option<String> {
    let ini = cuerpo.find("<Endpoint>")? + "<Endpoint>".len();
    let fin = cuerpo[ini..].find("</Endpoint>")? + ini;
    let host = cuerpo[ini..fin].trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Sufijos/prefijos que la industria usa para nombrar buckets. Curado y BREVE: cada uno
/// multiplica las peticiones, así que solo los que de verdad aparecen (backups, assets,
/// entornos, volcados). No es el diccionario entero de Raccoon.
const AFIJOS: &[&str] = &[
    "backup", "backups", "bak", "assets", "static", "media", "img", "images", "uploads",
    "files", "data", "public", "private", "dev", "test", "staging", "stage", "prod",
    "production", "logs", "db", "dump", "dumps", "archive", "cdn", "www", "web", "app",
    "config", "secret", "secrets", "internal",
];

/// A partir de un token base (el nombre del objetivo/empresa), genera candidatos de
/// bucket: el base solo, y `base-afijo` / `afijo-base` / `base.afijo` / `baseafijo`.
/// Saneado a un nombre de bucket VÁLIDO (minúsculas, `[a-z0-9.-]`, 3–63) y deduplicado;
/// un candidato inválido no se emite (no se prueba basura).
#[must_use]
pub fn permutaciones(base: &str) -> Vec<String> {
    let base = sanear(base);
    if base.is_empty() {
        return Vec::new();
    }
    let mut v = Vec::new();
    let mut empujar = |n: String| {
        if es_nombre_valido(&n) && !v.contains(&n) {
            v.push(n);
        }
    };
    empujar(base.clone());
    for a in AFIJOS {
        empujar(format!("{base}-{a}"));
        empujar(format!("{a}-{base}"));
        empujar(format!("{base}.{a}"));
        empujar(format!("{base}{a}"));
    }
    v
}

/// Deja solo `[a-z0-9.-]` (minúsculas), como exige el espacio de nombres de S3/GCS.
fn sanear(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '.')
        .collect()
}

/// Reglas mínimas de un nombre de bucket (comunes a S3 y GCS): 3–63 chars, empieza y
/// acaba en alfanumérico, sin `..`.
#[must_use]
pub fn es_nombre_valido(n: &str) -> bool {
    let len = n.len();
    (3..=63).contains(&len)
        && n.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && n.bytes().last().is_some_and(|b| b.is_ascii_alphanumeric())
        && !n.contains("..")
}

/// URL de listado anónimo (virtual-host para S3, path para GCS).
#[must_use]
pub fn url(prov: Proveedor, nombre: &str) -> String {
    match prov {
        Proveedor::S3 => format!("https://{nombre}.s3.amazonaws.com/"),
        Proveedor::Gcs => format!("https://storage.googleapis.com/{nombre}/"),
    }
}

/// Un bucket encontrado y su estado.
#[derive(Debug, Clone)]
pub struct Hallazgo {
    pub proveedor: Proveedor,
    pub nombre: String,
    pub estado: Estado,
    pub url: String,
}

/// Prueba UN nombre contra S3 y GCS (GET anónimo). Devuelve los estados que EXISTEN
/// (público o privado-existe); ignora `NoExiste`/`Desconocido` para no inundar la cola.
/// Un `OtraRegion` de S3 se re-prueba una vez contra su endpoint.
pub async fn probar(cliente: &reqwest::Client, nombre: &str) -> Vec<Hallazgo> {
    let mut out = Vec::new();
    for prov in [Proveedor::S3, Proveedor::Gcs] {
        let u = url(prov, nombre);
        let estado = match get_clasificar(cliente, &u).await {
            Some(e) => e,
            None => continue,
        };
        let estado = match estado {
            // Re-prueba en la región correcta (una sola vez, sin recursión infinita).
            Estado::OtraRegion(host) => {
                let u2 = format!("https://{host}/");
                match get_clasificar(cliente, &u2).await {
                    Some(e) => e,
                    None => Estado::Desconocido,
                }
            }
            otro => otro,
        };
        if matches!(estado, Estado::Publico | Estado::ExistePrivado) {
            out.push(Hallazgo { proveedor: prov, nombre: nombre.to_string(), estado, url: u });
        }
    }
    out
}

async fn get_clasificar(cliente: &reqwest::Client, u: &str) -> Option<Estado> {
    let resp = cliente.get(u).send().await.ok()?;
    let status = resp.status().as_u16();
    // `text()` trae el cuerpo completo a memoria; luego se clasifican solo los primeros
    // 64 KiB (un `ListBucketResult` cabe de sobra). NO acota la DESCARGA —para eso haría
    // falta `Range`/streaming—; acota lo que se inspecciona, en frontera de carácter.
    let cuerpo = resp.text().await.ok()?;
    let recorte = crate::parametros::recorte_seguro(&cuerpo, 64 * 1024);
    Some(clasificar(status, recorte))
}

/// FASE: prueba las permutaciones de cada token base y persiste los buckets EXPUESTOS
/// como hallazgos. `bases` son los tokens del objetivo (el handle/dominio del programa,
/// sin TLD). `max` acota el total de nombres probados (cada uno son 2 GET).
///
/// Marca cada hallazgo `TITULARIDAD SIN CONFIRMAR`: el nombre se derivó del objetivo pero
/// el espacio de S3 es global, así que la pertenencia y el alcance los confirma un humano
/// antes de reportar. Por eso NO va a la cola de auto-envío.
pub async fn fase_buckets(
    pool: &SqlitePool,
    program: &str,
    bases: &[String],
    max: usize,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    let cliente = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(crate::evasion::UA_POOL[0])
        // Sin auto-redirect: el `OtraRegion` se re-sondea a mano tras validar el cuerpo, y
        // un 30x a un host arbitrario NO debe seguirse solo (endurecimiento, como en `autz`).
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;

    // Candidatos de todas las bases, deduplicados, acotados a `max`.
    let mut candidatos: Vec<String> = Vec::new();
    for base in bases {
        for c in permutaciones(base) {
            if !candidatos.contains(&c) {
                candidatos.push(c);
            }
        }
    }
    candidatos.truncate(max);

    let mut n = 0usize;
    for nombre in &candidatos {
        for h in probar(&cliente, nombre).await {
            let (sev, cwe, nota) = match h.estado {
                Estado::Publico => (
                    "medium",
                    "CWE-200",
                    "LISTABLE sin credenciales (ListBucketResult): fuga de datos",
                ),
                Estado::ExistePrivado => (
                    "info",
                    "CWE-200",
                    "el bucket EXISTE (403 AccessDenied); revisar objetos públicos sueltos",
                ),
                _ => continue,
            };
            let evidencia = format!(
                "{} `{}` — {}. TITULARIDAD SIN CONFIRMAR: el nombre se derivó de «{}»; \
                 confirmar que el bucket pertenece al programa y está EN ALCANCE antes de \
                 reportar. GET anónimo, read-only.",
                h.proveedor.etiqueta(),
                h.nombre,
                nota,
                program
            );
            let f = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: "cloud-storage-expuesto".to_string(),
                severity: sev.to_string(),
                url: h.url.clone(),
                cwe: Some(cwe.to_string()),
                evidencia: Some(evidencia),
            };
            if crate::db::insert_finding_dedup(pool, &f, program_id).await? {
                n += 1;
                if let Some(wh) = webhook {
                    let _ = crate::notify::enviar(
                        wh,
                        &format!("🪣 bucket expuesto: {} `{}` ({sev})", h.proveedor.etiqueta(), h.nombre),
                    )
                    .await;
                }
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Cuerpos REALES de S3/GCS (recortados), la aguja validada contra el artefacto (D33).
    const LIST_PUBLICO: &str = r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>acme-assets</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>db-backup.sql</Key></Contents></ListBucketResult>"#;
    const ACCESO_DENEGADO: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>X</RequestId></Error>"#;
    const NO_EXISTE: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>acme-nope</BucketName></Error>"#;
    const REDIRIGE: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>PermanentRedirect</Code><Message>The bucket you are attempting to access must be addressed using the specified endpoint.</Message><Endpoint>acme-assets.s3.us-west-2.amazonaws.com</Endpoint><Bucket>acme-assets</Bucket></Error>"#;
    // Control anti-falso-positivo: un sitio estático servido DESDE un bucket devuelve 200
    // con HTML, no un ListBucketResult. NO es «listable».
    const SITIO_ESTATICO: &str = "<!doctype html><html><head><title>Acme</title></head><body>Hola</body></html>";

    #[test]
    fn clasifica_los_estados_por_la_senal_inequivoca_del_proveedor() {
        assert_eq!(clasificar(200, LIST_PUBLICO), Estado::Publico);
        assert_eq!(clasificar(403, ACCESO_DENEGADO), Estado::ExistePrivado);
        assert_eq!(clasificar(404, NO_EXISTE), Estado::NoExiste);
        assert_eq!(
            clasificar(301, REDIRIGE),
            Estado::OtraRegion("acme-assets.s3.us-west-2.amazonaws.com".to_string())
        );
    }

    #[test]
    fn un_200_que_no_es_listbucketresult_no_es_publico() {
        // El caso rojo del control (D33): sin esto, cualquier 200 pasaría por «listable».
        assert_eq!(clasificar(200, SITIO_ESTATICO), Estado::Desconocido);
        // Y un 403 de un WAF sin la señal de S3 tampoco es «existe-privado».
        assert_eq!(clasificar(403, "<html>Forbidden by WAF</html>"), Estado::Desconocido);
    }

    #[test]
    fn permutaciones_saneadas_deduplicadas_y_validas() {
        let p = permutaciones("Acme");
        assert!(p.contains(&"acme".to_string()), "el base solo");
        assert!(p.contains(&"acme-backup".to_string()), "base-afijo");
        assert!(p.contains(&"assets-acme".to_string()), "afijo-base");
        // Todos válidos y sin duplicados.
        assert!(p.iter().all(|n| es_nombre_valido(n)), "todos válidos");
        let mut orden = p.clone();
        orden.sort();
        orden.dedup();
        assert_eq!(orden.len(), p.len(), "sin duplicados");
    }

    #[test]
    fn un_base_demasiado_corto_no_produce_candidatos_invalidos() {
        // "ab" (2 chars) es inválido como bucket; el base solo NO se emite, pero
        // `ab-backup` (9) sí es válido. Nada inválido sale.
        assert!(permutaciones("ab").iter().all(|n| es_nombre_valido(n)));
        assert!(permutaciones("").is_empty(), "base vacío → nada");
    }

    #[test]
    fn url_por_proveedor() {
        assert_eq!(url(Proveedor::S3, "acme-assets"), "https://acme-assets.s3.amazonaws.com/");
        assert_eq!(url(Proveedor::Gcs, "acme-assets"), "https://storage.googleapis.com/acme-assets/");
    }
}
