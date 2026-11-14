// SPDX-License-Identifier: LicenseRef-Propietario
//! Molde de auth: ENDPOINT QUE EMITE UN TOKEN SIN CREDENCIAL.
//!
//! Generaliza la familia "la auth no se hace respetar" del lab JWT (firma no
//! verificada, alg:none) a un eslabón distinto y de caja negra: un endpoint de
//! emisión/refresh (`/token`, `/refresh`, `/RefreshAccessToken`…) que devuelve un
//! token USABLE a quien lo pide SIN autenticarse. Es el primer eslabón del leak de
//! partners de Microsoft (faav, 2025) y un patrón recurrente en portales B2B.
//!
//! Disciplina del razonador: NO se reporta por presencia de un token en la
//! respuesta. Se reporta `TokenEmitidoSinAuth` (observado, usabilidad SIN confirmar,
//! D30) y solo se eleva a `ConfirmadoUsable` cuando un ORÁCULO DIFERENCIAL lo prueba:
//! un endpoint protegido da 401/403 SIN el token y 2xx CON él. Sin un endpoint
//! protegido que ofrecer, el veredicto se queda en "emitido, sin confirmar".

/// Rutas candidatas de emisión/refresh de token. GET y POST vacío, sin credencial.
pub const RUTAS_EMISION: &[&str] = &[
    "/token",
    "/oauth/token",
    "/oauth2/token",
    "/connect/token",
    "/api/token",
    "/auth/token",
    "/refresh",
    "/auth/refresh",
    "/api/refresh",
    "/api/auth/refresh",
    "/renew",
    "/api/renew",
    "/RefreshAccessToken",
    "/api/RefreshAccessToken",
    "/session",
    "/api/session",
];

/// ¿La cadena tiene forma de JWT (tres segmentos base64url separados por punto)?
pub fn es_jwt(s: &str) -> bool {
    let partes: Vec<&str> = s.split('.').collect();
    if partes.len() != 3 {
        return false;
    }
    partes.iter().all(|p| {
        p.len() >= 2 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// Extrae un token USABLE del cuerpo de una respuesta. Busca claves JSON típicas
/// (`access_token`, `token`, `id_token`, `accessToken`, `authToken`, `jwt`) con un
/// valor no vacío, o un JWT suelto. Puro y testable. Parser tolerante (sin pull de
/// un deserializador): localiza `"clave"` y lee el string que sigue a `:`.
pub fn extraer_token(cuerpo: &str) -> Option<String> {
    const CLAVES: &[&str] = &[
        "access_token",
        "accessToken",
        "id_token",
        "idToken",
        "authToken",
        "auth_token",
        "jwt",
        "token",
    ];
    for clave in CLAVES {
        if let Some(v) = valor_json_string(cuerpo, clave) {
            if v.len() >= 8 {
                return Some(v);
            }
        }
    }
    // Un JWT suelto en el cuerpo (sin envoltorio JSON) también cuenta.
    for tok in cuerpo.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        if es_jwt(tok) {
            return Some(tok.to_string());
        }
    }
    None
}

/// Lee el valor string de `"clave": "valor"` en un cuerpo JSON (primera aparición,
/// tolerante a espacios). No maneja escapes complejos: basta para pescar un token.
fn valor_json_string(cuerpo: &str, clave: &str) -> Option<String> {
    let patron = format!("\"{clave}\"");
    let mut desde = 0;
    while let Some(pos) = cuerpo[desde..].find(&patron) {
        let tras = desde + pos + patron.len();
        let resto = &cuerpo[tras..];
        // Salta espacios y los dos puntos.
        let resto = resto.trim_start();
        if let Some(resto) = resto.strip_prefix(':') {
            let resto = resto.trim_start();
            if let Some(resto) = resto.strip_prefix('"') {
                if let Some(fin) = resto.find('"') {
                    return Some(resto[..fin].to_string());
                }
            }
        }
        desde = tras;
    }
    None
}

/// Veredicto por ruta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VeredictoToken {
    /// Un endpoint protegido dado se abrió CON el token y estaba cerrado SIN él.
    ConfirmadoUsable,
    /// Se emitió un token sin credencial, pero su usabilidad no se confirmó (no se
    /// dio endpoint protegido, o el protegido no discriminó). D30: no se sobreafirma.
    EmitidoSinConfirmar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HallazgoToken {
    pub ruta: String,
    pub metodo: &'static str,
    pub token_enmascarado: String,
    pub veredicto: VeredictoToken,
}

fn enmascarar(tok: &str) -> String {
    crate::secretos_js::enmascarar(tok)
}

/// Resultado del oráculo diferencial sobre un endpoint protegido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oraculo {
    /// SIN token 401/403 y CON token 2xx → el token abre lo cerrado.
    Discrimina,
    /// El protegido ya daba 2xx SIN token (no estaba protegido) → inconcluso.
    NoProtegido,
    /// CON token NO abrió (sigue 401/403) → el token no es usable ahí.
    NoAbre,
    /// Error de red / respuesta rara → inconcluso (no inventar).
    Inconcluso,
}

/// Oráculo diferencial: ¿el `token` abre `protegido` que SIN él está cerrado?
/// Re-observa la línea base en el momento de confirmar (disciplina de estado).
pub async fn confirmar(cliente: &reqwest::Client, protegido: &str, token: &str) -> Oraculo {
    let sin = cliente.get(protegido).send().await;
    let (st_sin, _) = match sin {
        Ok(r) => (r.status().as_u16(), ()),
        Err(_) => return Oraculo::Inconcluso,
    };
    if (200..300).contains(&st_sin) {
        return Oraculo::NoProtegido;
    }
    if st_sin != 401 && st_sin != 403 {
        return Oraculo::Inconcluso;
    }
    let con = cliente
        .get(protegido)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await;
    match con {
        Ok(r) => {
            let st = r.status().as_u16();
            if (200..300).contains(&st) {
                Oraculo::Discrimina
            } else {
                Oraculo::NoAbre
            }
        }
        Err(_) => Oraculo::Inconcluso,
    }
}

/// Driver: sondea las rutas de emisión SIN credencial (GET y POST vacío); por cada
/// token obtenido, si hay `protegido`, lo pasa por el oráculo. Antibaneo por `Guard`.
#[allow(clippy::too_many_arguments)]
pub async fn sondear(
    cliente: &reqwest::Client,
    base: &str,
    rutas: &[&str],
    protegido: Option<&str>,
    timeout_secs: u64,
    guard: &mut crate::protection::Guard,
    mut rng: impl FnMut() -> f64,
) -> Vec<HallazgoToken> {
    let base = if base.starts_with("http") {
        base.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", base.trim_end_matches('/'))
    };
    let mut out = Vec::new();
    let mut vistos = std::collections::BTreeSet::new();
    for ruta in rutas {
        let url = format!("{base}{ruta}");
        for metodo in ["GET", "POST"] {
            let req = match metodo {
                "POST" => cliente.post(&url).body(""),
                _ => cliente.get(&url),
            };
            let resp =
                tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), req.send()).await;
            tokio::time::sleep(guard.cooldown(1, rng())).await;
            let cuerpo = match resp {
                Ok(Ok(r)) if (200..300).contains(&r.status().as_u16()) => {
                    r.text().await.unwrap_or_default()
                }
                _ => continue,
            };
            if let Some(token) = extraer_token(&cuerpo) {
                if !vistos.insert((ruta.to_string(), metodo)) {
                    continue;
                }
                let veredicto = match protegido {
                    Some(p) => match confirmar(cliente, p, &token).await {
                        Oraculo::Discrimina => VeredictoToken::ConfirmadoUsable,
                        _ => VeredictoToken::EmitidoSinConfirmar,
                    },
                    None => VeredictoToken::EmitidoSinConfirmar,
                };
                out.push(HallazgoToken {
                    ruta: ruta.to_string(),
                    metodo: if metodo == "POST" { "POST" } else { "GET" },
                    token_enmascarado: enmascarar(&token),
                    veredicto,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconoce_jwt_y_no_cualquier_cosa() {
        assert!(es_jwt("aaa.bbb.ccc"));
        assert!(es_jwt("eyJhbGc.eyJzdWI.sign-_ature"));
        // PAREJA: no-JWT.
        assert!(!es_jwt("solo.dos"));
        assert!(!es_jwt("uno"));
        assert!(!es_jwt("a.b.c.d"));
        assert!(!es_jwt("tiene espacios.b.c"));
    }

    #[test]
    fn extrae_token_de_json_y_jwt_suelto() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF_-123";
        assert_eq!(extraer_token(&format!(r#"{{"access_token":"{jwt}"}}"#)).as_deref(), Some(jwt));
        assert_eq!(extraer_token(&format!(r#"{{ "token" : "{jwt}" }}"#)).as_deref(), Some(jwt));
        assert_eq!(extraer_token(jwt).as_deref(), Some(jwt), "JWT suelto sin envoltorio");
        // PAREJA (D33): respuestas que NO entregan un token usable.
        assert!(extraer_token(r#"{"error":"invalid_token"}"#).is_none());
        assert!(extraer_token(r#"{"message":"unauthorized"}"#).is_none());
        assert!(extraer_token(r#"{"token":""}"#).is_none(), "token vacío no cuenta");
        assert!(extraer_token("página normal sin nada").is_none());
    }
}
