// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Juan Carlos Isaza
//! Redacción de credenciales en la salida CRUDA de una herramienta externa antes
//! de que se guarde en un hallazgo/advisory.
//!
//! El hueco (medido 2026-10-18): `verify::verify_one` guarda los últimos ~2000
//! chars de `stdout+stderr` de sqlmap/xsstrike/commix en `Outcome::raw`, que viaja
//! al reporte y de ahí a la divulgación al mantenedor. Si uno de los argumentos que
//! nexus le pasó a la herramienta contiene un secreto del OPERADOR, la herramienta
//! lo eco en su salida (sqlmap imprime su configuración) y acabaría en el advisory.
//!
//! Hoy el único secreto así es el `--proxy` (de `HTTP_PROXY`/`HTTPS_PROXY`), que
//! puede llevar credenciales embebidas `http://user:pass@host`. El redactor es por
//! VALOR CONOCIDO —los valores que nexus puso en los args—, no por patrón: tapa la
//! fuga por la vía real sin depender de adivinar la forma del secreto. La lista de
//! flags sensibles incluye además los de autenticación (cookie/header/...) por si se
//! añaden más adelante (D19: el caso vivo es el proxy; el resto es la cascada), pero
//! NO inventa secretos donde no los hay: si un flag no está en los args, no tacha nada.

/// Marcador que sustituye a cada valor redactado.
const MARCA: &str = "[REDACTADO]";

/// Longitud mínima de un valor para tacharlo: por debajo, es ruido (`2`, `on`) y
/// tacharlo corrompería la salida sin proteger nada.
const MIN_LEN: usize = 4;

/// Flags cuyo VALOR ENTERO es una credencial/dato privado del operador (una cookie,
/// un header de auth, un cuerpo con contraseña): se tacha completo. Van por la cascada
/// (D19), inertes hoy —nexus no los añade a los args— pero listos si se añaden.
const FLAGS_VALOR_ENTERO: &[&str] = &[
    "--cookie", "--header", "--headers", "-H", "--auth-cred", "--data", "--data-raw",
];

/// Flags de CONEXIÓN cuyo valor es una dirección: NO se tacha si no lleva credenciales
/// (`http://127.0.0.1:8080` queda intacto — tacharlo sería un falso positivo, D23). PERO
/// si lleva credenciales embebidas (`://…@…`) se tacha el valor ENTERO: la dirección de
/// un proxy del operador no es dato del hallazgo, y over-redactarla cubre una contraseña
/// con cualquier carácter sin parseo frágil. El vivo: `--proxy` de `HTTP(S)_PROXY`.
const FLAGS_SOLO_USERINFO: &[&str] = &["--proxy"];

/// Valor de un dígito hexadecimal, o `None` si no lo es.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodifica `%XX` best-effort. Cubre el caso en que el arg trae la credencial
/// codificada (`%40`=@, `%3A`=:) y la herramienta la eco DECODIFICADA: sin esto, el
/// match literal de la forma codificada no casaría la salida. Lo que no sea `%XX`
/// válido se deja igual (over-redact sobre lo que haya).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Empuja `v` (con piso de longitud) y, si difiere, su forma percent-decodificada.
fn empujar(vals: &mut Vec<String>, v: &str) {
    let v = v.trim();
    if v.len() < MIN_LEN {
        return;
    }
    vals.push(v.to_string());
    let dec = percent_decode(v);
    if dec != v && dec.trim().len() >= MIN_LEN {
        vals.push(dec.trim().to_string());
    }
}

/// Parte de un valor de flag el tail tras el esquema `://`, o el valor entero si no
/// hay esquema (un `--proxy user:pass@host` sin `http://` es válido). Gate y extractor
/// usan ESTA misma función, para que lean el mismo límite (evita el diferencial).
fn tras_esquema(v: &str) -> &str {
    v.split_once("://").map_or(v, |(_, t)| t)
}

/// Extrae los COMPONENTES de credencial embebida (`userinfo@host`): el userinfo entero
/// y, si es `user:pass`, el password suelto (la herramienta puede ecoar solo la
/// contraseña). Cada uno con su forma percent-decodificada (vía [`empujar`]).
///
/// Over-redact deliberado: parte por el ÚLTIMO `@` del tail COMPLETO (no se acota a la
/// authority antes del `/?#`). Así una contraseña con `/`, `?`, `#` o `@` sin codificar
/// no escapa, y gate y extractor leen el mismo límite. El coste —sobre-tachar si hubiera
/// un `@` en un path— es nulo en la práctica: esto solo se llama sobre valores que ya se
/// tachan enteros (un `--proxy` del operador, o un flag de valor-entero privado); ninguno
/// es dato del hallazgo del target.
fn credenciales_embebidas(v: &str, vals: &mut Vec<String>) {
    let tras = tras_esquema(v);
    let Some(at) = tras.rfind('@') else {
        return;
    };
    let userinfo = &tras[..at];
    empujar(vals, userinfo);
    if let Some((_, pass)) = userinfo.split_once(':') {
        empujar(vals, pass);
    }
}

/// Reúne los valores sensibles presentes en `args`, de más largo a más corto (para
/// que, si uno contiene a otro, se reemplace el entero primero — truco de Archon).
fn valores_a_tachar(args: &[String]) -> Vec<String> {
    let mut vals: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        // Forma `--flag=valor` o `--flag valor`.
        let (flag, valor_inline): (&str, Option<&str>) = match a.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (a.as_str(), None),
        };
        let valor: Option<String> = if let Some(v) = valor_inline {
            Some(v.to_string())
        } else if (FLAGS_VALOR_ENTERO.contains(&flag) || FLAGS_SOLO_USERINFO.contains(&flag))
            && args.get(i + 1).is_some()
        {
            i += 1;
            args.get(i).cloned()
        } else {
            None
        };
        let Some(v) = valor else {
            i += 1;
            continue;
        };
        let v = v.trim();
        if FLAGS_VALOR_ENTERO.contains(&flag) {
            // Dato privado entero (cookie/header/cuerpo) + componentes si es URL.
            empujar(&mut vals, v);
            credenciales_embebidas(v, &mut vals);
        } else if FLAGS_SOLO_USERINFO.contains(&flag) {
            // Dirección de conexión: NO se tacha sola (falso positivo, D23). PERO si
            // lleva credenciales embebidas (un `@` en el tail, CON o SIN esquema), se
            // over-redacta el VALOR ENTERO —cubre una contraseña con CUALQUIER carácter
            // (`/?#@`), sin parseo frágil (D1)— más sus componentes para cuando la
            // herramienta los eco por separado. Gate y extractor usan `tras_esquema`.
            if tras_esquema(v).contains('@') {
                empujar(&mut vals, v);
                credenciales_embebidas(v, &mut vals);
            }
        }
        i += 1;
    }
    // Más largo primero, y sin duplicados (un mismo valor no se procesa dos veces).
    vals.sort_by_key(|a| std::cmp::Reverse(a.len()));
    vals.dedup();
    vals
}

/// Tacha en `texto` cada valor sensible que nexus puso en `args`. Si no hay ninguno
/// (el caso normal: solo la URL del target y flags inocuos), devuelve el texto igual.
pub fn redactar_args_sensibles(texto: &str, args: &[String]) -> String {
    let vals = valores_a_tachar(args);
    if vals.is_empty() {
        return texto.to_string();
    }
    let mut salida = texto.to_string();
    for v in vals {
        if salida.contains(&v) {
            salida = salida.replace(&v, MARCA);
        }
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn args(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    /// CASO ROJO (el hueco vivo): el proxy con credenciales embebidas que sqlmap eco
    /// en su salida NO puede sobrevivir a la redacción. Falla por la vía real: el
    /// secreto está en los args Y en el texto, como en producción.
    #[test]
    fn el_proxy_con_credenciales_se_tacha() {
        let a = args(&["-u", "http://victima.tld/p?id=1", "--proxy", "http://bob:s3cr3t0@127.0.0.1:8080"]);
        // sqlmap eco su config, incluyendo el proxy entero y, a veces, solo el user:pass.
        let salida_cruda = "[*] using proxy http://bob:s3cr3t0@127.0.0.1:8080\n[*] auth bob:s3cr3t0";
        let limpio = redactar_args_sensibles(salida_cruda, &a);
        assert!(!limpio.contains("s3cr3t0"), "la contraseña del proxy sobrevivió: {limpio}");
        assert!(!limpio.contains("bob:s3cr3t0"), "el user:pass del proxy sobrevivió: {limpio}");
    }

    /// Hallazgo HIGH del review: una contraseña con `@` sin codificar NO puede truncar
    /// la redacción. Se parte por el ÚLTIMO `@` de la authority, no el primero.
    #[test]
    fn una_contrasena_con_arroba_se_tacha_entera() {
        let a = args(&["--proxy", "http://bob:p@ss@127.0.0.1:8080"]);
        let cruda = "using proxy http://bob:p@ss@127.0.0.1:8080";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("p@ss"), "la contraseña con @ sobrevivió: {limpio}");
        assert!(!limpio.contains("bob:p@ss"), "el userinfo con @ sobrevivió: {limpio}");
    }

    /// Hallazgo MEDIUM del review: un userinfo SIN `:` (un token/usuario solo) también
    /// se tacha — antes el `contains(':')` lo dejaba pasar.
    #[test]
    fn un_userinfo_sin_dospuntos_se_tacha() {
        let a = args(&["--proxy", "http://s3cr3ttoken@proxy.interno:3128"]);
        let cruda = "using proxy http://s3cr3ttoken@proxy.interno:3128";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("s3cr3ttoken"), "el token-userinfo sin ':' sobrevivió: {limpio}");
    }

    /// Hallazgo MEDIUM del review: si la herramienta eco SOLO la contraseña (no el
    /// user:pass completo), igual se tacha — el `pass` suelto va en la lista.
    #[test]
    fn la_contrasena_sola_en_la_salida_se_tacha() {
        let a = args(&["--proxy", "http://bob:s3cr3t0@127.0.0.1:8080"]);
        let cruda = "proxy user: bob\nproxy password: s3cr3t0";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("s3cr3t0"), "la contraseña suelta sobrevivió: {limpio}");
    }

    /// Hallazgo MEDIUM de la 2ª ronda: una contraseña con `/` (o `?`,`#`) sin codificar
    /// empuja el límite de la authority y el parseo fino no vería el `@`. Al tachar el
    /// VALOR ENTERO del proxy-con-`@`, queda cubierta igual.
    #[test]
    fn una_contrasena_con_barra_se_tacha() {
        let a = args(&["--proxy", "http://bob:pa/ss?x@127.0.0.1:8080"]);
        let cruda = "using proxy http://bob:pa/ss?x@127.0.0.1:8080";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("pa/ss?x"), "la contraseña con / y ? sobrevivió: {limpio}");
    }

    /// Hallazgo MEDIUM de la 2ª ronda: la contraseña va percent-encoded en el arg
    /// (`%40`=@) y la herramienta la eco DECODIFICADA. Se tacha la forma decodificada.
    #[test]
    fn una_contrasena_percent_encoded_se_tacha_decodificada() {
        let a = args(&["--proxy", "http://bob:p%40ssword@127.0.0.1:8080"]);
        // sqlmap eco la forma decodificada del user:pass.
        let cruda = "proxy auth bob:p@ssword";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("p@ssword"), "la contraseña decodificada sobrevivió: {limpio}");
    }

    /// Hallazgo MEDIUM 3ª ronda (parser differential): la herramienta eco SOLO el
    /// password con `/` y `?`. Antes el extractor acotaba a la authority y no lo veía;
    /// ahora parte por el último `@` del tail completo, así que el componente se extrae.
    #[test]
    fn el_password_con_barra_ecoado_solo_se_tacha() {
        let a = args(&["--proxy", "http://bob:pa/ss?x@127.0.0.1:8080"]);
        let cruda = "proxy password: pa/ss?x";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("pa/ss?x"), "el password con /? ecoado solo sobrevivió: {limpio}");
    }

    /// Hallazgo MEDIUM 3ª ronda (scheme-less): un `--proxy user:pass@host` SIN `http://`
    /// —válido para sqlmap— también se redacta (gate y extractor usan `tras_esquema`).
    #[test]
    fn un_proxy_sin_esquema_con_credenciales_se_tacha() {
        let a = args(&["--proxy", "bob:s3cr3t0@127.0.0.1:8080"]);
        let cruda = "proxy set to bob:s3cr3t0@127.0.0.1:8080 (user bob)";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("s3cr3t0"), "la contraseña del proxy sin esquema sobrevivió: {limpio}");
        assert!(!limpio.contains("bob:s3cr3t0"), "el user:pass sin esquema sobrevivió: {limpio}");
    }

    /// CONTROL (lo que NO se puede tocar): una salida sin secretos de args queda
    /// idéntica. Sin este, un redactor que tachara de más pasaría el rojo igual.
    #[test]
    fn una_salida_sin_secretos_queda_intacta() {
        let a = args(&["-u", "http://victima.tld/p?id=1", "--level=2", "--proxy", "http://127.0.0.1:8080"]);
        let cruda = "parameter 'id' is vulnerable\n[*] using proxy http://127.0.0.1:8080";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert_eq!(limpio, cruda, "se tachó algo que no era un secreto");
    }

    /// Discrimina: la URL del target (dato del hallazgo, NO secreto) y un flag corto
    /// legítimo (`--level=2`) no se tachan.
    #[test]
    fn ni_la_url_ni_los_flags_cortos_se_tachan() {
        let a = args(&["-u", "http://victima.tld/p?id=1", "--level=2", "--risk=1"]);
        let cruda = "testing URL 'http://victima.tld/p?id=1' at --level=2";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(limpio.contains("http://victima.tld/p?id=1"), "se tachó la URL del target");
        assert!(limpio.contains("--level=2"), "se tachó un flag inocuo");
    }

    /// Cascada D19 (inerte hoy, viva si se añade): un `--cookie` con sesión se tacha.
    #[test]
    fn una_cookie_de_sesion_en_los_args_se_tacha() {
        let a = args(&["-u", "http://v.tld/", "--cookie", "SESSIONID=abc123deadbeef"]);
        let cruda = "[*] Cookie: SESSIONID=abc123deadbeef";
        let limpio = redactar_args_sensibles(cruda, &a);
        assert!(!limpio.contains("abc123deadbeef"), "la cookie de sesión sobrevivió: {limpio}");
    }

    /// MUTANTE (D33): sin el paso de redacción, el secreto sobrevive — esto prueba
    /// que el banco de arriba mide el redactor y no otra cosa.
    #[test]
    fn sin_redaccion_el_secreto_sobrevive() {
        let cruda = "using proxy http://bob:s3cr3t0@127.0.0.1:8080";
        // El "mutante" es NO llamar al redactor (o llamarlo con args vacíos).
        let sin_redactar = redactar_args_sensibles(cruda, &[]);
        assert!(sin_redactar.contains("s3cr3t0"), "con args vacíos no debe tachar nada");
    }
}
