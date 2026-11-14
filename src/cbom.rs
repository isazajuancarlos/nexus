// SPDX-License-Identifier: LicenseRef-Propietario
//! Ángulo B del CBOM: DESCUBRIR la criptografía de un proyecto AJENO y emitir su
//! CBOM (CycloneDX 1.6), marcando qué está cuánticamente vulnerable.
//!
//! Es la inversión del Ángulo A (quipu autodescribiéndose desde un descriptor
//! curado): aquí no hay descriptor, se ESCANEA. La detección es por MANIFIESTOS
//! DE DEPENDENCIAS —Cargo.lock, requirements.txt, package-lock.json—, no por
//! flujo de código: ve lo que el proyecto DECLARA usar, no cada llamada. Ese es
//! su límite, y se declara en la salida en vez de fingir cobertura que no tiene
//! (un CBOM que promete más de lo que mide es peor que ninguno).
//!
//! Alimenta a `nexus dictamen`: el inventario es el insumo del dictamen de
//! postura post-cuántica, como los hallazgos lo son del de Ley 1581.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Estado de un algoritmo frente a un adversario cuántico.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cuantico {
    /// Se rompe con Shor: RSA, Diffie-Hellman, y toda la curva elíptica clásica.
    Vulnerable,
    /// Diseñado contra el adversario cuántico (ML-KEM, ML-DSA, SLH-DSA…).
    PostCuantico,
    /// Simétrico o hash: Grover solo halva la seguridad; sigue en pie con tamaño suficiente.
    Simetrico,
}
impl Cuantico {
    fn etiqueta(self) -> &'static str {
        match self {
            Cuantico::Vulnerable => "cuántico-vulnerable",
            Cuantico::PostCuantico => "post-cuántico",
            Cuantico::Simetrico => "simétrico",
        }
    }
    fn pq_level(self) -> u32 {
        // Aproximación grosera para el campo CycloneDX; el eje real es `estado`.
        match self {
            Cuantico::PostCuantico => 5,
            Cuantico::Simetrico => 2,
            Cuantico::Vulnerable => 0,
        }
    }
}

/// Una primitiva criptográfica que un paquete aporta.
pub struct Prim {
    pub nombre: &'static str,
    pub primitive: &'static str, // taxonomía CycloneDX (signature, kem, ae, hash, kdf…)
    pub oid: Option<&'static str>,
    pub estado: Cuantico,
}

macro_rules! prim {
    ($n:expr, $p:expr, $oid:expr, $e:expr) => {
        Prim { nombre: $n, primitive: $p, oid: $oid, estado: $e }
    };
}
use Cuantico::{PostCuantico as PQ, Simetrico as SIM, Vulnerable as VUL};

/// Catálogo paquete → primitivas. El nombre se compara ya en minúsculas.
/// Cubre Rust (crates.io), Python (PyPI) y JS (npm) — los tres manifiestos que
/// parseamos. Un paquete «agregado» (ring, openssl, cryptography) aporta varias
/// familias; se marca lo que trae por defecto y la nota invita a revisar el uso.
fn catalogo(paquete: &str) -> &'static [Prim] {
    match paquete {
        // --- Clásicos cuántico-vulnerables (lo que HAY QUE MIGRAR) ---
        "rsa" | "rsa-pkcs1" => &[prim!("RSA", "pke", Some("1.2.840.113549.1.1.1"), VUL)],
        "ed25519-dalek" | "ed25519" | "ed25519-compact" | "ed25519-zebra" =>
            &[prim!("Ed25519", "signature", Some("1.3.101.112"), VUL)],
        "x25519-dalek" | "x25519" =>
            &[prim!("X25519", "keyagree", Some("1.3.101.110"), VUL)],
        "p256" => &[prim!("ECDSA/ECDH P-256", "signature", Some("1.2.840.10045.3.1.7"), VUL)],
        "p384" => &[prim!("ECDSA/ECDH P-384", "signature", Some("1.3.132.0.34"), VUL)],
        "p521" => &[prim!("ECDSA/ECDH P-521", "signature", Some("1.3.132.0.35"), VUL)],
        "k256" | "secp256k1" | "libsecp256k1" =>
            &[prim!("ECDSA secp256k1", "signature", None, VUL)],
        "ecdsa" | "ecc" | "elliptic" | "p224" =>
            &[prim!("ECDSA", "signature", None, VUL)],
        "dsa" => &[prim!("DSA", "signature", None, VUL)],
        "pynacl" | "tweetnacl" =>
            &[prim!("Ed25519", "signature", Some("1.3.101.112"), VUL),
              prim!("X25519", "keyagree", Some("1.3.101.110"), VUL)],
        // --- Post-cuánticos (el DESTINO de la migración) ---
        "ml-kem" | "ml_kem" | "fips203" | "pqcrypto-kyber" | "pqcrypto-mlkem" =>
            &[prim!("ML-KEM", "kem", Some("2.16.840.1.101.3.4.4"), PQ)],
        "ml-dsa" | "ml_dsa" | "fips204" | "pqcrypto-dilithium" | "pqcrypto-mldsa" =>
            &[prim!("ML-DSA", "signature", Some("2.16.840.1.101.3.4.3"), PQ)],
        "fips205" | "slh-dsa" | "slh_dsa" | "pqcrypto-sphincsplus" =>
            &[prim!("SLH-DSA", "signature", Some("2.16.840.1.101.3.4.3"), PQ)],
        // --- Simétricos / hash / KDF (se quedan, con tamaño suficiente) ---
        "aes" | "aes-gcm" | "aes-gcm-siv" | "aes-siv" =>
            &[prim!("AES", "ae", Some("2.16.840.1.101.3.4.1"), SIM)],
        "chacha20poly1305" | "chacha20" | "xchacha20poly1305" =>
            &[prim!("ChaCha20-Poly1305", "ae", None, SIM)],
        "sha2" => &[prim!("SHA-2", "hash", Some("2.16.840.1.101.3.4.2"), SIM)],
        "sha3" | "keccak" | "tiny-keccak" => &[prim!("SHA-3", "hash", None, SIM)],
        "sha1" | "sha-1" => &[prim!("SHA-1 (débil)", "hash", None, SIM)],
        "md-5" | "md5" | "md5-asm" => &[prim!("MD5 (débil)", "hash", None, SIM)],
        "blake2" | "blake2b" | "blake2b_simd" | "blake3" =>
            &[prim!("BLAKE2/3", "hash", None, SIM)],
        "hmac" => &[prim!("HMAC", "mac", None, SIM)],
        "hkdf" => &[prim!("HKDF", "kdf", None, SIM)],
        "argon2" | "argon2id" | "rust-argon2" => &[prim!("Argon2", "kdf", None, SIM)],
        "scrypt" => &[prim!("scrypt", "kdf", None, SIM)],
        "pbkdf2" => &[prim!("PBKDF2", "kdf", None, SIM)],
        "bcrypt" => &[prim!("bcrypt", "kdf", None, SIM)],
        // --- Agregados: traen varias familias, con clásicas por defecto ---
        "ring" | "openssl" | "openssl-sys" | "boring" =>
            &[prim!("suite clásica (RSA/ECDSA)", "signature", None, VUL),
              prim!("AES-GCM", "ae", Some("2.16.840.1.101.3.4.1"), SIM),
              prim!("SHA-2", "hash", Some("2.16.840.1.101.3.4.2"), SIM)],
        "cryptography" | "pycryptodome" | "pyopenssl" | "node-forge" | "jsrsasign" =>
            &[prim!("suite clásica (RSA/ECDSA)", "signature", None, VUL),
              prim!("AES", "ae", Some("2.16.840.1.101.3.4.1"), SIM)],
        _ => &[],
    }
}

/// Un paquete NO catalogado cuyo nombre huele a criptografía: no se calla, se
/// reporta para revisión manual (D20 — un falso negativo silencioso es peor que
/// un aviso). Evita afirmar «sin cripto vulnerable» cuando en realidad no se supo mirar.
fn sospechoso(p: &str) -> bool {
    const PISTAS: &[&str] = &[
        "crypt", "cipher", "aead", "rsa", "ecc", "ecdsa", "ecdh", "curve", "kem",
        "dsa", "kyber", "dilithium", "sphincs", "falcon", "pqc", "tls", "ssl",
        "x509", "jwt", "jose", "jwk", "signature", "signing", "keypair", "hash",
        "hmac", "kdf", "argon", "scrypt", "pbkdf", "nacl", "sodium", "gpg", "pgp",
    ];
    // Ya catalogado no es «sospechoso»: es conocido.
    if !catalogo(p).is_empty() {
        return false;
    }
    let l = p.to_ascii_lowercase();
    PISTAS.iter().any(|k| l.contains(k))
}

// ---------- Parsers de manifiestos (sin dependencias nuevas) ----------

/// Un parser de manifiesto: texto del archivo → nombres de paquete.
type Parser = fn(&str) -> Vec<String>;

/// Cargo.lock: bloques `[[package]]` con `name = "..."`. Devuelve nombres.
fn parse_cargo_lock(txt: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut en_pkg = false;
    for l in txt.lines() {
        let t = l.trim();
        if t == "[[package]]" {
            en_pkg = true;
        } else if t.starts_with('[') {
            en_pkg = false;
        } else if en_pkg {
            if let Some(v) = t.strip_prefix("name = ") {
                out.push(v.trim().trim_matches('"').to_string());
                en_pkg = false; // el name es lo primero del bloque; ya está
            }
        }
    }
    out
}

/// requirements.txt: `paquete[extras]==version`, ignora comentarios y opciones.
fn parse_requirements(txt: &str) -> Vec<String> {
    txt.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|l| {
            let corte = l.find(|c: char| "=<>!~[; ".contains(c)).unwrap_or(l.len());
            let n = l[..corte].trim();
            (!n.is_empty()).then(|| n.to_ascii_lowercase())
        })
        .collect()
}

/// package-lock.json: nombres de `packages`/`dependencies` (v2 y v1).
fn parse_package_lock(txt: &str) -> Vec<String> {
    let v: serde_json::Value = match serde_json::from_str(txt) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut recolectar = |obj: Option<&serde_json::Value>| {
        if let Some(serde_json::Value::Object(m)) = obj {
            for k in m.keys() {
                // v2 usa rutas "node_modules/<nombre>"; nos quedamos con la hoja.
                let nombre = k.rsplit('/').next().unwrap_or(k);
                if !nombre.is_empty() {
                    out.push(nombre.to_ascii_lowercase());
                }
            }
        }
    };
    recolectar(v.get("packages"));
    recolectar(v.get("dependencies"));
    out
}

// ---------- Detección ----------

pub struct Deteccion {
    pub proyecto: String,
    pub fuentes: Vec<String>,           // manifiestos que se leyeron
    pub activos: Vec<ActivoDetectado>,  // primitivas únicas, con sus orígenes
    pub sospechosos: Vec<String>,       // paquetes cripto no catalogados
    pub total_paquetes: usize,
}

pub struct ActivoDetectado {
    pub nombre: String,
    pub primitive: String,
    pub oid: Option<String>,
    pub estado: Cuantico,
    pub origenes: Vec<String>,
}

/// Escanea un directorio de proyecto por sus manifiestos y agrega las primitivas.
pub fn detectar(ruta: &Path) -> std::io::Result<Deteccion> {
    let proyecto = ruta
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| ruta.display().to_string());

    let manifiestos: &[(&str, Parser)] = &[
        ("Cargo.lock", parse_cargo_lock),
        ("requirements.txt", parse_requirements),
        ("package-lock.json", parse_package_lock),
    ];

    let mut fuentes = Vec::new();
    let mut paquetes: Vec<String> = Vec::new();
    for (archivo, parser) in manifiestos {
        let p = ruta.join(archivo);
        if let Ok(txt) = std::fs::read_to_string(&p) {
            let nombres = parser(&txt);
            if !nombres.is_empty() {
                fuentes.push(archivo.to_string());
                paquetes.extend(nombres);
            }
        }
    }
    paquetes.sort();
    paquetes.dedup();

    // Agregar primitivas por nombre, acumulando de qué paquetes vienen.
    let mut mapa: BTreeMap<String, ActivoDetectado> = BTreeMap::new();
    let mut sospechosos: Vec<String> = Vec::new();
    for pkg in &paquetes {
        let prims = catalogo(pkg);
        if prims.is_empty() {
            if sospechoso(pkg) {
                sospechosos.push(pkg.clone());
            }
            continue;
        }
        for pr in prims {
            let e = mapa.entry(pr.nombre.to_string()).or_insert(ActivoDetectado {
                nombre: pr.nombre.to_string(),
                primitive: pr.primitive.to_string(),
                oid: pr.oid.map(str::to_string),
                estado: pr.estado,
                origenes: Vec::new(),
            });
            if !e.origenes.contains(pkg) {
                e.origenes.push(pkg.clone());
            }
        }
    }
    sospechosos.sort();
    sospechosos.dedup();

    // Vulnerables primero: son el entregable (qué migrar).
    let mut activos: Vec<ActivoDetectado> = mapa.into_values().collect();
    activos.sort_by_key(|a| match a.estado {
        Cuantico::Vulnerable => 0,
        Cuantico::PostCuantico => 1,
        Cuantico::Simetrico => 2,
    });

    Ok(Deteccion { proyecto, fuentes, activos, sospechosos, total_paquetes: paquetes.len() })
}

// ---------- Emisión CycloneDX 1.6 ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Cbom {
    bom_format: &'static str,
    spec_version: &'static str,
    version: u32,
    metadata: Meta,
    components: Vec<Comp>,
}
#[derive(Serialize)]
struct Meta {
    tools: serde_json::Value,
    component: serde_json::Value,
    properties: Vec<Prop>,
}
#[derive(Serialize)]
struct Prop {
    name: String,
    value: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Comp {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    crypto_properties: serde_json::Value,
    properties: Vec<Prop>,
}

/// Serializa la detección como CBOM CycloneDX 1.6.
pub fn emitir(d: &Deteccion) -> String {
    let components = d.activos.iter().map(|a| {
        let ap = serde_json::json!({
            "primitive": a.primitive,
            "executionEnvironment": "software-plain-ram",
            "implementationPlatform": "generic",
            "nistQuantumSecurityLevel": a.estado.pq_level(),
        });
        let mut cp = serde_json::json!({ "assetType": "algorithm", "algorithmProperties": ap });
        if let Some(oid) = &a.oid {
            cp["oid"] = serde_json::Value::String(oid.clone());
        }
        Comp {
            kind: "cryptographic-asset",
            bom_ref: format!("crypto/{}", a.nombre),
            name: a.nombre.clone(),
            crypto_properties: cp,
            properties: vec![
                Prop { name: "cbom:estado-cuantico".into(), value: a.estado.etiqueta().into() },
                Prop { name: "cbom:origen".into(), value: a.origenes.join(", ") },
            ],
        }
    }).collect();

    let vulnerables = d.activos.iter().filter(|a| a.estado == Cuantico::Vulnerable).count();
    let cbom = Cbom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        version: 1,
        metadata: Meta {
            tools: serde_json::json!({ "components": [{ "type": "application", "name": "nexus-cbom" }] }),
            component: serde_json::json!({ "type": "application", "name": d.proyecto }),
            properties: vec![
                Prop { name: "cbom:metodo".into(), value: "deteccion-por-dependencias".into() },
                Prop { name: "cbom:manifiestos".into(), value: d.fuentes.join(", ") },
                Prop { name: "cbom:paquetes-analizados".into(), value: d.total_paquetes.to_string() },
                Prop { name: "cbom:cuantico-vulnerables".into(), value: vulnerables.to_string() },
                Prop { name: "cbom:sospechosos-sin-catalogar".into(), value: d.sospechosos.len().to_string() },
            ],
        },
        components,
    };
    serde_json::to_string_pretty(&cbom).unwrap_or_else(|_| "{}".into())
}

/// Resumen legible para stdout: el veredicto de migración.
pub fn resumen(d: &Deteccion) -> String {
    let mut s = String::new();
    let vul: Vec<&ActivoDetectado> = d.activos.iter().filter(|a| a.estado == Cuantico::Vulnerable).collect();
    let pq = d.activos.iter().filter(|a| a.estado == Cuantico::PostCuantico).count();
    let sim = d.activos.iter().filter(|a| a.estado == Cuantico::Simetrico).count();

    s.push_str(&format!("# CBOM de «{}»\n", d.proyecto));
    if d.fuentes.is_empty() {
        s.push_str("\nNo se halló ningún manifiesto de dependencias (Cargo.lock, requirements.txt, package-lock.json).\n");
        return s;
    }
    s.push_str(&format!(
        "Método: detección por dependencias · manifiestos: {} · {} paquetes analizados\n\n",
        d.fuentes.join(", "), d.total_paquetes
    ));
    s.push_str(&format!(
        "Primitivas: {} cuántico-vulnerables · {} post-cuánticas · {} simétricas\n\n",
        vul.len(), pq, sim
    ));

    if vul.is_empty() {
        s.push_str("✔ VEREDICTO: ninguna primitiva de clave pública cuántico-vulnerable detectada.\n");
    } else {
        s.push_str("⚠ VEREDICTO: hay que migrar estas primitivas antes de la era cuántica:\n");
        for a in &vul {
            s.push_str(&format!("  · {} ({}) — de: {}\n", a.nombre, a.primitive, a.origenes.join(", ")));
        }
    }
    if !d.sospechosos.is_empty() {
        s.push_str(&format!(
            "\n⚠ {} paquete(s) con pinta criptográfica SIN catalogar — revisar a mano: {}\n",
            d.sospechosos.len(), d.sospechosos.join(", ")
        ));
    }
    s
}

/// El reemplazo post-cuántico recomendado para una primitiva vulnerable — la IP
/// central del dictamen (como `mapear_obligacion` lo es del de Ley 1581). CNSA 2.0
/// y el consenso NIST prescriben migración HÍBRIDA (clásico + PQ) durante la
/// transición: no se apaga lo clásico, se le suma un socio PQ.
fn migracion_recomendada(primitive: &str) -> &'static str {
    match primitive {
        "pke" | "keyagree" | "kem" =>
            "ML-KEM-1024 (FIPS 203) en intercambio de clave HÍBRIDO con el actual, durante la transición",
        "signature" =>
            "ML-DSA-87 (FIPS 204) —o SLH-DSA (FIPS 205) donde se exija seguridad basada en hash— en firma HÍBRIDA con la actual",
        _ => "revisar caso por caso con el equipo criptográfico",
    }
}

/// Datos del encargo pericial que rellenan el dictamen. Lo que falte se deja como
/// placeholder `{...}` visible, para que nadie firme un dictamen a medias sin verlo.
#[derive(Default)]
pub struct Encargo<'a> {
    pub perito: Option<&'a str>,
    pub tarjeta: Option<&'a str>,
    pub cliente: Option<&'a str>,
    pub nit: Option<&'a str>,
}

/// Dictamen técnico-jurídico de POSTURA POST-CUÁNTICA a partir del CBOM.
/// Comparte encabezado y anclaje (D31) con el dictamen de Ley 1581, pero su eje
/// es distinto: el deber de seguridad (Art. 4 g) frente al riesgo «capturar hoy,
/// descifrar mañana», no un hallazgo ya explotable.
pub fn dictamen(d: &Deteccion, enc: &Encargo, fecha: &str, binario: &str) -> String {
    use std::fmt::Write;
    let cliente = enc.cliente.unwrap_or("{razón social}");
    let nit = enc.nit.unwrap_or("{nit}");
    let perito = enc.perito.unwrap_or("{nombre}");
    let tarjeta = enc.tarjeta.unwrap_or("{tarjeta}");
    let vul: Vec<&ActivoDetectado> =
        d.activos.iter().filter(|a| a.estado == Cuantico::Vulnerable).collect();
    let pq = d.activos.iter().filter(|a| a.estado == Cuantico::PostCuantico).count();
    let sim = d.activos.iter().filter(|a| a.estado == Cuantico::Simetrico).count();

    let veredicto = if !vul.is_empty() && pq > 0 {
        "EN TRANSICIÓN — coexisten primitivas clásicas y post-cuánticas (postura híbrida); resta completar la migración de las clásicas"
    } else if !vul.is_empty() {
        "EXPUESTO — toda la criptografía de clave pública detectada es clásica; la migración post-cuántica está pendiente"
    } else if pq > 0 {
        "PREPARADO — no se detectan primitivas de clave pública cuántico-vulnerables; la postura post-cuántica está activa"
    } else {
        "SIN CRIPTOGRAFÍA DE CLAVE PÚBLICA detectada en el alcance — no exime de verificar el §5"
    };

    let mut t = String::new();
    let _ = writeln!(t, "# DICTAMEN TÉCNICO-JURÍDICO DE POSTURA CRIPTOGRÁFICA POST-CUÁNTICA\n");
    let _ = writeln!(t, "**Responsable del tratamiento auditado:** {cliente} — NIT {nit}  ");
    let _ = writeln!(t, "**Alcance auditado:** proyecto `{}` (manifiestos: {})  ", d.proyecto,
        if d.fuentes.is_empty() { "ninguno".into() } else { d.fuentes.join(", ") });
    let _ = writeln!(t, "**Fecha del dictamen:** {fecha}  ");
    let _ = writeln!(t, "**Perito:** {perito}, abogado y programador — T.P. {tarjeta}  ");
    let _ = writeln!(t, "**Método / anclaje al artefacto (directiva 31):** nexus-cbom `{binario}` · detección por dependencias · {} paquetes analizados\n", d.total_paquetes);

    // §1
    let _ = writeln!(t, "## 1. Resumen ejecutivo\n");
    let _ = writeln!(t, "**Veredicto:** {veredicto}.\n");
    let _ = writeln!(t, "| Estado frente a la amenaza cuántica | Nº primitivas |");
    let _ = writeln!(t, "|---|---|");
    let _ = writeln!(t, "| Cuántico-vulnerables (clave pública clásica) | {} |", vul.len());
    let _ = writeln!(t, "| Post-cuánticas | {pq} |");
    let _ = writeln!(t, "| Simétricas / hash / KDF | {sim} |\n");

    // §2 fundamento del riesgo
    let _ = writeln!(t, "## 2. Fundamento del riesgo — «capturar hoy, descifrar mañana»\n");
    let _ = writeln!(t, "La criptografía de clave pública clásica (RSA, Diffie-Hellman y curva elíptica) se rompe con el algoritmo de Shor sobre un computador cuántico criptográficamente relevante. El riesgo no es futuro para los datos con retención larga: un adversario puede **capturar hoy** el tráfico o los respaldos cifrados y **descifrarlos mañana**. Para datos personales sujetos a conservación prolongada —clínicos, financieros, laborales—, la ventana de exposición ya está abierta.\n");
    let _ = writeln!(t, "El **deber de seguridad** del Art. 4(g) de la Ley 1581 de 2012 obliga al responsable a adoptar las medidas técnicas y administrativas **apropiadas y actualizadas**. Las agencias de referencia han fijado el estándar y el calendario: **NIST** publicó los algoritmos (FIPS 203/204/205, 2024) y la **NSA (CNSA 2.0)** exige la transición entre **2030 y 2033**. Mantener criptografía cuánticamente vulnerable sobre datos de retención larga, pasada esa ventana, es difícilmente conciliable con el deber de medidas *actualizadas*.\n");

    // §3 inventario
    let _ = writeln!(t, "## 3. Inventario criptográfico (CBOM)\n");
    let _ = writeln!(t, "| Primitiva | Tipo | Estado | Detectada en |");
    let _ = writeln!(t, "|---|---|---|---|");
    for a in &d.activos {
        let _ = writeln!(t, "| {} | {} | {} | {} |", a.nombre, a.primitive, a.estado.etiqueta(), a.origenes.join(", "));
    }
    let _ = writeln!(t);

    // §4 plan de migración
    let _ = writeln!(t, "## 4. Plan de migración\n");
    if vul.is_empty() {
        let _ = writeln!(t, "No hay primitivas de clave pública clásicas que migrar en el alcance analizado.\n");
    } else {
        let _ = writeln!(t, "| Primitiva a migrar | Reemplazo recomendado | Plazo (CNSA 2.0) |");
        let _ = writeln!(t, "|---|---|---|");
        for a in &vul {
            let _ = writeln!(t, "| {} | {} | 2030–2033 |", a.nombre, migracion_recomendada(&a.primitive));
        }
        let _ = writeln!(t);
    }

    // §5 método y límites
    let _ = writeln!(t, "## 5. Método, límites y puntos a verificar\n");
    let _ = writeln!(t, "El inventario se obtuvo por **detección de dependencias declaradas** (manifiestos), no por análisis del flujo de código: refleja las bibliotecas que el proyecto declara, no cada invocación. En particular, la coexistencia de una primitiva clásica y una post-cuántica en el mismo proyecto **no confirma por sí sola** que operen en modo híbrido acoplado; eso se verifica leyendo el código de integración.\n");
    if !d.sospechosos.is_empty() {
        let _ = writeln!(t, "**Puntos a verificar a mano** — paquetes con apariencia criptográfica sin catalogar: {}.\n", d.sospechosos.join(", "));
    }

    // §6 declaración
    let _ = writeln!(t, "## 6. Declaración del perito\n");
    let _ = writeln!(t, "El suscrito certifica que el presente dictamen se basa en el inventario criptográfico declarado en el encabezado (§ Método / anclaje), generado de forma reproducible, y que las conclusiones se limitan al alcance y método declarados.\n");
    let _ = writeln!(t, "_____________________________  \n{perito} — abogado y programador — T.P. {tarjeta}");

    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock_extrae_nombres() {
        let txt = "[[package]]\nname = \"rsa\"\nversion = \"0.9\"\n\n[[package]]\nname = \"aes-gcm\"\nversion = \"0.10\"\n";
        let n = parse_cargo_lock(txt);
        assert!(n.contains(&"rsa".to_string()) && n.contains(&"aes-gcm".to_string()));
    }

    #[test]
    fn requirements_ignora_ruido() {
        let txt = "# comentario\ncryptography==42.0\n-r otro.txt\nrsa>=4.9\nrequests==2.0\n";
        let n = parse_requirements(txt);
        assert!(n.contains(&"cryptography".to_string()) && n.contains(&"rsa".to_string()));
        assert!(n.contains(&"requests".to_string())); // no cripto, pero se lista
    }

    // CASO ROJO (D33): un proyecto con RSA/ECDSA DEBE salir marcado vulnerable, y
    // uno solo-PQ+simétrico NO. La misma sonda con las dos entradas discrimina.
    #[test]
    fn discrimina_vulnerable_de_pq() {
        // Vulnerable: rsa + p256
        let vul = ["rsa", "p256", "sha2"];
        let mut hay_vul = false;
        for p in vul {
            if catalogo(p).iter().any(|x| x.estado == Cuantico::Vulnerable) { hay_vul = true; }
        }
        assert!(hay_vul, "rsa/p256 deben ser vulnerables");

        // Limpio: ml-kem + ml-dsa + aes-gcm (nada vulnerable)
        let limpio = ["ml-kem", "ml-dsa", "aes-gcm", "sha2"];
        let vulnerables: usize = limpio.iter()
            .flat_map(|p| catalogo(p))
            .filter(|x| x.estado == Cuantico::Vulnerable)
            .count();
        assert_eq!(vulnerables, 0, "un stack PQ+simétrico no debe marcar vulnerables");
    }

    #[test]
    fn sospechoso_no_se_calla() {
        // Un paquete cripto no catalogado se reporta; uno catalogado no es sospechoso;
        // uno inocuo tampoco.
        assert!(sospechoso("falcon-sign"), "cripto no catalogada debe ser sospechosa");
        assert!(!sospechoso("rsa"), "lo catalogado no es sospechoso");
        assert!(!sospechoso("serde"), "un paquete inocuo no es sospechoso");
    }
}
