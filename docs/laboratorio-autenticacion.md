<!-- SPDX-License-Identifier: LicenseRef-Propietario -->
# Laboratorio de ataque a AUTENTICACIÓN

**Marco (Juan, 2026-08-24):** experimentar (laboratorio) → atacar SIN perjudicar →
reportar el vacío a H1. Investigación autorizada + divulgación responsable. Y la
directiva que da el edge: **el laboratorio no corre el playbook de todos —eso es un
escáner más, colmado y patcheado—; GENERA sus propios métodos por objetivo**, como arnm
mutó SSRF y bespoke generó superficie.

## Por qué esto NO es autz/IDOR
IDOR es *post-login* (ya dentro, abusas de autz). Esto es DERROTAR la autenticación:
entrar/forjar identidad sin credenciales válidas. Clase distinta, no confundir
([[no-repetir-el-cazador-autonomo]]).

## El oráculo (lo que hace este nicho ideal para el método adaptativo)
El más limpio de toda la seguridad: **¿la petición forjada/manipulada obtuvo ACCESO
AUTENTICADO donde un control inválido obtuvo 401?** Determinista, cero FP. Se confirma
forjando para una identidad DISTINTA (otro user/rol) y viendo que la app la acepta.
Combina con el transporte de evasión TLS (`impersonate.rs`) para llegar al login tras WAF.

## Catálogo de métodos (la SEMILLA, investigado — no el producto)
Fuentes: PortSwigger, cheatsheets bug-bounty, incidentes 2025 (ver Fuentes abajo).

1. **JWT**
   - `alg:none` (quitar firma, variantes none/None/NONE/nOnE).
   - Firma NO verificada → manipular payload libre (user→admin).
   - Confusión de algoritmo RS256→HS256 (firmar con la clave PÚBLICA como secreto HMAC).
   - Secreto HMAC débil (fuerza con diccionario).
   - `jku`/`x5u`/`kid` apuntando a clave del atacante; `kid` con path traversal / SQLi.
2. **OAuth / SSO**
   - `redirect_uri` manipulado → fuga del token a servidor del atacante (validación floja:
     subdominio, path, `@`, `#`, `.attacker.com`, sufijo).
   - `state`/PKCE ausente → CSRF de login; robo de `code`.
   - ROPC grant para saltar MFA; abuso del flujo de authorization code.
3. **Sesión / reset**
   - Reset devuelve sesión sin verificar el clic del enlace; token de reset predecible/
     no expira/reusable; sesión no invalidada en logout/reset; fijación de sesión.
4. **Lógica de login**
   - Manipulación de respuesta (`false→true`, `403→200`); SQLi en login; credenciales por
     defecto; enumeración + fuerza; bypass de OTP/2FA (reuso de código, carrera, sin
     rate-limit); bypass de bloqueo de cuenta.
5. **Bypass por manipulación de petición**
   - Cabeceras (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For` para allowlists de IP);
     verbo HTTP; normalización de path (`/Admin`, `/admin/`, `/admin%2f`, `..;/`).

## El LABORATORIO (capas, como bespoke+arnm) — lo que crea lo PROPIO
- **Capa 0 — FINGERPRINT de la auth**: ¿qué mecanismo? JWT (¿alg?, ¿kid?, ¿jwks?),
  cookie de sesión, OAuth (¿qué flujo, qué validación de redirect_uri?), OTP, login-form.
  Pasivo (observar un token/flujo) + activo mínimo.
- **Capa 1 — SUPERFICIE aplicable**: del fingerprint, qué primitivas del catálogo aplican
  a ESTE stack (no las 40; las 3 que encajan).
- **Capa 2 — GENERACIÓN ADAPTATIVA (el edge)**: mutar/combinar contra la DEFENSA
  OBSERVADA, no el payload de libro. Ej.: si el `kid` tiene formato propio, generar
  inyecciones que casen ESE formato; si `redirect_uri` valida sufijo, generar los bypass
  contra ESA validación. arnm-style: prueba, lee la respuesta, contra-muta.
- **Oráculo + memoria**: confirma por acceso-autenticado-vs-401; recuerda por objetivo qué
  familias funcionan/fallan (secuencias/exclusiones).

## SIN PERJUDICAR (reglas duras, por construcción)
- PoC de SOLO LECTURA; nada que borre/modifique datos.
- Nada de fuerza bruta que bloquee cuentas (rate-limit propio, cuentas de prueba propias).
- Solo in-scope de un programa H1 que nos invitó.
- El hallazgo NUNCA se auto-envía sin revisión humana (puerta de nexus).
- Forjar tokens para NUESTRA identidad / identidades de prueba; no exfiltrar datos reales
  de terceros más allá de la prueba mínima.

## Primer ladrillo propuesto
**Capa 0 — fingerprint de auth** (empezando por JWT: detectar y parsear el token, su
`alg`/`kid`/`jku`). Puro, testeable, no destructivo. Sobre él, capa 1+2 por método.

## Fuentes (investigación 2026-08-24)
- https://blog.bugv.io/bypassing-authentication-common-tricks-used-in-bug-bounty/
- https://github.com/aw-junaid/bug-bounty (OAuth Exploitation, JWT cheatsheet)
- https://devtechnoblog.in/authentication-bypass/

---

## Determinación 2026-10-01 — JWT: "deserialización insegura" NO es un primitivo JWT; el hueco real es INYECCIÓN DE HEADER

Pregunta de partida (Juan): "investigar formas de atacar jwt, p. ej. deserialización
insegura". **Hallazgo honesto, y redirige lo que hay que construir:**

**"Deserialización insegura" NO es una clase de ataque JWT detectable en caja negra.**
La deserialización con cadenas de gadgets (Java `readObject`, .NET `TypeNameHandling`/
`$type`, PHP `unserialize`, Ruby Marshal/YAML) ocurre cuando **la APP** mete un valor
de claim en un deserializador peligroso — es app-level y grey/whitebox, no un primitivo
de la librería JWT (que decodifica JSON con serde-equivalentes seguros). El único gancho
JWT-específico sería el header `cty` (content-type anidado) despachando a un
deserializador distinto, pero es raro y teórico. **No perseguir cadenas de gadgets en
caja negra: sería un escáner de humo (D30).** Si aparece, va en otra familia (el parseo
del CUERPO de la app), no en la de auth.

**Lo que SÍ es la superficie JWT viva en 2025–2026 (y valida los huecos de abajo) son
las INYECCIONES DE HEADER** — el atacante controla el header del token y la librería le
cree. CVEs recientes, todas de caja negra y todas forjables sin secreto:

| CVE | Librería | Clase | Oráculo | ¿Lo cubre nexus? |
|---|---|---|---|---|
| **CVE-2026-27962** | Authlib ≤1.6.8 | **`jwk` embebido en el header**: `key=None` → usa la clave del atacante incrustada en el token | token forjado aceptado (acceso vs 401) | **NO** — ni se parsea |
| CVE-2026-48522 | PyJWT <2.13 | **`jku` → SSRF** (`file://`, FTP, data-URI): lee archivo local / pivota | lectura de archivo local / callback OOB | NO — `jku` se parsea, no se arma |
| CVE-2026-44699 | LibJWT 3.0–3.3.2 | **confusión con clave de longitud CERO**: JWK RSA sin `alg` → HMAC con clave vacía | token HS* con clave `""` aceptado | parcial — `ConfusionAlg` usa la pubkey, no `""` |
| CVE-2026-48523/4 | PyJWT | bypass de allow-list / DoS por `kid` | — | DoS fuera de estatuto |

### Estado real del artefacto (anclado, `src/autenticacion.rs` @ hoy, 858 líneas)
- **Vivo y cableado al hunt**: `AlgNone` (none/None/NONE/nOnE), `FirmaNoVerificada`,
  `ConfusionAlg` (pubkey del JWKS como secreto HMAC). Moldes = `[AlgNone, AlgConfusion]`.
- **Declarado pero DORMIDO**: `AtaqueJwt::SecretoDebil` existe y el primitivo
  `verificar_hs256` existe, pero **no hay bucle ni diccionario** y no está en la lista de
  moldes → nunca corre.
- **Parseado pero NUNCA armado**: `kid`, `jku`/`x5u` (solo se leen en `parse_jwt`).
- **Ausente del todo**: header `jwk` embebido.

### Buildables, por valor (cada uno = molde `MoldeAuth` + oráculo acceso-vs-401 + pareja D33)
1. **`jwk` embebido** — forjar header con nuestra clave pública RSA + `jwk:{...}` y firmar
   con su privada. Oráculo limpísimo, CVE crítico y FRESCO (Authlib), reusa `jwks.rs`
   (PEM↔(n,e) ya validado byte-a-byte). **El de mayor valor y el más acotado → empezar aquí.**
2. **`SecretoDebil`** — despertar el dormido: bucle sobre diccionario (jwt.secrets/rockyou-top),
   `verificar_hs256` contra la firma ORIGINAL; si casa, forjar. Rate-limit propio, cero
   tráfico al objetivo hasta confirmar (se verifica OFFLINE). Casi gratis (el primitivo ya está).
3. **`jku`/`x5u` → clave del atacante** — apuntar a un JWKS que hospedamos (necesita el
   verificador OOB de [[nexus-ssrf-oob-verificador]]); y su variante **SSRF `file://`**
   (CVE PyJWT) encaja con el transporte de `arnm`.
4. **`kid` injection** — path traversal (`../../dev/null` → clave vacía conocida), SQLi en
   el lookup de `kid`, apuntar a un archivo de clave predecible. Contra-mutar al FORMATO del
   `kid` observado (capa 2), no payload de libro.
5. **Confusión clave-cero** (CVE LibJWT) — variante barata de `ConfusionAlg`: probar HMAC
   con clave `""` y con los bytes crudos del JWK.

NO construir: cadenas de gadgets de deserialización (app-level, no primitivo JWT).

### Estado 2026-10-01 — LOS 5 IMPLEMENTADOS (`src/autenticacion.rs`, 17/17 tests, clippy limpio)
Implementados sin dep nueva (vía simétrica HMAC que los CVEs también cubren; la variante
RSA-firmada queda como extensión dep-gated — necesitaría `aws-lc-rs`/`ring` directo):
- `MoldeAuth::JwkEmbebido` — jwk `kty:oct` + HS256 con clave propia (Authlib `key=None`).
- `MoldeAuth::SecretoDebil` — DESPERTADO: diccionario OFFLINE vs firma original; 0 variantes si
  el secreto no es débil (pareja D33: el secreto fuerte produce vacío).
- `MoldeAuth::KidInjection` — traversal a `/dev/null` (clave `""`) + SQLi `UNION SELECT` (clave
  inyectada), firmados HS256 con esa clave.
- `MoldeAuth::ConfusionClaveCero` — HMAC con clave `""` y NUL (LibJWT).
- `MoldeAuth::JkuSsrf` — muta el header `jku` (`file://`, metadata, OOB), conserva payload+firma.
  **Oráculo OOB, no de aceptación** → NO entra en el bucle de forja de `fase_autenticacion`;
  su confirmación va por el verificador SSRF-OOB ([[nexus-ssrf-oob-verificador]]).
Los otros 4 van cableados al hunt en el array `moldes` de `fase_autenticacion` (oráculo de
aceptación forjado-vs-control-401).

### Extensión ASIMÉTRICA 2026-10-01 — HECHA (dep `aws-lc-rs`, firma RS256)
Cubre servidores que exigen RS256 y no aceptan `oct`. Dep `aws-lc-rs` (ya en el árbol por
rustls → descarga cero; `default-features=false` para omitir `ring-io`/`ring-sig-verify`, que
tiran de `untrusted 0.7.1` NO vendorizado). Clave RSA del atacante FIJA (2048-bit, PKCS#1 DER
en `src/fixtures/atacante_rsa.pkcs1.der`), firma vía `firmar_rs256`; `from_der`, NO `from_pkcs8`
(aws-lc-rs rechaza el PKCS#8 de openssl con `InvalidEncoding`). Verificación en test por
RE-FIRMA determinista (PKCS#1 v1.5 no tiene sal) — no se usa `verify` (gateado).
- `MoldeAuth::JwkEmbebidoRsa` — jwk RSA incrustado + RS256. Self-contained → **cableado al hunt**.
- `MoldeAuth::JkuAtacante` — jku → JWKS que hospedamos (clave RSA propia). Oráculo de aceptación
  pero necesita el JWKS hospedado (infra OOB) → NO cableado por defecto (como `JkuSsrf`).
Total: **7 moldes nuevos**, 5 cableados al hunt, 2 (jku-ssrf/jku-atacante) a la espera de la
infra OOB. 20 tests de auth verdes (parejas D33), clippy `-D warnings` limpio, suite completa verde.

### Fuentes (investigación 2026-10-01)
- CVE-2026-27962 (Authlib `jwk` header injection), CVE-2026-48522/48523/48524 (PyJWT
  `jku` SSRF / allow-list bypass / `kid` DoS), CVE-2026-44699 (LibJWT clave-cero).
- PortSwigger JWT Attacks; "Friday the 13th JSON attacks" (A. Muñoz, .NET `$type`).
