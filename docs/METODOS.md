<!-- SPDX-License-Identifier: MIT -->
# Métodos de hackeo en nexus — catálogo, cotejo y brechas

Este documento cataloga las **técnicas de ataque web** que nexus puede ejecutar
hoy, coteja cuáles están realmente implementadas contra cuáles no, y —para las
que faltan y aplican a un programa de *bug bounty*— determina **qué herramienta y
qué protección** haría falta para añadirlas.

No es aspiracional: cada fila «implementado» cita el módulo y la función que lo
hace. Cada fila «no cubierto» se verificó por ausencia en el código
(`grep` sobre los 24 archivos de `src/`), no por memoria.

> **Alcance.** nexus caza en programas donde hay autorización explícita (el
> scope lo valida `scope.rs` antes de tocar nada). Este catálogo describe
> capacidad técnica dentro de ese marco, no permiso: el permiso lo da el
> programa.

## Cómo lee nexus el mundo (la tubería)

```
scope ──► recon ──► enhanced ──► nuclei ──► verify ──► confirm ──► autz/bypass ──► evidence ──► submit
(salvaguarda) (subdominios/  (gau,katana, (plantillas) (herramienta (Chromium   (IDOR/BAC,   (screenshot) (H1)
              hosts vivos)   ffuf,arjun)              especializada) real)      evasión 403)
```

Cruzando toda la tubería, dos capas de **protección** deciden el ritmo:
`evasion.rs` (anti-WAF adaptativo) y `protection.rs` (`Guard`: anti-baneo de IP).
Ninguna fase toca red sin pasar por ellas.

---

## 1. Métodos IMPLEMENTADOS (con motor propio o herramienta orquestada)

| Método | Clase OWASP | Estado | Módulo / función | Herramienta | Confirmación |
|---|---|---|---|---|---|
| **SQL injection** | A03 Injection | ✅ verificado | `verify.rs::sqlmap_cmd`/`interpret_sqlmap` | `sqlmap` | por la herramienta |
| **Command injection** | A03 | ✅ verificado | `verify.rs::commix_cmd`/`interpret_cmdi` | `commix` | por la herramienta |
| **XSS (reflejado/almacenado)** | A03 | ✅ **confirmado por ejecución** | `verify.rs` (pista) → `browser.rs::confirm_xss` | `xsstrike` + `chromium` | ejecución real en Chromium headless con marcador `data-nxproof` computado |
| **IDOR / BOLA** (acceso horizontal) | A01 Broken Access Control | ✅ motor propio | `autz.rs::fase_autz`/`observar`/`diffear` | ninguna (HTTP propio) | diff de respuestas entre identidades |
| **BAC** (privesc vertical / fuga sin auth) | A01 | ✅ motor propio | `autz.rs::clasificar`/`fase_autz` | ninguna | diff entre `Anon`/`Usuario`/`Tercero` |
| **Bypass de 401/403** | A01 (evasión de control) | ✅ 14 técnicas | `autz.rs::fase_bypass`/`observar_evasion`/`TECNICAS` | ninguna | cabeceras `X-Forwarded-For`/`X-Original-URL`, sufijos `/`,`/.`,`%2e`,`/..;/`, verb tampering |
| **Vulnerabilidades conocidas (CVE)** | — | ✅ por plantillas | `engine.rs::run_phase` (tag `cve`) | `nuclei` | por la plantilla |
| **Exposición de secretos** | A02 / API | ✅ propio + plantillas | `verify.rs::content_check`/`classify_exposure` + nuclei (`secret,token,exposure`) | `nuclei` | lectura de contenido (AWS key, private key, bearer, api_key, password) |
| **Default creds / misconfig** | A05 Security Misconfiguration | ✅ por plantillas | `engine.rs` (tags `default-login,misconfig,config`) | `nuclei` | por la plantilla |
| **Descubrimiento de contenido** | (recon) | ✅ | `enhanced.rs::parse_ffuf_json` | `ffuf` | fuerza bruta con wordlist |
| **Parámetros ocultos** | (recon) | ✅ | `enhanced.rs::parse_arjun_json` | `arjun` | fuzzing de parámetros |
| **Enumeración de subdominios** | (recon) | ✅ | `recon.rs::subfinder_one` | `subfinder` | pasivo |
| **URLs históricas / crawl** | (recon) | ✅ | `enhanced.rs` | `gau`,`waybackurls`,`katana` | archivos + crawl activo |

**Protección asociada (cruza todo lo anterior):** anti-baneo de IP
(`protection.rs::Guard` — cooldowns con jitter ±20 %, backoff exponencial,
cortacircuitos por fallos consecutivos) y evasión anti-WAF adaptativa
(`evasion.rs` — rotación de User-Agent, `note_block` baja el ritmo y sube el
delay, proxy saliente).

---

## 2. Métodos PARCIALES (se clasifican, pero SIN verificador propio)

`VulnType` (`verify.rs:12`) reconoce estos tipos y los enruta, pero su `tool()`
devuelve `None`: nuclei **puede** emitir un hallazgo con el tag correspondiente,
pero **no hay verificación automática posterior** — caen a revisión manual.

| Método | Clase | Estado | Qué falta |
|---|---|---|---|
| **SSRF** | A10 SSRF | ⚠️ solo clasificado (`VulnType::Ssrf`, tag nuclei `ssrf`) | verificador con **callback OOB** (dominio colaborador) que confirme la petición saliente |
| **LFI / Path Traversal** | A03/A05 | ⚠️ solo clasificado (`VulnType::Lfi`, tag `lfi`) | verificador que pruebe lectura de archivo canónico (`/etc/passwd`, `win.ini`) y traversal codificado |
| **RCE** | A03 | ⚠️ solo clasificado (`VulnType::Rce`) | más allá de commix: verificación por OOB / marcador de ejecución |
| **Open Redirect** | A01 | ⚠️ solo clasificado (`VulnType::Redirect`, tag) | verificador que siga el `Location` y confirme redirección a dominio externo controlado |
| **Subdomain takeover** | A05 | ⚠️ delegado a nuclei (tag `takeover`), sin motor propio | motor propio que resuelva CNAME colgante contra huellas de servicios (S3, GitHub Pages, Heroku…) |

**Clickjacking** aparece pero se **descarta activamente** como no accionable
(`is_informational_class`/`WONT_FIX`) — es una decisión deliberada, no una
brecha.

---

## 3. Métodos NO cubiertos y APLICABLES — brecha, herramienta y protección

Verificado por ausencia total en `src/` (0 menciones): **CORS mal configurado,
SSTI, XXE, request smuggling, cache poisoning, prototype pollution, GraphQL,
CSRF, subida de archivos, secretos en JS del cliente**. Para cada uno, si aplica
al *bug bounty* web, la técnica, la herramienta y la protección que exigiría:

| Método | Por qué aplica | Herramienta necesaria | Protección necesaria |
|---|---|---|---|
| **CORS mal configurado** | Muy común y de alta señal; `Access-Control-Allow-Origin` reflejado + `-Allow-Credentials: true` = robo de datos autenticados. Motor propio **trivial** (una petición con `Origin:` atacante, leer 2 cabeceras) | ninguna — HTTP propio, como `autz` | ninguna extra (1 petición por endpoint; entra en el ritmo del `Guard`) |
| **Subdomain takeover (motor propio)** | nexus ya enumera subdominios; el takeover es la explotación natural de esa lista. Hoy depende de una plantilla nuclei | resolución DNS de CNAME + tabla de huellas (fingerprints de servicios) | baja: consultas DNS, no al objetivo; poco riesgo de baneo |
| **SSRF (verificador OOB)** | Crítico y muy pagado; hoy solo se clasifica | **servidor de interacción OOB** propio (tipo interactsh) o integrar `interactsh-client` | media: el callback confirma sin martillear el objetivo |
| **SSTI** | Alta severidad (suele escalar a RCE); ausente | motor propio de *polyglot* (`${7*7}`, `{{7*7}}`, `<%= 7*7 %>`) + detección del producto (49) en la respuesta; o `tplmap` | media: pocas peticiones, payloads distinguibles → cuidado con WAF |
| **XXE** | Aplica donde hay XML/SOAP/SVG; ausente | motor propio (payload con entidad externa + OOB) o plantillas nuclei dedicadas | media (OOB) |
| **Secretos en JS del cliente** | nexus ya baja URLs (gau/katana) pero no analiza el JS; hay claves API/endpoints en bundles | descargar `.js` + reglas tipo `trufflehog`/`gitleaks` sobre el cuerpo (patrones de secreto) | baja: descarga estática, cacheable |
| **GraphQL** | Introspección abierta + IDOR sobre nodos; endpoints `/graphql` cada vez más comunes | motor propio: query de introspección + fuzzing de campos; casa con `autz` para BOLA sobre nodos | baja-media |
| **CSRF** | Aplica a acciones con estado sin token/SameSite | motor propio: detectar formularios/acciones sin token anti-CSRF | baja |
| **Subida de archivos** | Bypass de tipo/extensión → webshell; alta severidad | motor propio con matriz de bypass (doble extensión, `Content-Type`, magic bytes) | media: sube ficheros → ruido, cuidar el ritmo |
| **Request smuggling / cache poisoning / prototype pollution** | Alta severidad pero **especializados y frágiles**; ROI menor y riesgo de romper el objetivo | herramientas dedicadas (`smuggler`, específicos) | **alta**: pueden degradar el servicio → chocan con el marco de «no dañar» del bug bounty |

---

## 4. Herramientas — matriz actual y lo que falta

**Orquestadas hoy** (todas por `tools::run`/`run_streaming`, subproceso sin
shell, ruta configurable en `config.rs`): `subfinder`, `httpx`, `nuclei`,
`sqlmap`, `xsstrike`, `commix`, `gau`, `waybackurls`, `katana`, `ffuf`, `arjun`,
`chromium`.

**Que faltarían para cerrar las brechas de mayor ROI:**
- **Servidor de interacción OOB** (interactsh propio o `interactsh-client`) —
  desbloquea SSRF, XXE, RCE ciego, SSTI ciego. Es la pieza que más técnicas
  habilita de una vez.
- **Motores propios sin binario nuevo** (CORS, subdomain takeover, GraphQL
  introspección, CSRF, secretos-en-JS): son HTTP + parseo, el mismo patrón que
  `autz.rs`. **No añaden dependencia externa** — encajan con directiva 26/38
  (Rust propio) y con el estándar del proyecto.

---

## 5. Protecciones — postura actual y por método nuevo

**Hoy** (cruza toda la tubería):
- `protection.rs::Guard` — anti-baneo de IP: cooldowns con jitter ±20 %, backoff
  exponencial, cortacircuitos por fallos consecutivos, señales de baneo.
- `evasion.rs` — anti-WAF adaptativo: pool de User-Agent, `note_block` reduce el
  ritmo y sube el delay, proxy saliente.
- `scope.rs` — salvaguarda de alcance (dominio exacto / wildcard / CIDR) **antes**
  de tocar nada: la primera protección es no salirse del programa.

**Regla al añadir un método:** todo motor nuevo entra **detrás del `Guard` y de
`evasion`** (nunca abre su propio camino de red), y los métodos ruidosos (subida
de archivos, SSTI, smuggling) se acotan en concurrencia y se marcan como
degradables ante `note_block`. Los que confirman por **OOB** son los más seguros
para el objetivo, porque la prueba no lo martillea.

---

## 6. Determinación (directiva 27)

Orden por **(señal × facilidad) ÷ riesgo**. Los tres primeros son motores HTTP
propios, sin binario nuevo, patrón `autz.rs` — máxima relación valor/coste:

1. **CORS mal configurado** — motor propio trivial, alta señal, riesgo nulo. *(Construir.)*
2. **Subdomain takeover propio** — nexus ya tiene la lista de subdominios; cierra el ciclo. Resolución CNAME + tabla de huellas. *(Construir.)*
3. **Secretos en JS del cliente** — reusa las URLs de gau/katana; reglas de patrón sobre los `.js`. *(Construir.)*
4. **Servidor OOB (interactsh propio)** — habilita SSRF/XXE/RCE-ciego/SSTI-ciego de una vez; es la inversión de mayor apalancamiento, pero mayor esfuerzo. *(Diseñar primero.)*
5. **GraphQL** (introspección + BOLA sobre nodos vía `autz`) y **CSRF** — motores propios, señal media. *(Construir tras 1-3.)*
6. **SSTI / XXE / subida de archivos** — dependen del OOB (4) para confirmar a ciegas; ruidosos. *(Después del OOB.)*
7. **Request smuggling / cache poisoning / prototype pollution** — **no construir por ahora**: frágiles, riesgo de dañar el objetivo, ROI bajo. Se revisa si un programa concreto lo pide.

Cada ítem 1-6 es una tarea de ingeniería con desenlace en código; el 7 es una
determinación de *no hacer* con su motivo.
