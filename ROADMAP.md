<!-- SPDX-License-Identifier: LicenseRef-Propietario -->
# nexus — Hoja de ruta estratégica (2026-08-21)

> Fundada en dos investigaciones: mapa de integración del código (file:line +
> esfuerzo) y estado del arte 2026 (XBOW, Big Sleep, ASM, tooling de control de
> acceso). Las cifras de leaderboard/pagos vienen de blogs comerciales — **re-verificar
> antes de citarlas en el portafolio** (directiva 16/30).

## Posicionamiento: profundidad sobre escala

No se compite en cantidad de escaneo (ProjectDiscovery gana por plantillas +
comunidad; BBOT por amplitud; Axiom por escala distribuida — todos con nube que
nosotros no tenemos). Se compite donde los gigantes son **estructuralmente
débiles** y el estado del arte lo confirma:

- **La lección central de XBOW (que llegó al #1 de HackerOne) no fue el LLM: fue
  la VERIFICACIÓN DETERMINISTA.** "Usar algo distinto de un LLM para verificar
  vulnerabilidades." Los agentes AI **alucinan** vulns; lo que gana es un
  validador que ejecuta el PoC de extremo a extremo. Esa disciplina ya es la de
  nexus (`execution_confirmed`, reproducción N/M, no auto-enviar lo no verificado).
- **El 70% de las vulns web críticas son lógica de negocio, y los agentes AI
  fallan casi por completo ahí.** El control de acceso con estado (BOLA/IDOR,
  #1 de la API Top 10) NO tiene firma estática ni plantilla — **requiere dos
  identidades reales + estado**, y **el mercado EVITA automatizar ese paso**.
  nexus (autz) ya lo tiene montado; el filtro de operabilidad de hoy resuelve el
  cuello (elegir dónde las 2 cuentas cuestan minutos). **Es el foso.**
- **El flanco de XBOW es el RUIDO** (208 duplicados / ~1.060 envíos en 90 días;
  crítica pública de "flood"). **Precisión sobre volumen** es un diferenciador
  comercial y ético defendible — y coincide con la línea de honestidad del
  proyecto.

**En una frase: no competir en cantidad de escaneo; competir en inteligencia de
explotación verificada. El template-crowd está saturado; el control-de-acceso-con-estado
y el AI-chaining-con-validador-determinista están casi vacíos.**

Calibración honesta (para no sobreprometer la capa AI): el "lab-to-real gap" es
real — pentesting autónomo sin pistas ≈ 21%, sobre CVEs reales ≈ 13%, HTB difícil
≈ 0%. El estudio ARTEMIS: la AI halló 9 vulns a \$18/h vs 13 del mejor humano a
\$60/h, pero **los humanos retuvieron la ventaja en encadenamiento creativo**. La
capa AI es un ORQUESTADOR de herramientas deterministas, no un buscador mágico.

---

## Estado tras la sesión del 2026-08-21 (ya hecho, en verde)

- Anti-FP shell-SPA (`es_html`) · evidencia en MANUAL_READY · notificaciones
  webhook · filtro de claves publicables · fase bypass robustecida (23 técnicas +
  "trae datos, no una página") · filtro de operabilidad IDOR (`nexus operabilidad`).
- 165 tests nexus + 31 lib, clippy limpio, guardián de divergencia verde.
- **Local, sin desplegar.**

---

## FASE 0 — Blindaje de reputación (barato, arregla FP medidos). Prioridad máxima.

El activo más frágil en HackerOne es la reputación; el ruido la hunde. Todo esto
es determinista y ataca un FP concreto.

### 0.1 Verificación de secretos VIVOS por proveedor (estilo trufflehog `--only-verified`) — ✅ HECHO 2026-08-21 (`src/secretos.rs`, integrado en `verify.rs content_check`, 4 tests)
- **Qué**: antes de reportar un secreto, llamada API real al proveedor para
  confirmar si la credencial está **viva ahora**. Distingue una `pk_live` de
  Stripe (publicable, pública) de una `sk_live` viva.
- **Por qué**: trufflehog detecta 94% de credenciales activas verificándolas;
  gitleaks solo dice "parece secreto". Es la forma correcta del arreglo que la
  memoria `nexus-verificacion-por-string-no-por-ejecucion` pide: verificar por
  ejecución, no por match de string. **Extiende** el filtro de claves publicables
  de hoy (que es una lista estática) a verificación activa.
- **Integración**: `verify.rs` `content_check`/`VulnType::Exposure`; un
  `verificadores/` con un handler por proveedor (AWS STS `GetCallerIdentity`,
  GitHub `/user`, Stripe `/v1/account`, Slack `auth.test`, etc.).
- **Esfuerzo M.** **Prioridad #1 de paridad.**

---

## FASE 1 — Profundizar el foso (autz). El mayor ROI estratégico.

El mercado confirma que esto es lo que ningún autónomo hace bien. Y el código dice
que buena parte es barata.

### 1.1 Priv-esc VERTICAL — **esfuerzo S (dato, no código)**
- `Papel::MenorPrivilegio` ya está clasificado (`autz.rs:164` → `PrivEscVertical`)
  y `fase_autz` ya lo ejercita. **Solo falta registrar una identidad `papel='menor'`**
  en un programa real. Cero líneas nuevas.

### 1.2 Forced browsing — **esfuerzo S/M** — ✅ HECHO 2026-08-21 (`autz::semillas_forced_browsing`, corpus de bypass, cap 48)
- Tomar las URLs 401/403 que descubre `ffuf` (`enhanced.rs:193-222`) y pasarlas a
  la `fase_bypass` ya existente. "Acceder sin permiso a una ruta descubierta" =
  exactamente lo que bypass hace. El enganche es casi gratis (comparten `corpus`).

### 1.3 Cerrar el gate cero-FP N/M — **esfuerzo M** — ✅ HECHO 2026-08-21 (deepscan P3: reproducibilidad SQLi/CMDi solo en auto-enviable, `NEXUS_SQLI_CONFIRM_*`)
- **Grieta localizada**: `execution_confirmed` es asimétrico. XSS (3 intentos en
  navegador) y Exposure (N re-fetch) tienen gate N/M; **SQLi/CMDi se auto-confirman
  en UNA corrida** (`verify.rs:414-416,470-472`) — un falso "is vulnerable" pasa
  sin segunda oportunidad. Y SSRF/LFI/RCE figuran como "pagables" (`autosubmit.rs:41-46`)
  pero **nunca llegan** a confirmarse (`verify.rs:566` → manual): código muerto por
  incoherencia — implementarlos o quitarlos de `payable_auto`.
- El framework N/M ya existe (`deepscan.rs:104-152`); extenderlo a SQLi/CMDi es
  repetir el patrón de Exposure.

### 1.4 Mass-assignment — ✅ HECHO 2026-08-21 (`src/mass_assign.rs`, gateado `NEXUS_MASS_ASSIGN`, solo objeto propio, test+sim)
- Enviar campos extra (`role`, `is_admin`) en un update del objeto PROPIO; confirmar
  con **re-fetch** del objeto (¿cambió el campo no autorizado?). El estado del arte
  lo lista como alta-automatizable con re-fetch verification.
- **Coste real**: rompe el contrato "GET-only / sin daño" del motor (`autz.rs:296`
  hardcodea `.get()`). Necesita: `Solicitud` con método+cuerpo, una **salvaguarda
  anti-daño nueva**, una fuente de payloads por endpoint, y una **costura nueva**
  (comparar antes/después del mismo dueño, no dueño-vs-otro). Por eso va después de
  1.3: sin el rigor N/M, se repite el hueco de SQLi con daño real.

---

## FASE 2 — Paridad de recon (integración compartida; secuencia impuesta por el código)

### 2.0 Generalizar `notify` a un enum de eventos — ✅ HECHO 2026-08-21 (`notify::Evento`)
- Antes de que JS/ASM/takeover le añadan casos a mano, `HallazgoBreve`/`construir_mensaje`
  (`notify.rs:20-77`) pasa a un enum de eventos (hallazgo, superficie-nueva, takeover).

### 2.1 Extracción de endpoints de JS — ✅ HECHO 2026-08-21 (`src/js_extract.rs` Rust-nativo, wire en enhanced.rs; secretos-en-JS ya vía 0.1)
- **Parser (jsluice, tree-sitter) > regex** (LinkFinder): capta URLs concatenadas +
  secretos con mucho menos FP. Descubrir JS con `katana` (ya está) → extraer →
  endpoints **alimentan `autz_semillas`** (más superficie para el foso) + secretos
  pasan por 0.1 (verificación viva). Va **antes que 2.2** (cambia qué es un "endpoint
  nuevo").

### 2.2 ASM: histórico de assets + diffing — ✅ HECHO 2026-08-21 (migración 0008, `db::registrar_assets`, diff en cmd_hunt, `Evento::SuperficieNueva`)
- **El valor está en el DIFF, no en el escaneo puntual** (Assetnote re-escanea cada
  hora y alerta de lo nuevo). Nueva tabla de assets/subdominios por programa (hoy
  no existe histórico); `cmd_hunt` (`main.rs:491-505`) diffea contra la corrida
  anterior y notifica **solo lo nuevo**. Fuentes: CT logs + permutaciones + brute DNS.
- **Construir la tabla una vez** — 2.3 la reutiliza.

### 2.3 Subdomain takeover propio — ✅ HECHO 2026-08-21 (`src/takeover.rs`, CNAME por DoH + huellas can-i-take-over-xyz, `Evento::Takeover`)
- Confirmador que valida la **cadena CNAME→backend + match del fingerprint**
  can-i-take-over-xyz, **no un 404 desnudo**. Detecta mejor sobre hosts que dejaron
  de responder / cambiaron CNAME = justo el dato que 2.2 empieza a guardar.

---

## FASE 3 — Nuevas clases de alto valor (mejor pagadas + automatizables)

### 3.1 SSRF → metadata cloud con confirmación FUERTE — ✅ HECHO 2026-08-21 (`src/ssrf.rs` inyección GET + exfiltración in-band, wire cmd_hunt, test + simulación)
- **El rey de payouts** (\$3.5k–\$50k). Confirmación = **exfiltración real de
  metadata** (IAM AWS/GCP/Azure), no solo callback OOB. nuclei ya da el callback
  (interactsh); lo nuevo es el confirmador que prueba el pivote.

### 3.2 GraphQL — ✅ HECHO 2026-08-21 (`src/graphql.rs` introspección expuesta, wire en cmd_hunt, test + simulación)
- Introspección (Clairvoyance si está desactivada), alias-batching (brute-force
  amplificado), **IDOR de campo** (ata directo al foso autz). Alta automatizable,
  \$2.5k–\$10k+.

### 3.3 Request smuggling — ✅ HECHO 2026-08-21 (`src/smuggling.rs` timing, gateado `NEXUS_SMUGGLING`, best-effort reqwest; probe crudo con dep = follow-up)
- Técnica PortSwigger 2025 ("HTTP/1.1 must die"): detectar por **discrepancia de
  parsing**, no por payload. Poco automatizado, alto impacto, encadena a cache
  poisoning. Diferenciador defendible.

---

## FASE 4 — El salto: capa de planeación LLM-agente

**Va al final**: es transversal y depende de que 1-3 estabilicen sus interfaces.

### 4.0 Fundación — exponer las fases — **esfuerzo M**
- Hoy todo pasa por subcomandos `clap` en `main.rs`; no hay API interna y `web.rs`
  es solo lectura. Hace falta: brazos `Command` explícitos `Autz{program}`/`Bypass{program}`,
  rutas `POST` en el panel, y **salida JSON estructurada** por subcomando (hoy solo
  `tracing::info!`). Es fundación, no lógica.

### 4.1 El cerebro — arquitectura Planner-Executor (NO single-agent ReAct)
- El estado del arte es claro: single-agent ReAct (PentestGPT) se ahoga en el
  context window; **Planner-Executor (VulnBot) da ~4.3× sobre monolítico**. Un
  coordinador que lee recon/findings, forma hipótesis y despacha las herramientas
  DETERMINISTAS de nexus.
- **La regla de oro (lección XBOW): el LLM planea y encadena; NUNCA valida.** El
  oráculo siempre es determinista — el navegador de `browser.rs`, el diff de autz,
  el re-fetch de mass-assignment, la exfiltración real de SSRF. El LLM propone; el
  código confirma. Así se evita la alucinación de vulns.
- Calibrar expectativas: 13-21% en real; es multiplicador de las herramientas, no
  sustituto.

---

## Tejido transversal — Precisión como marca

- El gate N/M en TODAS las clases (0.1, 1.3), verificación de secreto viva,
  validación de PoC de extremo a extremo. Es lo que hace VIABLE el auto-envío sin
  quemar reputación — y el argumento comercial/ético frente al flood de XBOW.
  "Reportamos menos, pero todo verificado end-to-end."

---

## Secuenciación (dependencias reales)

```
FASE 0.1 (secretos vivos) ─── independiente, PRIMERO (arregla FP medido, barato)
FASE 1.1 (priv-esc vert.) ─── S, casi inmediato (solo una identidad)
FASE 1.2 (forced browsing)─── S/M, reusa bypass
FASE 1.3 (cero-FP N/M) ────── M, PREREQ de 1.4
FASE 1.4 (mass-assignment)── L, tras 1.3
FASE 2.0 (notify enum) ────── S, PREREQ de 2.1/2.2/2.3
FASE 2.1 (JS parser) ──────── M, antes de 2.2
FASE 2.2 (ASM diff+tabla) ─── M/L, construye la tabla de assets
FASE 2.3 (takeover) ───────── M, reusa la tabla de 2.2
FASE 3.1/3.2/3.3 (SSRF/GraphQL/smuggling) ── clases nuevas, valor alto
FASE 4.0 (exponer fases) ──── M, tras estabilizar 1-3
FASE 4.1 (planner LLM) ────── el salto, al final
```

**Prioridad #1 global (une paridad + foso):** (a) **secretos vivos** (0.1) protege
la reputación HOY; (b) **cerrar autz con identidades reales** (1.1 + el pipeline de
operabilidad ya hecho) es lo que ningún autónomo del mercado hace bien. Lo primero
es barato y urgente; lo segundo es el foso.

---

## Pendiente de ingeniería — Validación externa contra los benchmarks de XBOW (2026-09-05)

**Idea (del estudio `analisis/estudio-xbow.md`).** XBOW publicó
`xbow-engineering/validation-benchmarks`: **104 apps web vulnerables dockerizadas**
con scoring por flag exacto (SSRF, authz roto, SQLi/SSTI/cmdi, XSS, blind SQLi).
Son artefactos **abiertos y escritos por terceros**.

**Qué aporta, y por qué NO es dar vueltas (D37).** Hoy `fp_lab`/`fp_app` mide la
discriminación de las gates (`refutacion.rs`) y del certificado contra apps trampa
que escribimos NOSOTROS — D33 a medias (mutante y trampa propios). Correr las gates
+ `certificado::es_valido` + los oráculos que SÍ tenemos (authz, SSRF, XSS) contra un
subconjunto de las 104 es **medir el juicio contra un artefacto ajeno** (D16/D33 a
nivel de app), y da **evidencia de portafolio** ("gates verificadas contra el
benchmark público de XBOW") que sostiene el certificado de no-slop.

**Alcance acotado (no reconstruir el cazador autónomo, [[nexus-detenido-efecto-brain]]).**
NO es correr un solver autónomo contra las 104. Es: seleccionar las apps de las clases
con oráculo propio, levantarlas en Docker local, y pasar SOLO las gates + oráculos
diferenciales, midiendo FPR/TPR contra el flag conocido. Trabajo: M/L (clonar + compose
+ un runner que reuse `fp_app::evaluar_sistema`). No toca producción.

**Estado (2026-09-05):** GO dado por Juan. Iniciado — clon estudiado, verdad-de-terreno
decidida (el TAG, no el flag), **40 apps seleccionadas en 3 clases con oráculo propio**
(XSS 23 / IDOR 14 / SSRF 3) con su split positivo/negativo, y diseño del runner reusando
`fp_app::evaluar_sistema` (D9). Plan completo en `analisis/xbow-bench-plan.md`.
**RESULTADO (2026-09-05):** Docker instalado (data-root en /mnt/data/docker). Feasibility
medida sobre 6 apps → **yield 3/6**: SSRF 3/3, IDOR 0/2, XSS 0/1. **Bit-rot fundamental**
(apps de 2024: XSS con debian buster 404 + phantomjs extinto; IDOR con digests mysql
malformados). Y lo decisivo (D30): la clase EDGE (IDOR/authz) es la que NO compila.
**Determinación:** el benchmark de XBOW NO sirve como validador llave-en-mano en 2026 y
NO se repara app-por-app (D37). Camino recomendado: pivotar a suite MANTENIDA (Juice
Shop/DVWA/WebGoat) o quedarse con `fp_lab`. El pipeline de orquestación quedó probado y
reusable (`analisis/xbow-orquesta.sh`). Detalle: `analisis/xbow-bench-plan.md`.

**CERRADO (2026-09-05, Juan delegó la decisión).** Se cierra la validación externa: el
valor del hilo (el certificado anti-slop + su fix del edge) ya está banqueado y validado
internamente (`fp_lab` FPR=0/TPR=1 + mutación), y toda vía externa cuesta desproporcionado
(D37). La suite MANTENIDA (Juice Shop/DVWA) queda documentada como opción para cuando se
REACTIVE la caza de nexus — no antes. Residuo borrable: clon 1.5G + ~2G docker en
/mnt/data (el `rm -rf` quedó bloqueado por regla de permisos; lo borra Juan cuando quiera).

---

## Nexus dual-modo (whitebox + blackbox) — núcleo HECHO 2026-09-05

Pregunta de Juan: qué necesita nexus para operar en white y black. Insight: el razonador
(modelar→invariante→refutar→confirmar) y el certificado son IDÉNTICOS; solo cambian la
ENTRADA (fuente vs comportamiento observado) y la CONFIRMACIÓN (lab vs objetivo vivo).

**HECHO (commit 1f715410), con tests + clippy:**
- `oraculo_diferencial.rs` — el DESTINO de confirmación común. `Modo{Whitebox,Blackbox}` +
  `Identidad`/`Objetivo`/`CasoDiferencial` + `sonda()` → `Certificado`. Mismo runner para
  lab (white) y vivo con cuentas provisionadas (black).
- `modelo_authz.rs` — la ENTRADA whitebox. `asimetria_de_gate()`/`candidatos()`: surfacer de
  la "oveja negra" (gate ausente donde la mayoría lo tiene) para el razonador.

**PENDIENTE (siguientes incrementos, no urgentes):**
1. **Wiring CLI** — un subcomando `nexus oraculo --white|--black` que arme `Objetivo` +
   `CasoDiferencial` desde flags/archivo y llame `sonda`; imprimir el certificado.
2. **Constructor de lab genérico** — generalizar el `docker compose up` + siembra de N
   identidades (lo ad-hoc de Rocket.Chat/Zabbix) a un helper reutilizable, para el modo white.
3. **ENTRADA blackbox** — alimentar `CasoDiferencial` desde recon en vivo (superficie
   observada) en vez de del fuente; reusa recon/nuclei-moldes existentes.
4. **Barandillas por modo** — white no toca nada externo; black exige scope + pacing
   (`protection.rs`/`scope.rs`) + estatuto "sin daño" antes de `sonda` contra un vivo.

**Guardarraíl (D37):** NO reconstruir la caza autónoma de amplitud (era slop). El 20% de
razonar se queda Claude-en-el-loop; esto solo unifica la CONFIRMACIÓN (oráculo de verdad) y
mecaniza el PRIMER filtro del modelado.

### Actualización 2026-09-05 — los 4 incrementos CERRADOS (commit a88b2b77)
1. **CLI `nexus oraculo --black|--white`** ✅ (E2E: whitebox loopback con fuga → HALLAZGO +
   certificado 3/3 + exit 0).
2. **`lab.rs`** ✅ (docker compose up --wait/down -v + `esperar_http` con tope; `--lab` levanta
   y baja siempre).
3. **Entrada blackbox** ✅ vía caso JSON (endpoint + identidades provisionadas, same-shape que
   el lab); *auto-generar el caso desde recon en vivo* queda como único resto futuro.
4. **`guardia()`** ✅ barandilla por modo (white=loopback, black=scope obligatorio), verificada
   E2E que aborta ANTES de tocar red. 341 lib tests, clippy limpio.

### Actualización 2026-09-05 (2) — oráculo de TIEMPO REAL (DDP/websocket) HECHO (commit b9d96a1b)
El transporte que faltaba: el hallazgo de Rocket.Chat era por stream DDP. `ws_min.rs`
(cliente WS propio, RFC 6455, ws://, sin dependencia nueva — base64+sha1 ya vendorizados) +
`oraculo_realtime.rs` (`sonda_realtime`, mismo Veredicto/Certificado) + `nexus oraculo
--realtime`. E2E: server WS con fuga → HALLAZGO+certificado; owner-only → SÓLIDO. 344 tests.
**Pendiente menor:** `wss://` (TLS) para objetivo vivo blackbox — hoy solo `ws://` (lab).
Con esto los DOS transportes (HTTP y realtime) cierran por el mismo certificado.
