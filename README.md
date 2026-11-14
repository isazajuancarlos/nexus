<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 Juan Carlos Isaza
-->
# NEXUS

Orquestador de bug bounty en **Rust**. Unifica los dos proyectos Python previos
—`hacker/` (sniper mínimo) y `bounty/` (pipeline completo)— en un solo binario.

**Idea rectora:** el motor son binarios externos (`nuclei`, `subfinder`,
`httpx`, y luego `sqlmap`/`gau`/`katana`/…). Rust **no reimplementa el motor**:
lo dirige, **protege la IP** para que no la baneen, deduplica y persiste. Un
único ejecutable, una base SQLite por instancia, pensado para correr en un VPS
de **bajos recursos** (6 vCPU / 11 GiB / sin swap).

## Arquitectura

```
main.rs        CLI (clap) + runtime tokio + wiring de subcomandos
config.rs      ~22 flags heredados; safe-mode; rutas de herramientas
protection.rs  ANTI-BANEO: cooldowns, backoff, jitter ±20%, salud de red   ← núcleo
tools.rs       ejecutor de subprocess (tokio::process); conserva stdout al expirar
h1.rs          cliente HackerOne (reqwest, basic auth)
recon.rs       subfinder + httpx; SIEMBRA el activo del scope, resetea por ciclo
engine.rs      nuclei por fases (CRITICAL→HIGH), parseo JSONL, dedup
scope.rs       validación in-scope (wildcard + CIDR)
verify.rs      máquina de estados de verificación profunda (enums tipados)
report.rs      informe markdown + CVSS
db.rs          SQLite (sqlx), dedup por índice único (url, vuln_name)
```

## Uso

```bash
cargo build --release          # binario en target/release/nexus

cp .env.example .env           # y rellena H1_USER / H1_TOKEN
./target/release/nexus recon                 # H1 → subfinder → httpx → enhanced recon → targets
./target/release/nexus --sources h1,arkadiyt,chaos recon   # fusiona varias fuentes de scope (dedup)
./target/release/nexus scan --program acme   # nuclei por fases + deep-verify encadenada
./target/release/nexus verify --limit 500    # verifica pendientes (sqlmap/xsstrike/commix)
./target/release/nexus evidence              # screenshots (Chromium headless) de los verificados
./target/release/nexus submit                # informes por hallazgo con CVSS → manual_reports/
./target/release/nexus report                # regenera scans/scan_report.md
./target/release/nexus serve                 # panel web embebido (axum) en 127.0.0.1:8003

# SELECCIÓN de OSS joven para el carril whitebox de código-fuente (la capa que la auditoría
# 2026-10-21 halló ausente: el resto de nexus es live-DAST). Keyless (search API + advisories
# de GitHub). EMBUDO, no oráculo: `PERSEGUIR` = vale una lectura puerta-0, no "tiene un bug".
# SELECCIONA y TRÍA, nunca encuentra-y-envía. Cruza la LISTA-NEGRA para no re-ofrecer descartes.
# Demota a `evitar` lo que NO es app auditable (research/SDK/CLI/scraper/demo/escritorio): puerta
# conservadora medida sobre la 1ª corrida (mató 9/11 no-apps, 0 falsos positivos sobre apps reales).
./target/release/nexus candidatos --dominio helpdesk --dominio booking --lang Go --max 8
./target/release/nexus candidatos --dominio "patient management" --lang PHP --anios 2 --salida cand.md

# descubre PARÁMETROS OCULTOS de un endpoint por anomalía (técnica de Arjun): línea base
# de factores + reflexión de un centinela, bisección de lotes. Alimenta autz/mass_assign.
./target/release/nexus parametros --url https://t/api/x
./target/release/nexus parametros --url https://t/api/x --metodo post-json --cabecera "Authorization: Bearer …"
# (además: `nexus scan --mass-assign --mass-assign-descubrir` inyecta los campos ocultos
#  descubiertos como candidatos de mass-assignment sobre el objeto propio del dueño.)

# SECRETOS en el JS servido: baja el HTML raíz + sus bundles .js (con evasión de WAF) y los
# pasa por el detector por patrón. El valor se ENMASCARA; `--verificar` confirma por ejecución
# que la key está VIVA (opt-in, solo si el scope autoriza usar la credencial). Clase del leak
# de partners de Microsoft (key de Azure Search en el JS del cliente).
./target/release/nexus secretos-js --url https://t
./target/release/nexus secretos-js --url https://t --max-js 50 --verificar

# ENDPOINT QUE EMITE TOKEN SIN CREDENCIAL: sondea /token,/refresh,/RefreshAccessToken… sin auth.
# No reporta por presencia: con --protegido confirma por ORÁCULO DIFERENCIAL (abre el protegido
# CON el token, cerrado SIN él). Familia "la auth no se hace respetar".
./target/release/nexus token-sin-auth --url https://t
./target/release/nexus token-sin-auth --url https://t --protegido https://t/api/privado

# RED-TEAM de seguridad de LLM contra un endpoint de chat AUTORIZADO: corpus OWASP LLM
# Top 10 (prompt-injection/jailbreak/leak/exfil/indirect/guardrail) con oráculo de canario.
./target/release/nexus redteam-llm --url https://t/api/chat --campo message --ruta-respuesta reply
./target/release/nexus redteam-llm --url https://t/api/chat \
  --plantilla-cuerpo '{"messages":[{"role":"user","content":"{{PAYLOAD}}"}]}' \
  --ruta-respuesta choices.0.message.content --categoria jailbreak

./target/release/nexus scan --no-deep-scan --program acme   # solo nuclei, sin verificar

./target/release/nexus scan --safe-mode      # ritmo conservador para targets sensibles
```

Todo flag tiene su variable de entorno equivalente (`NEXUS_RATE_LIMIT`, etc.)
para fijarlo desde el `.service` sin tocar el `ExecStart`.

## Anti-baneo de IP (por qué no os banean)

`protection.rs` porta el sistema de protección de `bounty/`:

| Palanca | Normal | `--safe-mode` |
|---|---|---|
| Rate limit nuclei (`-rl`) | 150/s | ≤100/s |
| Concurrencia (`-c`) | 25 | ≤15 |
| Máx. hosts/programa | 750 | ≤300 |
| Cooldown entre programas | 60 s | ≥120 s |
| Cooldown entre fases | 30 s | ≥60 s |

Además, **siempre**: jitter ±20% en cada espera (rompe el patrón temporal),
backoff exponencial 120 s→30 min ante fallos, pausa tras 3 fallos / 5 errores de
red seguidos, y chequeo de salud de red antes de golpear. Las funciones de
jitter/backoff son puras y están probadas a escala (ver `tests/simulation.rs`).

## Pruebas

```bash
cargo test        # unitarias + integración (stubs de herramientas) + simulación
```

- **Unitarias**: jitter/backoff/timeout, parseo JSONL, scope, clasificación y
  reintento de verificación.
- **Integración** (`tests/`): arranca stubs reales de nuclei/subfinder/httpx como
  subprocess y comprueba el pipeline de punta a punta (cruza la frontera del
  programa).
- **Simulación**: 360 inserciones concurrentes → 120 únicas (el dedup discrimina
  bajo concurrencia); protección probada sobre 100+ valores.

## Protecciones y paridad con hack/

Portado de la versión Python más avanzada (`hack/`), todo en Rust:

- **Evasión adaptativa**: rota User-Agent, soporta `--proxy`, y al detectar
  WAF/429/403 **halva el ritmo y crece el delay** (el reintento difiere del que
  fue bloqueado) — cableada en nuclei y en la verificación profunda.
- **Scope fail-closed**: nunca escanea sin scope validado; filtra objetivos a
  in-scope antes de nuclei (`--no-scope-validation` para forzar).
- **Budget cap**: acota la entrada de nuclei a lo que cabe en el timeout al ritmo
  actual (bajos recursos).
- **Gate estricto** de envío: explotable + verificador real + severidad
  crítica/alta. **Agrupa** un reporte por (programa, vuln) con todas las URLs,
  con `structured_scope_id` y **PoC crudo**.
- **`nexus sync`**: refresca en H1 el estado del reporte y el **bounty cobrado**.
- **content_check** en proceso para EXPOSURE (secreto real→explotable, login→no),
  sin herramienta externa.

## Alcance y reporte

- **Solo programas que pagan.** Las tres fuentes filtran recompensa: H1 API
  (`eligible_for_bounty`), Chaos (`bounty:true`) y arkadiyt (por plataforma:
  H1 `offers_bounties`+`eligible_for_bounty`, Bugcrowd `max_payout>0`,
  Intigriti/YWH `max_bounty>0`). Medido: en H1 eso descarta ~89% de los targets
  (VDPs sin recompensa).
- **Reporte a H1: manual por defecto, auto-envío opt-in.**
  - Por defecto `submit` genera un `.md` por hallazgo (CVSS + impacto + evidencia
    + remediación) en `manual_reports/`, para revisar y pegar a mano.
  - Con **auto-envío** (opt-in, `--auto-submit` o `submit --auto`) nexus reporta
    solo a H1, sin esperar a un humano — porque el primero que reporta se lleva
    el bounty y un hallazgo puede llegar a cualquier hora. Vía API
    `POST /v1/hackers/reports`.
  - **Salvaguardas** para no quemar la cuenta: solo el tramo de máxima señal
    (VERIFIED + explotable + confianza **alta**); dedup por estado `REPORTED`
    (no reenvía); atribución obligatoria host→programa (si no mapea, queda
    manual); rate-limit con jitter entre envíos; y `submit --auto --dry-run`
    para previsualizar sin tocar H1.

```bash
nexus submit --auto --dry-run          # previsualiza qué auto-enviaría
nexus submit --auto                     # envía de verdad el tramo de alta señal
nexus --auto-submit scan --program acme # escanea y auto-envía en la misma pasada
```

## Control de acceso (IDOR/BAC) — el motor `autz`

nuclei empareja plantillas: no ve authz/IDOR/lógica de negocio, que es donde está
el dinero en programas maduros. El módulo `src/autz.rs` lo cubre comparando la
MISMA petición vista por varias IDENTIDADES: si una que NO es dueña del recurso
recibe 200 con el mismo cuerpo que la dueña, hay costura de acceso (el predicado
sale de nuestra doc defensiva invertida: un IDOR bien cerrado responde 404, nunca
403). Detecta `IdorHorizontal`, `PrivEscVertical` y `FugaSinAuth`, con confianza
Alta (firma exacta, tras normalizar lo reflejado de la credencial) o Media (solo
longitud). Los hallazgos NO se auto-envían: van a revisión manual.

Solo corre si el programa tiene un juego de identidades montado (config manual;
no-op para el resto). Se llenan dos tablas a mano:

```sql
-- identidades: papel = dueno | par | menor | anonimo (el anónimo va sin cabeceras)
INSERT INTO identidades (program_name, papel, cabeceras)
  VALUES ('acme', 'dueno', '[["Cookie","session=..."]]');
INSERT INTO identidades (program_name, papel, cabeceras)
  VALUES ('acme', 'par', '[["Cookie","session=..."]]');
-- semillas: URLs de recursos PROPIOS del dueño (privados) que el recon no ve
INSERT INTO autz_semillas (program_name, url)
  VALUES ('acme', 'https://acme.test/account/settings');
```

Para probar identidades sin el coste de nuclei: `nexus --no-scan scan --program
acme --targets <archivo>` corre solo la fase de control de acceso. Config:
`NEXUS_AUTZ_CAP` (tope de endpoints, 200) y `NEXUS_AUTZ_COOLDOWN_SECS` (pausa
anti-baneo, 2). Validado por simulación: 0 falsos positivos y 0 falsos negativos
en 120 endpoints (`tests/simulacion_autz.rs`).

## Cazador autónomo (systemd timer)

Para operar solo, `deploy/nexus-hunt.timer` dispara `deploy/nexus-cycle.sh` cada
2 h. Cada ciclo **rota al siguiente programa H1** (que paga y con submission
abierto) y hace `recon --only <handle>` + `scan` (nuclei → deep-verify →
auto-envío) en `--safe-mode`. Con N programas, cada uno se revisita cada ~N·2 h:
cobertura gradual, sin hammering ni riesgo de baneo.

Dos salvaguardas del scheduling por BD:
- **Reconciliación de huérfanos.** Si un ciclo muere a mitad de nuclei (SIGKILL
  de systemd al vencer `TimeoutStartSec`, OOM), su fila de `scan_logs` quedaría
  en `running` para siempre. Al arrancar, el cazador cierra a `interrupted` toda
  fila `running` más vieja que `TimeoutStartSec` (nunca una viva). El origen del
  problema se evita poniendo `NEXUS_SCAN_DEADLINE_SECS` por debajo del
  `TimeoutStartSec` del `.service`, para que el ciclo pare limpio antes del SIGKILL.
- **Cuarentena de estériles.** Un programa que acumula timeouts sin completar
  jamás un escaneo se deprioritiza (no se excluye): deja de elegirse por delante
  de programas frescos y se reintenta cuando los sanos están más recientes. En
  cuanto completa uno, vuelve solo a la prioridad normal (auto-sanable).

Y dos modos de enhanced recon según la cadencia:
- **Caza de 2 h → `--recon-passive-only`.** Da a nuclei una superficie real de
  endpoints con gau + waybackurls (pasivo, 0 peticiones al target) + katana
  (crawl siguiendo enlaces), pero **omite la fase activa** (ffuf brute-force +
  arjun): la parte agresiva que arriesga baneo de IP y viola políticas
  anti-scanner. Respeta el `NEXUS_SCAN_DEADLINE_SECS` (no se come el tiempo de
  escaneo).
- **Caza profunda semanal → enhanced recon completo** (con ffuf), sin deadline,
  a fondo sobre un programa.

- La lista de programas se cachea en `~/nexus/handles.txt` (semanal, de arkadiyt).
- **Para respetar políticas anti-automatización**: edita `handles.txt` a mano con
  solo los programas que permitan herramientas automáticas y hazlo `chmod 444`
  (el script no lo sobrescribe).
- El auto-envío dispara si `NEXUS_AUTO_SUBMIT=1` en el `.env`.

```bash
sudo cp deploy/nexus-hunt.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now nexus-hunt.timer
systemctl list-timers nexus-hunt.timer      # próximo disparo
journalctl -u nexus-hunt.service -f          # ver los ciclos
```

## Despliegue en el VPS (192.99.42.108)

El VPS **no** tiene Go ni las herramientas: hay que aprovisionarlas. Y no tiene
swap, así que el servicio se acota por cgroup.

```ini
# /etc/systemd/system/nexus.service
[Service]
WorkingDirectory=/home/debian/nexus
ExecStart=/home/debian/nexus/nexus serve
EnvironmentFile=/home/debian/nexus/.env
MemoryHigh=1G          # throttle antes de matar
MemoryMax=1500M        # techo duro: un pico solo mata a nexus, no a PostgreSQL/OPRF
Restart=on-failure
```

Colchón adicional (opcional, ver tarea de despliegue): swapfile de 4 GiB con
`vm.swappiness=10`. El `MemoryMax` es lo que de verdad protege a los servicios
que cobran.

## Estado

Pipeline completo end-to-end, funcional y probado (67 pruebas):
recon (H1+subfinder+httpx) · **enhanced recon** (gau/waybackurls/katana/ffuf/arjun)
· escaneo por fases con nuclei · dedup · protección anti-baneo · **deep-verify**
(sqlmap/xsstrike/commix con máquina de estados y reintentos) · **evidencia**
(Chromium headless) · **submitter** con CVSS/impacto · **panel web embebido**.

El panel embebido es maud + htmx (theme-aware, offline, CSP-safe), servido por el
mismo binario — el stack de la directiva 26. (La nota anterior pedía migrarlo a
una SPA Angular + @angular/material; era previa al cambio de stack del 2026-08-06
y **está retirada**: la directiva 26 prohíbe Angular. No hay migración pendiente.)

## Métodos de ataque

El catálogo completo de técnicas —qué está implementado, qué se clasifica sin
verificar, y las brechas con su herramienta y protección necesarias— está en
[`docs/METODOS.md`](docs/METODOS.md), con la determinación de qué construir a
continuación.

## Titularidad

MIT — Copyright (c) 2026 Juan Carlos Isaza. Herramienta de investigación de seguridad
autorizada (solo scopes con bounty de HackerOne).
