//! Configuración: los ~22 flags heredados de `bounty/main.py`, más las rutas de
//! herramientas externas. `clap` con `env`, para que el `.service` del VPS pueda
//! fijarlo todo por variables de entorno sin reescribir el ExecStart.
//!
//! Regla de diseño (directiva 21, sesgo a cerrar): los defaults son
//! CONSERVADORES. `--safe-mode` los baja aún más. Nadie sube el ritmo sin pedirlo.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Fuentes de programas/scope para `recon`. Cascada configurable.
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// API de HackerOne (precisa, requiere H1_USER/H1_TOKEN).
    H1,
    /// arkadiyt/bounty-targets-data (H1+Bugcrowd+Intigriti+YWH, sin cuenta).
    Arkadiyt,
    /// Lista pública Chaos de ProjectDiscovery (sin cuenta).
    Chaos,
    /// Scope YA ALMACENADO en program_scopes (no llama a ninguna API). Para
    /// programas cuyo scope vino de un feed —Intigriti, sembrado desde arkadiyt—:
    /// el recon lo lee de la BD y lo enumera. Se usa con `--only <programa>`.
    Almacenado,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Vigila el `submission_state` de un programa H1. Sale 10 si ACEPTA envíos
    /// (reabrió), 0 si sigue cerrado, 2 si no se pudo determinar. Para cron:
    /// avisa por `--notify-webhook` cuando el 10 dispara. Ej.: un programa en
    /// pausa (`liberapay`) que se quiere radicar en cuanto reabra.
    VigilarPrograma {
        /// Handle del programa en HackerOne (p.ej. `liberapay`).
        #[arg(long)]
        handle: String,
    },
    /// Recon: HackerOne → subfinder → httpx → archivo de objetivos.
    Recon {
        /// Solo SINCRONIZA el scope (jala y persiste el catálogo H1 en la BD) y para
        /// ANTES del subfinder/httpx. Es la base que alimenta a toda la maquinaria:
        /// el catálogo autorizado vivo, refrescable por un timer. Ligero para la IP.
        #[arg(long)]
        scope_only: bool,
    },
    /// Escanea un archivo de objetivos con nuclei (modo sniper por fases).
    Scan {
        /// Archivo de objetivos (una URL por línea). Por defecto scans/targets.txt.
        #[arg(long)]
        targets: Option<PathBuf>,
        /// Nombre del programa al que colgar los hallazgos.
        #[arg(long, default_value = "GLOBAL_FEED")]
        program: String,
    },
    /// Busca buckets S3/GCS EXPUESTOS (públicos/listables) permutando el nombre del
    /// objetivo. GET anónimo read-only; marca TITULARIDAD SIN CONFIRMAR y no auto-envía.
    Buckets {
        /// Token base del objetivo (nombre de empresa/dominio sin TLD). Repetible.
        #[arg(long = "base", required = true)]
        bases: Vec<String>,
        /// Nombre del programa al que colgar los hallazgos.
        #[arg(long, default_value = "GLOBAL_FEED")]
        program: String,
        /// Máximo de nombres a probar (cada uno son 2 GET: S3 + GCS).
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// Descubre PARÁMETROS OCULTOS de un endpoint por anomalía (técnica de Arjun,
    /// reimplementada). Superficie nueva para authz/mass-assignment; read-oriented,
    /// centinela benigno. Imprime los parámetros efectivos con su señal.
    Parametros {
        /// URL del endpoint a sondear.
        #[arg(long)]
        url: String,
        /// Método de inyección: get (por defecto), post-form o post-json.
        #[arg(long, default_value = "get")]
        metodo: String,
        /// Cabecera de identidad, repetible, formato `Nombre: valor` (cookie de sesión,
        /// `Authorization: Bearer …`). Sin ninguna → anónimo.
        #[arg(long = "cabecera")]
        cabeceras: Vec<String>,
        /// Enciende los factores de longitud/líneas (ruidosos; solo en endpoints estables).
        #[arg(long)]
        sensible_longitud: bool,
    },
    /// Busca SECRETOS en el JS servido de un objetivo: baja el HTML raíz y sus bundles
    /// `.js` (con evasión de WAF) y los pasa por el detector por patrón. Clase del leak
    /// de partners de Microsoft (key en el JS del cliente). GET read-only; el valor se
    /// ENMASCARA. Con `--verificar`, confirma por ejecución que la key está VIVA (opt-in,
    /// solo clases verificables; úsalo solo si el scope autoriza usar la credencial).
    SecretosJs {
        /// URL base del objetivo (con o sin esquema).
        #[arg(long)]
        url: String,
        /// Máximo de bundles `.js` a bajar del raíz.
        #[arg(long, default_value_t = 30)]
        max_js: usize,
        /// Confirma por ejecución que el secreto está VIVO (llama al proveedor). Opt-in.
        #[arg(long)]
        verificar: bool,
    },
    /// Sondea ENDPOINTS DE EMISIÓN de token (`/token`,`/refresh`,`/RefreshAccessToken`…) SIN
    /// credencial: si uno devuelve un token usable, es la familia "la auth no se hace respetar".
    /// No se reporta por presencia: con `--protegido <url>` confirma por ORÁCULO DIFERENCIAL
    /// (abre el protegido CON el token, cerrado SIN él). GET/POST vacío, read-oriented.
    TokenSinAuth {
        /// URL base del objetivo.
        #[arg(long)]
        url: String,
        /// Endpoint protegido para confirmar la usabilidad del token (401/403 sin él, 2xx con él).
        #[arg(long)]
        protegido: Option<String>,
    },
    /// Red-team de SEGURIDAD DE LLM contra un endpoint de chat AUTORIZADO: dispara un
    /// corpus categorizado (prompt-injection/jailbreak/leak/exfil/indirect/guardrail-bypass,
    /// OWASP LLM Top 10) y detecta cuáles pegaron por ORÁCULO DE CANARIO. Operator-directed,
    /// opt-in; el PoC es el canario (mínimo), no exfiltra ni persiste.
    RedteamLlm {
        /// URL del endpoint de chat.
        #[arg(long)]
        url: String,
        /// Campo JSON donde va el mensaje (cuerpo `{campo: payload}`). Por defecto `message`.
        #[arg(long, default_value = "message")]
        campo: String,
        /// Plantilla del cuerpo con `{{PAYLOAD}}` (p.ej. estilo OpenAI). Excluye a `--campo`.
        #[arg(long)]
        plantilla_cuerpo: Option<String>,
        /// Ruta con puntos a la salida del modelo (p.ej. `choices.0.message.content`).
        /// RECOMENDADA: sin ella se busca el canario en el cuerpo entero y el eco del request
        /// puede dar falso positivo.
        #[arg(long)]
        ruta_respuesta: Option<String>,
        /// Cabecera de identidad `Nombre: valor`, repetible (chatbots autenticados).
        #[arg(long = "cabecera")]
        cabeceras: Vec<String>,
        /// Limita a estas categorías (repetible); vacío = todas.
        #[arg(long = "categoria")]
        categorias: Vec<String>,
    },
    /// Verifica en profundidad los hallazgos pendientes (sqlmap/xsstrike/commix).
    Verify {
        /// Máximo de hallazgos a procesar en esta corrida.
        #[arg(long, default_value_t = 500)]
        limit: i64,
    },
    /// Captura evidencia (screenshots) de los hallazgos verificados.
    Evidence,
    /// Refresca en H1 el estado y el bounty de los reportes enviados.
    Sync,
    /// Un ciclo del cazador: elige el programa menos-reciente de la BD y hace
    /// recon+scan+verify+auto-envío. Scheduling por BD (reemplaza el cursor bash).
    Hunt {
        /// Dirige la caza a UN programa concreto (por nombre exacto), en vez de dejar
        /// que el planificador elija por frescura. Para la campaña de acreditación H1:
        /// apuntar el arsenal a un objetivo elegido del long-tail, no a la lotería.
        #[arg(long)]
        program: Option<String>,
    },
    /// Genera informes de envío (manual_reports/) y, con --auto, auto-envía a H1
    /// el tramo de máxima señal (VERIFIED+explotable+alta confianza).
    Submit {
        /// Auto-enviar a H1 los hallazgos de máxima señal (POST real salvo --dry-run).
        #[arg(long, default_value_t = false)]
        auto: bool,
        /// Con --auto: solo mostrar qué se enviaría, sin tocar H1.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Regenera el informe markdown desde la BD actual.
    Report,
    /// Arranca la UI web (axum) con el panel embebido.
    Serve,
    /// Arranca el COLECTOR out-of-band (SSRF): un servidor axum público que
    /// registra los callbacks (`http://<colector>/<token>`) que hace el servidor
    /// de un objetivo vulnerable. Escribe en la misma BD que consulta la sonda
    /// SSRF. Bind 0.0.0.0:NEXUS_OOB_PORT (debe ser alcanzable desde internet).
    OobServer,
    /// MIDE la elegibilidad de los hallazgos en MANUAL_READY contra las reglas
    /// publicadas de su programa en H1 (scope submittable + CWE aceptado): imprime
    /// el veredicto por hallazgo. Con `--aplicar` además DESCARTA (reclasifica a
    /// INFORMATIONAL, reversible, con motivo) los fuera-de-scope / clase-rechazada
    /// — el mismo efecto que el enforce del ciclo, a demanda.
    Elegibilidad {
        /// Aplica el descarte (reclasifica a INFORMATIONAL) además de medir.
        #[arg(long)]
        aplicar: bool,
    },
    /// RANKEA el pool de programas por operabilidad IDOR (dónde montar dos cuentas
    /// cuesta menos y es más probable), con señales del scope SIN sondear en vivo:
    /// API en scope, paga, y penaliza nombres con pinta de KYC financiero.
    Operabilidad {
        /// Cuántos imprimir (los mejores primero).
        #[arg(long, default_value_t = 25)]
        top: usize,
    },
    /// Baja de la API de H1 las STRUCTURED SCOPES (con su asset_type real, incluido
    /// SOURCE_CODE) de cada programa y las persiste, marcando `scope_status='fetched'`.
    /// Es la base para clasificar los programas (blanca/negra): ¿su código fuente está
    /// en scope? ¿paga por él? ¿acepta envíos? Resumable: por defecto salta los ya
    /// 'fetched'. Solo lectura hacia H1 (GET); no envía ni descarta nada.
    ScopesRefresh {
        /// Rebaja TODOS, incluso los ya 'fetched' (por defecto solo pending/error).
        #[arg(long)]
        todos: bool,
        /// Tope de programas a procesar en esta corrida (0 = sin tope).
        #[arg(long, default_value_t = 0)]
        limite: usize,
    },
    /// HACKTIVITY: baja del GraphQL PÚBLICO de H1 (sin credenciales) los reportes
    /// ya DIVULGADOS de uno o varios programas y arma un checklist "qué ya se
    /// explotó/reportó por programa" — para decidir DÓNDE y a QUIÉN atacar (dedup +
    /// mapa de las clases de bug que el programa ya premió). Solo lectura.
    Hacktivity {
        /// Handle del programa (columna H1, p.ej. `discourse`). Repetible.
        #[arg(long = "programa")]
        programas: Vec<String>,
        /// Archivo con un handle por línea (se ignoran vacías y las que empiezan por `#`).
        /// Se suma a los `--programa`. Para barrer el pool de candidatos.
        #[arg(long)]
        lista: Option<PathBuf>,
        /// Tope de reportes a bajar POR programa (pagina de 50 en 50).
        #[arg(long, default_value_t = 100)]
        cap: usize,
        /// Escribe el checklist Markdown aquí; si se omite, va a stdout.
        #[arg(long)]
        salida: Option<PathBuf>,
    },
    /// ENSAMBLA el dictamen técnico-jurídico de protección de datos de un programa:
    /// jala sus findings (sin falsos positivos), autollena las secciones técnicas
    /// (§1/§3/§4/§6) mapeando cada hallazgo a la obligación de la Ley 1581, y deja
    /// el §5 organizacional y el §8 (firma) para la persona. Imprime Markdown.
    Dictamen {
        /// Nombre del programa (columna `program_name` en la BD).
        programa: String,
        /// Archivo de respuestas del checklist §5 (de `nexus cumplimiento --plantilla`).
        /// Si se da, el §5 se llena con sus resultados; si no, queda en blanco.
        #[arg(long)]
        cumplimiento: Option<PathBuf>,
    },
    /// Emite la PLANTILLA del checklist §5 (cumplimiento organizacional: RNBD,
    /// política, autorización, Habeas Data, cifrado en reposo, retención, logs,
    /// oficial de datos, DPIA) para que el auditor la llene y la pase a
    /// `dictamen --cumplimiento`. Con `--catalogo`, imprime los ítems y su
    /// obligación legal en vez de la plantilla.
    /// Descubre la criptografía de un proyecto AJENO por sus manifiestos de
    /// dependencias (Cargo.lock, requirements.txt, package-lock.json) y emite su
    /// CBOM (CycloneDX 1.6), marcando qué está cuánticamente vulnerable. Ángulo B.
    Cbom {
        /// Ruta al directorio del proyecto a escanear.
        #[arg(long)]
        ruta: PathBuf,
        /// Escribe el CBOM JSON aquí; si se omite, va a stdout tras el resumen.
        #[arg(long)]
        salida: Option<PathBuf>,
        /// En vez del CBOM JSON, emite el DICTAMEN técnico-jurídico de postura
        /// post-cuántica (Markdown) a partir del inventario.
        #[arg(long)]
        dictamen: bool,
        /// Nombre del perito que firma el dictamen (tú). Lo que se omita queda como
        /// placeholder visible en el documento.
        #[arg(long)]
        perito: Option<String>,
        /// Tarjeta profesional del perito.
        #[arg(long)]
        tarjeta: Option<String>,
        /// Razón social del responsable del tratamiento auditado (el cliente).
        #[arg(long)]
        cliente: Option<String>,
        /// NIT del responsable auditado.
        #[arg(long)]
        nit: Option<String>,
    },
    Cumplimiento {
        /// Imprime el catálogo (ítem → obligación) en vez de la plantilla en blanco.
        #[arg(long)]
        catalogo: bool,
    },
    /// Monta una IDENTIDAD del juego de control de acceso (autz) de un programa:
    /// el papel y las cabeceras HTTP que la autentican. Es el paso MANUAL que la
    /// ruta IDOR necesita (dos cuentas reales, que crea la persona). Reemplaza la
    /// credencial del mismo papel si ya existía (rotación). Con `--listar` muestra
    /// los papeles montados (sin volcar secretos); con `--borrar <papel>` la quita.
    ///
    /// Ej.: nexus identidad --programa intigriti:acme --papel dueno \
    ///        --cabecera "Authorization: Bearer eyJ…" --cabecera "Cookie: sid=abc"
    Identidad {
        /// Programa (columna `program_name`).
        #[arg(long)]
        programa: String,
        /// Papel: dueno | par | menor | anonimo. El anónimo va SIN cabeceras.
        #[arg(long, required_unless_present_any = ["listar", "borrar"])]
        papel: Option<String>,
        /// Cabecera de autenticación "Clave: Valor". Repetible. El anónimo no lleva.
        #[arg(long = "cabecera")]
        cabeceras: Vec<String>,
        /// Solo lista los papeles montados del programa y sale.
        #[arg(long)]
        listar: bool,
        /// Borra el papel indicado (dueno|par|menor|anonimo) y sale.
        #[arg(long)]
        borrar: Option<String>,
    },
    /// Añade una URL SEMILLA al juego autz de un programa: un recurso PROPIO del
    /// dueño (privado, que el recon pasivo no descubre) que el motor reproduce con
    /// cada identidad para detectar el acceso indebido. Repetir `--url` añade varias.
    /// Con `--listar` muestra las semillas del programa.
    Semilla {
        /// Programa (columna `program_name`).
        #[arg(long)]
        programa: String,
        /// URL semilla. Repetible. Requerida salvo con `--listar`.
        #[arg(long = "url", required_unless_present = "listar")]
        urls: Vec<String>,
        /// Solo lista las semillas del programa y sale.
        #[arg(long)]
        listar: bool,
    },
    /// FP-LAB de extremo a extremo: levanta la app-trampa LOCAL (127.0.0.1) con
    /// parejas SAFE/VULN por clase y mide FPR/TPR del SISTEMA de deteccion contra HTTP
    /// real (directiva 28). SAFE = parece vuln pero NO debe reportarse; VULN = debe
    /// reportarse. No toca la BD principal ni la red externa (solo loopback).
    FpEval {
        /// Puerto de la app-trampa (0 = efimero). Siempre bind a 127.0.0.1.
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Intentos por punto del oraculo de ejecucion de XSS (reproducibilidad).
        #[arg(long, default_value_t = 2)]
        xss_tries: usize,
    },
    /// Oraculo diferencial unificado (whitebox/blackbox): confirma por ejecucion un
    /// invariante de control de acceso y emite el certificado anti-slop.
    Oraculo {
        /// blackbox = objetivo vivo en scope. Sin la bandera, whitebox (lab loopback).
        #[arg(long)]
        black: bool,
        /// URL base del objetivo (lab en loopback, o el vivo en scope).
        #[arg(long)]
        base: String,
        /// Archivo JSON con el CasoDiferencial (misma forma para white y black).
        #[arg(long)]
        caso: PathBuf,
        /// Host(s) autorizados. OBLIGATORIO en blackbox; ignorado en whitebox. Repetible.
        #[arg(long = "scope")]
        scope: Vec<String>,
        /// Intentos (reproducibilidad n/n del certificado).
        #[arg(long, default_value_t = 3)]
        intentos: usize,
        /// (whitebox) Directorio de un docker compose a levantar antes y bajar despues.
        #[arg(long)]
        lab: Option<PathBuf>,
        /// Oraculo de TIEMPO REAL (websocket/DDP): --base es la ws_url y --caso un
        /// CasoRealtime JSON. El transporte que el oraculo HTTP no cubre (streams).
        #[arg(long)]
        realtime: bool,
    },
    /// Recon de RPs/audiencias OIDC (mapa que alimenta el oraculo de confusion de
    /// audiencia). Lee el discovery PUBLICO del origen y parsea URLs de authorize
    /// observadas. No dispara nada mas: es recon, no confirmacion.
    OidcRecon {
        /// Origen del IdP (se le lee /.well-known/openid-configuration).
        #[arg(long)]
        base: String,
        /// URL(s) de `authorize` OBSERVADAS del objetivo (repetible) -> cada RP.
        #[arg(long = "authorize")]
        authorize: Vec<String>,
        /// Emitir el mapa como JSON (para el razonador / tuberia).
        #[arg(long)]
        json: bool,
    },
    /// SELECCIÓN de OSS joven para el carril whitebox de código-fuente (la capa que la
    /// auditoría 2026-10-21 halló ausente: todo nexus es live-DAST). Keyless: search API +
    /// advisories de GitHub, sin credenciales. EMBUDO, no oráculo — `PERSEGUIR` = vale una
    /// lectura puerta-0, no "tiene un bug". SELECCIONA y TRÍA, nunca encuentra-y-envía (D37).
    Candidatos {
        /// Dominio de negocio a buscar (repetible): `helpdesk`, `lms`, `booking`, `payroll`…
        #[arg(long = "dominio", required = true)]
        dominios: Vec<String>,
        /// Lenguaje de backend a filtrar (opcional): `Go`, `PHP`, `Python`, `TypeScript`, `Ruby`.
        #[arg(long)]
        lang: Option<String>,
        /// Ventana de "joven" en años (creado dentro de este plazo).
        #[arg(long, default_value_t = 3)]
        anios: i64,
        /// Máximo de repos por dominio a traer de la search API.
        #[arg(long, default_value_t = 8)]
        max: usize,
        /// Archivo markdown de salida (si falta, imprime a stdout).
        #[arg(long)]
        salida: Option<PathBuf>,
    },
}

#[derive(Parser, Debug, Clone)]
#[command(name = "nexus", version, about = "Orquestador de bug bounty (Rust). El motor son binarios externos; Rust dirige y protege la IP.")]
pub struct Config {
    #[command(subcommand)]
    pub command: Command,

    // ---- Servidor UI ----
    #[arg(short, long, env = "NEXUS_PORT", default_value_t = 8003)]
    pub port: u16,
    #[arg(long, env = "NEXUS_HOST", default_value = "127.0.0.1")]
    pub host: String,

    // ---- Ritmo / anti-baneo (los knobs que evitan que os baneen la IP) ----
    /// Peticiones por segundo de nuclei (-rl). Global, no por host.
    #[arg(long, env = "NEXUS_RATE_LIMIT", default_value_t = 150)]
    pub rate_limit: u32,
    /// Concurrencia de nuclei (-c).
    #[arg(long, env = "NEXUS_NUCLEI_CONCURRENCY", default_value_t = 25)]
    pub nuclei_concurrency: u32,
    /// Tamaño de lote de nuclei (-bs).
    #[arg(long, env = "NEXUS_BATCH_SIZE", default_value_t = 45)]
    pub batch_size: u32,
    /// Timeout por petición de nuclei, en segundos (-timeout).
    #[arg(long, env = "NEXUS_NUCLEI_REQUEST_TIMEOUT", default_value_t = 10)]
    pub nuclei_request_timeout: u32,
    /// Máximo de hosts por programa (recorte de superficie y de RAM).
    #[arg(long, env = "NEXUS_MAX_HOSTS", default_value_t = 750)]
    pub max_hosts: usize,

    // ---- Protección / cooldowns ----
    #[arg(long, env = "NEXUS_PROGRAM_COOLDOWN", default_value_t = 60)]
    pub program_cooldown: u64,
    #[arg(long, env = "NEXUS_PHASE_COOLDOWN", default_value_t = 30)]
    pub phase_cooldown: u64,
    /// Modo seguro: baja ritmo y sube cooldowns. Para targets sensibles.
    #[arg(long, env = "NEXUS_SAFE_MODE", default_value_t = false)]
    pub safe_mode: bool,

    // ---- Evasión anti-baneo (adaptativa) ----
    /// Proxy de salida (http/https) para las herramientas y peticiones propias.
    #[arg(long, env = "NEXUS_PROXY")]
    pub proxy: Option<String>,
    /// User-Agent fijo. Si se omite, se rota un pool realista.
    #[arg(long, env = "NEXUS_USER_AGENT")]
    pub user_agent: Option<String>,
    /// No rotar el User-Agent (usar siempre el primero del pool).
    #[arg(long, default_value_t = false)]
    pub no_rotate_ua: bool,

    // ---- SSRF out-of-band (colector auto-hospedado) ----
    /// Base pública del COLECTOR OOB, p.ej. `http://192.99.42.108:8004`. Si se
    /// fija, la sonda SSRF inyecta ADEMÁS `{oob_base}/{token}` y confirma el SSRF
    /// ciego por callback. Sin fijar, la fase SSRF es solo in-band (defecto). Es
    /// opt-in por CONFIGURACIÓN: sin colector desplegado no hay nada que apuntar.
    #[arg(long, env = "NEXUS_OOB_BASE")]
    pub oob_base: Option<String>,
    /// Puerto en el que escucha `nexus oob-server` (bind 0.0.0.0). Debe coincidir
    /// con el puerto de `oob_base` y estar abierto en el VPS.
    #[arg(long, env = "NEXUS_OOB_PORT", default_value_t = 8004)]
    pub oob_port: u16,
    /// Segundos de gracia que la sonda SSRF espera tras inyectar los payloads OOB
    /// antes de consultar los callbacks (un servidor vulnerable puede tardar en
    /// hacer la petición saliente). Tope acotado (directiva 39).
    #[arg(long, env = "NEXUS_OOB_WAIT", default_value_t = 12)]
    pub oob_wait: u64,

    /// Auto-enviar a H1 tras escanear: los hallazgos VERIFIED+explotables+alta
    /// confianza se reportan solos (el primero que reporta se lleva el bounty).
    /// El resto sigue en manual. Opt-in explícito. La variable de entorno
    /// NEXUS_AUTO_SUBMIT (1/true/yes) se resuelve a mano en main (bool+env en
    /// clap exige exactamente "true"/"false" y rompería el arranque con "1").
    #[arg(long, default_value_t = false)]
    pub auto_submit: bool,

    /// ENFORCE del gate de elegibilidad H1 en el ciclo `hunt`: descarta a
    /// INFORMATIONAL (reversible, con motivo) los hallazgos que el gate marca
    /// fuera-de-scope o de clase-rechazada contra las reglas del programa. Opt-in
    /// explícito (como `auto_submit`): en `false` (defecto) el gate solo MIDE
    /// (subcomando `elegibilidad`), no toca el ciclo. La variable de entorno
    /// NEXUS_H1_GATE_ENFORCE (1/true/yes) se resuelve a mano en main.
    #[arg(long, default_value_t = false)]
    pub h1_gate_enforce: bool,

    /// RELOJ TERMINAL: días que un hallazgo puede esperar en MANUAL_READY antes de
    /// resolverse solo a INFORMATIONAL (reversible, con motivo). En un sistema 24/7
    /// nadie revisa, así que un estado que espera a un humano es una fuga; el reloj
    /// garantiza que NADA espera para siempre. Ventana GENEROSA a propósito: da
    /// tiempo a que la auto-confirmación resuelva primero. `0` (defecto) = apagado.
    #[arg(long, env = "NEXUS_MANUAL_READY_MAX_DIAS", default_value_t = 0)]
    pub manual_ready_max_dias: u64,

    /// VERIFICACIÓN VIVA de secretos: usa la credencial AJENA hallada contra el
    /// proveedor real (GitHub/OpenAI/Stripe/Slack) para confirmar si está viva —
    /// estilo trufflehog `--only-verified`. OPT-IN explícito (defecto false): tocar
    /// un tercero con una credencial encontrada puede caer FUERA del alcance del
    /// programa (autorización), así que por defecto un secreto detectado va a
    /// revisión MANUAL, nunca auto-confirmado ni auto-enviado (directivas 21/30). La
    /// var de entorno NEXUS_SECRET_VERIFY (1/true/yes) se resuelve a mano en main.
    #[arg(long, default_value_t = false)]
    pub secret_verify: bool,

    /// Auto-envía las clases de CONTROL DE ACCESO (idor/bac) confirmadas por autz.
    /// Solo alcanza a lo que ya pasa el listón duro de `fetch_autosubmit`
    /// (VERIFIED, execution_confirmed, explotable, severidad alta/crítica,
    /// tool=autz): es decir, un bypass ALTA de `clasificar` (firma exacta, mismo
    /// recurso, las 4 reglas) de severidad alta (fuga-sin-auth / privesc). El
    /// IDOR-Alta es medium y NO llega. Opt-in (defecto false): auto-enviar a H1 es
    /// irreversible y cuesta Signal. La var de entorno NEXUS_AUTZ_PAYABLE
    /// (1/true/yes) se resuelve a mano en main.
    #[arg(long, default_value_t = false)]
    pub autz_payable: bool,

    // ---- Recursos (VPS sin swap: topar la concurrencia del propio orquestador) ----
    /// Workers concurrentes del pool de escaneo (Semaphore de tokio). Reemplaza
    /// NUM_WORKERS de hacker/ y el ThreadPoolExecutor de bounty/.
    #[arg(long, env = "NEXUS_WORKERS", default_value_t = 4)]
    pub workers: usize,
    /// Workers de verificación profunda (sqlmap/xsstrike/commix).
    #[arg(long, env = "NEXUS_DEEP_WORKERS", default_value_t = 2)]
    pub deep_workers: usize,

    /// Intentos del gate de ejecución en navegador (XSS) y del re-fetch de
    /// reproducibilidad (exposición). Cada intento es una carga de Chromium; el
    /// gate corre esto veces y exige `xss_confirm_min` aciertos para confirmar.
    #[arg(long, env = "NEXUS_XSS_CONFIRM_TRIES", default_value_t = 3)]
    pub xss_confirm_tries: usize,
    /// Aciertos mínimos (de `xss_confirm_tries`) para confirmar por reproducibilidad.
    /// Un reflejo intermitente (gateado por challenge) no los junta y NO se
    /// auto-envía — el triager de H1 lo cerraría como "not reproducible".
    #[arg(long, env = "NEXUS_XSS_CONFIRM_MIN", default_value_t = 2)]
    pub xss_confirm_min: usize,
    /// Reproducibilidad de SQLi/CMDi (fase 1.3): re-corre sqlmap/commix esta cantidad
    /// de veces y exige `sqli_confirm_min` confirmaciones antes de `execution_confirmed`
    /// —cierra la asimetría con XSS/Exposure: una sola corrida de sqlmap con un falso
    /// "is vulnerable" (WAF que refleja, jitter) se auto-confirmaba—. Bajo por defecto:
    /// sqlmap es CARO, así que el segundo pase solo se paga en lo AUTO-ENVIABLE.
    #[arg(long, env = "NEXUS_SQLI_CONFIRM_TRIES", default_value_t = 2)]
    pub sqli_confirm_tries: usize,
    /// Confirmaciones mínimas (de `sqli_confirm_tries`) para dar SQLi/CMDi por reproducible.
    #[arg(long, env = "NEXUS_SQLI_CONFIRM_MIN", default_value_t = 2)]
    pub sqli_confirm_min: usize,

    // ---- Auto-envío: defensas anti-baneo (H1 penaliza el Signal por reportes
    //      falsos/duplicados/informativos; con Signal bajo llegan límites y baneo) ----
    /// Tope DURO de auto-envíos por ventana de 24 h. Fail-closed: si la
    /// verificación fallara, no puede inundar H1. "Pocos pero pagados".
    #[arg(long, env = "NEXUS_AUTOSUBMIT_MAX_PER_DAY", default_value_t = 3)]
    pub autosubmit_max_per_day: i64,
    /// Cortacircuitos: si hay este número (o más) de reportes propios cerrados por
    /// H1 como duplicate/informative/not-applicable/spam, se PAUSA el auto-envío
    /// entero. Reacciona a la señal del propio H1 (la defensa anti-baneo más
    /// fuerte). Se reactiva cuando esos casos bajen del umbral (o a mano).
    #[arg(long, env = "NEXUS_AUTOSUBMIT_SIGNAL_FLOOR", default_value_t = 3)]
    pub autosubmit_signal_floor: i64,
    /// Auto-enviar SOLO clases de alto pago/aceptación (payability). Con esto en
    /// true (defecto), la XSS reflejada confirmada queda en MANUAL_READY para
    /// revisión humana en vez de auto-enviarse (P4/low o N-A en muchos programas,
    /// y lo que más arriesga el Signal). En false, se auto-envía toda clase con
    /// ejecución confirmada.
    #[arg(long, env = "NEXUS_AUTOSUBMIT_PAYABLE_ONLY", default_value_t = true)]
    pub autosubmit_payable_only: bool,

    /// Segundos, desde que arranca el ciclo `hunt`, en que el SCAN debe haber
    /// terminado. `0` = sin límite (comportamiento de siempre).
    ///
    /// Es el presupuesto de tiempo del ciclo, y existe porque el binario calcula
    /// timeouts de fase que pueden sumar más de lo que su supervisor le permite:
    /// con dos fases sobre un programa de ~40 objetivos, recon + scan rozan los
    /// 71 min, y `systemd` lo mata a los 60 (`TimeoutStartSec`) a mitad de
    /// nuclei — 57 corridas seguidas, 0 completadas. Aquí el ciclo se ENTERA del
    /// muro y para limpio antes: acota cada fase al tiempo que queda y salta las
    /// que no caben, dejando margen para verify + auto-envío.
    ///
    /// **Es un límite BLANDO, distinto de `TimeoutStartSec`**: este lo respeta el
    /// código y para ordenado guardando lo escaneado; aquél es el corte duro del
    /// supervisor, la red por si el binario se cuelga. Se pone por debajo del de
    /// systemd (p. ej. 2700 contra 3600) para que el ciclo cierre por sí mismo y
    /// el SIGKILL no llegue nunca.
    #[arg(long, env = "NEXUS_SCAN_DEADLINE_SECS", default_value_t = 0)]
    pub scan_deadline_secs: u64,

    /// Fracción del presupuesto del ciclo que el RECON puede consumir como
    /// mucho (el resto es para escanear). Medido el 2026-08-06: sin tope, la
    /// enumeración de subdominios se comía ~25 de 40 min y encontraba 0. 0.25 =
    /// una cuarta parte. Solo actúa dentro de `hunt` y con `scan_deadline_secs > 0`.
    #[arg(long, env = "NEXUS_RECON_FRAC", default_value_t = 0.25)]
    pub recon_frac: f64,

    /// Ventana de FRESCURA de un programa, en días. Un programa cuyo
    /// `created_at` (cuándo lo vio nexus por primera vez, o sea cuándo apareció
    /// en H1) cae dentro de esta ventana se caza con prioridad sobre los
    /// veteranos, aunque ya se haya escaneado una vez. Es la ventana de
    /// oportunidad: el escaneo automático de plantillas solo gana a la multitud
    /// en el hueco entre que un programa (o un scope) aparece y que todos lo
    /// exprimen. Pasada la ventana, el programa entra al round-robin normal por
    /// antigüedad de escaneo — es re-priorización, no exclusión, y se auto-sana
    /// sin tocar nada (directiva 22). 0 la desactiva (comportamiento anterior).
    #[arg(long, env = "NEXUS_FRESH_WINDOW_DAYS", default_value_t = 14)]
    pub fresh_window_days: i64,

    /// Motor de control de acceso (autz): tope de endpoints por corrida. El corpus
    /// de recon puede ser enorme y cada endpoint son 2-3 peticiones.
    #[arg(long, env = "NEXUS_AUTZ_CAP", default_value_t = 200)]
    pub autz_cap: usize,

    /// Motor autz: pausa base (s, con jitter) entre endpoints. Anti-baneo: no se
    /// ráfaga el corpus entero de un tirón.
    #[arg(long, env = "NEXUS_AUTZ_COOLDOWN_SECS", default_value_t = 2)]
    pub autz_cooldown_secs: u64,

    /// Activa la fase de EVASIÓN de control de acceso (bypass 403/401, sin login).
    /// OFF por defecto: prueba ~14 técnicas por endpoint protegido, y a escala
    /// eso banea la IP. Se enciende a propósito.
    #[arg(long, env = "NEXUS_BYPASS", default_value_t = false)]
    pub bypass: bool,

    /// Activa la fase KEYLESS de IDOR/BOLA sin auth (fuga sin auth): enumera ids
    /// vecinos SIN credenciales y detecta series por-registro legibles por anónimos.
    /// No necesita identidades (la forma operable de autz "sin crear cuentas",
    /// Juan 2026-08-25). OFF por defecto: hace hasta 3 peticiones por endpoint
    /// objeto-scoped, y a escala eso pesa sobre la IP compartida. Hallazgos a
    /// MANUAL_READY (nunca auto-confirmado), auto-envío OFF.
    #[arg(long = "fuga-sin-auth", env = "NEXUS_FUGA_SIN_AUTH", default_value_t = false)]
    pub fuga_sin_auth: bool,

    // ---- Interruptores de fase ----
    #[arg(long, env = "NEXUS_NO_SCAN", default_value_t = false)]
    pub no_scan: bool,
    #[arg(long, env = "NEXUS_NO_DEEP_SCAN", default_value_t = false)]
    pub no_deep_scan: bool,
    #[arg(long, env = "NEXUS_NO_PRIORITY_SCAN", default_value_t = false)]
    pub no_priority_scan: bool,
    #[arg(long, env = "NEXUS_NO_ENHANCED_RECON", default_value_t = false)]
    pub no_enhanced_recon: bool,
    /// Enhanced recon SOLO pasivo/crawl: gau + waybackurls + katana, y OMITE la
    /// fase activa (ffuf brute-force + arjun). Para la caza FRECUENTE: da a nuclei
    /// una superficie real de endpoints sin la fuerza bruta de directorios, que es
    /// la parte agresiva que arriesga baneo de IP y viola políticas anti-scanner de
    /// muchos programas. La caza PROFUNDA (semanal, sin este flag) sí hace ffuf.
    #[arg(long, env = "NEXUS_RECON_PASSIVE_ONLY", default_value_t = false)]
    pub recon_passive_only: bool,

    /// Descubrimiento de PARÁMETROS (arjun) incluso en modo pasivo. Desacopla arjun —que
    /// prueba nombres de parámetro sobre endpoints CONOCIDOS, targeted— de ffuf —la fuerza
    /// bruta de DIRECTORIOS, agresiva y con riesgo de baneo/política anti-scanner—. Es lo que
    /// da a la fase XSS (y a SSRF) su superficie parametrizada sin encender ffuf. Con
    /// `--recon-passive-only` sin esto, no hay params; con esto, hay params sin ffuf.
    #[arg(long = "recon-params", env = "NEXUS_RECON_PARAMS", default_value_t = false)]
    pub recon_params: bool,
    #[arg(long, env = "NEXUS_NO_SCOPE_VALIDATION", default_value_t = false)]
    pub no_scope_validation: bool,

    /// Fuentes de programas/scope para `recon` (coma-separadas). Se fusionan y
    /// deduplican. Ej.: --sources h1,arkadiyt,chaos
    #[arg(long, value_enum, value_delimiter = ',', default_value = "h1", env = "NEXUS_SOURCES")]
    pub sources: Vec<Source>,

    /// Limita `recon` a estos handles de programa H1 (coma-separados). Vacío =
    /// todos. Útil para acotar el reconocimiento a uno o pocos programas.
    #[arg(long, value_delimiter = ',', env = "NEXUS_ONLY")]
    pub only: Vec<String>,

    /// Request smuggling (3.3): opt-in EXPLÍCITO para las sondas de desync por
    /// timing. `false` por defecto — es la clase más sensible; se activa a
    /// conciencia por objetivo. Ver `smuggling.rs` (best-effort con reqwest).
    #[arg(long = "smuggling", env = "NEXUS_SMUGGLING", default_value_t = false)]
    pub smuggling: bool,

    /// Mass-assignment (1.4): opt-in EXPLÍCITO para permitir la ESCRITURA (PATCH)
    /// sobre el objeto propio del dueño. `false` por defecto = «sin daño»: el motor
    /// nunca escribe sin esto. Requiere además una identidad DUEÑO montada.
    #[arg(long = "mass-assign", env = "NEXUS_MASS_ASSIGN", default_value_t = false)]
    pub mass_assign: bool,

    /// Descubrimiento de PARÁMETROS OCULTOS antes del mass-assignment (`parametros`):
    /// sondea cada semilla (GET benigno) para hallar campos que el backend acepta pero no
    /// documenta, y los añade a la inyección — superficie que el listado estático no
    /// enumera. Requiere `--mass-assign` (no escribe sin él). Opt-in por añadir sondas GET.
    #[arg(long = "mass-assign-descubrir", env = "NEXUS_MASS_ASSIGN_DESCUBRIR", default_value_t = false)]
    pub mass_assign_descubrir: bool,

    /// DAST / fuzzing (motor `-dast` de nuclei): opt-in EXPLÍCITO. Fuzzea los
    /// parámetros de las URLs (SQLi, XSS, SSTI, cmdi reflejados/por tiempo) — lo
    /// que las plantillas-CVE no ven. `false` por defecto: es tráfico ACTIVO
    /// (muchos payloads/parámetro) sobre la IP compartida, se enciende a
    /// conciencia. SIEMPRE con `-no-interactsh` (sin fuga OOB a terceros).
    #[arg(long = "dast", env = "NEXUS_DAST", default_value_t = false)]
    pub dast: bool,

    /// XSS ADAPTATIVA (arnm): opt-in EXPLÍCITO. Por cada endpoint PARAMETRIZADO del corpus una
    /// señal barata de reflejo decide si hay sink; si lo hay, transcribe VECTORES
    /// (img/svg/onload/ontoggle…) del mismo JS de prueba y confirma por EJECUCIÓN en Chromium
    /// (no match de string — ese era el FP #11). `false` por defecto: cada confirmación carga
    /// el navegador, es tráfico activo sobre la IP compartida; se enciende a conciencia.
    #[arg(long = "xss", env = "NEXUS_XSS", default_value_t = false)]
    pub xss: bool,

    /// Directorio de templates de nuclei, del que la fase XSS LEE los vectores como MOLDES (la
    /// inversión: nuclei como fuente de fórmulas, no como atacante — su breakout, nuestro
    /// oráculo de ejecución). Vacío o inexistente → solo los 6 vectores a mano (falla suave).
    /// En el VPS: `/home/debian/nuclei-templates`.
    #[arg(long = "nuclei-templates", env = "NEXUS_NUCLEI_TEMPLATES", default_value = "")]
    pub nuclei_templates_dir: String,
    /// Tope de vectores XSS extraídos de nuclei (el oráculo es caro: una carga de Chromium por
    /// variante, y solo sobre sinks reflejados). `0` = sin tope.
    #[arg(long = "xss-nuclei-cap", env = "NEXUS_XSS_NUCLEI_CAP", default_value_t = 60)]
    pub xss_nuclei_cap: usize,

    /// Enforcement de la memoria NEGATIVA por causa (`exclusiones`): si está en
    /// `true`, la fase SSRF adaptativa SALTA la búsqueda cara sobre un objetivo
    /// cuyo veredicto negativo sigue vigente bajo su huella actual (arsenal
    /// agotado / sin superficie). En `false` (defecto) la memoria negativa solo
    /// REGISTRA, no decide — despliegue medido. La huella caduca el veredicto sola
    /// si el objetivo cambia su postura, así que un objetivo que se abrió se
    /// reintenta aunque el flag esté encendido.
    #[arg(long = "exclusiones-enforce", env = "NEXUS_EXCLUSIONES_ENFORCE", default_value_t = false)]
    pub exclusiones_enforce: bool,

    /// Días tras los que un veredicto negativo de "saltar" (MetodosAgotados /
    /// Inexistencia / InoperabilidadPermanente) CADUCA POR ANTIGÜEDAD y se vuelve a
    /// probar el arsenal completo, aunque la huella no haya cambiado. Cierra el
    /// falso negativo medido (un objetivo que se vuelve vulnerable conservando su
    /// postura observable): el enforcement lo salta, pero solo durante esta
    /// ventana; pasada, se re-caza. Coste medido: re-probar un host agotado ~44
    /// sondas, trivial frente al ~91% de ahorro diario. Solo aplica con
    /// `exclusiones-enforce`. Un salto NO refresca el timestamp, así que la edad
    /// cuenta desde el último SONDEO real → se re-prueba una vez por ventana.
    #[arg(long = "exclusiones-ttl-dias", env = "NEXUS_EXCLUSIONES_TTL_DIAS", default_value_t = 7)]
    pub exclusiones_ttl_dias: i64,

    /// Nivel de agresión del fuzzing: low|medium|high (nº de payloads por
    /// parámetro). `low` por defecto — protege la IP compartida; se sube por
    /// objetivo cuando merece la pena.
    #[arg(long = "dast-aggression", env = "NEXUS_DAST_AGGRESSION", default_value = "low",
          value_parser = ["low", "medium", "high"])]
    pub dast_aggression: String,

    /// Tope de URLs parametrizadas a fuzzear por ciclo (protege la IP compartida).
    #[arg(long = "dast-cap", env = "NEXUS_DAST_CAP", default_value_t = 60)]
    pub dast_cap: usize,

    // ---- Notificación ----
    /// Webhook para avisar de hallazgos nuevos (Slack / Discord / genérico,
    /// payload `{"text": …}`). Vacío = SIN notificación (comportamiento por
    /// defecto). Se dispara al cierre de cada ciclo de caza con los
    /// VERIFIED/MANUAL_READY que aún no se notificaron.
    #[arg(long = "notify-webhook", env = "NEXUS_NOTIFY_WEBHOOK")]
    pub notify_webhook: Option<String>,

    // ---- Datos ----
    #[arg(long = "db", env = "NEXUS_DB", default_value = "nexus.db")]
    pub db_path: PathBuf,
    #[arg(long, env = "NEXUS_SCANS_DIR", default_value = "scans")]
    pub scans_dir: PathBuf,
    /// BD SEPARADA del colector OOB. El colector es PÚBLICO y sin autenticar; se
    /// aísla de la BD principal (findings/programas, en un VPS que comparte datos
    /// clínicos) para que el radio de cualquier fallo futuro del escritor público
    /// no alcance lo sensible (revisión 2026-08-23, obs). Si se omite, cae a
    /// `oob.db` junto a la BD principal.
    #[arg(long, env = "NEXUS_OOB_DB")]
    pub oob_db: Option<PathBuf>,

    /// Bruteforce DNS PROPIO tras subfinder (keyless, sin cuenta — dir. 38/9).
    /// Encuentra subdominios internos sin certificado que lo pasivo no ve.
    #[arg(long, env = "NEXUS_BRUTEFORCE", default_value_t = true)]
    pub bruteforce_dns: bool,
    /// Diccionario de subdominios para el bruteforce (uno por línea). Si se omite,
    /// usa el curado embebido. Si se da y no existe, FALLA ruidosamente (dir. 20).
    #[arg(long, env = "NEXUS_BRUTEFORCE_WORDLIST")]
    pub bruteforce_wordlist: Option<PathBuf>,
    /// Concurrencia del resolvedor del bruteforce (acota el martilleo al DNS).
    #[arg(long, env = "NEXUS_BRUTEFORCE_CONCURRENCIA", default_value_t = 50)]
    pub bruteforce_concurrencia: usize,

    /// Evasión TLS: ruta a curl-impersonate (fingerprint de navegador) para cruzar
    /// WAFs que bloquean por fingerprint del cliente (Akamai/Cloudflare). Vacío = off.
    #[arg(long, env = "NEXUS_CURL_IMPERSONATE", default_value = "")]
    pub curl_impersonate_path: String,

    // ---- Rutas de herramientas (en el VPS no están en el PATH del servicio) ----
    #[arg(long, env = "NEXUS_SUBFINDER_PATH", default_value = "subfinder")]
    pub subfinder_path: String,
    #[arg(long, env = "NEXUS_HTTPX_PATH", default_value = "httpx")]
    pub httpx_path: String,
    #[arg(long, env = "NEXUS_NUCLEI_PATH", default_value = "nuclei")]
    pub nuclei_path: String,
    #[arg(long, env = "NEXUS_SQLMAP_PATH", default_value = "sqlmap")]
    pub sqlmap_path: String,
    #[arg(long, env = "NEXUS_XSSTRIKE_PATH", default_value = "xsstrike")]
    pub xsstrike_path: String,
    #[arg(long, env = "NEXUS_COMMIX_PATH", default_value = "commix")]
    pub commix_path: String,
    /// Timeout del subprocess de verificación profunda, en segundos. sqlmap en
    /// una primera corrida (probando blind time-based) tarda varios minutos; 150
    /// se quedaba corto y cortaba inyecciones ya halladas.
    #[arg(long, env = "NEXUS_DEEP_TIMEOUT", default_value_t = 300)]
    pub deep_timeout: u64,

    // ---- Enhanced recon (F4): herramientas y topes ----
    #[arg(long, env = "NEXUS_GAU_PATH", default_value = "gau")]
    pub gau_path: String,
    #[arg(long, env = "NEXUS_WAYBACKURLS_PATH", default_value = "waybackurls")]
    pub waybackurls_path: String,
    #[arg(long, env = "NEXUS_KATANA_PATH", default_value = "katana")]
    pub katana_path: String,
    #[arg(long, env = "NEXUS_FFUF_PATH", default_value = "ffuf")]
    pub ffuf_path: String,
    #[arg(long, env = "NEXUS_ARJUN_PATH", default_value = "arjun")]
    pub arjun_path: String,
    /// Profundidad de rastreo de katana.
    #[arg(long, env = "NEXUS_CRAWL_DEPTH", default_value_t = 2)]
    pub crawl_depth: u32,
    /// Máximo de URLs a añadir por enhanced recon (tope de RAM y de superficie).
    #[arg(long, env = "NEXUS_MAX_URLS", default_value_t = 2000)]
    pub max_urls: usize,
    /// Wordlist para ffuf (se genera una por defecto si no existe).
    #[arg(long, env = "NEXUS_WORDLIST", default_value = "wordlists/sensitive.txt")]
    pub wordlist: PathBuf,

    // ---- Evidencia (F5) y submitter (F6) ----
    /// Binario de Chromium para capturas de evidencia (subprocess headless).
    #[arg(long, env = "NEXUS_CHROMIUM_PATH", default_value = "chromium")]
    pub chromium_path: String,
    /// Directorio de capturas de evidencia.
    #[arg(long, env = "NEXUS_EVIDENCE_DIR", default_value = "evidence")]
    pub evidence_dir: PathBuf,
    /// Directorio de informes de envío generados.
    #[arg(long, env = "NEXUS_REPORTS_DIR", default_value = "manual_reports")]
    pub reports_dir: PathBuf,

    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

impl Config {
    /// Ruta de la BD del colector OOB: `oob_db` si se fijó, o `oob.db` junto a la
    /// BD principal (misma carpeta que `db_path`). Aislada a propósito de la
    /// principal (findings/clínica): el colector público solo toca esta.
    pub fn oob_db_path(&self) -> PathBuf {
        self.oob_db.clone().unwrap_or_else(|| {
            self.db_path
                .parent()
                .map(|p| p.join("oob.db"))
                .unwrap_or_else(|| PathBuf::from("oob.db"))
        })
    }

    /// Aplica el modo seguro: baja el ritmo y sube los cooldowns. Los `min`/`max`
    /// garantizan que safe-mode NUNCA relaja algo que el usuario apretó a mano.
    pub fn apply_safe_mode(&mut self) {
        if !self.safe_mode {
            return;
        }
        self.rate_limit = self.rate_limit.min(100);
        self.nuclei_concurrency = self.nuclei_concurrency.min(15);
        self.max_hosts = self.max_hosts.min(300);
        self.program_cooldown = self.program_cooldown.max(120);
        self.phase_cooldown = self.phase_cooldown.max(60);
    }
}

/// Grupos de tags de nuclei por prioridad (portado de bounty/). Se escanea
/// CRITICAL antes que HIGH: si la fase alta expira, los hallazgos que más pagan
/// ya están.
pub const HIGH_PRIORITY_TAGS: &str = "cve,rce,sqli,ssrf,lfi,cmdi,auth-bypass,takeover";
// default-login (98% high, credenciales por defecto reales) y misconfig (642
// plantillas high/crit) añadidos con base en el análisis de severidad. panel se
// EXCLUYE (97% info → H1 Informative). Las plantillas info-flood se excluyen en
// engine.rs (-eid) para no saturar la cola manual.
pub const MEDIUM_PRIORITY_TAGS: &str = "xss,exposure,token,secret,config,default-login,misconfig";

/// Plantillas de nuclei excluidas: verdaderos positivos pero severidad info que
/// disparan en casi todos los hosts (ruido no pagable en H1). Medido en vivo.
/// Es un COMPLEMENTO del filtro por severidad, no el filtro: enumerar IDs es
/// whack-a-mole (directiva 23), la regla de verdad es `EXCLUDED_SEVERITIES`.
pub const EXCLUDED_TEMPLATES: &[&str] = &["http-missing-security-headers", "weak-cipher-suites"];

/// Severidades que H1 no paga y solo saturan la cola manual: no se ejecutan en
/// nuclei (`-es`) ni se almacenan (filtro en `engine::es_severidad_pagable`).
/// `info` es informativo, no una vulnerabilidad; `unknown` es una plantilla sin
/// severidad. Es la REGLA por severidad, no la lista de plantillas: así un
/// hallazgo info NUEVO (que no esté en `EXCLUDED_TEMPLATES`) tampoco se cuela —
/// que es justo como se colaron los 7 de braze el 2026-08-07.
pub const EXCLUDED_SEVERITIES: &str = "info";
