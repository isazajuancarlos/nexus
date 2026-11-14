//! Tipos de error del orquestador. `thiserror` para la librería, `anyhow` en los bordes.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NexusError {
    #[error("base de datos: {0}")]
    Db(#[from] sqlx::Error),

    #[error("migración: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),

    #[error("E/S: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("herramienta externa ausente: {0} (instálala o pásale la ruta con --{0}-path)")]
    ToolMissing(String),

    #[error("faltan credenciales H1_USER/H1_TOKEN en el entorno (.env)")]
    NoCredentials,

    #[error("red no disponible: {0}")]
    NetworkDown(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NexusError>;
