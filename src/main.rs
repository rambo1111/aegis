// aegis-sealer-service/src/main.rs

use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use p256::ecdsa::SigningKey;
use std::env;
// NEW: Import `Any` for the open CORS policy
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, instrument, warn};
use hex;

// Import our core Aegis logic
mod core;
use crate::core::crypto;

#[tokio::main]
#[instrument]
async fn main() -> anyhow::Result<()> {
    // ... (tracing and dotenv setup is the same)
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Attempting to load .env file...");
    match dotenvy::dotenv() {
        Ok(_) => info!(".env file loaded successfully."),
        Err(_) => warn!(".env file not found. Service will rely on system environment variables."),
    };

    // --- NEW: Open CORS Configuration ---
    warn!("CORS is configured to allow all origins. This is a potential security risk.");

    let cors = CorsLayer::new()
        // Allow requests from any origin.
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::OPTIONS, Method::GET, Method::HEAD])
        .allow_headers([header::CONTENT_TYPE]);
    // --- End of new CORS code ---

    // Define the application routes and middleware
    let app = Router::new()
        .route("/seal", post(seal_handler))
        .route("/health", get(health_check_handler))
        .route("/", get(root_redirect_handler).head(root_redirect_handler))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(cors);

    // ... (rest of the file is the same)
    let port = env::var("PORT").unwrap_or_else(|_| "10000".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!(port = port, "✅ Aegis Sealer listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

// ... (all handler functions and AppError are the same)
async fn root_redirect_handler() -> Redirect {
    Redirect::to("https://www.google.com")
}

async fn health_check_handler() -> &'static str {
    "cron-job successfull"
}

#[instrument(skip_all, fields(image_size, metadata_size))]
async fn seal_handler(mut multipart: Multipart) -> Result<Response, AppError> {
    info!("Received new request for /seal endpoint.");

    let pk_hex = env::var("AEGIS_PRIVATE_KEY").map_err(|_| {
        error!("FATAL: AEGIS_PRIVATE_KEY environment variable not set.");
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server is not configured correctly. Administrator must set a private key.".into(),
        )
    })?;

    let pk_bytes = hex::decode(&pk_hex).map_err(|e| {
        error!(error = %e, "Failed to decode hex private key. Key must be a valid hex string.");
        AppError::from(e)
    })?;

    let private_key = SigningKey::from_slice(&pk_bytes).map_err(|e| {
        error!(error = %e, "Failed to create SigningKey from bytes. The key is likely invalid or malformed.");
        AppError::from(e)
    })?;

    let mut image_data: Option<Vec<u8>> = None;
    let mut metadata_str: Option<String> = None;

    info!("Processing multipart form data...");
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_string();
        let data = field.bytes().await?;

        if name == "image" {
            let size = data.len();
            tracing::Span::current().record("image_size", &size);
            info!(size, "Found 'image' field.");
            image_data = Some(data.to_vec());
        } else if name == "metadata" {
            let size = data.len();
            tracing::Span::current().record("metadata_size", &size);
            info!(size, "Found 'metadata' field.");
            metadata_str = Some(String::from_utf8(data.to_vec())?);
        }
    }

    let image_data = image_data.ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "Request is missing required 'image' field.".into()))?;
    let metadata_str = metadata_str.ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "Request is missing required 'metadata' field.".into()))?;

    info!("Calling core seal() function...");
    let ancient = crypto::seal(metadata_str, image_data, &private_key)?;

    let mut sealed_bytes = Vec::new();
    ancient.write(&mut sealed_bytes)?;
    info!(bytes_written = sealed_bytes.len(), "Data successfully sealed and serialized.");

    info!("Sending sealed file as response.");
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"sealed.aegis\"",
            ),
        ],
        sealed_bytes,
    )
        .into_response())
}

struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        let anyhow_err = err.into();
        error!(error = %anyhow_err, "An internal application error occurred.");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", anyhow_err),
        )
    }
}
