use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// HTTP client for communicating with the Go API backend
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, base_url }
    }

    /// Create a new API client with default localhost URL
    pub fn default() -> Self {
        Self::new("http://localhost:8080".to_string())
    }

    /// Make a GET request
    pub async fn get<T>(&self, endpoint: &str) -> Result<ApiResponse<T>, ApiError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, endpoint);
        let response = self.client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Make a POST request with JSON body
    pub async fn post<T, B>(&self, endpoint: &str, body: &B) -> Result<ApiResponse<T>, ApiError>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize,
    {
        let url = format!("{}{}", self.base_url, endpoint);



        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await?;
        self.handle_response(response).await
    }

    /// Make a PATCH request with JSON body
    pub async fn patch<T, B>(&self, endpoint: &str, body: &B) -> Result<ApiResponse<T>, ApiError>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize,
    {
        let url = format!("{}{}", self.base_url, endpoint);
        let response = self
            .client
            .patch(&url)
            .json(body)
            .send()
            .await?;
        self.handle_response(response).await
    }

    /// Handle HTTP response and parse JSON
    async fn handle_response<T>(&self, response: Response) -> Result<ApiResponse<T>, ApiError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let text = response.text().await?;



        if status.is_success() {
            match serde_json::from_str::<ApiResponse<T>>(&text) {
                Ok(api_response) => Ok(api_response),
                Err(_) => {
                    // Try to parse as direct data if it's not wrapped in ApiResponse
                    match serde_json::from_str::<T>(&text) {
                        Ok(data) => Ok(ApiResponse {
                            success: true,
                            data: Some(data),
                            error: None,
                        }),
                        Err(e) => Err(ApiError::ParseError(format!("Failed to parse response: {}", e))),
                    }
                }
            }
        } else {
            // Try to parse error response - Go backend may not include 'data' field in errors
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&text) {
                let success = json_value.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                let error = json_value.get("error").and_then(|v| v.as_str()).map(|s| s.to_string());

                Ok(ApiResponse {
                    success,
                    data: None,
                    error,
                })
            } else {
                Err(ApiError::HttpError(format!("HTTP {}: {}", status, text)))
            }
        }
    }

    /// Health check endpoint
    pub async fn health_check(&self) -> Result<ApiResponse<HealthResponse>, ApiError> {
        self.get("/health").await
    }
}

/// Standard API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

/// API client errors
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("API error: {0}")]
    ApiError(String),
}

impl From<ApiError> for String {
    fn from(error: ApiError) -> Self {
        error.to_string()
    }
}
