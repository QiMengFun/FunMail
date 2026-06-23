use crate::state::AppState;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct ContactResponse {
    pub id: i32,
    pub name: Option<String>,
    pub email: String,
    pub notes: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateContactRequest {
    pub name: Option<String>,
    pub email: String,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateContactRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub notes: Option<String>,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/contacts", axum::routing::get(list_contacts).post(create_contact))
        .route("/contacts/{id}", axum::routing::put(update_contact).delete(delete_contact))
        .route("/contacts/search", axum::routing::get(search_contacts))
}

/// 从 JWT 提取 claims 并校验 token_version（异步）
async fn extract_mailbox_id(headers: &HeaderMap, state: &AppState) -> Result<i32, (StatusCode, String)> {
    let claims = crate::api::webmail_routes::verify_claims(headers, state)
        .await
        .map_err(|(s, msg)| (s, msg))?;
    Ok(claims.mailbox_id)
}

async fn list_contacts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ContactResponse>>, (StatusCode, String)> {
    let mailbox_id = extract_mailbox_id(&headers, &state).await?;
    let rows = sqlx::query_as::<_, (i32, Option<String>, String, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, name, email, notes, created_at FROM contacts WHERE mailbox_id = $1 ORDER BY name NULLS LAST, email"
    )
    .bind(mailbox_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询联系人失败".to_string()))?;

    let contacts = rows.into_iter().map(|(id, name, email, notes, created_at)| ContactResponse {
        id, name, email, notes, created_at: created_at.to_rfc3339(),
    }).collect();
    Ok(Json(contacts))
}

async fn create_contact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateContactRequest>,
) -> Result<Json<ContactResponse>, (StatusCode, String)> {
    let mailbox_id = extract_mailbox_id(&headers, &state).await?;
    let email = req.email.trim().to_lowercase();
    if email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "邮箱不能为空".to_string()));
    }
    let row: (i32, Option<String>, String, Option<String>, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "INSERT INTO contacts (mailbox_id, name, email, notes) VALUES ($1, $2, $3, $4)
         ON CONFLICT (mailbox_id, email) DO UPDATE SET name = EXCLUDED.name, notes = EXCLUDED.notes, updated_at = NOW()
         RETURNING id, name, email, notes, created_at"
    )
    .bind(mailbox_id)
    .bind(req.name.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()))
    .bind(&email)
    .bind(req.notes.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()))
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("创建联系人失败: {}", e)))?;

    Ok(Json(ContactResponse {
        id: row.0, name: row.1, email: row.2, notes: row.3, created_at: row.4.to_rfc3339(),
    }))
}

async fn update_contact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
    Json(req): Json<UpdateContactRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mailbox_id = extract_mailbox_id(&headers, &state).await?;
    let result = sqlx::query(
        "UPDATE contacts SET name = COALESCE($3, name), email = COALESCE($4, email), notes = COALESCE($5, notes), updated_at = NOW()
         WHERE id = $1 AND mailbox_id = $2"
    )
    .bind(id)
    .bind(mailbox_id)
    .bind(req.name.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()))
    .bind(req.email.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()))
    .bind(req.notes.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()))
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "联系人不存在".to_string()));
    }
    Ok(StatusCode::OK)
}

async fn delete_contact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mailbox_id = extract_mailbox_id(&headers, &state).await?;
    let result = sqlx::query("DELETE FROM contacts WHERE id = $1 AND mailbox_id = $2")
        .bind(id)
        .bind(mailbox_id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "联系人不存在".to_string()));
    }
    Ok(StatusCode::OK)
}

/// 自动补全：按前缀查询联系人（name 或 email）
async fn search_contacts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<ContactResponse>>, (StatusCode, String)> {
    let mailbox_id = extract_mailbox_id(&headers, &state).await?;
    let q = params.get("q").map(|s| s.to_lowercase()).unwrap_or_default();
    if q.len() < 1 {
        return Ok(Json(Vec::new()));
    }
    let pattern = format!("{}%", q);
    let rows = sqlx::query_as::<_, (i32, Option<String>, String, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, name, email, notes, created_at FROM contacts
         WHERE mailbox_id = $1 AND (LOWER(email) LIKE $2 OR LOWER(COALESCE(name, '')) LIKE $2)
         ORDER BY email LIMIT 10"
    )
    .bind(mailbox_id)
    .bind(&pattern)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询失败".to_string()))?;

    let contacts = rows.into_iter().map(|(id, name, email, notes, created_at)| ContactResponse {
        id, name, email, notes, created_at: created_at.to_rfc3339(),
    }).collect();
    Ok(Json(contacts))
}
