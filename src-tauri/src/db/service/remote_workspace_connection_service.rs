use chrono::Utc;
use std::collections::{HashMap, HashSet};

use sea_orm::DatabaseConnection;
use sea_orm::{
    ActiveModelTrait, ActiveValue::NotSet, EntityTrait, IntoActiveModel, QueryOrder, Set,
    TransactionTrait,
};

use crate::app_error::AppCommandError;
use crate::db::entities::remote_workspace_connection;
use crate::db::error::DbError;
use crate::models::{RemoteWorkspaceConnectionRecord, RemoteWorkspaceHeader};

/// Names the client sets itself, on the HTTP calls and on the WebSocket
/// handshake. The save fails rather than silently drop what the user typed.
/// A slice, not a fixed-size array: the length is one more thing to forget to
/// bump when a name is added.
const RESERVED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "content-type",
    "content-length",
    // `hyper` frames the body itself and picks chunked for the streaming
    // workspace upload. A user-supplied framing header contradicts it, and it
    // is also the header a request-smuggling attempt rides in on — which is
    // the one thing not to hand to a fronting proxy.
    "transfer-encoding",
    "host",
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
];

/// What the legacy `headers` column holds once a row's secrets have moved into
/// `keyring_store`; its `token` column goes empty.
const EMPTY_HEADERS_JSON: &str = "[]";

fn record_with_secrets(
    model: remote_workspace_connection::Model,
    token: String,
    headers: Vec<RemoteWorkspaceHeader>,
) -> RemoteWorkspaceConnectionRecord {
    RemoteWorkspaceConnectionRecord {
        id: model.id,
        name: model.name,
        base_url: model.base_url,
        token,
        headers,
        sort_order: model.sort_order,
        created_at: model.created_at,
        updated_at: model.updated_at,
    }
}

/// The columns are read only as a fallback, for a row the startup migration
/// has not moved yet. Nothing writes them any more.
fn to_record(model: remote_workspace_connection::Model) -> RemoteWorkspaceConnectionRecord {
    let token = crate::keyring_store::get_remote_workspace_token(model.id)
        .unwrap_or_else(|| model.token.clone());
    let headers = crate::keyring_store::get_remote_workspace_headers(model.id)
        .unwrap_or_else(|| serde_json::from_str(&model.headers).unwrap_or_default());
    record_with_secrets(model, token, headers)
}

fn store_secrets(
    connection_id: i32,
    token: &str,
    headers: &[RemoteWorkspaceHeader],
) -> Result<(), String> {
    crate::keyring_store::set_remote_workspace_token(connection_id, token)?;
    crate::keyring_store::set_remote_workspace_headers(connection_id, headers)
}

/// Confirm the store can hand back what it was just given, so a write that
/// reports success without persisting cannot cost the caller its only copy.
fn secrets_readable(connection_id: i32, token: &str, headers: &[RemoteWorkspaceHeader]) -> bool {
    crate::keyring_store::get_remote_workspace_token(connection_id).as_deref() == Some(token)
        && crate::keyring_store::get_remote_workspace_headers(connection_id).as_deref()
            == Some(headers)
}

pub fn validate_headers(
    headers: &[RemoteWorkspaceHeader],
) -> Result<Vec<RemoteWorkspaceHeader>, AppCommandError> {
    let mut result = Vec::with_capacity(headers.len());
    for header in headers {
        let name = header.name.trim();
        let value = header.value.trim();
        if name.is_empty() && value.is_empty() {
            continue;
        }
        if name.is_empty() {
            return Err(AppCommandError::invalid_input(
                "Custom header name is required",
            ));
        }
        if RESERVED_HEADER_NAMES.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(AppCommandError::invalid_input(format!(
                "Custom header \"{name}\" is reserved by Codeg"
            )));
        }
        header.to_header_pair().map_err(|e| {
            AppCommandError::invalid_input(format!("Custom header \"{name}\" is invalid"))
                .with_detail(e.to_string())
        })?;
        result.push(RemoteWorkspaceHeader {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
    Ok(result)
}

pub fn normalize_base_url(raw: &str) -> Result<String, AppCommandError> {
    let trimmed = raw.trim().trim_end_matches('/').to_string();
    let parsed = reqwest::Url::parse(&trimmed).map_err(|e| {
        AppCommandError::invalid_input("Remote Workspace URL is invalid").with_detail(e.to_string())
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(trimmed),
        _ => Err(AppCommandError::invalid_input(
            "Remote Workspace URL must use http or https",
        )),
    }
}

fn validate_name(name: &str) -> Result<String, AppCommandError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppCommandError::invalid_input(
            "Remote connection name is required",
        ));
    }
    Ok(trimmed.to_string())
}

pub fn validate_token(token: &str) -> Result<String, AppCommandError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(AppCommandError::invalid_input(
            "Remote connection token is required",
        ));
    }
    Ok(trimmed.to_string())
}

pub async fn list(
    conn: &DatabaseConnection,
) -> Result<Vec<RemoteWorkspaceConnectionRecord>, DbError> {
    let rows = remote_workspace_connection::Entity::find()
        .order_by_asc(remote_workspace_connection::Column::SortOrder)
        .order_by_asc(remote_workspace_connection::Column::Name)
        .all(conn)
        .await?;
    Ok(rows.into_iter().map(to_record).collect())
}

pub async fn get(
    conn: &DatabaseConnection,
    id: i32,
) -> Result<Option<RemoteWorkspaceConnectionRecord>, DbError> {
    let row = remote_workspace_connection::Entity::find_by_id(id)
        .one(conn)
        .await?;
    Ok(row.map(to_record))
}

pub async fn create(
    conn: &DatabaseConnection,
    name: &str,
    base_url: &str,
    token: &str,
    headers: &[RemoteWorkspaceHeader],
) -> Result<RemoteWorkspaceConnectionRecord, AppCommandError> {
    let now = Utc::now();
    let headers = validate_headers(headers)?;
    let name = validate_name(name)?;
    let base_url = normalize_base_url(base_url)?;
    let token = validate_token(token)?;
    let max_order = remote_workspace_connection::Entity::find()
        .order_by_desc(remote_workspace_connection::Column::SortOrder)
        .one(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?
        .map(|m| m.sort_order)
        .unwrap_or(-1);
    let active = remote_workspace_connection::ActiveModel {
        id: NotSet,
        name: Set(name),
        base_url: Set(base_url),
        token: Set(String::new()),
        headers: Set(EMPTY_HEADERS_JSON.to_string()),
        sort_order: Set(max_order + 1),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let model = active
        .insert(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    // Secrets key off the id, which only exists after the insert. A row whose
    // secrets never landed can never authenticate, so it goes away again.
    if let Err(e) = store_secrets(model.id, &token, &headers) {
        let _ = remote_workspace_connection::Entity::delete_by_id(model.id)
            .exec(conn)
            .await;
        return Err(
            AppCommandError::io_error("Failed to store remote connection credentials")
                .with_detail(e),
        );
    }
    Ok(record_with_secrets(model, token, headers))
}

pub async fn update(
    conn: &DatabaseConnection,
    id: i32,
    name: &str,
    base_url: &str,
    token: &str,
    headers: &[RemoteWorkspaceHeader],
) -> Result<RemoteWorkspaceConnectionRecord, AppCommandError> {
    let headers = validate_headers(headers)?;
    let token = validate_token(token)?;
    let row = remote_workspace_connection::Entity::find_by_id(id)
        .one(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?
        .ok_or_else(|| AppCommandError::not_found(format!("Remote connection {id} not found")))?;

    let mut active = row.into_active_model();
    active.name = Set(validate_name(name)?);
    active.base_url = Set(normalize_base_url(base_url)?);
    active.token = Set(String::new());
    active.headers = Set(EMPTY_HEADERS_JSON.to_string());
    active.updated_at = Set(Utc::now());
    let model = active
        .update(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    store_secrets(model.id, &token, &headers).map_err(|e| {
        AppCommandError::io_error("Failed to store remote connection credentials").with_detail(e)
    })?;
    Ok(record_with_secrets(model, token, headers))
}

pub async fn delete(conn: &DatabaseConnection, id: i32) -> Result<(), DbError> {
    remote_workspace_connection::Entity::delete_by_id(id)
        .exec(conn)
        .await?;
    if let Err(e) = crate::keyring_store::delete_remote_workspace_secrets(id) {
        // The connection is gone either way, and whichever one next takes this
        // id overwrites the leftover entry.
        tracing::warn!("[remote-workspace] failed to delete secrets for connection {id}: {e}");
    }
    Ok(())
}

/// Move plaintext `token` / `headers` columns into `keyring_store`, then clear
/// them. A row whose secrets do not read back out of the store keeps its
/// plaintext for the next run, rather than losing the user's credentials.
pub async fn migrate_plaintext_secrets(conn: &DatabaseConnection) -> Result<usize, DbError> {
    let rows = remote_workspace_connection::Entity::find().all(conn).await?;
    let mut moved = 0;
    for row in rows {
        if row.token.is_empty() && row.headers == EMPTY_HEADERS_JSON {
            continue;
        }
        let id = row.id;
        let headers: Vec<RemoteWorkspaceHeader> =
            serde_json::from_str(&row.headers).unwrap_or_default();
        if let Err(e) = store_secrets(id, &row.token, &headers) {
            tracing::warn!("[remote-workspace] connection {id} secrets not migrated: {e}");
            continue;
        }
        if !secrets_readable(id, &row.token, &headers) {
            tracing::warn!(
                "[remote-workspace] connection {id} secrets did not read back; keeping plaintext"
            );
            continue;
        }
        let mut active = row.into_active_model();
        active.token = Set(String::new());
        active.headers = Set(EMPTY_HEADERS_JSON.to_string());
        active.update(conn).await?;
        moved += 1;
    }
    Ok(moved)
}

pub async fn reorder(conn: &DatabaseConnection, ids: Vec<i32>) -> Result<(), AppCommandError> {
    if ids.is_empty() {
        return Ok(());
    }

    let unique_ids = ids.iter().copied().collect::<HashSet<_>>();
    if unique_ids.len() != ids.len() {
        return Err(AppCommandError::invalid_input(
            "Remote workspace order contains duplicate connections",
        ));
    }

    let rows = remote_workspace_connection::Entity::find()
        .all(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    let existing_ids = rows.iter().map(|row| row.id).collect::<HashSet<_>>();
    if existing_ids != unique_ids {
        return Err(AppCommandError::invalid_input(
            "Remote workspace order must include every connection exactly once",
        ));
    }

    let now = Utc::now();
    let mut rows_by_id = rows
        .into_iter()
        .map(|row| (row.id, row))
        .collect::<HashMap<_, _>>();
    let txn = conn
        .begin()
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    for (idx, id) in ids.into_iter().enumerate() {
        let Some(row) = rows_by_id.remove(&id) else {
            return Err(AppCommandError::invalid_input(
                "Remote workspace order contains an unknown connection",
            ));
        };
        let mut active = row.into_active_model();
        active.sort_order = Set(idx as i32);
        active.updated_at = Set(now);
        active
            .update(&txn)
            .await
            .map_err(DbError::from)
            .map_err(AppCommandError::db)?;
    }
    txn.commit()
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "tauri-runtime"))]
    use crate::db::test_helpers::fresh_in_memory_db;
    use crate::models::ToHeaderMap;
    #[cfg(not(feature = "tauri-runtime"))]
    use std::future::Future;

    #[test]
    fn normalize_base_url_trims_and_removes_trailing_slashes() {
        let actual = normalize_base_url("  http://127.0.0.1:3080///  ").unwrap();
        assert_eq!(actual, "http://127.0.0.1:3080");
    }

    #[test]
    fn normalize_base_url_rejects_non_http_schemes() {
        let err = normalize_base_url("file:///tmp/codeg").unwrap_err();
        assert!(err.message.contains("http"));
    }

    fn header(name: &str, value: &str) -> RemoteWorkspaceHeader {
        RemoteWorkspaceHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn validate_headers_trims_and_drops_empty_rows() {
        let actual = validate_headers(&[
            header("  CF-Access-Client-Id  ", "  abc123  "),
            header("", ""),
            header("   ", "  "),
        ])
        .unwrap();
        assert_eq!(actual, vec![header("CF-Access-Client-Id", "abc123")]);
    }

    #[test]
    fn validate_headers_keeps_repeated_names_and_order() {
        let input = vec![header("X-Trace", "a"), header("X-Trace", "b")];
        assert_eq!(validate_headers(&input).unwrap(), input);
    }

    #[test]
    fn to_header_map_keeps_repeats_and_skips_unparsable_rows() {
        let map = [
            header("X-Trace", "a"),
            header("X-Trace", "b"),
            header("bad header", "dropped"),
            header("  ", "dropped"),
        ]
        .to_header_map();
        assert_eq!(
            map.get_all("x-trace")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn to_header_map_marks_every_value_sensitive() {
        // A custom header is a credential. Sensitive keeps it out of the HTTP/2
        // HPACK dynamic table and out of any `{:?}` of the request.
        let map = [header("CF-Access-Client-Secret", "s3cret")].to_header_map();
        let value = map.get("cf-access-client-secret").unwrap();
        assert!(value.is_sensitive());
        assert_eq!(format!("{value:?}"), "Sensitive");
    }

    #[test]
    fn validate_headers_rejects_reserved_names() {
        for name in [
            "Authorization",
            "content-type",
            "Transfer-Encoding",
            "Sec-WebSocket-Protocol",
        ] {
            let err = validate_headers(&[header(name, "x")]).unwrap_err();
            assert!(
                err.message.contains("reserved"),
                "expected {name} to be reserved, got {}",
                err.message
            );
        }
    }

    #[test]
    fn validate_headers_rejects_invalid_name_value_and_missing_name() {
        assert!(validate_headers(&[header("bad header", "x")]).is_err());
        assert!(validate_headers(&[header("X-Bad", "line\nbreak")]).is_err());
        assert!(validate_headers(&[header("", "orphan-value")]).is_err());
    }

    /// Writing a connection writes its secrets, and under `tauri-runtime` that
    /// is the real OS keyring. Server mode only, file store in a temp dir.
    #[cfg(not(feature = "tauri-runtime"))]
    async fn with_temp_secret_store<Fut>(body: impl FnOnce(crate::db::AppDatabase) -> Fut)
    where
        Fut: Future<Output = ()>,
    {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_string_lossy().to_string();
        let db = fresh_in_memory_db().await;
        temp_env::async_with_vars([("CODEG_DATA_DIR", Some(dir.as_str()))], body(db)).await;
    }

    /// A row as an older build wrote it: token and headers in the clear, with
    /// timestamps copied from a row SeaORM wrote.
    #[cfg(not(feature = "tauri-runtime"))]
    async fn seed_legacy_row(conn: &DatabaseConnection, token: &str, headers_json: &str) -> i32 {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};

        let anchor = create(conn, "Anchor", "http://127.0.0.1:3080", "anchor-token", &[])
            .await
            .expect("anchor row");
        conn.execute(Statement::from_string(
            DbBackend::Sqlite,
            format!(
                "INSERT INTO remote_workspace_connection \
                 (name, base_url, token, headers, sort_order, created_at, updated_at) \
                 SELECT 'Legacy', 'http://127.0.0.1:3099', '{token}', '{headers_json}', 1, \
                 created_at, updated_at FROM remote_workspace_connection WHERE id = {}",
                anchor.id
            ),
        ))
        .await
        .expect("seed legacy row");
        remote_workspace_connection::Entity::find()
            .order_by_desc(remote_workspace_connection::Column::Id)
            .one(conn)
            .await
            .expect("read back legacy row")
            .expect("legacy row exists")
            .id
    }

    #[cfg(not(feature = "tauri-runtime"))]
    async fn row(conn: &DatabaseConnection, id: i32) -> remote_workspace_connection::Model {
        remote_workspace_connection::Entity::find_by_id(id)
            .one(conn)
            .await
            .expect("read row")
            .expect("row exists")
    }

    #[cfg(not(feature = "tauri-runtime"))]
    #[tokio::test]
    async fn create_list_update_delete_roundtrip() {
        with_temp_secret_store(|db| async move {
            let created = create(
                &db.conn,
                "Local 3080",
                "http://127.0.0.1:3080/",
                "secret-token",
                &[header("CF-Access-Client-Id", "abc123")],
            )
            .await
            .unwrap();
            assert_eq!(created.name, "Local 3080");
            assert_eq!(created.base_url, "http://127.0.0.1:3080");
            assert_eq!(created.token, "secret-token");
            assert_eq!(
                created.headers,
                vec![header("CF-Access-Client-Id", "abc123")]
            );
            assert_eq!(created.sort_order, 0);

            // The secrets live in the store, and the columns stay empty.
            let stored = row(&db.conn, created.id).await;
            assert_eq!(stored.token, "");
            assert_eq!(stored.headers, "[]");

            let listed = list(&db.conn).await.unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].id, created.id);
            assert_eq!(listed[0].token, "secret-token");
            assert_eq!(listed[0].headers, created.headers);

            let updated = update(
                &db.conn,
                created.id,
                "Server A",
                "https://codeg.example.com/",
                "next-token",
                &[],
            )
            .await
            .unwrap();
            assert_eq!(updated.name, "Server A");
            assert_eq!(updated.base_url, "https://codeg.example.com");
            assert!(updated.headers.is_empty());
            assert_eq!(
                crate::keyring_store::get_remote_workspace_token(created.id).as_deref(),
                Some("next-token")
            );

            delete(&db.conn, created.id).await.unwrap();
            assert!(list(&db.conn).await.unwrap().is_empty());
            assert!(crate::keyring_store::get_remote_workspace_token(created.id).is_none());
            assert!(crate::keyring_store::get_remote_workspace_headers(created.id).is_none());
        })
        .await;
    }

    /// The upgrade path, which is every existing install. A migration that
    /// drops the token silently breaks a configured connection.
    #[cfg(not(feature = "tauri-runtime"))]
    #[tokio::test]
    async fn migrate_moves_plaintext_secrets_into_the_store() {
        with_temp_secret_store(|db| async move {
            let id = seed_legacy_row(
                &db.conn,
                "legacy-token",
                r#"[{"name":"CF-Access-Client-Id","value":"abc123"}]"#,
            )
            .await;

            assert_eq!(migrate_plaintext_secrets(&db.conn).await.unwrap(), 1);

            assert_eq!(
                crate::keyring_store::get_remote_workspace_token(id).as_deref(),
                Some("legacy-token")
            );
            assert_eq!(
                crate::keyring_store::get_remote_workspace_headers(id),
                Some(vec![header("CF-Access-Client-Id", "abc123")])
            );
            let cleared = row(&db.conn, id).await;
            assert_eq!(cleared.token, "");
            assert_eq!(cleared.headers, "[]");

            let record = get(&db.conn, id).await.unwrap().unwrap();
            assert_eq!(record.token, "legacy-token");
            assert_eq!(record.headers, vec![header("CF-Access-Client-Id", "abc123")]);

            // Idempotent: nothing left to move on the next start.
            assert_eq!(migrate_plaintext_secrets(&db.conn).await.unwrap(), 0);
        })
        .await;
    }

    /// A not-yet-migrated row must still connect — the plaintext column is the
    /// fallback until the migration succeeds.
    #[cfg(not(feature = "tauri-runtime"))]
    #[tokio::test]
    async fn unmigrated_row_still_resolves_its_secrets() {
        with_temp_secret_store(|db| async move {
            let id = seed_legacy_row(&db.conn, "legacy-token", "[]").await;
            let record = get(&db.conn, id).await.unwrap().unwrap();
            assert_eq!(record.token, "legacy-token");
        })
        .await;
    }

    /// The predicate that gates destroying the plaintext copy, so it has to
    /// discriminate rather than always answer yes.
    #[cfg(not(feature = "tauri-runtime"))]
    #[tokio::test]
    async fn secrets_readable_follows_the_store() {
        with_temp_secret_store(|_db| async move {
            let headers = vec![header("CF-Access-Client-Id", "abc123")];
            store_secrets(7, "tok", &headers).unwrap();
            assert!(secrets_readable(7, "tok", &headers));
            assert!(!secrets_readable(7, "different", &headers));

            crate::keyring_store::delete_remote_workspace_secrets(7).unwrap();
            assert!(!secrets_readable(7, "tok", &headers));
        })
        .await;
    }

    /// Rows written before the `headers` column existed. `ADD COLUMN NOT NULL
    /// DEFAULT '[]'` has to backfill them — a NULL there fails to deserialize
    /// into `Model.headers: String` and takes the whole connection list down,
    /// not just the headers. The insert omits `headers` exactly the way the old
    /// schema did.
    #[cfg(not(feature = "tauri-runtime"))]
    #[tokio::test]
    async fn list_reads_a_row_written_without_the_headers_column() {
        with_temp_secret_store(|db| async move {
            use sea_orm::{ConnectionTrait, DbBackend, Statement};

            let seed = create(&db.conn, "Seed", "http://127.0.0.1:3080", "token", &[])
                .await
                .unwrap();
            db.conn
                .execute(Statement::from_string(
                    DbBackend::Sqlite,
                    "INSERT INTO remote_workspace_connection \
                     (name, base_url, token, sort_order, created_at, updated_at) \
                     SELECT 'Legacy', 'http://127.0.0.1:3099', token, 1, \
                     created_at, updated_at FROM remote_workspace_connection"
                        .to_owned(),
                ))
                .await
                .unwrap();

            let listed = list(&db.conn).await.unwrap();
            assert_eq!(
                listed.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
                vec!["Seed", "Legacy"]
            );
            assert!(listed[1].headers.is_empty());

            // `create` re-reads every column to find the max sort order, so the
            // legacy row has to survive that read too.
            let next = create(&db.conn, "Next", "http://127.0.0.1:3081", "token", &[])
                .await
                .unwrap();
            assert_eq!(next.sort_order, 2);
            assert_ne!(next.id, seed.id);
        })
        .await;
    }

    #[cfg(not(feature = "tauri-runtime"))]
    #[tokio::test]
    async fn reorder_updates_list_order() {
        with_temp_secret_store(|db| async move {
            let first = create(&db.conn, "First", "http://127.0.0.1:3080", "token-a", &[])
                .await
                .unwrap();
            let second = create(&db.conn, "Second", "http://127.0.0.1:3081", "token-b", &[])
                .await
                .unwrap();
            let third = create(&db.conn, "Third", "http://127.0.0.1:3082", "token-c", &[])
                .await
                .unwrap();

            reorder(&db.conn, vec![third.id, first.id, second.id])
                .await
                .unwrap();

            let listed = list(&db.conn).await.unwrap();
            assert_eq!(
                listed.iter().map(|item| item.id).collect::<Vec<_>>(),
                vec![third.id, first.id, second.id]
            );
            assert_eq!(
                listed
                    .iter()
                    .map(|item| item.sort_order)
                    .collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
        })
        .await;
    }

    #[cfg(not(feature = "tauri-runtime"))]
    #[tokio::test]
    async fn reorder_rejects_partial_or_duplicate_ids() {
        with_temp_secret_store(|db| async move {
            let first = create(&db.conn, "First", "http://127.0.0.1:3080", "token-a", &[])
                .await
                .unwrap();
            let second = create(&db.conn, "Second", "http://127.0.0.1:3081", "token-b", &[])
                .await
                .unwrap();

            let duplicate = reorder(&db.conn, vec![first.id, first.id])
                .await
                .unwrap_err();
            assert!(matches!(
                duplicate.code,
                crate::app_error::AppErrorCode::InvalidInput
            ));

            let partial = reorder(&db.conn, vec![second.id]).await.unwrap_err();
            assert!(matches!(
                partial.code,
                crate::app_error::AppErrorCode::InvalidInput
            ));

            let listed = list(&db.conn).await.unwrap();
            assert_eq!(
                listed.iter().map(|item| item.id).collect::<Vec<_>>(),
                vec![first.id, second.id]
            );
        })
        .await;
    }
}
