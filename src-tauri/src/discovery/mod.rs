//! Surfacing agent sessions codeg did not spawn.
//!
//! Two rules keep it from fighting the rest of the system:
//!
//! * A conversation held by a live ACP connection is never touched — the
//!   lifecycle subscriber owns that row's status.
//! * Only rows this sweep marked running are ever moved back, so it cannot
//!   settle a conversation somebody else is driving.

pub mod probe;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use sea_orm::DatabaseConnection;

use crate::acp::manager::ConnectionManager;
use crate::db::entities::conversation::ConversationStatus;
use crate::db::service::{conversation_service, folder_service, import_service};
use crate::parsers::{build_agent_parser, normalize_path_for_matching};
use crate::web::event_bridge::EventEmitter;

use probe::{probe_live_sessions, LiveSession};

/// How often to look for external sessions when the interval is not overridden.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);

/// Whether discovery should run, and how often.
///
/// Off switch and cadence come from the environment rather than a settings row:
/// the sweep only ever reflects what is already running, so there is nothing
/// for a user to configure beyond "stop doing that".
pub fn interval_from_env() -> Option<Duration> {
    let enabled = std::env::var("CODEG_SESSION_DISCOVERY").unwrap_or_default();
    if matches!(enabled.trim().to_ascii_lowercase().as_str(), "0" | "off" | "false" | "no") {
        return None;
    }
    let seconds = std::env::var("CODEG_SESSION_DISCOVERY_INTERVAL_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0);
    Some(seconds.map_or(DEFAULT_INTERVAL, Duration::from_secs))
}

/// Never returns; the caller drops the handle at process exit.
pub async fn live_session_sweep_task(
    conn: DatabaseConnection,
    emitter: EventEmitter,
    connections: ConnectionManager,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    // Rows this sweep marked running. Scoped to the process: after a restart a
    // still-running session is re-adopted on the next tick and settles
    // normally; only one that ended during the downtime keeps a stale status.
    let mut adopted: HashSet<i32> = HashSet::new();

    loop {
        ticker.tick().await;
        if let Err(error) = sweep(&conn, &emitter, &connections, &mut adopted).await {
            tracing::warn!("external session discovery failed: {error}");
        }
    }
}

async fn sweep(
    conn: &DatabaseConnection,
    emitter: &EventEmitter,
    connections: &ConnectionManager,
    adopted: &mut HashSet<i32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let live = tokio::task::spawn_blocking(probe_live_sessions).await?;
    let folders = registered_folders(conn).await?;

    let mut running = HashSet::new();
    for session in live {
        match adopt(conn, emitter, connections, &folders, &session).await {
            Ok(Some(conversation_id)) => {
                running.insert(conversation_id);
                adopted.insert(conversation_id);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(
                    "could not adopt {} session {}: {error}",
                    session.agent_type.as_wire(),
                    session.external_id
                );
            }
        }
    }

    for conversation_id in settled(adopted, &running) {
        if connections
            .find_connection_by_conversation_id(conversation_id)
            .await
            .is_some()
        {
            continue;
        }
        conversation_service::update_status(conn, conversation_id, ConversationStatus::PendingReview)
            .await?;
        adopted.remove(&conversation_id);
        crate::commands::conversations::emit_conversation_upsert(emitter, conn, conversation_id).await;
    }

    Ok(())
}

/// Keeps failed status writes eligible for retry.
fn settled(adopted: &HashSet<i32>, running: &HashSet<i32>) -> Vec<i32> {
    adopted.difference(running).copied().collect()
}

/// Mark one running session's conversation as running, importing it first if
/// this is the first time we have seen it. Returns the conversation id, or
/// `None` when the session belongs to a folder the workspace does not track.
async fn adopt(
    conn: &DatabaseConnection,
    emitter: &EventEmitter,
    connections: &ConnectionManager,
    folders: &HashMap<String, i32>,
    session: &LiveSession,
) -> Result<Option<i32>, Box<dyn std::error::Error + Send + Sync>> {
    let existing =
        import_service::find_imported_row(conn, &session.agent_type, &session.external_id).await?;

    let row = match existing {
        Some(row) => row,
        None => match import_running(conn, folders, session).await? {
            Some(row) => row,
            None => return Ok(None),
        },
    };

    // The ACP lifecycle owns the status of anything codeg is driving itself.
    if connections
        .find_connection_by_conversation_id(row.id)
        .await
        .is_some()
    {
        return Ok(None);
    }

    if row.status != ConversationStatus::InProgress {
        conversation_service::update_status(conn, row.id, ConversationStatus::InProgress).await?;
        crate::commands::conversations::emit_conversation_upsert(emitter, conn, row.id).await;
    }

    Ok(Some(row.id))
}

/// First sighting: read the transcript for a summary, then import it into the
/// folder it runs in. A session outside the workspace's folders is left alone —
/// discovery surfaces work in projects the user already opened, it does not
/// enrol new ones.
async fn import_running(
    conn: &DatabaseConnection,
    folders: &HashMap<String, i32>,
    session: &LiveSession,
) -> Result<Option<crate::db::entities::conversation::Model>, Box<dyn std::error::Error + Send + Sync>>
{
    let agent_type = session.agent_type.clone();
    let external_id = session.external_id.clone();
    let detail =
        tokio::task::spawn_blocking(move || build_agent_parser(agent_type).get_conversation(&external_id))
            .await??;
    let summary = detail.summary;

    let cwd = session
        .cwd
        .clone()
        .or_else(|| summary.folder_path.clone());
    let Some(folder_id) = cwd
        .as_deref()
        .map(normalize_path_for_matching)
        .and_then(|path| folders.get(&path).copied())
    else {
        return Ok(None);
    };

    import_service::import_one_discovered(conn, folder_id, &session.agent_type, &summary).await?;
    Ok(import_service::find_imported_row(conn, &session.agent_type, &session.external_id).await?)
}

/// Normalized path to folder id, for every folder in the workspace.
async fn registered_folders(
    conn: &DatabaseConnection,
) -> Result<HashMap<String, i32>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(folder_service::list_all_folder_details(conn)
        .await?
        .into_iter()
        .map(|folder| (normalize_path_for_matching(&folder.path), folder.id))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_is_on_by_default_and_switchable_off() {
        temp_env::with_vars(
            [
                ("CODEG_SESSION_DISCOVERY", None::<&str>),
                ("CODEG_SESSION_DISCOVERY_INTERVAL_SECS", None),
            ],
            || assert_eq!(interval_from_env(), Some(DEFAULT_INTERVAL)),
        );
        for off in ["0", "off", "false", "no", "OFF"] {
            temp_env::with_var("CODEG_SESSION_DISCOVERY", Some(off), || {
                assert_eq!(interval_from_env(), None, "{off} must disable discovery");
            });
        }
    }

    #[test]
    fn a_bad_interval_falls_back_instead_of_spinning() {
        for bad in ["0", "-5", "abc", ""] {
            temp_env::with_vars(
                [
                    ("CODEG_SESSION_DISCOVERY", None::<&str>),
                    ("CODEG_SESSION_DISCOVERY_INTERVAL_SECS", Some(bad)),
                ],
                || assert_eq!(interval_from_env(), Some(DEFAULT_INTERVAL), "{bad:?}"),
            );
        }
        temp_env::with_vars(
            [
                ("CODEG_SESSION_DISCOVERY", None::<&str>),
                ("CODEG_SESSION_DISCOVERY_INTERVAL_SECS", Some("3")),
            ],
            || assert_eq!(interval_from_env(), Some(Duration::from_secs(3))),
        );
    }

    #[test]
    fn only_rows_no_longer_running_are_candidates_to_settle() {
        let adopted: HashSet<i32> = [1, 2, 3].into_iter().collect();
        let running: HashSet<i32> = [2].into_iter().collect();

        let mut gone = settled(&adopted, &running);
        gone.sort_unstable();

        assert_eq!(gone, vec![1, 3]);
        assert_eq!(adopted, [1, 2, 3].into_iter().collect::<HashSet<i32>>());
    }
}
