//! Liveness probes for agent sessions codeg did not spawn.
//!
//! The import pipeline answers "what sessions exist on disk"; that is a
//! different question from "what is running right now", and transcript mtime
//! cannot answer the second one — a session that exited a second ago and one
//! parked waiting for input look identical. Each probe here reads the runtime
//! bookkeeping its CLI already keeps, so liveness is observed rather than
//! guessed:
//!
//! * Claude Code writes `<config>/sessions/<pid>.json` per session, so a live
//!   session is one whose pid still exists.
//! * pi holds an advisory `flock` on `.<session>.jsonl.lock.os` for as long as
//!   the session owns the transcript, so a live session is a lock we cannot
//!   take.
//!
//! Both signals are unix-only; on other platforms the probes yield nothing
//! rather than guessing from timestamps.

use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::models::agent::AgentType;

/// An external agent session observed running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSession {
    pub agent_type: AgentType,
    /// The session id as the CLI names it on disk — the conversation's `external_id`.
    pub external_id: String,
    /// Working directory, when the probe learns it without parsing the
    /// transcript. `None` means the caller must resolve it through the parser.
    pub cwd: Option<String>,
}

/// Every external session running right now, across supported agents.
///
/// Blocking filesystem work: call from `spawn_blocking`.
pub fn probe_live_sessions() -> Vec<LiveSession> {
    let mut sessions = probe_claude_in(&crate::parsers::claude::resolve_claude_config_dir().join("sessions"));
    sessions.extend(probe_pi_in(&crate::parsers::pi::resolve_pi_sessions_dir()));
    sessions
}

/// One entry in Claude Code's per-pid session registry. Extra keys are ignored,
/// so registry additions never break the probe.
#[derive(Deserialize)]
struct ClaudeSessionEntry {
    pid: i32,
    #[serde(rename = "sessionId")]
    session_id: String,
    cwd: Option<String>,
    entrypoint: Option<String>,
}

pub(crate) fn probe_claude_in(dir: &Path) -> Vec<LiveSession> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut live = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(session) = serde_json::from_str::<ClaudeSessionEntry>(&raw) else {
            continue;
        };
        if is_embedded(session.entrypoint.as_deref()) || !pid_alive(session.pid) {
            continue;
        }
        live.push(LiveSession {
            agent_type: AgentType::ClaudeCode,
            external_id: session.session_id,
            cwd: session.cwd,
        });
    }
    live
}

/// Sessions another tool drives through the agent SDK are that tool's
/// internals, not work the user is having a conversation about — one agent run
/// can spawn dozens. Discovery surfaces the session the person started, not the
/// fan-out underneath it.
fn is_embedded(entrypoint: Option<&str>) -> bool {
    entrypoint.is_some_and(|entrypoint| entrypoint.starts_with("sdk"))
}

/// Walks every project directory under pi's sessions root. There is no cheaper
/// scoping: pi's directory names are a lossy encoding of the cwd, so they
/// cannot be matched back to a folder path without opening the transcript.
pub(crate) fn probe_pi_in(root: &Path) -> Vec<LiveSession> {
    let Ok(projects) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut live = Vec::new();
    for project in projects.flatten() {
        let Ok(files) = fs::read_dir(project.path()) else {
            continue;
        };
        for file in files.flatten() {
            let name = file.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(session_file) = lock_target(name) else {
                continue;
            };
            let Some(external_id) = pi_session_id(session_file) else {
                continue;
            };
            if !lock_is_held(&file.path()) {
                continue;
            }
            live.push(LiveSession {
                agent_type: AgentType::Pi,
                external_id,
                cwd: None,
            });
        }
    }
    live
}

/// `.<session>.jsonl.lock.os` names the transcript it guards.
fn lock_target(file_name: &str) -> Option<&str> {
    file_name.strip_prefix('.')?.strip_suffix(".lock.os")
}

/// pi names a transcript `<timestamp>_<id>.jsonl`, and that id is what it
/// records in the session header — the same value the parser reports.
fn pi_session_id(session_file: &str) -> Option<String> {
    let stem = session_file.strip_suffix(".jsonl")?;
    let (_, id) = stem.split_once('_')?;
    (!id.is_empty()).then(|| id.to_string())
}

/// Whether another process holds the advisory lock. Taking it means nobody did,
/// so the probe immediately drops it again.
#[cfg(unix)]
fn lock_is_held(path: &Path) -> bool {
    use std::os::unix::io::AsRawFd;

    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let fd = file.as_raw_fd();
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        unsafe { libc::flock(fd, libc::LOCK_UN) };
        return false;
    }
    true
}

#[cfg(not(unix))]
fn lock_is_held(_path: &Path) -> bool {
    false
}

/// `EPERM` still means the process exists — it is just owned by someone else.
#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn pid_alive(_pid: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn claude_registry_yields_only_sessions_whose_process_survives() {
        let dir = tempdir().expect("tempdir");
        let mine = std::process::id() as i32;
        fs::write(
            dir.path().join("1.json"),
            format!(r#"{{"pid":{mine},"sessionId":"alive","cwd":"/work/app"}}"#),
        )
        .expect("write");
        // pid 1 exists but is not ours; use an unallocated high pid for the dead case.
        fs::write(
            dir.path().join("2.json"),
            r#"{"pid":999999,"sessionId":"dead","cwd":"/work/app"}"#,
        )
        .expect("write");

        let live = probe_claude_in(dir.path());

        assert_eq!(live.len(), 1, "a dead pid is not a live session");
        assert_eq!(live[0].external_id, "alive");
        assert_eq!(live[0].cwd.as_deref(), Some("/work/app"));
        assert_eq!(live[0].agent_type, AgentType::ClaudeCode);
    }

    #[test]
    fn sdk_embedded_sessions_are_not_the_users_session() {
        let dir = tempdir().expect("tempdir");
        let mine = std::process::id() as i32;
        for (file, entrypoint, id) in [
            ("1.json", "sdk-ts", "embedded-ts"),
            ("2.json", "sdk-py", "embedded-py"),
            ("3.json", "cli", "terminal"),
        ] {
            fs::write(
                dir.path().join(file),
                format!(
                    r#"{{"pid":{mine},"sessionId":"{id}","cwd":"/work/app","entrypoint":"{entrypoint}"}}"#
                ),
            )
            .expect("write");
        }

        let live = probe_claude_in(dir.path());

        assert_eq!(live.len(), 1, "only the terminal session counts");
        assert_eq!(live[0].external_id, "terminal");
    }

    #[test]
    fn claude_registry_survives_unreadable_and_foreign_files() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("notes.txt"), "ignored").expect("write");
        fs::write(dir.path().join("broken.json"), "{ not json").expect("write");

        assert!(probe_claude_in(dir.path()).is_empty());
    }

    #[test]
    fn missing_roots_probe_empty_rather_than_failing() {
        let dir = tempdir().expect("tempdir");
        let absent = dir.path().join("nope");

        assert!(probe_claude_in(&absent).is_empty());
        assert!(probe_pi_in(&absent).is_empty());
    }

    #[test]
    fn pi_lock_names_map_to_the_session_id_the_header_records() {
        assert_eq!(
            lock_target(".2026-09-24T02-15-26-466Z_01a0d132.jsonl.lock.os"),
            Some("2026-09-24T02-15-26-466Z_01a0d132.jsonl"),
        );
        assert_eq!(lock_target("2026_01a0.jsonl"), None, "a transcript is not a lock");
        assert_eq!(
            pi_session_id("2026-09-24T02-15-26-466Z_01a0d132-4002-71ea").as_deref(),
            None,
            "a name without the .jsonl suffix is not a transcript",
        );
        assert_eq!(
            pi_session_id("2026-09-24T02-15-26-466Z_01a0d132-4002-71ea.jsonl").as_deref(),
            Some("01a0d132-4002-71ea"),
        );
    }

    /// An unheld lock file must not read as a running session, or every
    /// transcript pi ever wrote would show up live.
    #[cfg(unix)]
    #[test]
    fn pi_reports_only_locks_another_process_holds() {
        let root = tempdir().expect("tempdir");
        let project = root.path().join("-work-app-");
        fs::create_dir_all(&project).expect("mkdir");
        let lock = project.join(".2026-09-24T02-15-26-466Z_01a0d132.jsonl.lock.os");
        fs::write(&lock, "").expect("write");

        assert!(probe_pi_in(root.path()).is_empty(), "nobody holds the lock");

        use std::os::unix::io::AsRawFd;
        let held = fs::File::open(&lock).expect("open");
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "test must be able to take the lock it is simulating",
        );

        let live = probe_pi_in(root.path());

        assert_eq!(live.len(), 1, "a held lock is a running session");
        assert_eq!(live[0].external_id, "01a0d132");
        assert_eq!(live[0].agent_type, AgentType::Pi);
    }
}
