use chrono::{DateTime, Utc};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWorkspaceHeader {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

impl RemoteWorkspaceHeader {
    pub fn to_header_pair(&self) -> Result<(HeaderName, HeaderValue), http::Error> {
        let name: HeaderName = self.name.trim().try_into()?;
        let mut value: HeaderValue = self.value.trim().try_into()?;
        // A custom header on a remote connection normally carries a credential
        // (a Cloudflare Access service token, a proxy secret), so it gets the
        // same treatment `reqwest` gives its own `bearer_auth` value: never
        // added to the HTTP/2 HPACK dynamic table, and redacted from `Debug`.
        value.set_sensitive(true);
        Ok((name, value))
    }
}

pub trait ToHeaderMap {
    fn to_header_map(&self) -> HeaderMap;
}

impl ToHeaderMap for [RemoteWorkspaceHeader] {
    fn to_header_map(&self) -> HeaderMap {
        self.iter()
            .filter_map(|header| header.to_header_pair().ok())
            .collect()
    }
}

/// A connection plus its `keyring_store` secrets; not `Serialize`, so no
/// command can hand the token to a webview.
#[derive(Debug, Clone)]
pub struct RemoteWorkspaceConnectionRecord {
    pub id: i32,
    pub name: String,
    pub base_url: String,
    pub token: String,
    pub headers: Vec<RemoteWorkspaceHeader>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RemoteWorkspaceConnectionRecord {
    pub fn into_info(self) -> RemoteWorkspaceConnectionInfo {
        RemoteWorkspaceConnectionInfo {
            id: self.id,
            name: self.name,
            base_url: self.base_url,
            has_token: !self.token.is_empty(),
            headers: self.headers,
            sort_order: self.sort_order,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// What the frontend sees: token presence only, since every remote request is
/// proxied by connection id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteWorkspaceConnectionInfo {
    pub id: i32,
    pub name: String,
    pub base_url: String,
    pub has_token: bool,
    #[serde(default)]
    pub headers: Vec<RemoteWorkspaceHeader>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
