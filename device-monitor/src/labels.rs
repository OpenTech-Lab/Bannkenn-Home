use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelEntry {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub macs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct LabelFile {
    entries: Vec<LabelEntry>,
}

pub struct LabelStore {
    entries: RwLock<Vec<LabelEntry>>,
    path: PathBuf,
}

impl LabelStore {
    pub fn load(path: impl Into<PathBuf>) -> Arc<Self> {
        let path = path.into();
        let entries = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<LabelFile>(&s).ok())
                .map(|f| f.entries)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        info!("Loaded {} custom labels from {:?}", entries.len(), path);
        Arc::new(Self {
            entries: RwLock::new(entries),
            path,
        })
    }

    pub async fn list(&self) -> Vec<LabelEntry> {
        self.entries.read().await.clone()
    }

    /// Find label that matches an IP or MAC (case-insensitive for MAC).
    pub async fn find_by_ip_or_mac(&self, ip: &str, mac: Option<&str>) -> Option<LabelEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .find(|e| {
                e.ips.iter().any(|i| i == ip)
                    || mac
                        .map(|m| e.macs.iter().any(|em| em.eq_ignore_ascii_case(m)))
                        .unwrap_or(false)
            })
            .cloned()
    }

    /// Upsert by name: if a label with this name exists, add IP/MAC to it;
    /// otherwise create a new one. IP/MAC from any other label are also
    /// migrated to this name (re-tag use-case).
    pub async fn upsert(&self, name: &str, ip: Option<&str>, mac: Option<&str>) -> LabelEntry {
        let name = name.trim().to_string();
        let mut entries = self.entries.write().await;

        // Remove this IP/MAC from any other label first (re-tag)
        for entry in entries.iter_mut() {
            if entry.name == name {
                continue;
            }
            if let Some(ip) = ip {
                entry.ips.retain(|i| i != ip);
            }
            if let Some(mac) = mac {
                entry.macs.retain(|m| !m.eq_ignore_ascii_case(mac));
            }
        }
        // Remove now-empty orphan labels
        entries.retain(|e| e.name == name || !e.ips.is_empty() || !e.macs.is_empty());

        // Find or create the target label
        if let Some(entry) = entries.iter_mut().find(|e| e.name == name) {
            if let Some(ip) = ip {
                if !entry.ips.contains(&ip.to_string()) {
                    entry.ips.push(ip.to_string());
                }
            }
            if let Some(mac) = mac {
                if !entry.macs.iter().any(|m| m.eq_ignore_ascii_case(mac)) {
                    entry.macs.push(mac.to_lowercase());
                }
            }
            let result = entry.clone();
            drop(entries);
            self.persist().await;
            result
        } else {
            let entry = LabelEntry {
                id: new_id(),
                name,
                ips: ip.map(|i| vec![i.to_string()]).unwrap_or_default(),
                macs: mac.map(|m| vec![m.to_lowercase()]).unwrap_or_default(),
            };
            let result = entry.clone();
            entries.push(entry);
            drop(entries);
            self.persist().await;
            result
        }
    }

    pub async fn delete(&self, id: &str) -> bool {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|e| e.id != id);
        let deleted = entries.len() < before;
        drop(entries);
        if deleted {
            self.persist().await;
        }
        deleted
    }

    async fn persist(&self) {
        let entries = self.entries.read().await.clone();
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let file = LabelFile { entries };
            match serde_json::to_string_pretty(&file) {
                Ok(json) => {
                    let tmp = path.with_extension("tmp");
                    if std::fs::write(&tmp, &json).is_ok() {
                        if let Err(e) = std::fs::rename(&tmp, &path) {
                            warn!("Failed to save labels: {}", e);
                        }
                    }
                }
                Err(e) => warn!("Failed to serialize labels: {}", e),
            }
        });
    }
}

/// Sync helper to find a label name for an IP (using a pre-snapshotted list).
pub fn find_label_name<'a>(labels: &'a [LabelEntry], ip: &str, mac: Option<&str>) -> Option<&'a str> {
    labels
        .iter()
        .find(|e| {
            e.ips.iter().any(|i| i == ip)
                || mac
                    .map(|m| e.macs.iter().any(|em| em.eq_ignore_ascii_case(m)))
                    .unwrap_or(false)
        })
        .map(|e| e.name.as_str())
}

fn new_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(1);
    format!("lbl-{}", C.fetch_add(1, Ordering::Relaxed))
}
