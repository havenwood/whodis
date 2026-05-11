//! Append-only JSONL observation log. Each line is one `Observation` event.
//! Replay is idempotent — the graph's merge logic absorbs duplicates.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::error::Result;
use crate::inventory::graph::{CandidateChange, IdentityGraph};
use crate::inventory::observation::Observation;

/// Append one observation as a JSONL record to `path`. Creates the file if
/// it does not exist. Flushes after each line so a `kill -9` does not lose
/// the last record.
pub fn append(path: &Path, obs: &Observation) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| crate::error::Error::Inventory {
            reason: e.to_string(),
        })?;
    let line = serde_json::to_string(obs).map_err(|e| crate::error::Error::Inventory {
        reason: e.to_string(),
    })?;
    writeln!(f, "{line}").map_err(|e| crate::error::Error::Inventory {
        reason: e.to_string(),
    })?;
    f.flush().map_err(|e| crate::error::Error::Inventory {
        reason: e.to_string(),
    })?;
    Ok(())
}

/// Replay every observation from `path` into `graph`. Returns the total
/// number of change events emitted across all observations.
pub fn replay_into(graph: &mut IdentityGraph, path: &Path) -> Result<usize> {
    let f = std::fs::File::open(path).map_err(|e| crate::error::Error::Inventory {
        reason: e.to_string(),
    })?;
    let reader = BufReader::new(f);
    let mut total = 0usize;
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| crate::error::Error::Inventory {
            reason: e.to_string(),
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let obs: Observation =
            serde_json::from_str(&line).map_err(|e| crate::error::Error::Inventory {
                reason: format!("line {} parse error: {e}", i + 1),
            })?;
        let changes: Vec<CandidateChange> = graph.observe(obs);
        total = total.saturating_add(changes.len());
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        dir.join(format!(
            "whodis-inventory-test-{}-{label}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn append_and_replay_round_trips() {
        let path = tmp_path("round_trip");
        drop(std::fs::remove_file(&path));

        let obs = Observation::Neighbor {
            ip: "10.0.5.20".parse().expect("ip"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: Some("Apple".into()),
            interface: "en0".into(),
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
        };
        append(&path, &obs).expect("append");
        append(&path, &obs).expect("append twice");

        let mut g = IdentityGraph::new();
        let n = replay_into(&mut g, &path).expect("replay");
        // Two observations, but identical → second one is an Updated event.
        assert!(n >= 2, "should emit at least two change events, got {n}");
        assert_eq!(g.len(), 1, "duplicate ARP collapses");

        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn replay_is_idempotent() {
        let path = tmp_path("idempotent");
        drop(std::fs::remove_file(&path));

        let obs_a = Observation::Neighbor {
            ip: "10.0.5.20".parse().expect("ip"),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            vendor: None,
            interface: "en0".into(),
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
        };
        let obs_b = Observation::MdnsInstance {
            fqdn: "Living._airplay._tcp.local.".into(),
            service_type: "_airplay._tcp.local.".into(),
            instance_name: "Living".into(),
            host: "AppleTV.local.".into(),
            port: 7000,
            addrs: vec!["10.0.5.20".parse().expect("ip")],
            txt: std::collections::BTreeMap::new(),
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10_001),
        };
        append(&path, &obs_a).expect("a");
        append(&path, &obs_b).expect("b");

        let mut g1 = IdentityGraph::new();
        let _n1 = replay_into(&mut g1, &path).expect("replay1");
        let mut g2 = IdentityGraph::new();
        let _n2 = replay_into(&mut g2, &path).expect("replay2");
        let mut g3 = IdentityGraph::new();
        let _n3 = replay_into(&mut g3, &path).expect("replay3");
        assert_eq!(g1.len(), g2.len());
        assert_eq!(g2.len(), g3.len());
        assert_eq!(g1.len(), 1);

        drop(std::fs::remove_file(&path));
    }
}
