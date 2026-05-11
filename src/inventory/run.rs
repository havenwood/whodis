//! Orchestrator: spawns one task per enabled observation source, forwards
//! each into the `IdentityGraph`, optionally writes to the JSONL log.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio_stream::StreamExt as _;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::inventory::graph::{CandidateChange, IdentityGraph};
use crate::inventory::observation::Observation;

type ChangeCallback = Arc<dyn Fn(&CandidateChange) + Send + Sync>;

#[allow(
    clippy::struct_excessive_bools,
    reason = "four enable_* flags mirror four independent observer sources; an enum or bitflag would obscure the per-source semantics"
)]
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub enable_arp: bool,
    pub enable_mdns: bool,
    pub enable_ssdp: bool,
    pub enable_ble: bool,
    pub log_path: Option<PathBuf>,
    pub arp_poll_interval: Duration,
    pub ssdp_browse_window: Duration,
    pub tick_interval: Duration,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            enable_arp: true,
            enable_mdns: true,
            enable_ssdp: true,
            enable_ble: true,
            log_path: None,
            arp_poll_interval: Duration::from_secs(30),
            ssdp_browse_window: Duration::from_secs(5),
            tick_interval: Duration::from_secs(10),
        }
    }
}

/// Run the orchestrator until `cancel` fires. Each change is forwarded to
/// `on_change`. Returns the owned graph after the run completes.
#[allow(
    clippy::too_many_lines,
    reason = "orchestrator spawns 4 observer tasks plus main multiplex loop; splitting hides the spawn order"
)]
pub async fn run(
    cfg: RunConfig,
    cancel: CancellationToken,
    on_change: impl Fn(&CandidateChange) + Send + Sync + 'static,
) -> Result<Arc<Mutex<IdentityGraph>>> {
    let graph = Arc::new(Mutex::new(IdentityGraph::new()));
    let cb: ChangeCallback = Arc::new(on_change);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Observation>(1024);

    if cfg.enable_arp {
        let tx_arp = tx.clone();
        let cancel_arp = cancel.clone();
        let interval = cfg.arp_poll_interval;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    () = cancel_arp.cancelled() => return,
                    _ = tick.tick() => {
                        if let Ok(entries) = crate::arp::read_neighbors().await {
                            let now = SystemTime::now();
                            for e in entries {
                                let obs = Observation::Neighbor {
                                    ip: e.ip,
                                    mac: e.mac,
                                    vendor: e.vendor,
                                    interface: e.interface,
                                    observed_at: now,
                                };
                                if tx_arp.send(obs).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    if cfg.enable_mdns {
        let tx_mdns = tx.clone();
        let cancel_mdns = cancel.clone();
        tokio::spawn(async move {
            let Ok(browser) = crate::browse::Browser::new(crate::mode::Mode::Listen) else {
                return;
            };
            let cancel_browser = browser.cancel_token();
            let cancel_for_select = cancel_mdns.clone();
            tokio::spawn(async move {
                cancel_for_select.cancelled().await;
                cancel_browser.cancel();
            });
            let mut stream = std::pin::pin!(browser.run());
            while let Some(ev) = stream.next().await {
                if let Some(obs) = mdns_event_to_observation(ev)
                    && tx_mdns.send(obs).await.is_err()
                {
                    return;
                }
            }
            drop(cancel_mdns);
        });
    }

    if cfg.enable_ssdp {
        let tx_ssdp = tx.clone();
        let cancel_ssdp = cancel.clone();
        let window = cfg.ssdp_browse_window;
        tokio::spawn(async move {
            loop {
                if cancel_ssdp.is_cancelled() {
                    return;
                }
                let Ok(stream) = crate::ssdp::browse(window) else {
                    return;
                };
                let mut pinned = std::pin::pin!(stream);
                loop {
                    tokio::select! {
                        () = cancel_ssdp.cancelled() => return,
                        next = pinned.next() => match next {
                            None => break, // restart a new browse window
                            Some(ev) => {
                                if let Some(obs) = ssdp_event_to_observation(ev)
                                    && tx_ssdp.send(obs).await.is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    if cfg.enable_ble {
        let tx_ble = tx.clone();
        let cancel_ble = cancel.clone();
        tokio::spawn(async move {
            let Ok(source) = crate::ble::scan::BtleplugSource::new().await else {
                return;
            };
            let scanner = crate::ble::scan::Scanner::new(source).on_event(move |ad| {
                let payloads: Vec<_> = ad
                    .manufacturer_data
                    .get(&0x004C)
                    .map(|b| crate::ble::continuity::decode(b))
                    .unwrap_or_default();
                let device_class = crate::ble::fingerprint::device_class(&ad, &payloads);
                let vendor = crate::ble::fingerprint::vendor(&ad);
                let product = crate::ble::fingerprint::product(&payloads);
                let obs = Observation::BleDevice {
                    peripheral_id: ad.peripheral_id.clone(),
                    local_name: ad.local_name.clone(),
                    vendor,
                    product,
                    device_class,
                    rssi: ad.rssi,
                    service_uuids: ad.service_uuids.clone(),
                    observed_at: ad.timestamp,
                };
                drop(tx_ble.try_send(obs));
            });
            drop(scanner.run(cancel_ble).await);
        });
    }

    drop(tx); // when all observer senders drop, main loop exits

    let graph_for_loop = graph.clone();
    let cancel_for_loop = cancel.clone();
    let log_path = cfg.log_path.clone();
    let cb_for_loop = cb.clone();
    let mut tick = tokio::time::interval(cfg.tick_interval);
    tick.tick().await;
    loop {
        tokio::select! {
            () = cancel_for_loop.cancelled() => break,
            _ = tick.tick() => {
                let mut g = match graph_for_loop.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                for ch in g.tick() {
                    cb_for_loop(&ch);
                }
            }
            maybe_obs = rx.recv() => match maybe_obs {
                None => break,
                Some(obs) => {
                    if let Some(p) = log_path.as_deref()
                        && let Err(e) = crate::inventory::log::append(p, &obs)
                    {
                        tracing::warn!(error = %e, "inventory: log append failed");
                    }
                    let mut g = match graph_for_loop.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    for ch in g.observe(obs) {
                        cb_for_loop(&ch);
                    }
                }
            }
        }
    }
    Ok(graph)
}

fn mdns_event_to_observation(ev: crate::browse::Event) -> Option<Observation> {
    use crate::browse::Event;
    match ev {
        Event::InstanceFound { instance } | Event::InstanceUpdated { instance } => {
            let txt: std::collections::BTreeMap<String, String> = instance
                .txt
                .iter()
                .map(|(k, v)| {
                    let val = std::str::from_utf8(v).map_or_else(
                        |_| {
                            let mut s = String::from("0x");
                            for b in v {
                                use std::fmt::Write as _;
                                let _r = write!(s, "{b:02x}");
                            }
                            s
                        },
                        str::to_string,
                    );
                    (k.clone(), val)
                })
                .collect();
            Some(Observation::MdnsInstance {
                fqdn: instance.fqdn(),
                service_type: instance.service_type.fqdn(),
                instance_name: instance.instance_name.clone(),
                host: instance.host.clone(),
                port: instance.port,
                addrs: instance.addrs,
                txt,
                observed_at: SystemTime::now(),
            })
        }
        Event::InstanceGoodbye { fqdn } => Some(Observation::MdnsGoodbye {
            fqdn,
            observed_at: SystemTime::now(),
        }),
        Event::ServiceTypeFound { .. } => None,
    }
}

fn ssdp_event_to_observation(ev: crate::ssdp::SsdpEvent) -> Option<Observation> {
    use crate::ssdp::SsdpEvent;
    match ev {
        SsdpEvent::Alive { device, src } | SsdpEvent::Reply { device, src } => {
            let src_ip: std::net::IpAddr = src
                .rsplit_once(':')
                .and_then(|(host, _)| host.parse().ok())
                .or_else(|| src.parse().ok())?;
            let max_age = device
                .headers
                .get("cache-control")
                .or_else(|| device.headers.get("CACHE-CONTROL"))
                .and_then(|cc| {
                    cc.split(',').find_map(|part| {
                        let part = part.trim().to_ascii_lowercase();
                        part.strip_prefix("max-age=")
                            .and_then(|n| n.parse::<u32>().ok())
                    })
                });
            Some(Observation::SsdpService {
                usn: device.usn,
                st: device.st,
                location: device.location,
                server: device.server,
                src_ip,
                max_age,
                observed_at: SystemTime::now(),
            })
        }
        SsdpEvent::Byebye { usn, nt: _, src } => {
            let src_ip: std::net::IpAddr = src
                .rsplit_once(':')
                .and_then(|(host, _)| host.parse().ok())
                .or_else(|| src.parse().ok())?;
            Some(Observation::SsdpByebye {
                usn,
                src_ip,
                observed_at: SystemTime::now(),
            })
        }
    }
}
