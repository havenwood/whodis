//! TCP relay for spoof MITM mode.
//!
//! When the spoof responder is paired with `--relay`, this module listens on every
//! port advertised in the spoof's SRV records. For each inbound TCP connection, it
//! dials the relay target and bidirectionally streams bytes between client and target.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};

pub(crate) async fn run(
    ports: &[u16],
    target: SocketAddr,
    cancel: CancellationToken,
) -> Result<()> {
    if ports.is_empty() {
        tracing::warn!("relay enabled but spoof table has no SRV records to listen on");
        return Ok(());
    }
    let target = Arc::new(target);
    let mut listeners: Vec<(u16, TcpListener)> = Vec::with_capacity(ports.len());
    for port in ports {
        let bind: SocketAddr = SocketAddr::from(([0, 0, 0, 0], *port));
        match TcpListener::bind(bind).await {
            Ok(l) => {
                tracing::info!(port = port, target = %target, "relay listening");
                listeners.push((*port, l));
            }
            Err(e) => {
                tracing::error!(port = port, error = %e, "relay bind failed");
                return Err(Error::Transport(e));
            }
        }
    }

    for (port, listener) in listeners {
        let target = target.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            accept_loop(port, listener, *target, cancel).await;
        });
    }
    Ok(())
}

async fn accept_loop(
    listen_port: u16,
    listener: TcpListener,
    target: SocketAddr,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                tracing::debug!(port = listen_port, "relay listener cancelled");
                return;
            }
            r = listener.accept() => {
                match r {
                    Ok((client, src)) => {
                        let cancel = cancel.clone();
                        tokio::spawn(async move {
                            bridge(client, src, target, listen_port, cancel).await;
                        });
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "relay accept error, continuing");
                    }
                }
            }
        }
    }
}

async fn bridge(
    mut client: TcpStream,
    src: SocketAddr,
    target: SocketAddr,
    listen_port: u16,
    cancel: CancellationToken,
) {
    let started = Instant::now();
    tracing::info!(client = %src, listen_port = listen_port, target = %target, "relay open");

    let mut upstream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(client = %src, target = %target, error = %e, "relay connect failed");
            let _shutdown = client.shutdown().await;
            return;
        }
    };

    let result = tokio::select! {
        () = cancel.cancelled() => {
            tracing::debug!(client = %src, "relay cancelled mid-stream");
            return;
        }
        r = tokio::io::copy_bidirectional(&mut client, &mut upstream) => r,
    };
    let elapsed = started.elapsed();
    match result {
        Ok((c2u, u2c)) => tracing::info!(
            client = %src,
            target = %target,
            bytes_client_to_target = c2u,
            bytes_target_to_client = u2c,
            elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            "relay close"
        ),
        Err(e) => tracing::info!(
            client = %src,
            target = %target,
            error = %e,
            elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            "relay close (error)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_with_no_ports_succeeds_silently() {
        let target: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 1));
        let cancel = CancellationToken::new();
        let result = run(&[], target, cancel).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_returns_err_when_listen_bind_fails() {
        let blocker = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .expect("blocker");
        let blocked_port = blocker.local_addr().expect("addr").port();

        let target = SocketAddr::from(([127, 0, 0, 1], 1));
        let cancel = CancellationToken::new();
        let result = run(&[blocked_port], target, cancel).await;
        assert!(result.is_err(), "expected Err when listen port is already bound");
    }
}
