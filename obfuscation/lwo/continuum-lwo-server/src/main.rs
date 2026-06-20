use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use continuum_lwo_core::{deobfuscate, decode_public_key, obfuscate, relay_buf_size};
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Debug, Deserialize)]
struct ServerConfig {
    listen_port: u16,
    wg_port: u16,
    client_public_key: String,
    server_public_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = parse_config_path()?;
    let cfg = load_config(&config_path)?;

    let client_key = decode_public_key(&cfg.client_public_key)?;
    let server_key = decode_public_key(&cfg.server_public_key)?;

    let relay_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.listen_port));
    let wg_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, cfg.wg_port));

    let relay_socket = Arc::new(UdpSocket::bind(relay_addr).await?);
    let wg_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    wg_socket.connect(wg_addr).await?;

    eprintln!(
        "continuum-lwo-server: listening on {} -> WireGuard {}",
        relay_addr, wg_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let relay_to_wg = {
        let relay_socket = Arc::clone(&relay_socket);
        let wg_socket = Arc::clone(&wg_socket);
        let client_addr = Arc::clone(&client_addr);
        tokio::spawn(async move {
            let mut buf = vec![0u8; relay_buf_size()];
            loop {
                let (read_n, peer) = match relay_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(err) => {
                        eprintln!("continuum-lwo-server: relay recv: {err}");
                        return;
                    }
                };
                {
                    let mut guard = client_addr.lock().await;
                    *guard = Some(peer);
                }
                deobfuscate(&mut buf[..read_n], &server_key);
                if let Err(err) = wg_socket.send(&buf[..read_n]).await {
                    eprintln!("continuum-lwo-server: wg send: {err}");
                }
            }
        })
    };

    let wg_to_relay = {
        let relay_socket = Arc::clone(&relay_socket);
        let wg_socket = Arc::clone(&wg_socket);
        let client_addr = Arc::clone(&client_addr);
        tokio::spawn(async move {
            let mut buf = vec![0u8; relay_buf_size()];
            loop {
                let read_n = match wg_socket.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(err) => {
                        eprintln!("continuum-lwo-server: wg recv: {err}");
                        return;
                    }
                };
                let peer = {
                    let guard = client_addr.lock().await;
                    match *guard {
                        Some(addr) => addr,
                        None => continue,
                    }
                };
                obfuscate(&mut rand::rng(), &mut buf[..read_n], &client_key);
                if let Err(err) = relay_socket.send_to(&buf[..read_n], peer).await {
                    eprintln!("continuum-lwo-server: relay send: {err}");
                }
            }
        })
    };

    tokio::select! {
        _ = relay_to_wg => {},
        _ = wg_to_relay => {},
    }

    Ok(())
}

fn parse_config_path() -> Result<String, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut config = String::new();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            config = args.next().ok_or("missing value for --config")?;
        } else if config.is_empty() && !arg.starts_with('-') {
            config = arg;
        }
    }
    if config.is_empty() {
        return Err("usage: continuum-lwo-server --config server.json".into());
    }
    Ok(config)
}

fn load_config(path: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let body = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body)?)
}
