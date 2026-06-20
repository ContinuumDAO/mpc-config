use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;

use continuum_lwo_core::{deobfuscate, decode_public_key, obfuscate, relay_buf_size};
use serde::Deserialize;
use tokio::net::UdpSocket;

#[derive(Debug, Deserialize)]
struct ClientConfig {
    server: String,
    server_port: u16,
    local_port: u16,
    client_public_key: String,
    server_public_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = parse_config_path()?;
    let cfg = load_config(&config_path)?;

    let client_key = decode_public_key(&cfg.client_public_key)?;
    let server_key = decode_public_key(&cfg.server_public_key)?;

    let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, cfg.local_port));
    let server_addr = resolve_server(&cfg.server, cfg.server_port)?;

    let local_socket = Arc::new(UdpSocket::bind(local_addr).await?);
    let remote_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    remote_socket.connect(server_addr).await?;

    eprintln!(
        "continuum-lwo-client: WireGuard -> {} forwarding to {}",
        local_addr, server_addr
    );

    let send_task = {
        let local_socket = Arc::clone(&local_socket);
        let remote_socket = Arc::clone(&remote_socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; relay_buf_size()];
            loop {
                let read_n = match local_socket.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(err) => {
                        eprintln!("continuum-lwo-client: local recv: {err}");
                        return;
                    }
                };
                obfuscate(&mut rand::rng(), &mut buf[..read_n], &server_key);
                if let Err(err) = remote_socket.send(&buf[..read_n]).await {
                    eprintln!("continuum-lwo-client: remote send: {err}");
                    return;
                }
            }
        })
    };

    let recv_task = {
        let local_socket = Arc::clone(&local_socket);
        let remote_socket = Arc::clone(&remote_socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; relay_buf_size()];
            loop {
                let read_n = match remote_socket.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(err) => {
                        eprintln!("continuum-lwo-client: remote recv: {err}");
                        return;
                    }
                };
                deobfuscate(&mut buf[..read_n], &client_key);
                if let Err(err) = local_socket.send(&buf[..read_n]).await {
                    eprintln!("continuum-lwo-client: local send: {err}");
                    return;
                }
            }
        })
    };

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
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
        return Err("usage: continuum-lwo-client --config continuum-lwo-client.json".into());
    }
    Ok(config)
}

fn load_config(path: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let body = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body)?)
}

fn resolve_server(host: &str, port: u16) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    addrs
        .into_iter()
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("no IPv4 address for {host}").into())
}
