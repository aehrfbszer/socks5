use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use clap::Parser;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Duration, timeout},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "[::]")]
    listen_addr: String,
    #[arg(short, long, default_value_t)]
    auth: bool,
    #[arg(short, long, default_value_t = 1080)]
    port: u16,
    #[arg(required_if_eq("auth", "true"), long)]
    username: Option<String>,
    #[arg(required_if_eq("auth", "true"), long)]
    password: Option<String>,
}

const RANDOM_ADDR: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
];

#[tokio::main]
async fn main() -> Result<()> {
    let config = Args::parse();

    // 2. 初始化日志 (tracing)
    // 默认级别为 info，除非设置了 RUST_LOG 环境变量
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    tracing::info!("Starting SOCKS5 server with config: {:?}", config);

    // 监听本地 8080 端口
    let listener = TcpListener::bind(format!("{}:{}", config.listen_addr, config.port)).await?;

    let local_addr = listener.local_addr()?;

    tracing::info!(?local_addr, "Server is listening on",);

    let username: &'static str =
        Box::leak(config.username.clone().unwrap_or_default().into_boxed_str());
    let password: &'static str =
        Box::leak(config.password.clone().unwrap_or_default().into_boxed_str());

    loop {
        let (socket, addr) = listener.accept().await?;
        tracing::info!(?addr, "[open]New client connected");

        // 每个连接 spawn 一个任务
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client(socket, config.auth, username, password).await {
                tracing::error!(?addr, ?e, "[close]Error handling client");
            } else {
                tracing::info!(?addr, "[close]Client disconnected");
            }
        });
    }
}

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const USER_PASS_AUTH: u8 = 0x02;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

fn build_reply_data(rep: u8, addr_info: &[u8], port: u16) -> Vec<u8> {
    let mut res = vec![
        SOCKS5_VERSION,
        rep,
        0x00, // RSV
    ];

    res.extend_from_slice(addr_info);
    res.extend_from_slice(&port.to_be_bytes());
    res
}

fn build_reply_with_ip(rep: u8, ip: std::net::IpAddr, port: u16) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let mut buf = [0u8; 5];
            buf[0] = ATYP_IPV4;
            buf[1..5].copy_from_slice(&ipv4.octets());
            return build_reply_data(rep, &buf, port);
        }
        std::net::IpAddr::V6(ipv6) => {
            let mut buf = [0u8; 17];
            buf[0] = ATYP_IPV6;
            buf[1..17].copy_from_slice(&ipv6.octets());
            return build_reply_data(rep, &buf, port);
        }
    }
}

fn build_reply(rep: u8, bind_addr: &str, bind_port: u16) -> Vec<u8> {
    if let Ok(ip) = bind_addr.parse::<std::net::Ipv4Addr>() {
        return build_reply_with_ip(rep, std::net::IpAddr::V4(ip), bind_port);
    } else if let Ok(ip) = bind_addr.parse::<std::net::Ipv6Addr>() {
        return build_reply_with_ip(rep, std::net::IpAddr::V6(ip), bind_port);
    } else {
        let mut buf = vec![ATYP_DOMAIN, bind_addr.len() as u8];
        buf.extend_from_slice(bind_addr.as_bytes());
        return build_reply_data(rep, &buf, bind_port);
    }
}

// UDP 转发任务：处理单个 (client_addr, target) 对的双向数据转发
async fn udp_forward_task(
    udp_socket: Arc<tokio::net::UdpSocket>,
    client_addr: SocketAddr,
    target_addr: String,
    target_port: u16,
    atyp_and_addr: Vec<u8>, // ATYP + DST.ADDR + DST.PORT
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let remote_udp = Arc::new(tokio::net::UdpSocket::bind(&RANDOM_ADDR[..]).await?);
    tracing::info!(
        ?client_addr,
        ?target_addr,
        ?target_port,
        "UDP forward task started"
    );
    remote_udp
        .connect(format!("{}:{}", target_addr, target_port))
        .await?;

    // 任务1: 接收来自客户端的数据并转发到目标
    let remote_udp_clone1 = Arc::clone(&remote_udp);
    let task_send = async {
        while let Some(data) = rx.recv().await {
            if let Err(e) = remote_udp_clone1.send(&data).await {
                tracing::error!(?e, "Failed to send UDP packet to target");
                return Err::<(), String>(e.to_string());
            }
            tracing::debug!("Forwarded UDP packet to target");
        }
        // 客户端通道关闭
        Ok(())
    };

    // 任务2: 接收来自目标的响应并转发回客户端
    let remote_udp_clone2 = Arc::clone(&remote_udp);
    let udp_socket_clone = Arc::clone(&udp_socket);
    let atyp_and_addr_clone = atyp_and_addr.clone();
    let task_recv = async {
        let mut recv_buf = [0u8; 65535];
        let timeout_duration = Duration::from_secs(30); // 单个响应 30 秒超时

        loop {
            match timeout(timeout_duration, remote_udp_clone2.recv(&mut recv_buf)).await {
                Ok(Ok(len)) => {
                    tracing::debug!("Received UDP response from target, len={}", len);
                    let mut response = vec![0x00, 0x00, 0x00]; // RSV
                    response.extend_from_slice(&atyp_and_addr_clone);
                    response.extend_from_slice(&recv_buf[..len]);
                    if let Err(e) = udp_socket_clone.send_to(&response, &client_addr).await {
                        tracing::error!(?e, "Failed to send UDP response to client");
                        return Err::<(), String>(e.to_string());
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!(?e, "UDP receive from target error");
                    return Err(e.to_string());
                }
                Err(_) => {
                    // 30秒无数据，认为会话已结束
                    tracing::debug!("UDP forward task: recv timeout");
                    return Ok(());
                }
            }
        }
    };

    // 并发运行两个任务，等待两个都完成
    // 如果有一个出错，整体返回错误；都成功则返回 Ok
    match tokio::join!(task_send, task_recv) {
        (Ok(()), Ok(())) => {
            tracing::info!("UDP forward task completed normally");
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!("UDP forward task error: {}", e);
        }
    }

    tracing::info!(
        ?client_addr,
        ?target_addr,
        ?target_port,
        "UDP forward task ended"
    );
    Ok(())
}

fn parse_udp_address_and_port(data: &[u8]) -> Result<(String, u16, u16)> {
    if data.is_empty() {
        return Err("Not enough data to parse address type".into());
    }
    
    let mut offset = 0usize;
    let atyp = data[offset];
    offset += 1;

    let addr = match atyp {
        ATYP_IPV4 => {
            if data.len() < offset + 4 {
                return Err("Not enough data for IPv4 address".into());
            }
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;
            std::net::Ipv4Addr::from(buf).to_string()
        }
        ATYP_IPV6 => {
            if data.len() < offset + 16 {
                return Err("Not enough data for IPv6 address".into());
            }
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        ATYP_DOMAIN => {
            if data.len() < offset + 1 {
                return Err("Not enough data for domain length".into());
            }
            let len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + len {
                return Err("Not enough data for domain name".into());
            }
            let domain = String::from_utf8(data[offset..offset + len].to_vec())?;
            offset += len;
            domain
        }
        _ => return Err(format!("Unsupported address type: {}", atyp).into()),
    };

    if data.len() < offset + 2 {
        return Err("Not enough data for port".into());
    }
    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    Ok((addr, port, offset as u16))
}

async fn read_address_and_port<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(String, u16, u16)> {
    let atyp = reader.read_u8().await?;
    let mut offset: u16 = 0;
    let addr = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            offset += 4;
            std::net::Ipv4Addr::from(buf).to_string()
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await?;
            offset += 16;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        ATYP_DOMAIN => {
            let len = reader.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            offset += len as u16 + 1;

            String::from_utf8(buf)?
        }
        _ => return Err("Unsupported address type".into()),
    };

    let port = reader.read_u16().await?;
    offset += 2;
    Ok((addr, port, offset))
}

async fn handle_socks5_client(
    mut socket: tokio::net::TcpStream,
    need_auth: bool,
    config_username: &'static str,
    config_password: &'static str,
) -> Result<()> {
    // 这里我们会维护一个状态机来处理 SOCKS5 协议的不同阶段

    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;
    if buf[0] != SOCKS5_VERSION {
        tracing::error!("Unsupported SOCKS version: {}", buf[0]);
        socket.shutdown().await?;
        return Ok(());
    }

    let nmethods = buf[1] as usize;
    if nmethods == 0 {
        tracing::error!("No authentication methods provided by client");
        socket.shutdown().await?;
        return Ok(());
    }
    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    let method = if need_auth { USER_PASS_AUTH } else { NO_AUTH };

    if methods.contains(&method) {
        socket.write_all(&[SOCKS5_VERSION, method]).await?;
    } else {
        socket
            .write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_METHODS])
            .await?;
        socket.shutdown().await?;
        tracing::error!("No acceptable authentication methods offered by client");
        return Ok(());
    }

    if need_auth {
        // 处理用户名密码认证
        let mut auth_buf = [0u8; 2];
        socket.read_exact(&mut auth_buf).await?;
        if auth_buf[0] != 0x01 {
            tracing::error!("Unsupported authentication version: {}", auth_buf[0]);
            socket.shutdown().await?;
            return Ok(());
        }
        let ulen = auth_buf[1] as usize;
        let mut username = vec![0u8; ulen];
        socket.read_exact(&mut username).await?;

        let plen = socket.read_u8().await? as usize;

        let mut password = vec![0u8; plen];
        socket.read_exact(&mut password).await?;

        if username != config_username.as_bytes() || password != config_password.as_bytes() {
            tracing::error!("Invalid username or password");
            socket.write_all(&[0x01, 0x01]).await?; // 认证失败
            socket.shutdown().await?;
            return Ok(());
        } else {
            socket.write_all(&[0x01, 0x00]).await?;
            // stage = Stage::Connected;
        }
    }

    tracing::info!("Client handshake successfully, waiting for command");

    let mut cmd_buf = [0u8; 3];
    socket.read_exact(&mut cmd_buf).await?;
    if cmd_buf[0] != SOCKS5_VERSION {
        tracing::error!("Unsupported SOCKS version in command: {}", cmd_buf[0]);
        socket.shutdown().await?;
        return Ok(());
    }

    match cmd_buf[1] {
        CMD_CONNECT => {
            let (target_addr, target_port, _) = read_address_and_port(&mut socket).await?;
            tracing::info!(
                ?target_addr,
                ?target_port,
                "Client requested CONNECT command"
            );
            let mut tcp_client =
                tokio::net::TcpStream::connect(format!("{}:{}", target_addr, target_port)).await?;
            let local_addr = socket.local_addr()?;

            socket
                .write_all(&build_reply_with_ip(
                    REP_SUCCEEDED,
                    local_addr.ip(),
                    local_addr.port(),
                ))
                .await?;

            let (mut socket_reader, mut socket_writer) = socket.split();
            let (mut tcp_reader, mut tcp_writer) = tcp_client.split();

            let client_to_remote = tokio::io::copy(&mut socket_reader, &mut tcp_writer);
            let remote_to_client = tokio::io::copy(&mut tcp_reader, &mut socket_writer);

            tokio::try_join!(client_to_remote, remote_to_client)?;
        }
        CMD_BIND => {
            let (target_addr, target_port, _) = read_address_and_port(&mut socket).await?;

            tracing::info!(
                ?target_addr,
                ?target_port,
                "Client requested BIND command, setting up listener"
            );

            let bind_listener = TcpListener::bind(&RANDOM_ADDR[..]).await?;

            let local_addr = bind_listener.local_addr()?;
            socket
                .write_all(&build_reply_with_ip(
                    REP_SUCCEEDED,
                    local_addr.ip(),
                    local_addr.port(),
                ))
                .await?;

            // 只处理一个连接，之后关闭
            if let Ok((mut remote, remote_addr)) = bind_listener.accept().await {
                tracing::info!(
                    ?remote_addr,
                    "Received incoming connection for BIND command"
                );
                socket
                    .write_all(&build_reply_with_ip(
                        REP_SUCCEEDED,
                        remote_addr.ip(),
                        remote_addr.port(),
                    ))
                    .await?;
                let (mut socket_reader, mut socket_writer) = socket.split();
                let (mut remote_reader, mut remote_writer) = remote.split();

                let client_to_remote = tokio::io::copy(&mut socket_reader, &mut remote_writer);
                let remote_to_client = tokio::io::copy(&mut remote_reader, &mut socket_writer);

                // tokio::select! {
                //     res = client_to_remote => {
                //         if let Err(e) = res {
                //             tracing::error!(?e, "Error forwarding data from client to remote");
                //         }
                //     }
                //     res = remote_to_client => {
                //         if let Err(e) = res {
                //             tracing::error!(?e, "Error forwarding data from remote to client");
                //         }
                //     }
                // }
                tokio::try_join!(client_to_remote, remote_to_client)?;
            } else {
                tracing::error!("Failed to accept incoming connection for BIND command");
            }
        }
        CMD_UDP_ASSOCIATE => {
            // RFC 1928: UDP ASSOCIATE 请求中的地址信息应该被忽略，不读取
            tracing::info!(
                "Client requested UDP ASSOCIATE command, setting up UDP socket"
            );
            let udp_socket = Arc::new(tokio::net::UdpSocket::bind(&RANDOM_ADDR[..]).await?);
            let local_addr = udp_socket.local_addr()?;
            socket
                .write_all(&build_reply_with_ip(
                    REP_SUCCEEDED,
                    local_addr.ip(),
                    local_addr.port(),
                ))
                .await?;
            tracing::info!(
                ?local_addr,
                "UDP associate established, waiting for UDP packets"
            );

            // 存储每个 (client_addr, target) 对应的转发通道
            // Key: (client_addr, target_addr:port)
            // Value: Sender<Vec<u8>>
            let forward_channels: Arc<
                Mutex<HashMap<(SocketAddr, String), tokio::sync::mpsc::Sender<Vec<u8>>>>,
            > = Arc::new(Mutex::new(HashMap::new()));

            let mut buf = [0u8; 65535];
            let timeout_duration = Duration::from_secs(600); // 整个 UDP 会话 10 分钟超时

            loop {
                // let forward_channels = Arc::clone(&forward_channels);
                match timeout(timeout_duration, udp_socket.recv_from(&mut buf)).await {
                    Ok(Ok((len, client_addr))) => {
                        tracing::info!(?client_addr, "Received UDP packet from client");

                        let data = &buf[..len];
                        if data.len() < 4 || data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x00 {
                            tracing::error!("Invalid UDP packet format");
                            continue;
                        }

                        let (target_addr, target_port, offset) =
                            match parse_udp_address_and_port(&data[3..]) {
                                Ok(res) => res,
                                Err(e) => {
                                    tracing::error!(
                                        ?e,
                                        "Failed to parse target address and port from UDP packet"
                                    );
                                    continue;
                                }
                            };

                        let forward_key = (client_addr, format!("{}:{}", target_addr, target_port));
                        let data_to_send = data[(offset as usize + 3)..].to_vec();
                        let atyp_and_addr = data[3..(offset as usize + 3)].to_vec();

                        let res = forward_channels.lock().unwrap().get(&forward_key).cloned();

                        // 检查是否已有该转发通道
                        if let Some(tx) = res {
                            // 通道已存在，直接发送数据
                            if let Err(e) = tx.send(data_to_send).await {
                                tracing::error!(?e, "Failed to send data to forward channel");
                                forward_channels.lock().unwrap().remove(&forward_key);
                            } else {
                                tracing::info!(?client_addr, "Sent UDP packet to existing forward channel");
                            }
                        } else {
                            // 创建新的转发通道和任务
                            let (tx, rx) = tokio::sync::mpsc::channel(100);
                            if tx.send(data_to_send).await.is_ok() {
                                forward_channels
                                    .lock()
                                    .unwrap()
                                    .insert(forward_key.clone(), tx.clone());

                                // 启动后台转发任务
                                let udp_socket_clone = Arc::clone(&udp_socket);
                                let forward_channels_clone = Arc::clone(&forward_channels);

                                tokio::spawn(async move {
                                    match udp_forward_task(
                                        udp_socket_clone,
                                        client_addr,
                                        target_addr,
                                        target_port,
                                        atyp_and_addr,
                                        rx,
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            tracing::debug!(
                                                "UDP forward task completed for {:?}",
                                                forward_key
                                            );
                                        }
                                        Err(e) => {
                                            tracing::error!(?e, "UDP forward task error");
                                        }
                                    }
                                    // 清理通道
                                    forward_channels_clone.lock().unwrap().remove(&forward_key);
                                    tracing::info!(?forward_key, "Cleaned up forward channel");
                                });
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!(?e, "UDP receive error");
                        break;
                    }
                    Err(_) => {
                        tracing::warn!("UDP session timeout, closing connection");
                        break;
                    }
                }
            }
        }
        _ => {
            tracing::error!("Unsupported command: {}", cmd_buf[1]);
            socket
                .write_all(&build_reply(REP_COMMAND_NOT_SUPPORTED, "0.0.0.0", 0))
                .await?;
            socket.shutdown().await?;
            return Ok(());
        }
    }

    Ok(())
}
