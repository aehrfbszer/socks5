use clap::Parser;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t)]
    listen_addr: String,
    #[arg(short, long, default_value_t)]
    auth: bool,
    #[arg(short, long, default_value_t)]
    port: u16,
    #[arg(required_if_eq("auth", "true"), short, long)]
    username: Option<String>,
    #[arg(required_if_eq("auth", "true"), short, long)]
    password: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".into(),
            auth: false,
            port: 1080,
            username: None,
            password: None,
        }
    }
}

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
        tracing::info!(?addr, "New client connected");

        // 每个连接 spawn 一个任务
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client(socket, config.auth, username, password).await {
                tracing::error!(?e, "Error handling client");
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

fn build_reply(rep: u8, bind_addr: &str, bind_port: u16) -> Vec<u8> {
    let mut reply = vec![
        SOCKS5_VERSION,
        rep,
        0x00, // RSV
    ];

    if let Ok(ip) = bind_addr.parse::<std::net::Ipv4Addr>() {
        reply.push(ATYP_IPV4);
        reply.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = bind_addr.parse::<std::net::Ipv6Addr>() {
        reply.push(ATYP_IPV6);
        reply.extend_from_slice(&ip.octets());
    } else {
        reply.push(ATYP_DOMAIN);
        reply.push(bind_addr.len() as u8);
        reply.extend_from_slice(bind_addr.as_bytes());
    }

    reply.extend_from_slice(&bind_port.to_be_bytes());
    reply
}

async fn handle_socks5_client(
    mut socket: tokio::net::TcpStream,
    need_auth: bool,
    config_username: &'static str,
    config_password: &'static str,
) -> Result<()> {
    // 这里我们会维护一个状态机来处理 SOCKS5 协议的不同阶段
    let mut state = SocksState::default();

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
        state.stage = if need_auth {
            Stage::Authentication
        } else {
            Stage::Connected
        };
    } else {
        socket
            .write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_METHODS])
            .await?;
        socket.shutdown().await?;
        return Ok(());
    }

    if state.stage == Stage::Authentication {
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
            state.stage = Stage::Connected;
        }
    }

    tracing::info!(?state.stage, "Client authenticated successfully, waiting for command");

    let mut cmd_buf = [0u8; 4];
    socket.read_exact(&mut cmd_buf).await?;
    if cmd_buf[0] != SOCKS5_VERSION {
        tracing::error!("Unsupported SOCKS version in command: {}", cmd_buf[0]);
        socket.shutdown().await?;
        return Ok(());
    }

    match cmd_buf[1] {
        CMD_CONNECT => {
            state.cmd = Some(Cmd::Connect);
        }
        CMD_BIND => {
            state.cmd = Some(Cmd::Bind);
        }
        CMD_UDP_ASSOCIATE => {
            state.cmd = Some(Cmd::UdpAssociate);
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

    tracing::info!("Client is fully connected and ready to proxy data");
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
enum Stage {
    #[default]
    Handshake,
    Authentication,
    Connected,
}

#[derive(Debug)]
enum Cmd {
    Connect,
    Bind,
    UdpAssociate,
}

#[derive(Debug, Default)]
struct SocksState {
    stage: Stage,
    ready: bool,
    cmd: Option<Cmd>,
    tcp_socket: Option<tokio::net::TcpStream>,
    udp_socket: Option<tokio::net::UdpSocket>,
    bind_socket: Option<tokio::net::TcpListener>,
}
