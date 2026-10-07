//! tako-tunnel — headless TCP port-forward over the Tako (RustDesk) channel.
//!
//! This is the transport of the Tako agent plane: the controller's MCP server
//! runs it to open `127.0.0.1:<local-port>` and forward every connection through
//! hbbs/hbbr (P2P when possible, relay otherwise) to `<remote-host>:<remote-port>`
//! as seen from the target device — e.g. the device's own sshd — so the user's
//! AI agent reaches the user's own machine with no exposed ports, no VPN and no
//! GUI session, authenticated exactly like the human plane (account token for the
//! server's MUST_LOGIN + the device's permanent password).
//!
//! Usage:
//!   tako-tunnel --id <device-id> --password <device permanent password> \
//!               --local-port 2222 [--remote-host 127.0.0.1] [--remote-port 22] \
//!               [--token <Tako account access_token>]
//!
//! `--password` / `--token` may instead come from the TAKO_DEVICE_PASSWORD /
//! TAKO_TOKEN environment variables (preferred: keeps secrets out of `ps`). When
//! no token is given, the logged-in Tako app's local config is consulted.

use std::sync::{Arc, RwLock};

use hbb_common::{
    config::LocalConfig,
    log,
    message_proto::*,
    rendezvous_proto::ConnType,
    tokio::{self, sync::mpsc},
    Stream,
};
use librustdesk::client::*;

#[derive(Clone)]
struct Tunnel {
    lc: Arc<RwLock<LoginConfigHandler>>,
    sender: mpsc::UnboundedSender<Data>,
    password: String,
}

#[async_trait::async_trait]
impl Interface for Tunnel {
    fn get_lch(&self) -> Arc<RwLock<LoginConfigHandler>> {
        self.lc.clone()
    }

    fn send(&self, data: Data) {
        self.sender.send(data).ok();
    }

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str) {
        match msgtype {
            "input-password" => {
                self.sender
                    .send(Data::Login((
                        String::new(),
                        String::new(),
                        self.password.clone(),
                        true,
                    )))
                    .ok();
            }
            "re-input-password" => {
                eprintln!("tako-tunnel: device rejected the password ({title}: {text})");
                std::process::exit(2);
            }
            m if m.starts_with("insecure-connection") => {
                // The server public key is baked in, so this only happens when the
                // peer's key could not be verified. Refuse instead of running an
                // unverified session for an unattended agent.
                eprintln!("tako-tunnel: refusing unverified (insecure) connection");
                self.sender.send(Data::RejectInsecureConnection).ok();
            }
            m if m.contains("error") => {
                eprintln!("tako-tunnel: {msgtype}: {title}: {text}");
            }
            _ => log::info!("{msgtype}: {title}: {text}"),
        }
    }

    fn handle_login_error(&self, err: &str) -> bool {
        handle_login_error(self.lc.clone(), err, self)
    }

    fn handle_peer_info(&self, pi: PeerInfo) {
        self.lc.write().unwrap().handle_peer_info(&pi);
    }

    fn set_multiple_windows_session(&self, _sessions: Vec<WindowsSession>) {}

    async fn handle_hash(&self, pass: &str, hash: Hash, peer: &mut Stream) {
        handle_hash(self.lc.clone(), pass, hash, self, peer).await;
    }

    async fn handle_login_from_ui(
        &self,
        os_username: String,
        os_password: String,
        password: String,
        remember: bool,
        peer: &mut Stream,
    ) {
        handle_login_from_ui(
            self.lc.clone(),
            os_username,
            os_password,
            password,
            remember,
            peer,
        )
        .await;
    }

    async fn handle_test_delay(&self, t: TestDelay, peer: &mut Stream) {
        handle_test_delay(t, peer).await;
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: tako-tunnel --id <device-id> --password <permanent-password> --local-port <port> \
         [--remote-host 127.0.0.1] [--remote-port 22] [--token <access_token>]"
    );
    std::process::exit(64);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut id = String::new();
    let mut password = std::env::var("TAKO_DEVICE_PASSWORD").unwrap_or_default();
    let mut token = std::env::var("TAKO_TOKEN").unwrap_or_default();
    let mut local_port: i32 = 0;
    let mut remote_host = "127.0.0.1".to_owned();
    let mut remote_port: i32 = 22;

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let value = |i: usize| -> String { argv.get(i + 1).cloned().unwrap_or_else(|| usage()) };
        match argv[i].as_str() {
            "--id" => id = value(i),
            "--password" => password = value(i),
            "--token" => token = value(i),
            "--local-port" => local_port = value(i).parse().unwrap_or_else(|_| usage()),
            "--remote-host" => remote_host = value(i),
            "--remote-port" => remote_port = value(i).parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
        i += 2;
    }
    let id = id.replace(' ', "");
    if id.is_empty() || password.is_empty() || local_port <= 0 || local_port > 65535 {
        usage();
    }

    if !librustdesk::common::global_init() {
        eprintln!("tako-tunnel: global init failed");
        std::process::exit(1);
    }
    let key = librustdesk::common::get_key(true).await;
    if token.is_empty() {
        token = LocalConfig::get_option("access_token");
    }
    if token.is_empty() {
        eprintln!(
            "tako-tunnel: warning: no account token; the Tako server requires a login (pass --token or TAKO_TOKEN)"
        );
    }

    let (sender, receiver) = mpsc::unbounded_channel::<Data>();
    let lc = Arc::new(RwLock::new(LoginConfigHandler::default()));
    lc.write()
        .unwrap()
        .initialize(id.clone(), ConnType::PORT_FORWARD, None, false, None, None, None);
    let tunnel = Tunnel {
        lc: lc.clone(),
        sender,
        password: password.clone(),
    };

    println!("tako-tunnel: listening on 127.0.0.1:{local_port} -> {id} {remote_host}:{remote_port}");
    if let Err(err) = librustdesk::port_forward::listen(
        id,
        password,
        local_port,
        tunnel,
        receiver,
        &key,
        &token,
        lc,
        remote_host,
        remote_port,
    )
    .await
    {
        eprintln!("tako-tunnel: {err}");
        std::process::exit(1);
    }
    librustdesk::common::global_clean();
}
