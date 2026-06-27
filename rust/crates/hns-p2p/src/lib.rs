use hns_core::bytes::{ParseError, Reader};
use hns_core::network::Network;
use hns_core::{BlockHeader, Hash, Height};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

pub const PROTOCOL_VERSION: u32 = 3;
pub const SERVICE_NETWORK: u64 = 1;
pub const MAX_INV: usize = 50_000;
pub const MAX_ADDR: usize = 1_000;
pub const MAX_HEADERS: usize = 2_000;
pub const MAX_AGENT_LEN: usize = 255;
pub const FRAME_HEADER_SIZE: usize = 9;
pub const MAX_MESSAGE: usize = 8 * 1000 * 1000;
pub const ZERO_NONCE: [u8; 8] = [0u8; 8];
pub const BAN_SCORE: i32 = 100;
pub const MALFORMED_SCORE: i32 = 100;
pub const STALE_TIP_SCORE: i32 = 10;
pub const TRANSIENT_FAILURE_SCORE: i32 = 5;
pub const SUCCESS_REWARD: i32 = 2;
pub const DEFAULT_DNS_SEED_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    Version = 0,
    Verack = 1,
    Ping = 2,
    Pong = 3,
    GetAddr = 4,
    Addr = 5,
    GetHeaders = 10,
    Headers = 11,
    SendHeaders = 12,
    GetProof = 26,
    Proof = 27,
    Unknown = 30,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetAddress {
    pub time: u64,
    pub services: u64,
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionPacket {
    pub version: u32,
    pub services: u64,
    pub time: u64,
    pub remote: NetAddress,
    pub nonce: [u8; 8],
    pub agent: String,
    pub height: Height,
    pub no_relay: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocatorPacket {
    pub locator: Vec<Hash>,
    pub stop: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadersPacket {
    pub items: Vec<BlockHeader>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddrPacket {
    pub items: Vec<NetAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRequest {
    pub root: Hash,
    pub key: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofPacket {
    pub root: Hash,
    pub key: Hash,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    Version(VersionPacket),
    Verack,
    Ping([u8; 8]),
    Pong([u8; 8]),
    GetAddr,
    Addr(AddrPacket),
    GetHeaders(LocatorPacket),
    Headers(HeadersPacket),
    SendHeaders,
    GetProof(ProofRequest),
    Proof(ProofPacket),
    Unknown { packet_type: u8, payload: Vec<u8> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSyncState {
    AwaitingVersion,
    AwaitingVerack,
    Ready,
    HeadersRequested,
    ProofRequested,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderSyncAction {
    Send(Packet),
    Ready,
    Headers(Vec<BlockHeader>),
    Proof(ProofPacket),
    Disconnect(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderSyncSession {
    state: HeaderSyncState,
    local_version: VersionPacket,
    remote_version: Option<VersionPacket>,
    ack_received: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub magic: u32,
    pub packet_type: u8,
    pub payload_len: u32,
}

#[derive(Debug)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    network: Network,
}

#[derive(Debug)]
pub struct PeerConnection<T> {
    transport: T,
    network: Network,
    decoder: FrameDecoder,
    pending: VecDeque<Packet>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerState {
    pub address: SocketAddr,
    pub score: i32,
    pub last_height: Height,
    pub last_connected_at: Option<u64>,
    pub banned_until: Option<u64>,
    pub successes: u32,
    pub failures: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PeerAddressGroup {
    Ipv4([u8; 2]),
    Ipv6([u8; 4]),
}

#[derive(Default)]
pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerState>,
}

#[derive(Debug)]
pub struct SqlitePeerStore {
    connection: Connection,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StaticPeerSource {
    peers: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSeedPeerSource {
    seeds: Vec<String>,
    port: u16,
    limit: usize,
}

pub trait PeerSource {
    fn discover(&self) -> Result<Vec<SocketAddr>, P2pError>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum P2pError {
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("varint is non-canonical")]
    NonCanonicalVarint,
    #[error("count exceeds protocol limit")]
    CountLimit,
    #[error("user agent is too long")]
    AgentTooLong,
    #[error("payload has trailing bytes")]
    TrailingBytes,
    #[error("invalid network magic")]
    InvalidMagic,
    #[error("message exceeds protocol limit")]
    MessageTooLarge,
    #[error("network I/O error: {0:?}")]
    Io(std::io::ErrorKind),
    #[error("peer closed the connection")]
    ConnectionClosed,
    #[error("peer session disconnected: {0}")]
    SessionDisconnected(&'static str),
    #[error("unexpected peer session action")]
    UnexpectedAction,
    #[error("peer storage error: {0}")]
    Storage(String),
}

impl Default for NetAddress {
    fn default() -> Self {
        Self {
            time: 0,
            services: SERVICE_NETWORK,
            address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 0,
        }
    }
}

impl Default for VersionPacket {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            services: SERVICE_NETWORK,
            time: 0,
            remote: NetAddress::default(),
            nonce: ZERO_NONCE,
            agent: "/hns-browser:0.1.1/".to_owned(),
            height: Height(0),
            no_relay: true,
        }
    }
}

impl PeerState {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            score: 0,
            last_height: Height(0),
            last_connected_at: None,
            banned_until: None,
            successes: 0,
            failures: 0,
        }
    }

    pub fn is_banned(&self, now: u64) -> bool {
        self.banned_until.is_some_and(|until| until > now)
    }
}

impl PeerManager {
    pub fn from_states<I>(states: I) -> Self
    where
        I: IntoIterator<Item = PeerState>,
    {
        let mut manager = Self::default();
        for state in states {
            manager.peers.insert(state.address, state);
        }
        manager
    }

    pub fn upsert(&mut self, address: SocketAddr) -> &mut PeerState {
        self.peers
            .entry(address)
            .or_insert_with(|| PeerState::new(address))
    }

    pub fn seed<I>(&mut self, addresses: I) -> usize
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let mut inserted = 0usize;
        for address in addresses {
            if !self.peers.contains_key(&address) {
                inserted = inserted.saturating_add(1);
            }
            self.upsert(address);
        }
        inserted
    }

    pub fn seed_from<S: PeerSource>(&mut self, source: &S) -> Result<usize, P2pError> {
        source.discover().map(|peers| self.seed(peers))
    }

    pub fn record_success(&mut self, address: SocketAddr, height: Height, now: u64) {
        let peer = self.upsert(address);
        peer.score = peer.score.saturating_sub(SUCCESS_REWARD).max(0);
        peer.last_height = height;
        peer.last_connected_at = Some(now);
        peer.successes = peer.successes.saturating_add(1);
    }

    pub fn record_transient_failure(&mut self, address: SocketAddr) {
        let peer = self.upsert(address);
        peer.score = peer.score.saturating_add(TRANSIENT_FAILURE_SCORE);
        peer.failures = peer.failures.saturating_add(1);
    }

    pub fn record_stale_tip(&mut self, address: SocketAddr) {
        self.penalize(address, STALE_TIP_SCORE, None);
    }

    pub fn record_malformed(&mut self, address: SocketAddr, now: u64, ban_seconds: u64) {
        self.penalize(
            address,
            MALFORMED_SCORE,
            Some(now.saturating_add(ban_seconds)),
        );
    }

    pub fn select_outbound(&self, preferred_count: usize, now: u64) -> Vec<SocketAddr> {
        let mut peers = self
            .peers
            .values()
            .filter(|peer| !peer.is_banned(now))
            .collect::<Vec<_>>();
        peers.sort_by(|left, right| {
            left.score
                .cmp(&right.score)
                .then_with(|| right.last_height.cmp(&left.last_height))
                .then_with(|| left.address.cmp(&right.address))
        });

        let mut selected = Vec::new();
        let mut selected_groups = HashSet::new();
        for peer in &peers {
            if selected.len() >= preferred_count {
                return selected;
            }

            let group = PeerAddressGroup::from_socket_addr(peer.address);
            if selected_groups.insert(group) {
                selected.push(peer.address);
            }
        }

        for peer in peers {
            if selected.len() >= preferred_count {
                break;
            }

            if !selected.contains(&peer.address) {
                selected.push(peer.address);
            }
        }

        selected
    }

    pub fn get(&self, address: SocketAddr) -> Option<&PeerState> {
        self.peers.get(&address)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerState> {
        self.peers.values()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn address_group_count(&self, now: u64) -> usize {
        self.peers
            .values()
            .filter(|peer| !peer.is_banned(now))
            .map(|peer| PeerAddressGroup::from_socket_addr(peer.address))
            .collect::<HashSet<_>>()
            .len()
    }

    fn penalize(&mut self, address: SocketAddr, score: i32, banned_until: Option<u64>) {
        let peer = self.upsert(address);
        peer.score = peer.score.saturating_add(score);
        if peer.score >= BAN_SCORE && banned_until.is_some() {
            peer.banned_until = banned_until;
        }
    }
}

impl PeerAddressGroup {
    pub fn from_socket_addr(address: SocketAddr) -> Self {
        match address.ip() {
            IpAddr::V4(address) => {
                let octets = address.octets();
                Self::Ipv4([octets[0], octets[1]])
            }
            IpAddr::V6(address) => {
                let octets = address.octets();
                Self::Ipv6([octets[0], octets[1], octets[2], octets[3]])
            }
        }
    }
}

impl StaticPeerSource {
    pub fn new<I>(peers: I) -> Self
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let mut unique = Vec::new();
        for peer in peers {
            if !unique.contains(&peer) {
                unique.push(peer);
            }
        }
        Self { peers: unique }
    }

    pub fn peers(&self) -> &[SocketAddr] {
        &self.peers
    }
}

impl PeerSource for StaticPeerSource {
    fn discover(&self) -> Result<Vec<SocketAddr>, P2pError> {
        Ok(self.peers.clone())
    }
}

impl DnsSeedPeerSource {
    pub fn from_network(network: &Network) -> Self {
        Self::new(network.dns_seeds.iter().copied(), network.port)
    }

    pub fn new<I, S>(seeds: I, port: u16) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            seeds: dedupe_seed_names(seeds),
            port,
            limit: DEFAULT_DNS_SEED_LIMIT,
        }
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn seeds(&self) -> &[String] {
        &self.seeds
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl PeerSource for DnsSeedPeerSource {
    fn discover(&self) -> Result<Vec<SocketAddr>, P2pError> {
        if self.limit == 0 || self.seeds.is_empty() {
            return Ok(Vec::new());
        }

        let mut peers = Vec::new();
        let mut last_error = None;

        for seed in &self.seeds {
            match (seed.as_str(), self.port).to_socket_addrs() {
                Ok(addresses) => {
                    push_unique_addresses(&mut peers, addresses, self.limit);
                    if peers.len() >= self.limit {
                        return Ok(peers);
                    }
                }
                Err(error) => last_error = Some(error.kind()),
            }
        }

        if peers.is_empty()
            && let Some(kind) = last_error
        {
            return Err(P2pError::Io(kind));
        }

        Ok(peers)
    }
}

impl SqlitePeerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, P2pError> {
        let connection = Connection::open(path).map_err(sqlite_error)?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, P2pError> {
        let connection = Connection::open_in_memory().map_err(sqlite_error)?;
        Self::from_connection(connection)
    }

    pub fn from_connection(connection: Connection) -> Result<Self, P2pError> {
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<(), P2pError> {
        self.connection
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS peers (
                    address TEXT PRIMARY KEY NOT NULL,
                    score INTEGER NOT NULL,
                    last_height INTEGER NOT NULL,
                    last_connected_at TEXT,
                    banned_until TEXT,
                    successes INTEGER NOT NULL,
                    failures INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS peers_score_height
                    ON peers(score, last_height);
                ",
            )
            .map_err(sqlite_error)
    }

    pub fn save_peer(&self, peer: &PeerState) -> Result<(), P2pError> {
        self.connection
            .execute(
                "
                INSERT INTO peers(
                    address,
                    score,
                    last_height,
                    last_connected_at,
                    banned_until,
                    successes,
                    failures
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(address) DO UPDATE SET
                    score = excluded.score,
                    last_height = excluded.last_height,
                    last_connected_at = excluded.last_connected_at,
                    banned_until = excluded.banned_until,
                    successes = excluded.successes,
                    failures = excluded.failures
                ",
                params![
                    peer.address.to_string(),
                    peer.score,
                    i64::from(peer.last_height.0),
                    optional_u64_to_text(peer.last_connected_at),
                    optional_u64_to_text(peer.banned_until),
                    i64::from(peer.successes),
                    i64::from(peer.failures),
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn save_manager(&self, manager: &PeerManager) -> Result<usize, P2pError> {
        let mut saved = 0usize;
        for peer in manager.iter() {
            self.save_peer(peer)?;
            saved = saved.saturating_add(1);
        }
        Ok(saved)
    }

    pub fn load_peer(&self, address: SocketAddr) -> Result<Option<PeerState>, P2pError> {
        self.connection
            .query_row(
                "
                SELECT
                    address,
                    score,
                    last_height,
                    last_connected_at,
                    banned_until,
                    successes,
                    failures
                FROM peers
                WHERE address = ?1
                ",
                params![address.to_string()],
                row_to_peer_state,
            )
            .optional()
            .map_err(sqlite_error)
    }

    pub fn load_manager(&self) -> Result<PeerManager, P2pError> {
        let mut statement = self
            .connection
            .prepare(
                "
                SELECT
                    address,
                    score,
                    last_height,
                    last_connected_at,
                    banned_until,
                    successes,
                    failures
                FROM peers
                ",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], row_to_peer_state)
            .map_err(sqlite_error)?;
        let mut states = Vec::new();
        for row in rows {
            states.push(row.map_err(sqlite_error)?);
        }
        Ok(PeerManager::from_states(states))
    }

    pub fn len(&self) -> Result<usize, P2pError> {
        self.connection
            .query_row("SELECT COUNT(*) FROM peers", [], |row| {
                let count: i64 = row.get(0)?;
                usize_from_i64(count, 0)
            })
            .map_err(sqlite_error)
    }

    pub fn is_empty(&self) -> Result<bool, P2pError> {
        self.len().map(|len| len == 0)
    }

    pub fn flush(self) -> Result<(), P2pError> {
        self.connection
            .close()
            .map_err(|(_, error)| sqlite_error(error))
    }
}

fn row_to_peer_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerState> {
    let address_text: String = row.get(0)?;
    let score: i32 = row.get(1)?;
    let last_height_raw: i64 = row.get(2)?;
    let last_connected_at_text: Option<String> = row.get(3)?;
    let banned_until_text: Option<String> = row.get(4)?;
    let successes_raw: i64 = row.get(5)?;
    let failures_raw: i64 = row.get(6)?;

    let banned_until = optional_u64_from_text(banned_until_text, 4)?
        .filter(|banned_until| *banned_until != u64::MAX);

    Ok(PeerState {
        address: socket_addr_from_text(&address_text, 0)?,
        score,
        last_height: Height(u32_from_i64(last_height_raw, 2)?),
        last_connected_at: optional_u64_from_text(last_connected_at_text, 3)?,
        banned_until,
        successes: u32_from_i64(successes_raw, 5)?,
        failures: u32_from_i64(failures_raw, 6)?,
    })
}

fn dedupe_seed_names<I, S>(seeds: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut unique = Vec::new();
    for seed in seeds {
        let seed = seed.into();
        if !seed.is_empty() && !unique.contains(&seed) {
            unique.push(seed);
        }
    }
    unique
}

fn push_unique_addresses<I>(peers: &mut Vec<SocketAddr>, addresses: I, limit: usize)
where
    I: IntoIterator<Item = SocketAddr>,
{
    for address in addresses {
        if peers.len() >= limit {
            break;
        }
        if !peers.contains(&address) {
            peers.push(address);
        }
    }
}

fn socket_addr_from_text(value: &str, column: usize) -> rusqlite::Result<SocketAddr> {
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn optional_u64_to_text(value: Option<u64>) -> Option<String> {
    value.map(|value| value.to_string())
}

fn optional_u64_from_text(value: Option<String>, column: usize) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| {
            value.parse().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn u32_from_i64(value: i64, column: usize) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn usize_from_i64(value: i64, column: usize) -> rusqlite::Result<usize> {
    usize::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn sqlite_error(error: rusqlite::Error) -> P2pError {
    P2pError::Storage(error.to_string())
}

impl HeaderSyncSession {
    pub fn new(local_version: VersionPacket) -> Self {
        Self {
            state: HeaderSyncState::AwaitingVersion,
            local_version,
            remote_version: None,
            ack_received: false,
        }
    }

    pub fn start(&self) -> HeaderSyncAction {
        HeaderSyncAction::Send(Packet::Version(self.local_version.clone()))
    }

    pub fn state(&self) -> HeaderSyncState {
        self.state
    }

    pub fn remote_version(&self) -> Option<&VersionPacket> {
        self.remote_version.as_ref()
    }

    pub fn on_packet(&mut self, packet: Packet) -> Vec<HeaderSyncAction> {
        match (self.state, packet) {
            (HeaderSyncState::AwaitingVersion, Packet::Version(version)) => {
                if version.version < 1 || version.services & SERVICE_NETWORK == 0 {
                    self.state = HeaderSyncState::Closed;
                    return vec![HeaderSyncAction::Disconnect(
                        "peer lacks required network service",
                    )];
                }

                self.remote_version = Some(version);
                if self.ack_received {
                    self.state = HeaderSyncState::Ready;
                    vec![
                        HeaderSyncAction::Send(Packet::Verack),
                        HeaderSyncAction::Ready,
                    ]
                } else {
                    self.state = HeaderSyncState::AwaitingVerack;
                    vec![HeaderSyncAction::Send(Packet::Verack)]
                }
            }
            (HeaderSyncState::AwaitingVersion, Packet::Verack) => {
                self.ack_received = true;
                Vec::new()
            }
            (HeaderSyncState::AwaitingVerack, Packet::Verack) => {
                self.ack_received = true;
                self.state = HeaderSyncState::Ready;
                vec![HeaderSyncAction::Ready]
            }
            (HeaderSyncState::HeadersRequested, Packet::Headers(headers)) => {
                self.state = HeaderSyncState::Ready;
                vec![HeaderSyncAction::Headers(headers.items)]
            }
            (HeaderSyncState::ProofRequested, Packet::Proof(proof)) => {
                self.state = HeaderSyncState::Ready;
                vec![HeaderSyncAction::Proof(proof)]
            }
            (HeaderSyncState::Closed, _) => {
                vec![HeaderSyncAction::Disconnect("session is closed")]
            }
            (
                _,
                Packet::GetAddr | Packet::Addr(_) | Packet::SendHeaders | Packet::Unknown { .. },
            ) => Vec::new(),
            (_, Packet::Ping(nonce)) => vec![HeaderSyncAction::Send(Packet::Pong(nonce))],
            (_, Packet::Pong(_)) => Vec::new(),
            _ => vec![HeaderSyncAction::Disconnect(
                "unexpected packet for sync state",
            )],
        }
    }

    pub fn request_headers(
        &mut self,
        locator: Vec<Hash>,
        stop: Hash,
    ) -> Result<HeaderSyncAction, P2pError> {
        if self.state != HeaderSyncState::Ready {
            return Ok(HeaderSyncAction::Disconnect(
                "headers requested before peer ready",
            ));
        }

        if locator.len() > MAX_INV {
            return Err(P2pError::CountLimit);
        }

        self.state = HeaderSyncState::HeadersRequested;
        Ok(HeaderSyncAction::Send(Packet::GetHeaders(LocatorPacket {
            locator,
            stop,
        })))
    }

    pub fn request_proof(&mut self, root: Hash, key: Hash) -> HeaderSyncAction {
        if self.state != HeaderSyncState::Ready {
            return HeaderSyncAction::Disconnect("proof requested before peer ready");
        }

        self.state = HeaderSyncState::ProofRequested;
        HeaderSyncAction::Send(Packet::GetProof(ProofRequest { root, key }))
    }
}

impl FrameHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.magic.to_le_bytes());
        out.push(self.packet_type);
        out.extend(self.payload_len.to_le_bytes());
    }

    pub fn parse(data: &[u8]) -> Result<Self, P2pError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(ParseError::UnexpectedEof.into());
        }

        Ok(Self {
            magic: u32::from_le_bytes(data[0..4].try_into().expect("checked frame magic length")),
            packet_type: data[4],
            payload_len: u32::from_le_bytes(
                data[5..9].try_into().expect("checked frame payload length"),
            ),
        })
    }
}

impl FrameDecoder {
    pub fn new(network: Network) -> Self {
        Self {
            buffer: Vec::new(),
            network,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Packet>, P2pError> {
        if self.buffer.len().saturating_add(data.len()) > MAX_MESSAGE + FRAME_HEADER_SIZE {
            return Err(P2pError::MessageTooLarge);
        }

        self.buffer.extend(data);
        let mut packets = Vec::new();
        let mut consumed = 0usize;

        while let Some((packet, used)) = decode_frame(&self.network, &self.buffer[consumed..])? {
            consumed += used;
            packets.push(packet);
            if consumed == self.buffer.len() {
                break;
            }
        }

        if consumed > 0 {
            self.buffer.drain(0..consumed);
        }

        Ok(packets)
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl PeerConnection<TcpStream> {
    pub fn connect(
        address: SocketAddr,
        network: Network,
        timeout: Duration,
    ) -> Result<Self, P2pError> {
        let stream = TcpStream::connect_timeout(&address, timeout).map_err(io_error)?;
        stream.set_read_timeout(Some(timeout)).map_err(io_error)?;
        stream.set_write_timeout(Some(timeout)).map_err(io_error)?;
        Ok(Self::new(stream, network))
    }
}

impl<T: Read + Write> PeerConnection<T> {
    pub fn new(transport: T, network: Network) -> Self {
        Self {
            transport,
            decoder: FrameDecoder::new(network.clone()),
            network,
            pending: VecDeque::new(),
        }
    }

    pub fn network(&self) -> &Network {
        &self.network
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub fn send_packet(&mut self, packet: &Packet) -> Result<(), P2pError> {
        let frame = encode_frame(&self.network, packet)?;
        self.transport.write_all(&frame).map_err(io_error)?;
        self.transport.flush().map_err(io_error)
    }

    pub fn receive_packet(&mut self) -> Result<Packet, P2pError> {
        if let Some(packet) = self.pending.pop_front() {
            return Ok(packet);
        }

        let mut buffer = [0u8; 8192];
        loop {
            let read = self.transport.read(&mut buffer).map_err(io_error)?;
            if read == 0 {
                return Err(P2pError::ConnectionClosed);
            }

            let packets = self.decoder.feed(&buffer[..read])?;
            self.pending.extend(packets);
            if let Some(packet) = self.pending.pop_front() {
                return Ok(packet);
            }
        }
    }

    pub fn handshake(
        &mut self,
        session: &mut HeaderSyncSession,
    ) -> Result<VersionPacket, P2pError> {
        self.apply_action(session.start())?;
        loop {
            let packet = self.receive_packet()?;
            for action in session.on_packet(packet) {
                match action {
                    HeaderSyncAction::Ready => {
                        return session
                            .remote_version()
                            .cloned()
                            .ok_or(P2pError::UnexpectedAction);
                    }
                    HeaderSyncAction::Send(packet) => self.send_packet(&packet)?,
                    HeaderSyncAction::Disconnect(reason) => {
                        return Err(P2pError::SessionDisconnected(reason));
                    }
                    HeaderSyncAction::Headers(_) | HeaderSyncAction::Proof(_) => {
                        return Err(P2pError::UnexpectedAction);
                    }
                }
            }
        }
    }

    pub fn request_headers(
        &mut self,
        session: &mut HeaderSyncSession,
        locator: Vec<Hash>,
        stop: Hash,
    ) -> Result<Vec<BlockHeader>, P2pError> {
        let action = session.request_headers(locator, stop)?;
        self.apply_action(action)?;
        loop {
            let packet = self.receive_packet()?;
            for action in session.on_packet(packet) {
                match action {
                    HeaderSyncAction::Headers(headers) => return Ok(headers),
                    HeaderSyncAction::Send(packet) => self.send_packet(&packet)?,
                    HeaderSyncAction::Disconnect(reason) => {
                        return Err(P2pError::SessionDisconnected(reason));
                    }
                    HeaderSyncAction::Ready | HeaderSyncAction::Proof(_) => {
                        return Err(P2pError::UnexpectedAction);
                    }
                }
            }
        }
    }

    pub fn request_addresses(&mut self) -> Result<Vec<SocketAddr>, P2pError> {
        self.send_packet(&Packet::GetAddr)?;
        loop {
            match self.receive_packet()? {
                Packet::Addr(addresses) => return Ok(addresses.service_sockets(SERVICE_NETWORK)),
                Packet::Ping(nonce) => self.send_packet(&Packet::Pong(nonce))?,
                Packet::GetAddr
                | Packet::Pong(_)
                | Packet::SendHeaders
                | Packet::Unknown { .. }
                | Packet::Verack => {}
                Packet::Version(_)
                | Packet::GetHeaders(_)
                | Packet::Headers(_)
                | Packet::GetProof(_)
                | Packet::Proof(_) => return Err(P2pError::UnexpectedAction),
            }
        }
    }

    pub fn request_proof(
        &mut self,
        session: &mut HeaderSyncSession,
        root: Hash,
        key: Hash,
    ) -> Result<ProofPacket, P2pError> {
        self.apply_action(session.request_proof(root, key))?;
        loop {
            let packet = self.receive_packet()?;
            for action in session.on_packet(packet) {
                match action {
                    HeaderSyncAction::Proof(proof) => return Ok(proof),
                    HeaderSyncAction::Send(packet) => self.send_packet(&packet)?,
                    HeaderSyncAction::Disconnect(reason) => {
                        return Err(P2pError::SessionDisconnected(reason));
                    }
                    HeaderSyncAction::Ready | HeaderSyncAction::Headers(_) => {
                        return Err(P2pError::UnexpectedAction);
                    }
                }
            }
        }
    }

    fn apply_action(&mut self, action: HeaderSyncAction) -> Result<(), P2pError> {
        match action {
            HeaderSyncAction::Send(packet) => self.send_packet(&packet),
            HeaderSyncAction::Disconnect(reason) => Err(P2pError::SessionDisconnected(reason)),
            HeaderSyncAction::Ready | HeaderSyncAction::Headers(_) | HeaderSyncAction::Proof(_) => {
                Err(P2pError::UnexpectedAction)
            }
        }
    }
}

pub fn encode_frame(network: &Network, packet: &Packet) -> Result<Vec<u8>, P2pError> {
    let payload = packet.encode_payload()?;
    if payload.len() > MAX_MESSAGE {
        return Err(P2pError::MessageTooLarge);
    }

    let mut out = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    FrameHeader {
        magic: network.magic,
        packet_type: packet.packet_type() as u8,
        payload_len: payload.len() as u32,
    }
    .encode(&mut out);
    out.extend(payload);
    Ok(out)
}

pub fn decode_frame(network: &Network, data: &[u8]) -> Result<Option<(Packet, usize)>, P2pError> {
    if data.len() < FRAME_HEADER_SIZE {
        return Ok(None);
    }

    let header = FrameHeader::parse(data)?;
    if header.magic != network.magic {
        return Err(P2pError::InvalidMagic);
    }

    let payload_len = header.payload_len as usize;
    if payload_len > MAX_MESSAGE {
        return Err(P2pError::MessageTooLarge);
    }

    let frame_len = FRAME_HEADER_SIZE
        .checked_add(payload_len)
        .ok_or(P2pError::MessageTooLarge)?;
    if data.len() < frame_len {
        return Ok(None);
    }

    let payload = &data[FRAME_HEADER_SIZE..frame_len];
    let packet = Packet::decode_payload(header.packet_type, payload)?;
    Ok(Some((packet, frame_len)))
}

impl Packet {
    pub fn packet_type(&self) -> PacketType {
        match self {
            Self::Version(_) => PacketType::Version,
            Self::Verack => PacketType::Verack,
            Self::Ping(_) => PacketType::Ping,
            Self::Pong(_) => PacketType::Pong,
            Self::GetAddr => PacketType::GetAddr,
            Self::Addr(_) => PacketType::Addr,
            Self::GetHeaders(_) => PacketType::GetHeaders,
            Self::Headers(_) => PacketType::Headers,
            Self::SendHeaders => PacketType::SendHeaders,
            Self::GetProof(_) => PacketType::GetProof,
            Self::Proof(_) => PacketType::Proof,
            Self::Unknown { .. } => PacketType::Unknown,
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, P2pError> {
        let mut out = Vec::new();
        match self {
            Self::Version(packet) => packet.encode(&mut out)?,
            Self::Verack | Self::GetAddr | Self::SendHeaders => {}
            Self::Ping(nonce) | Self::Pong(nonce) => out.extend(nonce),
            Self::Addr(packet) => packet.encode(&mut out)?,
            Self::GetHeaders(packet) => packet.encode(&mut out)?,
            Self::Headers(packet) => packet.encode(&mut out)?,
            Self::GetProof(packet) => {
                out.extend(packet.root.as_bytes());
                out.extend(packet.key.as_bytes());
            }
            Self::Proof(packet) => {
                out.extend(packet.root.as_bytes());
                out.extend(packet.key.as_bytes());
                out.extend(&packet.proof);
            }
            Self::Unknown { payload, .. } => out.extend(payload),
        }
        Ok(out)
    }

    pub fn decode_payload(packet_type: u8, payload: &[u8]) -> Result<Self, P2pError> {
        let mut reader = Reader::new(payload);
        let packet = match packet_type {
            0 => Self::Version(VersionPacket::decode(&mut reader)?),
            1 => Self::Verack,
            2 => Self::Ping(reader.read_array()?),
            3 => Self::Pong(reader.read_array()?),
            4 => Self::GetAddr,
            5 => Self::Addr(AddrPacket::decode(&mut reader)?),
            10 => Self::GetHeaders(LocatorPacket::decode(&mut reader)?),
            11 => Self::Headers(HeadersPacket::decode(&mut reader)?),
            12 => Self::SendHeaders,
            26 => {
                let root = Hash::new(reader.read_array()?);
                let key = Hash::new(reader.read_array()?);
                Self::GetProof(ProofRequest { root, key })
            }
            27 => {
                let root = Hash::new(reader.read_array()?);
                let key = Hash::new(reader.read_array()?);
                let proof = reader.read_bytes(reader.remaining())?.to_vec();
                Self::Proof(ProofPacket { root, key, proof })
            }
            other => Self::Unknown {
                packet_type: other,
                payload: payload.to_vec(),
            },
        };

        if !matches!(packet, Self::Unknown { .. }) && reader.remaining() != 0 {
            return Err(P2pError::TrailingBytes);
        }

        Ok(packet)
    }
}

impl VersionPacket {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), P2pError> {
        let agent = self.agent.as_bytes();
        if agent.len() > MAX_AGENT_LEN {
            return Err(P2pError::AgentTooLong);
        }

        write_u32_le(out, self.version);
        write_u64_service(out, self.services);
        write_u64_le(out, self.time);
        self.remote.encode(out);
        out.extend(self.nonce);
        out.push(agent.len() as u8);
        out.extend(agent);
        write_u32_le(out, self.height.0);
        out.push(u8::from(self.no_relay));
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let version = reader.read_u32_le()?;
        let services = read_u64_service(reader)?;
        let time = reader.read_u64_le()?;
        let remote = NetAddress::decode(reader)?;
        let nonce = reader.read_array()?;
        let agent_len = reader.read_u8()? as usize;
        if agent_len > MAX_AGENT_LEN {
            return Err(P2pError::AgentTooLong);
        }
        let agent = std::str::from_utf8(reader.read_bytes(agent_len)?)
            .map_err(|_| ParseError::InvalidDnsLabel)?
            .to_owned();
        let height = Height(reader.read_u32_le()?);
        let no_relay = reader.read_u8()? == 1;

        Ok(Self {
            version,
            services,
            time,
            remote,
            nonce,
            agent,
            height,
            no_relay,
        })
    }
}

impl NetAddress {
    pub fn from_socket(socket: SocketAddr, services: u64) -> Self {
        Self {
            time: 0,
            services,
            address: socket.ip(),
            port: socket.port(),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_u64_le(out, self.time);
        write_u64_service(out, self.services);
        out.push(0);
        match self.address {
            IpAddr::V4(address) => {
                out.extend([0u8; 10]);
                out.extend([0xff, 0xff]);
                out.extend(address.octets());
            }
            IpAddr::V6(address) => out.extend(address.octets()),
        }
        out.extend([0u8; 20]);
        out.extend(self.port.to_le_bytes());
        out.extend([0u8; 33]);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let time = reader.read_u64_le()?;
        let services = read_u64_service(reader)?;
        let raw_address = if reader.read_u8()? == 0 {
            let raw_address = reader.read_array()?;
            reader.read_bytes(20)?;
            raw_address
        } else {
            reader.read_bytes(36)?;
            [0u8; 16]
        };
        let port = u16::from_le_bytes(reader.read_array()?);
        reader.read_bytes(33)?;
        let address = if raw_address[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
            IpAddr::V4(
                [
                    raw_address[12],
                    raw_address[13],
                    raw_address[14],
                    raw_address[15],
                ]
                .into(),
            )
        } else {
            IpAddr::V6(raw_address.into())
        };

        Ok(Self {
            time,
            services,
            address,
            port,
        })
    }
}

impl AddrPacket {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), P2pError> {
        if self.items.len() > MAX_ADDR {
            return Err(P2pError::CountLimit);
        }

        write_varint(out, self.items.len() as u64);
        for address in &self.items {
            address.encode(out);
        }
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let count = read_varint(reader)? as usize;
        if count > MAX_ADDR {
            return Err(P2pError::CountLimit);
        }

        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(NetAddress::decode(reader)?);
        }
        Ok(Self { items })
    }

    pub fn service_sockets(&self, required_services: u64) -> Vec<SocketAddr> {
        let mut sockets = Vec::new();
        let mut seen = HashSet::new();
        for item in &self.items {
            if item.services & required_services != required_services
                || item.port == 0
                || item.address.is_unspecified()
            {
                continue;
            }
            let socket = SocketAddr::new(item.address, item.port);
            if seen.insert(socket) {
                sockets.push(socket);
            }
        }
        sockets
    }
}

impl LocatorPacket {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), P2pError> {
        if self.locator.len() > MAX_INV {
            return Err(P2pError::CountLimit);
        }

        write_varint(out, self.locator.len() as u64);
        for hash in &self.locator {
            out.extend(hash.as_bytes());
        }
        out.extend(self.stop.as_bytes());
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let count = read_varint(reader)? as usize;
        if count > MAX_INV {
            return Err(P2pError::CountLimit);
        }

        let mut locator = Vec::with_capacity(count);
        for _ in 0..count {
            locator.push(Hash::new(reader.read_array()?));
        }
        let stop = Hash::new(reader.read_array()?);
        Ok(Self { locator, stop })
    }
}

impl HeadersPacket {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), P2pError> {
        if self.items.len() > MAX_HEADERS {
            return Err(P2pError::CountLimit);
        }

        write_varint(out, self.items.len() as u64);
        for header in &self.items {
            out.extend(header.serialize());
        }
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let count = read_varint(reader)? as usize;
        if count > MAX_HEADERS {
            return Err(P2pError::CountLimit);
        }

        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(BlockHeader::parse(
                reader.read_bytes(hns_core::HEADER_SIZE)?,
            )?);
        }
        Ok(Self { items })
    }
}

fn read_varint(reader: &mut Reader<'_>) -> Result<u64, P2pError> {
    let first = reader.read_u8()?;
    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => {
            let value = reader.read_u16_be()?.swap_bytes() as u64;
            if value < 0xfd {
                return Err(P2pError::NonCanonicalVarint);
            }
            Ok(value)
        }
        0xfe => {
            let value = reader.read_u32_le()? as u64;
            if value <= 0xffff {
                return Err(P2pError::NonCanonicalVarint);
            }
            Ok(value)
        }
        0xff => {
            let value = reader.read_u64_le()?;
            if value <= 0xffff_ffff {
                return Err(P2pError::NonCanonicalVarint);
            }
            Ok(value)
        }
    }
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0x00..=0xfc => out.push(value as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend((value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend((value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend(value.to_le_bytes());
        }
    }
}

fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend(value.to_le_bytes());
}

fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend(value.to_le_bytes());
}

fn write_u64_service(out: &mut Vec<u8>, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    write_u32_le(out, low);
    write_u32_le(out, high);
}

fn read_u64_service(reader: &mut Reader<'_>) -> Result<u64, ParseError> {
    let low = reader.read_u32_le()? as u64;
    let high = reader.read_u32_le()? as u64;
    Ok(low | (high << 32))
}

fn io_error(error: std::io::Error) -> P2pError {
    P2pError::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_core::network;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn getheaders_round_trip() {
        let packet = Packet::GetHeaders(LocatorPacket {
            locator: vec![BlockHeader::mainnet_genesis().hash()],
            stop: Hash::ZERO,
        });
        let payload = packet.encode_payload().unwrap();
        let decoded = Packet::decode_payload(PacketType::GetHeaders as u8, &payload).unwrap();

        assert_eq!(decoded, packet);
    }

    #[test]
    fn headers_round_trip() {
        let packet = Packet::Headers(HeadersPacket {
            items: vec![BlockHeader::mainnet_genesis()],
        });
        let payload = packet.encode_payload().unwrap();
        let decoded = Packet::decode_payload(PacketType::Headers as u8, &payload).unwrap();

        assert_eq!(decoded, packet);
    }

    #[test]
    fn addr_round_trip_filters_service_sockets() {
        let good: SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let missing_service: SocketAddr = "127.0.0.3:12038".parse().unwrap();
        let missing_port: SocketAddr = "127.0.0.4:0".parse().unwrap();
        let unspecified: SocketAddr = "0.0.0.0:12038".parse().unwrap();
        let packet = Packet::Addr(AddrPacket {
            items: vec![
                NetAddress::from_socket(good, SERVICE_NETWORK),
                NetAddress::from_socket(good, SERVICE_NETWORK),
                NetAddress::from_socket(missing_service, 0),
                NetAddress::from_socket(missing_port, SERVICE_NETWORK),
                NetAddress::from_socket(unspecified, SERVICE_NETWORK),
            ],
        });
        let payload = packet.encode_payload().unwrap();
        let decoded = Packet::decode_payload(PacketType::Addr as u8, &payload).unwrap();

        assert_eq!(decoded, packet);
        match decoded {
            Packet::Addr(addresses) => {
                assert_eq!(addresses.service_sockets(SERVICE_NETWORK), vec![good]);
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn rejects_noncanonical_varint() {
        assert_eq!(
            Packet::decode_payload(PacketType::GetHeaders as u8, &[0xfd, 1, 0]).unwrap_err(),
            P2pError::NonCanonicalVarint,
        );
    }

    #[test]
    fn version_round_trip() {
        let packet = Packet::Version(VersionPacket::default());
        let payload = packet.encode_payload().unwrap();
        let decoded = Packet::decode_payload(PacketType::Version as u8, &payload).unwrap();

        assert_eq!(decoded, packet);
    }

    #[test]
    fn version_packet_uses_hsd_netaddress_wire_size() {
        let packet = VersionPacket::default();
        let payload = Packet::Version(packet.clone()).encode_payload().unwrap();

        assert_eq!(payload.len(), 20 + 88 + 8 + 1 + packet.agent.len() + 4 + 1,);
    }

    #[test]
    fn frame_round_trip() {
        let network = network::mainnet();
        let packet = Packet::Ping([7u8; 8]);

        let frame = encode_frame(&network, &packet).unwrap();
        let decoded = decode_frame(&network, &frame).unwrap().unwrap();

        assert_eq!(decoded.0, packet);
        assert_eq!(decoded.1, FRAME_HEADER_SIZE + 8);
    }

    #[test]
    fn frame_decoder_handles_split_frames() {
        let network = network::mainnet();
        let packet = Packet::Pong([9u8; 8]);
        let frame = encode_frame(&network, &packet).unwrap();
        let split = FRAME_HEADER_SIZE + 3;
        let mut decoder = FrameDecoder::new(network);

        assert!(decoder.feed(&frame[..split]).unwrap().is_empty());
        assert_eq!(decoder.buffered_len(), split);
        assert_eq!(decoder.feed(&frame[split..]).unwrap(), vec![packet]);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn frame_decoder_rejects_wrong_magic() {
        let network = network::mainnet();
        let mut frame = encode_frame(&network, &Packet::Verack).unwrap();
        frame[0] ^= 0xff;

        assert_eq!(
            decode_frame(&network, &frame).unwrap_err(),
            P2pError::InvalidMagic,
        );
    }

    #[test]
    fn peer_connection_handshakes_and_requests_data_over_socket() {
        let network = network::mainnet();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let genesis = BlockHeader::mainnet_genesis();
        let server_genesis = genesis.clone();
        let root = Hash::new([1; 32]);
        let key = Hash::new([2; 32]);
        let proof_payload = vec![0xaa, 0xbb, 0xcc];
        let server_proof_payload = proof_payload.clone();
        let server_network = network.clone();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut peer = PeerConnection::new(stream, server_network);

            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_),));
            peer.send_packet(&Packet::Version(VersionPacket::default()))
                .unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();

            assert_eq!(peer.receive_packet().unwrap(), Packet::GetAddr);
            peer.send_packet(&Packet::Addr(AddrPacket {
                items: vec![NetAddress::from_socket(address, SERVICE_NETWORK)],
            }))
            .unwrap();

            match peer.receive_packet().unwrap() {
                Packet::GetHeaders(request) => {
                    assert_eq!(request.locator, vec![server_genesis.hash()]);
                    assert_eq!(request.stop, Hash::ZERO);
                }
                other => panic!("unexpected packet: {other:?}"),
            }
            peer.send_packet(&Packet::Headers(HeadersPacket {
                items: vec![server_genesis],
            }))
            .unwrap();

            match peer.receive_packet().unwrap() {
                Packet::GetProof(request) => {
                    assert_eq!(request.root, root);
                    assert_eq!(request.key, key);
                }
                other => panic!("unexpected packet: {other:?}"),
            }
            peer.send_packet(&Packet::Proof(ProofPacket {
                root,
                key,
                proof: server_proof_payload,
            }))
            .unwrap();
        });

        let mut peer = PeerConnection::connect(address, network, Duration::from_secs(2)).unwrap();
        let mut session = HeaderSyncSession::new(VersionPacket::default());

        let remote = peer.handshake(&mut session).unwrap();
        assert_eq!(remote.services & SERVICE_NETWORK, SERVICE_NETWORK);
        assert_eq!(peer.request_addresses().unwrap(), vec![address]);
        assert_eq!(
            peer.request_headers(&mut session, vec![genesis.hash()], Hash::ZERO)
                .unwrap(),
            vec![genesis],
        );
        assert_eq!(
            peer.request_proof(&mut session, root, key).unwrap(),
            ProofPacket {
                root,
                key,
                proof: proof_payload,
            },
        );

        server.join().unwrap();
    }

    #[test]
    fn peer_manager_selects_best_non_banned_peers() {
        let mut manager = PeerManager::default();
        let good: SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let stale: SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let bad: SocketAddr = "127.0.0.3:12038".parse().unwrap();

        manager.record_success(good, Height(10), 100);
        manager.record_success(stale, Height(9), 100);
        manager.record_stale_tip(stale);
        manager.record_malformed(bad, 100, 60);

        assert_eq!(manager.select_outbound(2, 120), vec![good, stale]);
        assert!(manager.get(bad).unwrap().is_banned(120));
    }

    #[test]
    fn peer_manager_prefers_distinct_address_groups() {
        let mut manager = PeerManager::default();
        let best_same_group: SocketAddr = "10.1.0.1:12038".parse().unwrap();
        let next_same_group: SocketAddr = "10.1.0.2:12038".parse().unwrap();
        let diverse: SocketAddr = "10.2.0.1:12038".parse().unwrap();

        manager.record_success(best_same_group, Height(100), 100);
        manager.record_success(next_same_group, Height(99), 100);
        manager.record_success(diverse, Height(98), 100);
        manager.record_stale_tip(diverse);

        assert_eq!(
            manager.select_outbound(2, 100),
            vec![best_same_group, diverse],
        );
        assert_eq!(manager.address_group_count(100), 2);
    }

    #[test]
    fn transient_failures_do_not_exhaust_peer_pool() {
        let mut manager = PeerManager::default();
        let flaky: SocketAddr = "127.0.0.1:12038".parse().unwrap();

        for _ in 0..25 {
            manager.record_transient_failure(flaky);
        }

        let peer = manager.get(flaky).unwrap();
        assert!(peer.score >= BAN_SCORE);
        assert_eq!(peer.banned_until, None);
        assert_eq!(manager.select_outbound(1, 1_000), vec![flaky]);
        assert_eq!(manager.address_group_count(1_000), 1);
    }

    #[test]
    fn peer_manager_seeds_static_peers_without_resetting_state() {
        let mut manager = PeerManager::default();
        let known: SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let discovered: SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let source = StaticPeerSource::new([known, discovered, discovered]);

        manager.record_success(known, Height(42), 100);

        assert_eq!(source.peers(), &[known, discovered]);
        assert_eq!(manager.seed_from(&source).unwrap(), 1);
        assert_eq!(manager.len(), 2);
        assert_eq!(manager.get(known).unwrap().last_height, Height(42));
        assert_eq!(manager.select_outbound(2, 100), vec![known, discovered],);
    }

    #[test]
    fn dns_seed_source_uses_mainnet_hsd_seeds_and_port() {
        let network = network::mainnet();
        let source = DnsSeedPeerSource::from_network(&network);

        assert_eq!(
            source.seeds(),
            &[
                "hs-mainnet.bcoin.ninja".to_owned(),
                "seed.htools.work".to_owned(),
            ],
        );
        assert_eq!(source.port(), 12_038);
        assert_eq!(source.limit(), DEFAULT_DNS_SEED_LIMIT);
    }

    #[test]
    fn dns_seed_address_collection_dedupes_and_caps_results() {
        let first: SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let second: SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let third: SocketAddr = "127.0.0.3:12038".parse().unwrap();
        let mut peers = vec![first];

        push_unique_addresses(&mut peers, [first, second, second, third], 2);

        assert_eq!(peers, vec![first, second]);
    }

    #[test]
    fn dns_seed_source_dedupes_seed_names() {
        let source = DnsSeedPeerSource::new(["seed.example", "", "seed.example"], 12038);

        assert_eq!(source.seeds(), &["seed.example".to_owned()]);
    }

    #[test]
    fn sqlite_peer_store_persists_manager_across_reopen() {
        let path = temp_db_path("peers");
        let good: SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let bad: SocketAddr = "127.0.0.2:12038".parse().unwrap();

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let mut manager = PeerManager::default();
            manager.record_success(good, Height(100), 1_000);
            manager.record_malformed(bad, 1_000, 600);

            assert_eq!(store.save_manager(&manager).unwrap(), 2);
            assert_eq!(store.len().unwrap(), 2);
            store.flush().unwrap();
        }

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let manager = store.load_manager().unwrap();
            let persisted_good = manager.get(good).unwrap();
            let persisted_bad = store.load_peer(bad).unwrap().unwrap();

            assert_eq!(persisted_good.last_height, Height(100));
            assert_eq!(persisted_good.last_connected_at, Some(1_000));
            assert_eq!(persisted_bad.banned_until, Some(1_600));
            assert!(persisted_bad.is_banned(1_200));
            assert_eq!(manager.select_outbound(8, 1_200), vec![good]);
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sqlite_peer_store_clears_legacy_permanent_ban_on_load() {
        let path = temp_db_path("legacy-permanent-ban");
        let address: SocketAddr = "127.0.0.1:12038".parse().unwrap();

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let mut peer = PeerState::new(address);
            peer.score = BAN_SCORE;
            peer.banned_until = Some(u64::MAX);
            store.save_peer(&peer).unwrap();
            store.flush().unwrap();
        }

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let peer = store.load_peer(address).unwrap().unwrap();

            assert_eq!(peer.score, BAN_SCORE);
            assert_eq!(peer.banned_until, None);
            assert!(!peer.is_banned(1_000));
            store.flush().unwrap();
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sync_session_performs_version_handshake() {
        let mut session = HeaderSyncSession::new(VersionPacket::default());

        assert!(matches!(
            session.start(),
            HeaderSyncAction::Send(Packet::Version(_)),
        ));
        assert_eq!(
            session.on_packet(Packet::Version(VersionPacket::default())),
            vec![HeaderSyncAction::Send(Packet::Verack)],
        );
        assert_eq!(session.state(), HeaderSyncState::AwaitingVerack);
        assert_eq!(
            session.on_packet(Packet::Verack),
            vec![HeaderSyncAction::Ready],
        );
        assert_eq!(session.state(), HeaderSyncState::Ready);
    }

    #[test]
    fn sync_session_ignores_advisory_packets_during_handshake() {
        let mut session = HeaderSyncSession::new(VersionPacket::default());

        assert!(
            session
                .on_packet(Packet::Unknown {
                    packet_type: 99,
                    payload: vec![1, 2, 3],
                })
                .is_empty()
        );
        assert_eq!(session.state(), HeaderSyncState::AwaitingVersion);
        assert_eq!(
            session.on_packet(Packet::Version(VersionPacket::default())),
            vec![HeaderSyncAction::Send(Packet::Verack)],
        );
        assert!(session.on_packet(Packet::SendHeaders).is_empty());
        assert_eq!(session.state(), HeaderSyncState::AwaitingVerack);
        assert_eq!(
            session.on_packet(Packet::Verack),
            vec![HeaderSyncAction::Ready],
        );
        assert_eq!(session.state(), HeaderSyncState::Ready);
    }

    #[test]
    fn sync_session_accepts_verack_before_version() {
        let mut session = HeaderSyncSession::new(VersionPacket::default());

        assert!(session.on_packet(Packet::Verack).is_empty());
        assert_eq!(session.state(), HeaderSyncState::AwaitingVersion);
        assert_eq!(
            session.on_packet(Packet::Version(VersionPacket::default())),
            vec![
                HeaderSyncAction::Send(Packet::Verack),
                HeaderSyncAction::Ready
            ],
        );
        assert_eq!(session.state(), HeaderSyncState::Ready);
    }

    #[test]
    fn sync_session_requests_and_receives_headers() {
        let mut session = ready_session();
        let genesis = BlockHeader::mainnet_genesis();
        let locator = vec![genesis.hash()];

        assert_eq!(
            session
                .request_headers(locator.clone(), Hash::ZERO)
                .unwrap(),
            HeaderSyncAction::Send(Packet::GetHeaders(LocatorPacket {
                locator,
                stop: Hash::ZERO,
            })),
        );
        assert_eq!(session.state(), HeaderSyncState::HeadersRequested);
        assert_eq!(
            session.on_packet(Packet::Headers(HeadersPacket {
                items: vec![genesis.clone()],
            })),
            vec![HeaderSyncAction::Headers(vec![genesis])],
        );
        assert_eq!(session.state(), HeaderSyncState::Ready);
    }

    #[test]
    fn sync_session_ignores_advisory_packets_while_waiting_for_headers() {
        let mut session = ready_session();
        let genesis = BlockHeader::mainnet_genesis();

        session
            .request_headers(vec![genesis.hash()], Hash::ZERO)
            .unwrap();

        assert!(session.on_packet(Packet::SendHeaders).is_empty());
        assert!(
            session
                .on_packet(Packet::Unknown {
                    packet_type: 100,
                    payload: Vec::new(),
                })
                .is_empty()
        );
        assert_eq!(session.state(), HeaderSyncState::HeadersRequested);
        assert_eq!(
            session.on_packet(Packet::Headers(HeadersPacket {
                items: vec![genesis.clone()],
            })),
            vec![HeaderSyncAction::Headers(vec![genesis])],
        );
    }

    #[test]
    fn sync_session_rejects_peer_without_network_service() {
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        let version = VersionPacket {
            services: 0,
            ..VersionPacket::default()
        };

        assert_eq!(
            session.on_packet(Packet::Version(version)),
            vec![HeaderSyncAction::Disconnect(
                "peer lacks required network service",
            )],
        );
        assert_eq!(session.state(), HeaderSyncState::Closed);
    }

    fn ready_session() -> HeaderSyncSession {
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        session.on_packet(Packet::Version(VersionPacket::default()));
        session.on_packet(Packet::Verack);
        session
    }

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hns-p2p-{label}-{}-{now}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup_db_path(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
