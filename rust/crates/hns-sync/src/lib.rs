use hns_chain::{ChainError, HeaderChain, HeaderStore, StoredHeader};
use hns_core::Height;
use hns_core::network::Network;
use hns_core::{BlockHeader, Hash, NameHash};
use hns_p2p::{
    HeaderSyncAction, HeaderSyncSession, MAX_HEADERS, P2pError, Packet, PeerConnection,
    PeerManager, ProofPacket, SqlitePeerStore, VersionPacket,
};
use hns_resolver::{
    MemoryResourceValueProvider, ResolverError, SqliteResourceValueProvider, VerifiedResourceValue,
};
use hns_urkel::{ParsedProof, ProofError, ProofKind, ProofVerifier};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

pub const DEFAULT_LOCATOR_LIMIT: usize = 32;
pub const DEFAULT_OUTBOUND_PEERS: usize = 8;
pub const DEFAULT_MAX_HEADER_BATCHES_PER_PEER: usize = 16;
pub const DEFAULT_SYNC_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_MALFORMED_BAN_SECONDS: u64 = 24 * 60 * 60;
const MAX_HSD_NAME_STATE_NAME_BYTES: usize = 63;
const MAX_HSD_NAME_STATE_DATA_BYTES: usize = 512;
const HSD_NAME_STATE_FIXED_TAIL_BYTES: usize = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderBatchResult {
    pub accepted: usize,
    pub best: Option<StoredHeader>,
}

pub struct HeaderSyncCoordinator<S> {
    chain: HeaderChain<S>,
    locator_limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderSyncRunnerConfig {
    pub preferred_peers: usize,
    pub max_header_batches_per_peer: usize,
    pub discover_peers: bool,
    pub timeout: Duration,
    pub stop: Hash,
    pub malformed_ban_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderPeerSyncResult {
    pub address: SocketAddr,
    pub remote_height: Height,
    pub accepted: usize,
    pub best: Option<StoredHeader>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderPeerFailure {
    pub address: SocketAddr,
    pub stage: HeaderPeerFailureStage,
    pub error: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderPeerFailureStage {
    Connect,
    Handshake,
    Headers,
    Chain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderSyncRunResult {
    pub attempted: usize,
    pub successful: usize,
    pub accepted: usize,
    pub best: Option<StoredHeader>,
    pub failures: Vec<HeaderPeerFailure>,
}

pub trait HeaderPeerClient {
    fn handshake(&mut self, session: &mut HeaderSyncSession) -> Result<VersionPacket, P2pError>;

    fn request_headers(
        &mut self,
        session: &mut HeaderSyncSession,
        locator: Vec<Hash>,
        stop: Hash,
    ) -> Result<Vec<BlockHeader>, P2pError>;

    fn request_addresses(&mut self) -> Result<Vec<SocketAddr>, P2pError> {
        Ok(Vec::new())
    }
}

pub trait HeaderPeerConnector {
    type Peer: HeaderPeerClient;

    fn connect(
        &self,
        address: SocketAddr,
        network: &Network,
        timeout: Duration,
    ) -> Result<Self::Peer, P2pError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpHeaderPeerConnector;

pub struct HeaderSyncRunner<C> {
    connector: C,
    network: Network,
    local_version: VersionPacket,
    config: HeaderSyncRunnerConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofValidationResult {
    pub root: Hash,
    pub key: Hash,
    pub kind: ProofKind,
    pub value: Option<Vec<u8>>,
}

pub struct ProofSyncCoordinator<V> {
    verifier: V,
    pending: HashSet<(Hash, Hash)>,
}

pub struct ProofScheduler<V, S> {
    coordinator: ProofSyncCoordinator<V>,
    sink: S,
}

pub trait VerifiedResourceValueSink {
    fn insert_verified_resource_value(
        &self,
        value: VerifiedResourceValue,
    ) -> Result<(), ResolverError>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SyncError {
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("p2p error: {0}")]
    P2p(#[from] P2pError),
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("resolver error: {0}")]
    Resolver(#[from] ResolverError),
    #[error("unexpected sync action")]
    UnexpectedAction,
    #[error("proof response was not requested")]
    UnexpectedProof,
    #[error("proof payload does not match requested root or key")]
    ProofMismatch,
    #[error("proof verification failed")]
    UnverifiedProof,
    #[error("verified inclusion proof did not contain a resource value")]
    MissingProofValue,
    #[error("HSD name state value is malformed")]
    MalformedNameStateValue,
}

impl Default for HeaderSyncRunnerConfig {
    fn default() -> Self {
        Self {
            preferred_peers: DEFAULT_OUTBOUND_PEERS,
            max_header_batches_per_peer: DEFAULT_MAX_HEADER_BATCHES_PER_PEER,
            discover_peers: true,
            timeout: DEFAULT_SYNC_TIMEOUT,
            stop: Hash::ZERO,
            malformed_ban_seconds: DEFAULT_MALFORMED_BAN_SECONDS,
        }
    }
}

impl HeaderSyncRunResult {
    pub fn empty() -> Self {
        Self {
            attempted: 0,
            successful: 0,
            accepted: 0,
            best: None,
            failures: Vec::new(),
        }
    }
}

impl HeaderPeerFailureStage {
    pub fn as_str(self) -> &'static str {
        match self {
            HeaderPeerFailureStage::Connect => "connect",
            HeaderPeerFailureStage::Handshake => "handshake",
            HeaderPeerFailureStage::Headers => "headers",
            HeaderPeerFailureStage::Chain => "chain",
        }
    }
}

impl<T: Read + Write> HeaderPeerClient for PeerConnection<T> {
    fn handshake(&mut self, session: &mut HeaderSyncSession) -> Result<VersionPacket, P2pError> {
        PeerConnection::handshake(self, session)
    }

    fn request_headers(
        &mut self,
        session: &mut HeaderSyncSession,
        locator: Vec<Hash>,
        stop: Hash,
    ) -> Result<Vec<BlockHeader>, P2pError> {
        PeerConnection::request_headers(self, session, locator, stop)
    }

    fn request_addresses(&mut self) -> Result<Vec<SocketAddr>, P2pError> {
        PeerConnection::request_addresses(self)
    }
}

impl HeaderPeerConnector for TcpHeaderPeerConnector {
    type Peer = PeerConnection<std::net::TcpStream>;

    fn connect(
        &self,
        address: SocketAddr,
        network: &Network,
        timeout: Duration,
    ) -> Result<Self::Peer, P2pError> {
        PeerConnection::connect(address, network.clone(), timeout)
    }
}

impl<C> HeaderSyncRunner<C> {
    pub fn new(network: Network, connector: C) -> Self {
        Self {
            connector,
            network,
            local_version: VersionPacket::default(),
            config: HeaderSyncRunnerConfig::default(),
        }
    }

    pub fn with_config(network: Network, connector: C, config: HeaderSyncRunnerConfig) -> Self {
        Self {
            connector,
            network,
            local_version: VersionPacket::default(),
            config,
        }
    }

    pub fn with_local_version(mut self, local_version: VersionPacket) -> Self {
        self.local_version = local_version;
        self
    }

    pub fn config(&self) -> &HeaderSyncRunnerConfig {
        &self.config
    }

    pub fn connector(&self) -> &C {
        &self.connector
    }
}

impl<C: HeaderPeerConnector> HeaderSyncRunner<C> {
    pub fn sync_once<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        now: u64,
    ) -> Result<HeaderSyncRunResult, SyncError> {
        let outbound = peers.select_outbound(self.config.preferred_peers, now);
        let mut result = HeaderSyncRunResult::empty();

        for address in outbound {
            result.attempted = result.attempted.saturating_add(1);
            match self.sync_peer(coordinator, peers, address, now)? {
                HeaderPeerSyncOutcome::Success(peer_result) => {
                    result.successful = result.successful.saturating_add(1);
                    result.accepted = result.accepted.saturating_add(peer_result.accepted);
                    result.best = peer_result.best;
                }
                HeaderPeerSyncOutcome::Failure(failure) => result.failures.push(failure),
            }
        }

        Ok(result)
    }

    pub fn sync_once_and_persist<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
    ) -> Result<HeaderSyncRunResult, SyncError> {
        let result = self.sync_once(coordinator, peers, now)?;
        store.save_manager(peers)?;
        Ok(result)
    }

    fn sync_peer<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        address: SocketAddr,
        now: u64,
    ) -> Result<HeaderPeerSyncOutcome, SyncError> {
        let mut peer = match self
            .connector
            .connect(address, &self.network, self.config.timeout)
        {
            Ok(peer) => peer,
            Err(error) => {
                peers.record_transient_failure(address);
                return Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                    address,
                    stage: HeaderPeerFailureStage::Connect,
                    error: error.to_string(),
                }));
            }
        };
        let mut session = HeaderSyncSession::new(self.local_version.clone());
        let remote = match peer.handshake(&mut session) {
            Ok(remote) => remote,
            Err(error) => {
                peers.record_transient_failure(address);
                return Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                    address,
                    stage: HeaderPeerFailureStage::Handshake,
                    error: error.to_string(),
                }));
            }
        };
        if self.config.discover_peers
            && let Ok(discovered) = peer.request_addresses()
        {
            peers.seed(discovered);
        }
        let mut accepted = 0usize;
        let mut best = coordinator.chain().best_header()?;
        if best
            .as_ref()
            .is_some_and(|best_header| remote.height <= best_header.height)
        {
            peers.record_success(address, remote.height, now);
            return Ok(HeaderPeerSyncOutcome::Success(Box::new(
                HeaderPeerSyncResult {
                    address,
                    remote_height: remote.height,
                    accepted,
                    best,
                },
            )));
        }
        let max_batches = self.config.max_header_batches_per_peer.max(1);

        for _ in 0..max_batches {
            let locator = coordinator.locator()?;
            let headers = match peer.request_headers(&mut session, locator, self.config.stop) {
                Ok(headers) => headers,
                Err(error) => {
                    peers.record_transient_failure(address);
                    return Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                        address,
                        stage: HeaderPeerFailureStage::Headers,
                        error: error.to_string(),
                    }));
                }
            };
            let header_count = headers.len();
            if header_count == 0 {
                break;
            }

            match coordinator.ingest_headers(headers) {
                Ok(batch) => {
                    accepted = accepted.saturating_add(batch.accepted);
                    best = batch.best;
                    if header_count < MAX_HEADERS || batch.accepted == 0 {
                        break;
                    }
                }
                Err(SyncError::Chain(error)) => {
                    record_chain_failure(
                        peers,
                        address,
                        now,
                        &error,
                        self.config.malformed_ban_seconds,
                    );
                    return match error {
                        ChainError::Storage(_) | ChainError::MissingBestHeader => {
                            Err(SyncError::Chain(error))
                        }
                        ChainError::UnknownParent
                        | ChainError::DuplicateHeader
                        | ChainError::InvalidGenesisHeader
                        | ChainError::InvalidDifficultyBits { .. }
                        | ChainError::InvalidDifficultyWindow
                        | ChainError::InvalidProofOfWork
                        | ChainError::Pow(_) => {
                            Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                                address,
                                stage: HeaderPeerFailureStage::Chain,
                                error: error.to_string(),
                            }))
                        }
                    };
                }
                Err(error) => return Err(error),
            }
        }

        peers.record_success(address, remote.height, now);
        Ok(HeaderPeerSyncOutcome::Success(Box::new(
            HeaderPeerSyncResult {
                address,
                remote_height: remote.height,
                accepted,
                best,
            },
        )))
    }
}

enum HeaderPeerSyncOutcome {
    Success(Box<HeaderPeerSyncResult>),
    Failure(HeaderPeerFailure),
}

impl<S: HeaderStore> HeaderSyncCoordinator<S> {
    pub fn new(chain: HeaderChain<S>) -> Self {
        Self {
            chain,
            locator_limit: DEFAULT_LOCATOR_LIMIT,
        }
    }

    pub fn with_locator_limit(chain: HeaderChain<S>, locator_limit: usize) -> Self {
        Self {
            chain,
            locator_limit,
        }
    }

    pub fn chain(&self) -> &HeaderChain<S> {
        &self.chain
    }

    pub fn chain_mut(&mut self) -> &mut HeaderChain<S> {
        &mut self.chain
    }

    pub fn into_chain(self) -> HeaderChain<S> {
        self.chain
    }

    pub fn ingest_action(
        &mut self,
        action: HeaderSyncAction,
    ) -> Result<HeaderBatchResult, SyncError> {
        match action {
            HeaderSyncAction::Headers(headers) => self.ingest_headers(headers),
            _ => Err(SyncError::UnexpectedAction),
        }
    }

    pub fn ingest_headers(
        &mut self,
        headers: Vec<BlockHeader>,
    ) -> Result<HeaderBatchResult, SyncError> {
        let mut accepted = 0;
        for header in headers {
            if self.chain.get_header(header.hash()).is_some() {
                continue;
            }
            match self.chain.insert_header(header) {
                Ok(_) => accepted += 1,
                Err(ChainError::DuplicateHeader) => continue,
                Err(error) => return Err(error.into()),
            }
        }

        Ok(HeaderBatchResult {
            accepted,
            best: self.chain.best_header()?,
        })
    }

    pub fn locator(&self) -> Result<Vec<Hash>, SyncError> {
        self.locator_with_limit(self.locator_limit)
    }

    pub fn locator_with_limit(&self, limit: usize) -> Result<Vec<Hash>, SyncError> {
        let Some(mut current) = self.chain.best_header()? else {
            return Ok(Vec::new());
        };
        let mut locator = Vec::new();
        let mut step = 1usize;

        while locator.len() < limit {
            locator.push(current.hash);
            if current.height.0 == 0 {
                break;
            }

            for _ in 0..step {
                if current.height.0 == 0 {
                    break;
                }

                current = self
                    .chain
                    .get_header(current.header.prev_block)
                    .ok_or(ChainError::UnknownParent)?;
            }

            if locator.len() >= 10 {
                step = step.saturating_mul(2);
            }
        }

        Ok(locator)
    }

    pub fn request_next_headers(
        &self,
        session: &mut HeaderSyncSession,
        stop: Hash,
    ) -> Result<HeaderSyncAction, SyncError> {
        Ok(session.request_headers(self.locator()?, stop)?)
    }
}

impl<V: ProofVerifier> ProofSyncCoordinator<V> {
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            pending: HashSet::new(),
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn track_request(&mut self, root: Hash, key: Hash) {
        self.pending.insert((root, key));
    }

    pub fn forget_request(&mut self, root: Hash, key: Hash) -> bool {
        self.pending.remove(&(root, key))
    }

    pub fn request_proof(
        &mut self,
        session: &mut HeaderSyncSession,
        root: Hash,
        key: Hash,
    ) -> HeaderSyncAction {
        let action = session.request_proof(root, key);
        if matches!(action, HeaderSyncAction::Send(Packet::GetProof(_))) {
            self.track_request(root, key);
        }
        action
    }

    pub fn ingest_action(
        &mut self,
        action: HeaderSyncAction,
    ) -> Result<ProofValidationResult, SyncError> {
        match action {
            HeaderSyncAction::Proof(proof) => self.ingest_proof(proof),
            _ => Err(SyncError::UnexpectedAction),
        }
    }

    pub fn ingest_proof(
        &mut self,
        packet: ProofPacket,
    ) -> Result<ProofValidationResult, SyncError> {
        if !self.pending.remove(&(packet.root, packet.key)) {
            return Err(SyncError::UnexpectedProof);
        }

        let proof =
            ParsedProof::parse_for_key(&packet.proof, packet.root, NameHash::new(packet.key))?;
        if proof.root != packet.root || proof.name_hash.as_hash() != packet.key {
            return Err(SyncError::ProofMismatch);
        }

        if !self.verifier.verify(&proof, packet.root)? {
            return Err(SyncError::UnverifiedProof);
        }

        Ok(ProofValidationResult {
            root: packet.root,
            key: packet.key,
            kind: proof.kind,
            value: proof.value().map(<[u8]>::to_vec),
        })
    }
}

impl VerifiedResourceValueSink for MemoryResourceValueProvider {
    fn insert_verified_resource_value(
        &self,
        value: VerifiedResourceValue,
    ) -> Result<(), ResolverError> {
        self.insert(value)
    }
}

impl VerifiedResourceValueSink for &MemoryResourceValueProvider {
    fn insert_verified_resource_value(
        &self,
        value: VerifiedResourceValue,
    ) -> Result<(), ResolverError> {
        (*self).insert(value)
    }
}

impl VerifiedResourceValueSink for SqliteResourceValueProvider {
    fn insert_verified_resource_value(
        &self,
        value: VerifiedResourceValue,
    ) -> Result<(), ResolverError> {
        self.insert(value)
    }
}

impl VerifiedResourceValueSink for &SqliteResourceValueProvider {
    fn insert_verified_resource_value(
        &self,
        value: VerifiedResourceValue,
    ) -> Result<(), ResolverError> {
        (*self).insert(value)
    }
}

impl<V: ProofVerifier, S: VerifiedResourceValueSink> ProofScheduler<V, S> {
    pub fn new(verifier: V, sink: S) -> Self {
        Self {
            coordinator: ProofSyncCoordinator::new(verifier),
            sink,
        }
    }

    pub fn with_coordinator(coordinator: ProofSyncCoordinator<V>, sink: S) -> Self {
        Self { coordinator, sink }
    }

    pub fn pending_len(&self) -> usize {
        self.coordinator.pending_len()
    }

    pub fn coordinator(&self) -> &ProofSyncCoordinator<V> {
        &self.coordinator
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn into_parts(self) -> (ProofSyncCoordinator<V>, S) {
        (self.coordinator, self.sink)
    }

    pub fn request_and_store<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
    ) -> Result<ProofValidationResult, SyncError> {
        let name_hash = NameHash::from_name(root_name).map_err(ResolverError::from)?;
        self.request_hash_and_store_with_height(peer, session, root_name, root, name_hash, None)
    }

    pub fn request_and_store_at_height<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        proof_height: Height,
    ) -> Result<ProofValidationResult, SyncError> {
        let name_hash = NameHash::from_name(root_name).map_err(ResolverError::from)?;
        self.request_hash_and_store_with_height(
            peer,
            session,
            root_name,
            root,
            name_hash,
            Some(proof_height),
        )
    }

    pub fn request_hash_and_store<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        name_hash: NameHash,
    ) -> Result<ProofValidationResult, SyncError> {
        self.request_hash_and_store_with_height(peer, session, root_name, root, name_hash, None)
    }

    pub fn request_hash_and_store_at_height<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        name_hash: NameHash,
        proof_height: Height,
    ) -> Result<ProofValidationResult, SyncError> {
        self.request_hash_and_store_with_height(
            peer,
            session,
            root_name,
            root,
            name_hash,
            Some(proof_height),
        )
    }

    fn request_hash_and_store_with_height<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        name_hash: NameHash,
        proof_height: Option<Height>,
    ) -> Result<ProofValidationResult, SyncError> {
        let key = name_hash.as_hash();
        match self.coordinator.request_proof(session, root, key) {
            HeaderSyncAction::Send(packet) => {
                if let Err(error) = peer.send_packet(&packet) {
                    self.coordinator.forget_request(root, key);
                    return Err(error.into());
                }
            }
            HeaderSyncAction::Disconnect(reason) => {
                return Err(SyncError::P2p(P2pError::SessionDisconnected(reason)));
            }
            HeaderSyncAction::Ready | HeaderSyncAction::Headers(_) | HeaderSyncAction::Proof(_) => {
                return Err(SyncError::UnexpectedAction);
            }
        }

        loop {
            let packet = match peer.receive_packet() {
                Ok(packet) => packet,
                Err(error) => {
                    self.coordinator.forget_request(root, key);
                    return Err(error.into());
                }
            };

            for action in session.on_packet(packet) {
                match action {
                    HeaderSyncAction::Proof(proof) => {
                        let result = self.coordinator.ingest_proof(proof)?;
                        let mut verified =
                            verified_resource_value(root_name.to_owned(), name_hash, &result)?;
                        if let Some(proof_height) = proof_height {
                            verified = verified.with_anchor(result.root, proof_height);
                        }
                        self.sink.insert_verified_resource_value(verified)?;
                        return Ok(result);
                    }
                    HeaderSyncAction::Send(packet) => {
                        if let Err(error) = peer.send_packet(&packet) {
                            self.coordinator.forget_request(root, key);
                            return Err(error.into());
                        }
                    }
                    HeaderSyncAction::Disconnect(reason) => {
                        self.coordinator.forget_request(root, key);
                        return Err(SyncError::P2p(P2pError::SessionDisconnected(reason)));
                    }
                    HeaderSyncAction::Ready | HeaderSyncAction::Headers(_) => {
                        self.coordinator.forget_request(root, key);
                        return Err(SyncError::UnexpectedAction);
                    }
                }
            }
        }
    }
}

fn record_chain_failure(
    peers: &mut PeerManager,
    address: SocketAddr,
    now: u64,
    error: &ChainError,
    malformed_ban_seconds: u64,
) {
    match error {
        ChainError::InvalidGenesisHeader
        | ChainError::InvalidDifficultyBits { .. }
        | ChainError::InvalidDifficultyWindow
        | ChainError::InvalidProofOfWork
        | ChainError::Pow(_) => peers.record_malformed(address, now, malformed_ban_seconds),
        ChainError::UnknownParent | ChainError::DuplicateHeader => peers.record_stale_tip(address),
        ChainError::MissingBestHeader | ChainError::Storage(_) => {
            peers.record_transient_failure(address)
        }
    }
}

fn verified_resource_value(
    root_name: String,
    name_hash: NameHash,
    result: &ProofValidationResult,
) -> Result<VerifiedResourceValue, SyncError> {
    match result.kind {
        ProofKind::Inclusion => {
            let value = result.value.clone().ok_or(SyncError::MissingProofValue)?;
            let resource_value = extract_name_state_resource_value(&root_name, &value)?;
            Ok(VerifiedResourceValue::inclusion(
                root_name,
                name_hash,
                resource_value,
            ))
        }
        ProofKind::NonInclusion => Ok(VerifiedResourceValue::non_inclusion(root_name, name_hash)),
    }
}

fn extract_name_state_resource_value(root_name: &str, value: &[u8]) -> Result<Vec<u8>, SyncError> {
    let name_len = usize::from(*value.first().ok_or(SyncError::MalformedNameStateValue)?);
    if name_len > MAX_HSD_NAME_STATE_NAME_BYTES {
        return Err(SyncError::MalformedNameStateValue);
    }

    let name_start = 1usize;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(SyncError::MalformedNameStateValue)?;
    let data_len_start = name_end;
    let data_len_end = data_len_start
        .checked_add(2)
        .ok_or(SyncError::MalformedNameStateValue)?;
    if value.len() < data_len_end {
        return Err(SyncError::MalformedNameStateValue);
    }
    if &value[name_start..name_end] != root_name.as_bytes() {
        return Err(SyncError::ProofMismatch);
    }

    let data_len = usize::from(u16::from_le_bytes([
        value[data_len_start],
        value[data_len_start + 1],
    ]));
    if data_len > MAX_HSD_NAME_STATE_DATA_BYTES {
        return Err(SyncError::MalformedNameStateValue);
    }

    let data_start = data_len_end;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(SyncError::MalformedNameStateValue)?;
    let min_end = data_end
        .checked_add(HSD_NAME_STATE_FIXED_TAIL_BYTES)
        .ok_or(SyncError::MalformedNameStateValue)?;
    if value.len() < min_end {
        return Err(SyncError::MalformedNameStateValue);
    }

    Ok(value[data_start..data_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_chain::DifficultyPolicy;
    use hns_chain::MemoryHeaderStore;
    use hns_core::network;
    use hns_core::pow::verify_pow;
    use hns_p2p::{PeerConnection, VersionPacket};
    use hns_resolver::HnsResourceValueProvider;
    use hns_urkel::{FailClosedProofVerifier, ProofKind};
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn empty_batch_keeps_best_tip() {
        let mut coordinator = seeded_coordinator();
        let best = coordinator.chain().best_header().unwrap();

        assert_eq!(
            coordinator.ingest_headers(Vec::new()).unwrap(),
            HeaderBatchResult { accepted: 0, best },
        );
    }

    #[test]
    fn duplicate_headers_are_successful_noops() {
        let mut coordinator = seeded_coordinator();
        let genesis = BlockHeader::mainnet_genesis();
        let best = coordinator.chain().best_header().unwrap();

        assert_eq!(
            coordinator.ingest_headers(vec![genesis]).unwrap(),
            HeaderBatchResult { accepted: 0, best },
        );
    }

    #[test]
    fn duplicate_headers_inside_batch_do_not_abort_progress() {
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let child = low_difficulty_child(&genesis);

        let result = coordinator
            .ingest_headers(vec![child.clone(), child])
            .unwrap();

        assert_eq!(result.accepted, 1);
        assert_eq!(result.best.unwrap().height, Height(1));
    }

    #[test]
    fn unexpected_action_is_rejected() {
        let mut coordinator = seeded_coordinator();

        assert_eq!(
            coordinator
                .ingest_action(HeaderSyncAction::Ready)
                .unwrap_err(),
            SyncError::UnexpectedAction,
        );
    }

    #[test]
    fn unknown_parent_batch_is_rejected() {
        let mut coordinator = seeded_coordinator();
        let mut orphan = BlockHeader::mainnet_genesis();
        orphan.nonce = 1;

        assert_eq!(
            coordinator
                .ingest_action(HeaderSyncAction::Headers(vec![orphan]))
                .unwrap_err(),
            SyncError::Chain(ChainError::UnknownParent),
        );
    }

    #[test]
    fn invalid_pow_batch_is_rejected() {
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = genesis.hash;
        child.bits = 0x01010000;

        assert_eq!(
            coordinator.ingest_headers(vec![child]).unwrap_err(),
            SyncError::Chain(ChainError::InvalidProofOfWork),
        );
    }

    #[test]
    fn locator_starts_from_best_tip() {
        let coordinator = seeded_coordinator();
        let best = coordinator.chain().best_header().unwrap().unwrap();

        assert_eq!(coordinator.locator().unwrap(), vec![best.hash]);
    }

    #[test]
    fn header_sync_runner_requests_headers_and_persists_peer_state() {
        let path = temp_db_path("sync-peers");
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let child = low_difficulty_child(&genesis);
        let address: std::net::SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(1), vec![child]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let result = runner
                .sync_once_and_persist(&mut coordinator, &mut peers, &store, 500)
                .unwrap();

            assert_eq!(result.attempted, 1);
            assert_eq!(result.successful, 1);
            assert_eq!(result.accepted, 1);
            assert!(result.failures.is_empty());
            assert_eq!(result.best.unwrap().height, Height(1));
            store.flush().unwrap();
        }

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let persisted = store.load_peer(address).unwrap().unwrap();

            assert_eq!(persisted.last_height, Height(1));
            assert_eq!(persisted.last_connected_at, Some(500));
            assert_eq!(persisted.successes, 1);
            assert_eq!(persisted.failures, 0);
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_requests_multiple_header_batches_per_peer() {
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let headers = low_difficulty_chain(&genesis, MAX_HEADERS + 1);
        let address: std::net::SocketAddr = "127.0.0.1:12040".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::header_batches(
                Height((MAX_HEADERS + 1) as u32),
                [
                    headers[..MAX_HEADERS].to_vec(),
                    headers[MAX_HEADERS..].to_vec(),
                ],
            ),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                max_header_batches_per_peer: 2,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(result.accepted, MAX_HEADERS + 1);
        assert!(result.failures.is_empty());
        assert_eq!(
            result.best.unwrap().height,
            Height((MAX_HEADERS + 1) as u32)
        );
    }

    #[test]
    fn header_sync_runner_stops_duplicate_only_full_batch() {
        let mut coordinator = seeded_coordinator();
        let genesis = BlockHeader::mainnet_genesis();
        let best = coordinator.chain().best_header().unwrap();
        let address: std::net::SocketAddr = "127.0.0.1:12041".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(0), vec![genesis; MAX_HEADERS]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                max_header_batches_per_peer: 2,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(result.accepted, 0);
        assert!(result.failures.is_empty());
        assert_eq!(result.best, best);
    }

    #[test]
    fn header_sync_runner_skips_headers_when_peer_is_not_ahead() {
        let mut coordinator = seeded_coordinator();
        let best = coordinator.chain().best_header().unwrap();
        let address: std::net::SocketAddr = "127.0.0.1:12042".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::header_errors(Height(0), [P2pError::UnexpectedAction]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(result.accepted, 0);
        assert!(result.failures.is_empty());
        assert_eq!(result.best, best);
        assert_eq!(peers.get(address).unwrap().successes, 1);
    }

    #[test]
    fn header_sync_runner_discovers_addresses_from_successful_peer() {
        let mut coordinator = seeded_coordinator();
        let address: std::net::SocketAddr = "127.0.0.1:12043".parse().unwrap();
        let discovered: std::net::SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(0), Vec::new()).with_addresses(vec![discovered]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.successful, 1);
        assert!(peers.get(discovered).is_some());
    }

    #[test]
    fn header_sync_runner_reports_peer_failure_stage() {
        let mut coordinator = seeded_coordinator();
        let address: std::net::SocketAddr = "127.0.0.1:12039".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            ScriptedHeaderConnector::new(std::iter::empty::<(
                std::net::SocketAddr,
                ScriptedHeaderPeer,
            )>()),
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 0);
        assert_eq!(result.accepted, 0);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].address, address);
        assert_eq!(result.failures[0].stage, HeaderPeerFailureStage::Connect);
        assert!(result.failures[0].error.contains("connection"));
        assert_eq!(peers.get(address).unwrap().failures, 1);
    }

    #[test]
    fn header_sync_runner_bans_invalid_pow_peer_and_continues() {
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let invalid = invalid_pow_child(&genesis);
        let address: std::net::SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(1), vec![invalid]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                malformed_ban_seconds: 60,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 0);
        assert_eq!(result.accepted, 0);
        assert_eq!(peers.get(address).unwrap().banned_until, Some(1_060));
        assert!(peers.get(address).unwrap().is_banned(1_001));
    }

    #[test]
    fn proof_coordinator_rejects_unrequested_proof() {
        let mut coordinator = ProofSyncCoordinator::new(AcceptingProofVerifier);

        assert_eq!(
            coordinator.ingest_proof(proof_packet(1, 2)).unwrap_err(),
            SyncError::UnexpectedProof,
        );
    }

    #[test]
    fn proof_coordinator_rejects_malformed_payload() {
        let mut coordinator = ProofSyncCoordinator::new(AcceptingProofVerifier);
        let root = hash(1);
        let key = hash(2);
        coordinator.track_request(root, key);

        assert_eq!(
            coordinator
                .ingest_proof(ProofPacket {
                    root,
                    key,
                    proof: vec![0],
                })
                .unwrap_err(),
            SyncError::Proof(ProofError::Malformed),
        );
    }

    #[test]
    fn proof_coordinator_fails_closed_without_verifier() {
        let mut coordinator = ProofSyncCoordinator::new(FailClosedProofVerifier);
        let packet = proof_packet(1, 2);
        coordinator.track_request(packet.root, packet.key);

        assert_eq!(
            coordinator.ingest_proof(packet).unwrap_err(),
            SyncError::Proof(ProofError::UnsupportedVerifier),
        );
    }

    #[test]
    fn proof_coordinator_accepts_verified_proof() {
        let mut coordinator = ProofSyncCoordinator::new(AcceptingProofVerifier);
        let packet = proof_packet(1, 2);
        coordinator.track_request(packet.root, packet.key);

        assert_eq!(
            coordinator.ingest_proof(packet.clone()).unwrap(),
            ProofValidationResult {
                root: packet.root,
                key: packet.key,
                kind: ProofKind::Inclusion,
                value: Some(proof_bytes(packet.root, packet.key)[6..].to_vec()),
            },
        );
        assert_eq!(coordinator.pending_len(), 0);
    }

    #[test]
    fn proof_scheduler_requests_verifies_and_stores_value() {
        let network = network::mainnet();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let root_name = "welcome";
        let root = hash(9);
        let name_hash = NameHash::from_name(root_name).unwrap();
        let key = name_hash.as_hash();
        let expected_value = vec![0, 4, 127, 0, 0, 1];
        let name_state_value = name_state_value(root_name, &expected_value);
        let proof_payload = proof_bytes_with_value(&name_state_value);
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
                proof: proof_payload,
            }))
            .unwrap();
        });

        let store = MemoryResourceValueProvider::new();
        let mut scheduler = ProofScheduler::new(AcceptingProofVerifier, &store);
        let mut peer = PeerConnection::connect(address, network, Duration::from_secs(2)).unwrap();
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        peer.handshake(&mut session).unwrap();

        let result = scheduler
            .request_and_store_at_height(&mut peer, &mut session, root_name, root, Height(7))
            .unwrap();

        assert_eq!(result.root, root);
        assert_eq!(result.key, key);
        assert_eq!(result.kind, ProofKind::Inclusion);
        assert_eq!(result.value, Some(name_state_value));
        assert_eq!(scheduler.pending_len(), 0);
        let stored = store.prove_resource_value(root_name, name_hash).unwrap();
        assert_eq!(stored.value, Some(expected_value));
        assert_eq!(stored.anchor.unwrap().tree_root, root);
        assert_eq!(stored.anchor.unwrap().height, Height(7));

        server.join().unwrap();
    }

    #[test]
    fn proof_scheduler_fails_closed_for_invalid_name() {
        let store = MemoryResourceValueProvider::new();
        let mut scheduler = ProofScheduler::new(AcceptingProofVerifier, &store);
        let network = network::mainnet();
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        let mut peer = PeerConnection::new(VecTransport::default(), network);

        assert!(matches!(
            scheduler.request_and_store(&mut peer, &mut session, "bad.name", hash(1)),
            Err(SyncError::Resolver(_)),
        ));
        assert_eq!(scheduler.pending_len(), 0);
    }

    fn seeded_coordinator() -> HeaderSyncCoordinator<MemoryHeaderStore> {
        let mut chain = HeaderChain::with_difficulty_policy(
            MemoryHeaderStore::default(),
            DifficultyPolicy::Permissive,
        );
        chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        HeaderSyncCoordinator::new(chain)
    }

    fn low_difficulty_child(parent: &StoredHeader) -> BlockHeader {
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = parent.hash;
        child.bits = 0x207f_ffff;
        for nonce in 0..10_000 {
            child.nonce = nonce;
            if verify_pow(child.hash(), child.bits).unwrap() {
                return child;
            }
        }
        panic!("could not find low-difficulty header nonce");
    }

    fn low_difficulty_chain(parent: &StoredHeader, count: usize) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(count);
        let mut parent_hash = parent.hash;

        for _ in 0..count {
            let mut child = BlockHeader::mainnet_genesis();
            child.prev_block = parent_hash;
            child.bits = 0x207f_ffff;
            for nonce in 0..10_000 {
                child.nonce = nonce;
                if verify_pow(child.hash(), child.bits).unwrap() {
                    parent_hash = child.hash();
                    headers.push(child);
                    break;
                }
            }
        }

        assert_eq!(headers.len(), count);
        headers
    }

    fn invalid_pow_child(parent: &StoredHeader) -> BlockHeader {
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = parent.hash;
        child.bits = 0x0101_0000;
        child
    }

    fn proof_packet(root: u8, key: u8) -> ProofPacket {
        let root = hash(root);
        let key = hash(key);
        ProofPacket {
            root,
            key,
            proof: proof_bytes(root, key),
        }
    }

    fn proof_bytes(root: Hash, key: Hash) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&root.as_bytes()[..2]);
        value.extend_from_slice(&key.as_bytes()[..2]);
        proof_bytes_with_value(&value)
    }

    fn proof_bytes_with_value(value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_u16_le(&mut bytes, 3 << 14);
        write_u16_le(&mut bytes, 0);
        write_u16_le(&mut bytes, value.len() as u16);
        bytes.extend_from_slice(value);
        bytes
    }

    fn name_state_value(name: &str, data: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.push(name.len() as u8);
        value.extend(name.as_bytes());
        write_u16_le(&mut value, data.len() as u16);
        value.extend(data);
        value.extend(7_u32.to_le_bytes());
        value.extend(7_u32.to_le_bytes());
        value.extend(0_u16.to_le_bytes());
        value
    }

    fn write_u16_le(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_le_bytes());
    }

    fn hash(value: u8) -> Hash {
        Hash::new([value; 32])
    }

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hns-sync-{label}-{}-{now}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup_db_path(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    struct ScriptedHeaderConnector {
        peers: RefCell<HashMap<std::net::SocketAddr, ScriptedHeaderPeer>>,
    }

    impl ScriptedHeaderConnector {
        fn new<I>(peers: I) -> Self
        where
            I: IntoIterator<Item = (std::net::SocketAddr, ScriptedHeaderPeer)>,
        {
            Self {
                peers: RefCell::new(peers.into_iter().collect()),
            }
        }
    }

    impl HeaderPeerConnector for ScriptedHeaderConnector {
        type Peer = ScriptedHeaderPeer;

        fn connect(
            &self,
            address: std::net::SocketAddr,
            _network: &Network,
            _timeout: Duration,
        ) -> Result<Self::Peer, P2pError> {
            self.peers
                .borrow_mut()
                .remove(&address)
                .ok_or(P2pError::ConnectionClosed)
        }
    }

    struct ScriptedHeaderPeer {
        remote_height: Height,
        headers: VecDeque<Result<Vec<BlockHeader>, P2pError>>,
        addresses: Vec<SocketAddr>,
    }

    impl ScriptedHeaderPeer {
        fn headers(remote_height: Height, headers: Vec<BlockHeader>) -> Self {
            Self::header_batches(remote_height, [headers])
        }

        fn header_batches<I>(remote_height: Height, batches: I) -> Self
        where
            I: IntoIterator<Item = Vec<BlockHeader>>,
        {
            Self {
                remote_height,
                headers: batches.into_iter().map(Ok).collect(),
                addresses: Vec::new(),
            }
        }

        fn header_errors<I>(remote_height: Height, errors: I) -> Self
        where
            I: IntoIterator<Item = P2pError>,
        {
            Self {
                remote_height,
                headers: errors.into_iter().map(Err).collect(),
                addresses: Vec::new(),
            }
        }

        fn with_addresses(mut self, addresses: Vec<SocketAddr>) -> Self {
            self.addresses = addresses;
            self
        }
    }

    impl HeaderPeerClient for ScriptedHeaderPeer {
        fn handshake(
            &mut self,
            _session: &mut HeaderSyncSession,
        ) -> Result<VersionPacket, P2pError> {
            Ok(VersionPacket {
                height: self.remote_height,
                ..VersionPacket::default()
            })
        }

        fn request_headers(
            &mut self,
            _session: &mut HeaderSyncSession,
            _locator: Vec<Hash>,
            _stop: Hash,
        ) -> Result<Vec<BlockHeader>, P2pError> {
            self.headers.pop_front().unwrap_or_else(|| Ok(Vec::new()))
        }

        fn request_addresses(&mut self) -> Result<Vec<SocketAddr>, P2pError> {
            Ok(self.addresses.clone())
        }
    }

    struct AcceptingProofVerifier;

    impl ProofVerifier for AcceptingProofVerifier {
        fn verify(&self, proof: &ParsedProof, expected_root: Hash) -> Result<bool, ProofError> {
            Ok(proof.kind == ProofKind::Inclusion && proof.root == expected_root)
        }
    }

    #[derive(Default)]
    struct VecTransport {
        read: std::io::Cursor<Vec<u8>>,
        write: Vec<u8>,
    }

    impl std::io::Read for VecTransport {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(out)
        }
    }

    impl std::io::Write for VecTransport {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.write.extend(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
