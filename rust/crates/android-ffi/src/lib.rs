use hns_chain::{HeaderChain, SqliteHeaderStore};
use hns_core::dns::{
    DnsEncodeConfig, DnsFlags, DnsHeader, DnsMessage, DnsName, DnsQuestion, RecordType,
    ResourceRecord,
};
use hns_core::network;
use hns_core::{BlockHeader, Height, NameHash};
use hns_dane::{DaneDecision, TlsaMatching, TlsaRecord, TlsaSelector, TlsaUsage};
use hns_gateway::{Gateway, GatewayConfig, GatewayError, GatewayRequest, HnsHttpsMode};
use hns_p2p::{
    DnsSeedPeerSource, HeaderSyncSession, PeerConnection, SqlitePeerStore, VersionPacket,
};
use hns_resolver::{
    AuthoritativeDnssecResolver, DelegatingResolver, DnsTransport, HnsProofProvider,
    HnsResourceValueProvider, ProvenNameRecords, ResolutionAnswer, ResolutionRequest, Resolver,
    ResolverError, ResourceValueAnchor, SqliteResourceValueProvider, SystemDnssecVerifier,
    UdpTcpDnsTransport,
};
use hns_sync::{
    HeaderSyncCoordinator, HeaderSyncRunner, HeaderSyncRunnerConfig, ProofScheduler, SyncError,
    TcpHeaderPeerConnector,
};
use hns_transport::{
    OriginProtocol, OriginRequest, OriginResponse, OriginResponseHead, OriginTransport, ReadWrite,
    TcpHttpTransport, TlsCertificateInspection, TlsValidation, TransportError,
};
use hns_urkel::UrkelProofVerifier;
use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jstring};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_RESOURCE_CACHE_LIMIT_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_GATEWAY_HEADER_TEXT_BYTES: usize = 64 * 1024;
pub const LOCAL_TLS_CERT_FINGERPRINT_BYTES: usize = 32;
const DNS_CLASS_IN: u16 = 1;
const DNS_OPT_RECORD_TYPE: u16 = 41;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const DNSSEC_DO_FLAG: u32 = 0x8000;
const DEFAULT_DNS_UDP_PAYLOAD: usize = 1232;
const DEFAULT_GATEWAY_PROOF_PEERS: usize = 8;
const DEFAULT_GATEWAY_PROOF_TIMEOUT: Duration = Duration::from_secs(3);
const ANDROID_COMPAT_AUTHORITATIVE_DNS_TIMEOUT: Duration = Duration::from_millis(900);
const RESOURCE_PROOF_CACHE_CANONICAL_WINDOW: u32 = 144;
const ANDROID_HEADER_SYNC_PEERS: usize = 12;
const ANDROID_HEADER_SYNC_BATCHES_PER_PEER: usize = 16;
const ANDROID_PARALLEL_PEER_PROBES: usize = 32;
const ANDROID_PARALLEL_HEADER_FETCH_PEERS: usize = 4;
const ANDROID_MIN_PEER_TARGET: usize = 64;
const ANDROID_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS: u64 = 10 * 60;
const MAINNET_GENESIS_TIME: u64 = 1_580_745_078;
const MAINNET_TARGET_SPACING_SECONDS: u64 = 10 * 60;
const HNS_DOH_HOST: &str = "hnsdoh.com";
const HNS_DOH_PATH: &str = "/dns-query";
const HNS_GATEWAY_STRICT_MODE_HEADER: &str = "X-HNS-Browser-Strict-Mode";
const HNS_RESOLUTION_TRACE_HEADER: &str = "X-HNS-Resolution-Trace";
const HNS_RESOLVER_MODE_HEADER: &str = "X-HNS-Resolver-Mode";
const HNS_DOH_FALLBACK_HEADER: &str = "X-HNS-DoH-Fallback";
const TUNNEL_COPY_BUFFER_BYTES: usize = 16 * 1024;
static DOH_QUERY_ID: AtomicU16 = AtomicU16::new(0x484e);

pub struct GatewayHttpRequestInput<'a> {
    pub data_dir: &'a str,
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path_and_query: &'a str,
    pub header_text: &'a str,
    pub body: &'a [u8],
}

struct ParsedGatewayHeaders {
    headers: Vec<(String, String)>,
    strict_hns_mode: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayResolutionMode {
    Strict,
    Compatibility,
}

impl GatewayResolutionMode {
    fn from_strict_hns_mode(strict_hns_mode: bool) -> Self {
        if strict_hns_mode {
            Self::Strict
        } else {
            Self::Compatibility
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Compatibility => "compatibility",
        }
    }
}

struct JniGatewayHttpRequest<'local> {
    data_dir: JString<'local>,
    method: JString<'local>,
    scheme: JString<'local>,
    host: JString<'local>,
    port: jint,
    path_and_query: JString<'local>,
    header_text: JString<'local>,
    body: JByteArray<'local>,
}

struct JavaInputStream {
    vm: Arc<JavaVM>,
    stream: GlobalRef,
}

struct JavaOutputStream {
    vm: Arc<JavaVM>,
    stream: GlobalRef,
}

impl JavaInputStream {
    fn new(vm: Arc<JavaVM>, stream: GlobalRef) -> Self {
        Self { vm, stream }
    }
}

impl JavaOutputStream {
    fn new(vm: Arc<JavaVM>, stream: GlobalRef) -> Self {
        Self { vm, stream }
    }
}

impl Read for JavaInputStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let length = buf.len().min(TUNNEL_COPY_BUFFER_BYTES);
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array = env
            .new_byte_array(length as i32)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array_object = JObject::from(array);
        let read = env
            .call_method(
                self.stream.as_obj(),
                "read",
                "([B)I",
                &[JValue::Object(&array_object)],
            )
            .and_then(|value| value.i())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if read < 0 {
            return Ok(0);
        }
        let array = JByteArray::from(array_object);
        let bytes = env
            .convert_byte_array(&array)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let read = read as usize;
        buf[..read].copy_from_slice(&bytes[..read]);
        Ok(read)
    }
}

impl Write for JavaOutputStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let length = buf.len().min(TUNNEL_COPY_BUFFER_BYTES);
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array = env
            .byte_array_from_slice(&buf[..length])
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let array_object = JObject::from(array);
        env.call_method(
            self.stream.as_obj(),
            "write",
            "([BII)V",
            &[
                JValue::Object(&array_object),
                JValue::Int(0),
                JValue::Int(length as i32),
            ],
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(length)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        env.call_method(self.stream.as_obj(), "flush", "()V", &[])
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
    }
}

struct GatewayProofProvider {
    base: PathBuf,
    values: SqliteResourceValueProvider,
    preferred_peers: usize,
    timeout: Duration,
    seed_on_empty: bool,
}

impl GatewayProofProvider {
    fn new(base: PathBuf, values: SqliteResourceValueProvider) -> Self {
        Self {
            base,
            values,
            preferred_peers: DEFAULT_GATEWAY_PROOF_PEERS,
            timeout: DEFAULT_GATEWAY_PROOF_TIMEOUT,
            seed_on_empty: true,
        }
    }

    fn cached_records(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        let verified = self.values.prove_resource_value(root_name, name_hash)?;
        if verified.root_name != root_name || verified.name_hash != name_hash || !verified.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if !self.anchor_is_recent_canonical(verified.anchor)? {
            return Err(ResolverError::ProofUnavailable);
        }
        ProvenNameRecords::from_verified_resource_value(verified)
    }

    fn anchor_is_recent_canonical(
        &self,
        anchor: Option<ResourceValueAnchor>,
    ) -> Result<bool, ResolverError> {
        let Some(anchor) = anchor else {
            return Ok(false);
        };
        let header_store = SqliteHeaderStore::open(self.base.join("headers.sqlite"))
            .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
        let chain = HeaderChain::new(header_store);
        let best = chain
            .best_header()
            .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?;
        let Some(best) = best else {
            return Ok(false);
        };
        if anchor.height.0 == 0 || anchor.height.0 > best.height.0 {
            return Ok(false);
        }
        if best.height.0.saturating_sub(anchor.height.0) > RESOURCE_PROOF_CACHE_CANONICAL_WINDOW {
            return Ok(false);
        }
        Ok(chain
            .canonical_header(anchor.height)
            .is_some_and(|header| header.header.tree_root == anchor.tree_root))
    }

    fn fetch_and_store_live_proof(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<(), ResolverError> {
        let best = best_synced_header(&self.base)?;
        let network = network::mainnet();
        let peer_store = SqlitePeerStore::open(self.base.join("peers.sqlite"))
            .map_err(|error| ResolverError::Storage(format!("open peer store: {error}")))?;
        let mut peers = peer_store
            .load_manager()
            .map_err(|error| ResolverError::Storage(format!("load peer store: {error}")))?;
        if self.seed_on_empty && peers.is_empty() {
            let source = DnsSeedPeerSource::from_network(&network);
            let _ = peers.seed_from(&source);
        }

        let now = now_unix_seconds();
        let selected = select_live_proof_peers(&peers, self.preferred_peers, now, best.height);
        if selected.is_empty() {
            peer_store
                .save_manager(&peers)
                .map_err(|error| ResolverError::Storage(format!("save peer store: {error}")))?;
            return Err(ResolverError::ProofUnavailable);
        }

        for address in selected {
            match self.fetch_from_peer(
                address,
                root_name,
                name_hash,
                best.header.tree_root,
                best.height,
            ) {
                Ok(remote_height) => {
                    peers.record_success(address, remote_height, now);
                    peer_store.save_manager(&peers).map_err(|error| {
                        ResolverError::Storage(format!("save peer store: {error}"))
                    })?;
                    return Ok(());
                }
                Err(_) => {
                    peers.record_transient_failure(address);
                }
            }
        }

        peer_store
            .save_manager(&peers)
            .map_err(|error| ResolverError::Storage(format!("save peer store: {error}")))?;
        Err(ResolverError::ProofUnavailable)
    }

    fn fetch_from_peer(
        &self,
        address: SocketAddr,
        root_name: &str,
        name_hash: NameHash,
        proof_root: hns_core::Hash,
        proof_height: Height,
    ) -> Result<Height, SyncError> {
        let network = network::mainnet();
        let mut peer = PeerConnection::connect(address, network, self.timeout)?;
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        let remote = peer.handshake(&mut session)?;
        if remote.height < proof_height {
            return Err(SyncError::UnexpectedAction);
        }
        let mut scheduler = ProofScheduler::new(UrkelProofVerifier, &self.values);
        scheduler.request_hash_and_store_at_height(
            &mut peer,
            &mut session,
            root_name,
            proof_root,
            name_hash,
            proof_height,
        )?;
        Ok(remote.height)
    }
}

impl HnsProofProvider for GatewayProofProvider {
    fn prove_name(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        match self.cached_records(root_name, name_hash) {
            Ok(records) => Ok(records),
            Err(ResolverError::ProofUnavailable) => {
                self.fetch_and_store_live_proof(root_name, name_hash)?;
                self.cached_records(root_name, name_hash)
            }
            Err(error) => Err(error),
        }
    }
}

type AndroidPrimaryResolver = DelegatingResolver<
    GatewayProofProvider,
    AuthoritativeDnssecResolver<TracingDnsTransport<UdpTcpDnsTransport>, SystemDnssecVerifier>,
>;

enum AndroidGatewayResolver {
    Strict(AndroidPrimaryResolver),
    Compatibility(FallbackResolver<AndroidPrimaryResolver, HnsDohResolver>),
}

#[derive(Clone, Debug, Default)]
struct DnsTraceRecorder {
    events: Arc<Mutex<Vec<DnsTraceEvent>>>,
}

impl DnsTraceRecorder {
    fn push(&self, event: DnsTraceEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    fn snapshot(&self) -> Vec<DnsTraceEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsTraceEvent {
    protocol: &'static str,
    server: String,
    status: String,
    elapsed_ms: u64,
    error: Option<String>,
}

struct TracingDnsTransport<T> {
    inner: T,
    trace: DnsTraceRecorder,
}

impl<T> TracingDnsTransport<T> {
    fn new(inner: T, trace: DnsTraceRecorder) -> Self {
        Self { inner, trace }
    }
}

impl<T: DnsTransport> DnsTransport for TracingDnsTransport<T> {
    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let result = self.inner.exchange_udp(server, query);
        self.trace.push(dns_trace_event(
            "udp53",
            server.to_string(),
            elapsed_millis(started),
            &result,
        ));
        result
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let started = Instant::now();
        let result = self.inner.exchange_tcp(server, query);
        self.trace.push(dns_trace_event(
            "tcp53",
            server.to_string(),
            elapsed_millis(started),
            &result,
        ));
        result
    }
}

fn dns_trace_event(
    protocol: &'static str,
    server: String,
    elapsed_ms: u64,
    result: &Result<Vec<u8>, ResolverError>,
) -> DnsTraceEvent {
    match result {
        Ok(_) => DnsTraceEvent {
            protocol,
            server,
            status: "ok".to_owned(),
            elapsed_ms,
            error: None,
        },
        Err(error) => DnsTraceEvent {
            protocol,
            server,
            status: dns_trace_error_status(error).to_owned(),
            elapsed_ms,
            error: Some(error.to_string()),
        },
    }
}

fn doh_trace_event(
    server: String,
    elapsed_ms: u64,
    result: &Result<OriginResponse, TransportError>,
) -> DnsTraceEvent {
    match result {
        Ok(response) if response.status == 200 => DnsTraceEvent {
            protocol: "hns_doh",
            server,
            status: "ok".to_owned(),
            elapsed_ms,
            error: None,
        },
        Ok(response) => DnsTraceEvent {
            protocol: "hns_doh",
            server,
            status: "http_error".to_owned(),
            elapsed_ms,
            error: Some(format!("HTTP {}", response.status)),
        },
        Err(error) => DnsTraceEvent {
            protocol: "hns_doh",
            server,
            status: "transport_error".to_owned(),
            elapsed_ms,
            error: Some(error.to_string()),
        },
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn dns_trace_error_status(error: &ResolverError) -> &'static str {
    match error {
        ResolverError::DnsTransport(message)
            if message.contains("timed out")
                || message.contains("timeout")
                || message.contains("deadline") =>
        {
            "timeout"
        }
        ResolverError::DnsTransport(_) => "transport_error",
        ResolverError::InvalidDnsResponse => "invalid_response",
        ResolverError::DnssecFailed => "dnssec_failed",
        _ => "error",
    }
}

impl Resolver for AndroidGatewayResolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        match self {
            Self::Strict(resolver) => resolver.resolve(request),
            Self::Compatibility(resolver) => resolver.resolve(request),
        }
    }
}

#[derive(Clone, Default)]
struct FallbackMarker {
    used: Arc<AtomicBool>,
    reason: Arc<Mutex<Option<&'static str>>>,
}

impl FallbackMarker {
    fn mark(&self, reason: &'static str) {
        self.used.store(true, Ordering::Relaxed);
        if let Ok(mut fallback_reason) = self.reason.lock()
            && fallback_reason.is_none()
        {
            *fallback_reason = Some(reason);
        }
    }

    fn used(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    fn reason(&self) -> Option<&'static str> {
        self.reason.lock().ok().and_then(|reason| *reason)
    }
}

struct FallbackResolver<P, F> {
    primary: P,
    fallback: F,
    fallback_marker: FallbackMarker,
    fallback_roots: Arc<Mutex<HashMap<String, &'static str>>>,
}

impl<P, F> FallbackResolver<P, F> {
    #[cfg(test)]
    fn new(primary: P, fallback: F) -> Self {
        Self::with_marker(primary, fallback, FallbackMarker::default())
    }

    fn with_marker(primary: P, fallback: F, fallback_marker: FallbackMarker) -> Self {
        Self {
            primary,
            fallback,
            fallback_marker,
            fallback_roots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cached_fallback_reason(&self, request: &ResolutionRequest) -> Option<&'static str> {
        let root = fallback_cache_root(request);
        self.fallback_roots
            .lock()
            .ok()
            .and_then(|roots| roots.get(&root).copied())
    }

    fn remember_fallback_reason(&self, request: &ResolutionRequest, reason: &'static str) {
        let root = fallback_cache_root(request);
        if let Ok(mut roots) = self.fallback_roots.lock() {
            roots.entry(root).or_insert(reason);
        }
    }
}

impl<P, F> Resolver for FallbackResolver<P, F>
where
    P: Resolver,
    F: Resolver,
{
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        if let Some(reason) = self.cached_fallback_reason(request) {
            self.fallback_marker.mark(reason);
            return self.fallback.resolve(request);
        }

        match self.primary.resolve(request) {
            Ok(answer) => Ok(answer),
            Err(error) if doh_fallback_reason(&error).is_some() => {
                let reason = doh_fallback_reason(&error).expect("fallback reason checked");
                self.remember_fallback_reason(request, reason);
                self.fallback_marker.mark(reason);
                self.fallback.resolve(request)
            }
            Err(error) => Err(error),
        }
    }
}

fn fallback_cache_root(request: &ResolutionRequest) -> String {
    hns_trace_root(&request.qname).to_ascii_lowercase()
}

#[derive(Clone, Debug)]
struct HnsDohResolver {
    host: String,
    path: String,
    trace: DnsTraceRecorder,
}

impl Default for HnsDohResolver {
    fn default() -> Self {
        Self::new(DnsTraceRecorder::default())
    }
}

impl HnsDohResolver {
    fn new(trace: DnsTraceRecorder) -> Self {
        Self {
            host: HNS_DOH_HOST.to_owned(),
            path: HNS_DOH_PATH.to_owned(),
            trace,
        }
    }
}

impl Resolver for HnsDohResolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        let qname =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let qtype = RecordType::from_code(request.qtype);
        let id = next_doh_query_id();
        let query = build_doh_query(id, &qname, qtype)?;
        let started = Instant::now();
        let response = TcpHttpTransport::default().fetch(&OriginRequest {
            method: "POST".to_owned(),
            scheme: "https".to_owned(),
            host: self.host.clone(),
            connect_host: None,
            port: 443,
            path_and_query: self.path.clone(),
            protocol: OriginProtocol::Http11,
            tls: TlsValidation::default(),
            headers: vec![
                ("Accept".to_owned(), "application/dns-message".to_owned()),
                (
                    "Content-Type".to_owned(),
                    "application/dns-message".to_owned(),
                ),
            ],
            body: query,
        });
        self.trace.push(doh_trace_event(
            format!("{}:443{}", self.host, self.path),
            elapsed_millis(started),
            &response,
        ));
        let response = response.map_err(|error| {
            ResolverError::DnsTransport(format!("HNS DoH compatibility resolver failed: {error}"))
        })?;
        if response.status != 200 {
            return Err(ResolverError::DnsTransport(format!(
                "HNS DoH compatibility resolver returned HTTP {}",
                response.status
            )));
        }

        doh_answer_from_body(id, &qname, qtype, &response.body)
    }
}

fn doh_fallback_reason(error: &ResolverError) -> Option<&'static str> {
    match error {
        ResolverError::ProofUnavailable => Some("local_hns_proof_unavailable"),
        ResolverError::NoNameserverAddress => Some("no_verified_nameserver_address"),
        ResolverError::DnsTransport(_) => Some("authoritative_nameserver_transport_failed"),
        ResolverError::InvalidDnsResponse => Some("authoritative_nameserver_invalid_response"),
        ResolverError::DnssecFailed => Some("delegated_dnssec_validation_failed"),
        _ => None,
    }
}

fn next_doh_query_id() -> u16 {
    DOH_QUERY_ID.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

fn build_doh_query(id: u16, qname: &DnsName, qtype: RecordType) -> Result<Vec<u8>, ResolverError> {
    let message = DnsMessage {
        header: DnsHeader {
            id,
            flags: DnsFlags::new(0x0100),
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 1,
        },
        questions: vec![DnsQuestion {
            name: qname.clone(),
            record_type: qtype,
            class: DNS_CLASS_IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![ResourceRecord {
            name: DnsName::root(),
            record_type: RecordType::Unknown(DNS_OPT_RECORD_TYPE),
            class: DEFAULT_DNS_UDP_PAYLOAD as u16,
            ttl: DNSSEC_DO_FLAG,
            rdata: Vec::new(),
        }],
    };

    message
        .encode(&DnsEncodeConfig {
            max_message_len: DEFAULT_DNS_UDP_PAYLOAD,
        })
        .map_err(|_| ResolverError::InvalidDnsResponse)
}

fn doh_answer_from_body(
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    body: &[u8],
) -> Result<ResolutionAnswer, ResolverError> {
    let message = DnsMessage::parse(body).map_err(|_| ResolverError::InvalidDnsResponse)?;
    let rcode = message.header.flags.rcode();
    if message.header.id != id
        || !message.header.flags.is_response()
        || message.header.flags.opcode() != 0
        || !matches!(rcode, DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN)
        || message.questions.len() != 1
        || message.questions[0].name != *qname
        || message.questions[0].record_type != qtype
        || message.questions[0].class != DNS_CLASS_IN
    {
        return Err(ResolverError::InvalidDnsResponse);
    }

    Ok(ResolutionAnswer {
        name: qname.clone(),
        records: message.answers,
        secure: message.header.flags.bits() & 0x0020 != 0,
    })
}

pub fn core_version() -> &'static str {
    "hns-browser-rust-core/0.2.3"
}

pub fn diagnostics_json() -> String {
    r#"{"core":"hns-browser-rust-core","version":"0.1.5","features":["header-hash","header-pow-validation","header-mainnet-difficulty-retarget","header-canonical-height-index","hns-name-hash","hns-dotted-root-label","urkel-proof-verification","urkel-proof-value-handoff","hns-name-state-resource-extraction","hns-resource-decoder","hns-resource-provider-adapter","hns-memory-resource-provider","hns-sqlite-resource-provider","hns-negative-cache","hns-ttl-cache-lru","hns-resource-cache-stats","hns-resource-cache-eviction","hns-resource-cache-cap-enforcement","hns-resource-cache-chain-anchors","hns-resource-cache-reorg-invalidation","hns-resource-cache-current-tip","hns-proof-backed-resolver-boundary","hns-delegating-resolver-boundary","hns-proof-backed-ns-address-hydration","hns-authoritative-dnssec-delegated-resolver","android-hns-doh-compat-resolver","dns-wire","dns-svcb-https","dnssec-ds-dnskey-link","dnssec-ds-sha1","dnssec-ds-sha384","dnssec-rrsig-signed-data","dnssec-canonical-name-rdata","dnssec-ecdsa-p256-verify","dnssec-ecdsa-p384-verify","dnssec-rsa-sha1-verify","dnssec-rsa-sha256-sha512-verify","dnssec-ed25519-verify","dnssec-signed-rrset-validation","dnssec-delegated-chain-validation","dnssec-delegated-no-data-validation","dnssec-delegated-name-error-validation","dnssec-delegated-cname-chain","dnssec-child-referral-validation","dnssec-child-cname-chain","dnssec-child-no-data-validation","dnssec-child-name-error-validation","dnssec-nsec-denial-validation","dnssec-nsec3-denial-validation","dnssec-nxdomain-name-error-validation","dane-policy","dane-certificate-chain-policy","x509-spki-extraction","p2p-codec","p2p-tcp-peer-connection","p2p-static-peer-source","p2p-dns-seed-source","p2p-getaddr-peer-discovery","p2p-discovery-rotation","p2p-peer-diversity","p2p-sqlite-peer-store","sync-coordinator","sync-header-runner","sync-multi-batch-header-runner","sync-parallel-peer-probing","sync-ranged-peer-rotation","sync-proof-scheduler","android-native-sync-once","android-sync-status","android-sync-outcome-status","android-sync-progress-heights","android-sync-high-batch-catchup","android-clear-resolver-cache","android-persistent-gateway-resolver","android-gateway-live-proof-fetch","android-gateway-header-forwarding","android-gateway-range-forwarding","android-gateway-body-forwarding","android-gateway-file-body-stream","android-webview-hns-intercept","android-service-worker-hns-intercept","android-hns-redirect-follow","android-actionable-hns-errors","hns-name-not-found-error","gateway-policy","gateway-hns-address-required","gateway-tlsa-service-scope","gateway-delegated-origin-address-lookup","gateway-origin-address-query","gateway-https-service-query","gateway-svcb-alpn-policy","gateway-actionable-nameserver-errors","gateway-cname-address-routing","android-proxy-gateway-hook","android-random-loopback-proxy-port","android-local-hns-connect-certs","hns-websocket-native-tunnel","http-origin-transport","http-origin-connection-pooling","http2-origin-transport","http3-origin-transport","http-origin-response-framing","https-rustls-transport","https-tls-session-resumption","https-alt-svc-promotion","dane-tls-policy"],"securityDefault":"fail-closed"}"#
    .replace("\"version\":\"0.1.5\"", "\"version\":\"0.2.3\"")
}

pub fn sync_once(data_dir: &str) -> String {
    sync_once_with_options(
        data_dir,
        true,
        Duration::from_secs(3),
        DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
    )
    .to_json()
}

pub fn sync_status(data_dir: &str) -> String {
    read_sync_status(data_dir)
        .unwrap_or_else(NativeSyncStatus::error)
        .to_json()
}

pub fn clear_resolver_cache(data_dir: &str) -> String {
    clear_resolver_cache_inner(data_dir)
        .unwrap_or_else(NativeSyncStatus::error)
        .to_json()
}

pub fn local_tls_certificate_bundle(host: &str) -> Option<Vec<u8>> {
    let host = normalized_local_tls_host(host)?;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![host]).ok()?;
    let cert_der = cert.der().as_ref();
    let key_der = signing_key.serialize_der();
    let fingerprint = Sha256::digest(cert_der);
    let mut bundle = Vec::with_capacity(
        4 + cert_der.len() + 4 + key_der.len() + LOCAL_TLS_CERT_FINGERPRINT_BYTES,
    );
    bundle.extend(u32::try_from(cert_der.len()).ok()?.to_be_bytes());
    bundle.extend(cert_der);
    bundle.extend(u32::try_from(key_der.len()).ok()?.to_be_bytes());
    bundle.extend(&key_der);
    bundle.extend(fingerprint);
    Some(bundle)
}

fn normalized_local_tls_host(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return None;
    }
    if normalized.contains(':') || normalized.starts_with('[') || normalized.ends_with(']') {
        return None;
    }
    if is_ipv4_literal(&normalized) {
        return None;
    }
    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.iter().any(|label| !valid_local_tls_label(label)) {
        return None;
    }
    Some(normalized)
}

fn is_ipv4_literal(host: &str) -> bool {
    let parts = host.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

fn valid_local_tls_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn sync_once_with_options(
    data_dir: &str,
    seed_on_empty: bool,
    timeout: Duration,
    resource_cache_limit_bytes: usize,
) -> NativeSyncStatus {
    match run_sync_once(data_dir, seed_on_empty, timeout, resource_cache_limit_bytes) {
        Ok(status) => status,
        Err(error) => NativeSyncStatus::error(error),
    }
}

pub fn gateway_http_response(input: GatewayHttpRequestInput<'_>) -> Vec<u8> {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => return plain_response_for_request(&input, 400, "Bad Request", error),
    };
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = Path::new(input.data_dir).join("hns");
    if let Err(error) = fs::create_dir_all(&base) {
        return plain_response_for_request(
            &input,
            500,
            "Gateway Storage Error",
            &format!("create gateway directory: {error}"),
        );
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return plain_response_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("open resource cache: {error}"),
            );
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        mode,
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Compatibility,
            ..GatewayConfig::default()
        },
        resolver,
        TcpHttpTransport::default(),
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return plain_response_for_request(
                &input,
                500,
                "Gateway Configuration Error",
                &error.to_string(),
            );
        }
    };

    match gateway.handle(&request) {
        Ok(response) => {
            let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
            let trace = resolution_trace_json(
                &input,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            origin_response_with_resolver_policy_and_trace(response.origin, resolver_policy, &trace)
        }
        Err(error) => {
            let (status, reason, detail) = map_gateway_error(&error);
            let trace = resolution_trace_json(
                &input,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            plain_response_for_request_with_trace(&input, status, reason, detail, &trace)
        }
    }
}

pub fn gateway_http_response_body_to_file(
    input: GatewayHttpRequestInput<'_>,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                400,
                "Bad Request",
                error,
                body_path,
            );
        }
    };
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = Path::new(input.data_dir).join("hns");
    if let Err(error) = fs::create_dir_all(&base) {
        return plain_response_to_file_for_request(
            &input,
            500,
            "Gateway Storage Error",
            &format!("create gateway directory: {error}"),
            body_path,
        );
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("open resource cache: {error}"),
                body_path,
            );
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        mode,
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Compatibility,
            ..GatewayConfig::default()
        },
        resolver,
        TcpHttpTransport::default(),
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return plain_response_to_file_for_request(
                &input,
                500,
                "Gateway Configuration Error",
                &error.to_string(),
                body_path,
            );
        }
    };

    if let Some(parent) = body_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create response directory: {error}"))?;
    }
    let mut body_file =
        fs::File::create(body_path).map_err(|error| format!("create response body: {error}"))?;
    match gateway.handle_to_writer(&request, &mut body_file) {
        Ok(response) => {
            let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
            let trace = resolution_trace_json(
                &input,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            Ok(origin_response_head_with_resolver_policy_and_trace(
                response.origin,
                resolver_policy,
                &trace,
            ))
        }
        Err(error) => {
            let (status, reason, detail) = map_gateway_error(&error);
            let trace = resolution_trace_json(
                &input,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            plain_response_to_file_for_request_with_trace(
                &input, status, reason, detail, body_path, &trace,
            )
        }
    }
}

pub fn gateway_http_upgrade_tunnel(
    input: GatewayHttpRequestInput<'_>,
    mut client_input: impl Read + Send + 'static,
    mut client_output: impl Write + Send + 'static,
) -> bool {
    let parsed_headers = match parse_gateway_headers(input.header_text) {
        Ok(headers) => headers,
        Err(error) => {
            return write_tunnel_response(
                &mut client_output,
                &plain_response_for_request(&input, 400, "Bad Request", error),
            );
        }
    };
    let mode = GatewayResolutionMode::from_strict_hns_mode(parsed_headers.strict_hns_mode);
    let request = gateway_request(&input, parsed_headers.headers);
    let dns_trace = DnsTraceRecorder::default();

    let base = Path::new(input.data_dir).join("hns");
    if let Err(error) = fs::create_dir_all(&base) {
        return write_tunnel_response(
            &mut client_output,
            &plain_response_for_request(
                &input,
                500,
                "Gateway Storage Error",
                &format!("create gateway directory: {error}"),
            ),
        );
    }
    let values = match SqliteResourceValueProvider::open(base.join("resources.sqlite")) {
        Ok(values) => values,
        Err(error) => {
            return write_tunnel_response(
                &mut client_output,
                &plain_response_for_request(
                    &input,
                    500,
                    "Gateway Storage Error",
                    &format!("open resource cache: {error}"),
                ),
            );
        }
    };
    let fallback_marker = FallbackMarker::default();
    let resolver = android_gateway_resolver(
        base.clone(),
        values,
        mode,
        fallback_marker.clone(),
        dns_trace.clone(),
    );
    let gateway = match Gateway::new(
        GatewayConfig {
            hns_https_mode: HnsHttpsMode::Compatibility,
            ..GatewayConfig::default()
        },
        resolver,
        TcpHttpTransport::default(),
    ) {
        Ok(gateway) => gateway,
        Err(error) => {
            return write_tunnel_response(
                &mut client_output,
                &plain_response_for_request(
                    &input,
                    500,
                    "Gateway Configuration Error",
                    &error.to_string(),
                ),
            );
        }
    };

    match gateway.handle_tunnel(&request) {
        Ok(response) => {
            let resolver_policy = fallback_marker.used().then_some("hns-doh-compat");
            let trace = resolution_trace_json(
                &input,
                mode,
                Some(&response.resolution),
                TlsTraceInput {
                    validation: Some(&response.origin_request.tls),
                    decision: Some(&response.origin.dane_decision),
                    inspection: response.origin.tls_inspection.as_ref(),
                },
                None,
                &fallback_marker,
                &dns_trace,
            );
            let response_head = upgrade_response_head_with_resolver_policy_and_trace(
                &response.origin.response_head,
                &response.origin.dane_decision,
                resolver_policy,
                &trace,
            );
            if !write_tunnel_response(&mut client_output, &response_head) {
                return false;
            }

            let origin = Arc::new(Mutex::new(response.origin.stream));
            let done = Arc::new(AtomicBool::new(false));
            let origin_writer = Arc::clone(&origin);
            let writer_done = Arc::clone(&done);
            let _client_to_origin = thread::spawn(move || {
                let _ = copy_client_to_origin(&mut client_input, origin_writer);
                writer_done.store(true, Ordering::SeqCst);
            });
            let result = copy_origin_to_client(origin, &mut client_output, Arc::clone(&done));
            done.store(true, Ordering::SeqCst);
            result.is_ok()
        }
        Err(error) => {
            let (status, reason, detail) = map_gateway_error(&error);
            let trace = resolution_trace_json(
                &input,
                mode,
                None,
                TlsTraceInput::default(),
                Some(&error),
                &fallback_marker,
                &dns_trace,
            );
            write_tunnel_response(
                &mut client_output,
                &plain_response_for_request_with_trace(&input, status, reason, detail, &trace),
            )
        }
    }
}

fn write_tunnel_response(output: &mut impl Write, bytes: &[u8]) -> bool {
    output.write_all(bytes).and_then(|_| output.flush()).is_ok()
}

fn copy_client_to_origin(
    client_input: &mut impl Read,
    origin: Arc<Mutex<Box<dyn ReadWrite>>>,
) -> std::io::Result<()> {
    let mut buffer = [0u8; TUNNEL_COPY_BUFFER_BYTES];
    loop {
        let read = match client_input.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let mut origin = origin
            .lock()
            .map_err(|_| std::io::Error::other("origin tunnel lock is poisoned"))?;
        origin.write_all(&buffer[..read])?;
        origin.flush()?;
    }
}

fn copy_origin_to_client(
    origin: Arc<Mutex<Box<dyn ReadWrite>>>,
    client_output: &mut impl Write,
    done: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut buffer = [0u8; TUNNEL_COPY_BUFFER_BYTES];
    loop {
        let read = {
            let mut origin = origin
                .lock()
                .map_err(|_| std::io::Error::other("origin tunnel lock is poisoned"))?;
            match origin.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(read) => Some(read),
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    None
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => None,
                Err(error) => return Err(error),
            }
        };
        let Some(read) = read else {
            if done.load(Ordering::SeqCst) {
                return Ok(());
            }
            continue;
        };
        client_output.write_all(&buffer[..read])?;
        client_output.flush()?;
    }
}

fn gateway_request(
    input: &GatewayHttpRequestInput<'_>,
    headers: Vec<(String, String)>,
) -> GatewayRequest {
    GatewayRequest {
        origin: OriginRequest {
            method: input.method.to_owned(),
            scheme: input.scheme.to_ascii_lowercase(),
            host: input.host.to_owned(),
            connect_host: None,
            port: input.port,
            path_and_query: input.path_and_query.to_owned(),
            protocol: OriginProtocol::Http11,
            tls: if input.scheme.eq_ignore_ascii_case("https")
                || input.scheme.eq_ignore_ascii_case("wss")
            {
                TlsValidation::hns_compatibility(false, Vec::new())
            } else {
                TlsValidation::default()
            },
            headers,
            body: input.body.to_vec(),
        },
        resolution: ResolutionRequest {
            qname: input.host.to_owned(),
            qtype: RecordType::A.code(),
        },
    }
}

fn android_gateway_resolver(
    base: PathBuf,
    values: SqliteResourceValueProvider,
    mode: GatewayResolutionMode,
    fallback_marker: FallbackMarker,
    dns_trace: DnsTraceRecorder,
) -> AndroidGatewayResolver {
    let authoritative_dns_transport = android_authoritative_dns_transport(mode);
    let primary = DelegatingResolver::new(
        GatewayProofProvider::new(base, values),
        AuthoritativeDnssecResolver::new(
            TracingDnsTransport::new(authoritative_dns_transport, dns_trace.clone()),
            SystemDnssecVerifier,
        ),
    );
    match mode {
        GatewayResolutionMode::Strict => AndroidGatewayResolver::Strict(primary),
        GatewayResolutionMode::Compatibility => AndroidGatewayResolver::Compatibility(
            FallbackResolver::with_marker(primary, HnsDohResolver::new(dns_trace), fallback_marker),
        ),
    }
}

fn android_authoritative_dns_transport(mode: GatewayResolutionMode) -> UdpTcpDnsTransport {
    let mut transport = UdpTcpDnsTransport::default();
    if mode == GatewayResolutionMode::Compatibility {
        transport.timeout = ANDROID_COMPAT_AUTHORITATIVE_DNS_TIMEOUT;
    }
    transport
}

fn parse_gateway_headers(header_text: &str) -> Result<ParsedGatewayHeaders, &'static str> {
    if header_text.len() > MAX_GATEWAY_HEADER_TEXT_BYTES {
        return Err("request headers are too large");
    }

    let mut headers = Vec::new();
    let mut strict_hns_mode = false;
    for line in header_text.split("\r\n").filter(|line| !line.is_empty()) {
        let Some(separator) = line.find(':') else {
            return Err("request header is malformed");
        };
        let name = line[..separator].trim();
        let value = line[separator + 1..].trim();
        if name.is_empty()
            || name
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b':')
            || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
        {
            return Err("request header is invalid");
        }
        if name.eq_ignore_ascii_case(HNS_GATEWAY_STRICT_MODE_HEADER) {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                strict_hns_mode = true;
            }
            continue;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }

    Ok(ParsedGatewayHeaders {
        headers,
        strict_hns_mode,
    })
}

#[cfg(test)]
fn origin_response(response: OriginResponse) -> Vec<u8> {
    origin_response_with_resolver_policy_and_trace(response, None, "{}")
}

fn origin_response_with_resolver_policy_and_trace(
    response: OriginResponse,
    resolver_policy: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let body = response.body;
    let mut out = origin_response_head_with_resolver_policy_and_trace(
        OriginResponseHead {
            status: response.status,
            headers: response.headers,
            body_len: body.len(),
            dane_decision: response.dane_decision,
            tls_inspection: response.tls_inspection,
        },
        resolver_policy,
        trace_json,
    );
    out.extend(body);
    out
}

#[cfg(test)]
fn origin_response_with_resolver_policy(
    response: OriginResponse,
    resolver_policy: Option<&str>,
) -> Vec<u8> {
    origin_response_with_resolver_policy_and_trace(response, resolver_policy, "{}")
}

fn origin_response_head_with_resolver_policy_and_trace(
    response: OriginResponseHead,
    resolver_policy: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let mut out = response_head(response.status, "OK", None, response.body_len);
    for (name, value) in response.headers {
        if suppressed_origin_response_header(&name) {
            continue;
        }
        out.extend(format!("{name}: {value}\r\n").as_bytes());
    }
    if let Some(policy) = hns_tls_policy_header(&response.dane_decision) {
        out.extend(format!("X-HNS-TLS-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(policy) = resolver_policy {
        out.extend(format!("X-HNS-Resolver-Policy: {policy}\r\n").as_bytes());
    }
    out.extend(format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes());
    out.extend(
        format!(
            "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
            trace_doh_fallback(trace_json)
        )
        .as_bytes(),
    );
    out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    out.extend(b"\r\n");
    out
}

fn upgrade_response_head_with_resolver_policy_and_trace(
    response_head: &[u8],
    decision: &DaneDecision,
    resolver_policy: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    let header_text = String::from_utf8_lossy(response_head);
    let header_text = header_text.strip_suffix("\r\n\r\n").unwrap_or(&header_text);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("HTTP/1.1 101 Switching Protocols");
    let mut out = format!("{status_line}\r\n").into_bytes();
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, _)) = line.split_once(':') else {
            continue;
        };
        if suppressed_origin_response_header(name.trim()) {
            continue;
        }
        out.extend(line.as_bytes());
        out.extend(b"\r\n");
    }
    if let Some(policy) = hns_tls_policy_header(decision) {
        out.extend(format!("X-HNS-TLS-Policy: {policy}\r\n").as_bytes());
    }
    if let Some(policy) = resolver_policy {
        out.extend(format!("X-HNS-Resolver-Policy: {policy}\r\n").as_bytes());
    }
    out.extend(format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes());
    out.extend(
        format!(
            "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
            trace_doh_fallback(trace_json)
        )
        .as_bytes(),
    );
    out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    out.extend(b"\r\n");
    out
}

fn suppressed_origin_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("x-hns-tls-policy")
        || name.eq_ignore_ascii_case("x-hns-resolver-policy")
        || name.eq_ignore_ascii_case(HNS_RESOLUTION_TRACE_HEADER)
        || name.eq_ignore_ascii_case(HNS_RESOLVER_MODE_HEADER)
        || name.eq_ignore_ascii_case(HNS_DOH_FALLBACK_HEADER)
}

#[derive(Clone, Copy, Default)]
struct TlsTraceInput<'a> {
    validation: Option<&'a TlsValidation>,
    decision: Option<&'a DaneDecision>,
    inspection: Option<&'a TlsCertificateInspection>,
}

fn resolution_trace_json(
    input: &GatewayHttpRequestInput<'_>,
    mode: GatewayResolutionMode,
    resolution: Option<&ResolutionAnswer>,
    tls: TlsTraceInput<'_>,
    error: Option<&GatewayError>,
    fallback_marker: &FallbackMarker,
    dns_trace: &DnsTraceRecorder,
) -> String {
    let dns_events = dns_trace.snapshot();
    let resource_types = resolution
        .map(|answer| {
            answer
                .records
                .iter()
                .map(|record| record_type_name(&record.record_type))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(|record_type| format!(r#""{}""#, json_escape(record_type)))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let authoritative_dns_used = dns_events
        .iter()
        .any(|event| event.protocol == "udp53" || event.protocol == "tcp53");
    let delegation = resolution
        .map(|answer| {
            authoritative_dns_used
                || answer.records.iter().any(|record| {
                    matches!(
                        record.record_type,
                        RecordType::Ns | RecordType::Ds | RecordType::Unknown(6)
                    )
                })
        })
        .unwrap_or(false);
    let origin_address = resolution
        .map(|answer| {
            answer
                .records
                .iter()
                .any(|record| matches!(record.record_type, RecordType::A | RecordType::Aaaa))
        })
        .unwrap_or(false);
    let hns_proof = match (resolution, error) {
        (Some(answer), _) if answer.secure => "verified",
        (_, Some(GatewayError::Resolver(ResolverError::ProofUnavailable))) => "unavailable",
        (_, Some(GatewayError::Resolver(ResolverError::NameNotFound))) => "not_found",
        (_, Some(GatewayError::Resolver(ResolverError::ProofNameMismatch))) => "failed",
        _ => "unknown",
    };
    let fallback_reason = fallback_marker.reason().unwrap_or("none");
    let fallback_type = if fallback_marker.used() {
        r#""HNS_DOH""#
    } else {
        "null"
    };
    let fallback_reason_json = if fallback_marker.used() {
        format!(r#""{}""#, json_escape(fallback_reason))
    } else {
        "null".to_owned()
    };
    let final_error = error
        .map(|error| format!(r#""{}""#, json_escape(&error.to_string())))
        .unwrap_or_else(|| "null".to_owned());
    let authoritative_dns = authoritative_dns_trace_json(&dns_events);
    let dns_attempts = dns_trace_attempts_json(&dns_events);

    format!(
        r#"{{"host":"{}","url":"{}","root":"{}","mode":"{}","hnsProof":"{}","delegation":{},"resourceRecords":[{}],"nameserverCandidates":{},"authoritativeDns":{},"dnssec":"{}","originAddress":"{}","tls":{},"fallback":{{"used":{},"type":{},"reason":{}}},"dnsAttempts":[{}],"finalError":{}}}"#,
        json_escape(input.host),
        json_escape(&gateway_request_address(input)),
        json_escape(&hns_trace_root(input.host)),
        mode.as_str(),
        hns_proof,
        delegation,
        resource_types,
        nameserver_candidates_json(&dns_events),
        authoritative_dns,
        dnssec_trace_status(resolution, error),
        if origin_address { "found" } else { "missing" },
        tls_trace_json(input, tls.validation, tls.decision, tls.inspection, error),
        fallback_marker.used(),
        fallback_type,
        fallback_reason_json,
        dns_attempts,
        final_error,
    )
}

fn authoritative_dns_trace_json(events: &[DnsTraceEvent]) -> String {
    format!(
        r#"{{"udp53":"{}","tcp53":"{}"}}"#,
        dns_protocol_status(events, "udp53"),
        dns_protocol_status(events, "tcp53"),
    )
}

fn tls_trace_json(
    input: &GatewayHttpRequestInput<'_>,
    tls_validation: Option<&TlsValidation>,
    dane_decision: Option<&DaneDecision>,
    tls_inspection: Option<&TlsCertificateInspection>,
    error: Option<&GatewayError>,
) -> String {
    if !input.scheme.eq_ignore_ascii_case("https")
        && tls_validation
            .map(|tls| tls.tlsa_records.is_empty())
            .unwrap_or(true)
        && dane_decision.is_none()
    {
        return "null".to_owned();
    }

    let owner = tlsa_owner_name(input.host, input.port);
    let records = tls_validation
        .map(|tls| tlsa_records_json(&tls.tlsa_records))
        .unwrap_or_else(|| "[]".to_owned());
    let records_found = tls_validation
        .map(|tls| !tls.tlsa_records.is_empty())
        .unwrap_or(false);
    let dnssec_secure = tls_validation
        .map(|tls| if tls.dnssec_secure { "true" } else { "false" })
        .unwrap_or("null");
    let mode = tls_validation
        .map(|tls| format!(r#""{}""#, json_escape(tls_mode_name(tls))))
        .unwrap_or_else(|| "null".to_owned());
    let decision = dane_trace_decision(dane_decision, error);
    let matched_usage = dane_decision
        .and_then(|decision| match decision {
            DaneDecision::Matched(usage) => Some(format!(r#""{}""#, tlsa_usage_name(*usage))),
            _ => None,
        })
        .unwrap_or_else(|| "null".to_owned());
    let certificate_match = dane_certificate_match(dane_decision, error);
    let fallback = matches!(dane_decision, Some(DaneDecision::WebPkiFallback));

    format!(
        r#"{{"mode":{},"tlsaOwner":"{}","tlsaFound":{},"dnssecSecure":{},"records":{},"certificate":{},"dane":{{"decision":"{}","matchedUsage":{},"certificateMatch":"{}","webPkiFallback":{}}}}}"#,
        mode,
        json_escape(&owner),
        records_found,
        dnssec_secure,
        records,
        tls_certificate_inspection_json(tls_inspection),
        decision,
        matched_usage,
        certificate_match,
        fallback,
    )
}

fn tls_certificate_inspection_json(inspection: Option<&TlsCertificateInspection>) -> String {
    let Some(inspection) = inspection else {
        return "null".to_owned();
    };
    format!(
        r#"{{"webPkiStatus":"{}","endEntitySha256":"{}","spkiSha256":"{}","spkiDerHex":"{}","intermediateCount":{},"intermediateSha256":[{}]}}"#,
        webpki_status_name(inspection.webpki_status),
        sha256_hex(&inspection.end_entity_der),
        sha256_hex(&inspection.end_entity_spki_der),
        hex_lower(&inspection.end_entity_spki_der),
        inspection.intermediate_der.len(),
        inspection
            .intermediate_der
            .iter()
            .map(|certificate| format!(r#""{}""#, sha256_hex(certificate)))
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn webpki_status_name(status: hns_dane::WebPkiStatus) -> &'static str {
    match status {
        hns_dane::WebPkiStatus::Valid => "valid",
        hns_dane::WebPkiStatus::Invalid => "invalid",
        hns_dane::WebPkiStatus::NotEvaluated => "not_evaluated",
    }
}

fn sha256_hex(value: &[u8]) -> String {
    hex_lower(&Sha256::digest(value))
}

fn tlsa_owner_name(host: &str, port: u16) -> String {
    format!("_{}._tcp.{}", port, host.trim_end_matches('.'))
}

fn tls_mode_name(tls: &TlsValidation) -> &'static str {
    match tls.mode {
        hns_dane::DomainTrustMode::HnsStrict => "hns_strict",
        hns_dane::DomainTrustMode::HnsCompatibility => "hns_compatibility",
        hns_dane::DomainTrustMode::IcannWebPki => "icann_webpki",
    }
}

fn dane_trace_decision(
    dane_decision: Option<&DaneDecision>,
    error: Option<&GatewayError>,
) -> &'static str {
    match (dane_decision, error) {
        (Some(DaneDecision::Matched(_)), _) => "verified",
        (Some(DaneDecision::WebPkiFallback), _) => "webpki_fallback",
        (Some(DaneDecision::NoTlsa), _) => "no_tlsa",
        (Some(DaneDecision::Failed), _) => "failed",
        (_, Some(GatewayError::InvalidTlsa(_)))
        | (_, Some(GatewayError::Transport(TransportError::DaneFailed))) => "failed",
        _ => "not_evaluated",
    }
}

fn dane_certificate_match(
    dane_decision: Option<&DaneDecision>,
    error: Option<&GatewayError>,
) -> &'static str {
    match (dane_decision, error) {
        (Some(DaneDecision::Matched(_)), _) => "pass",
        (Some(DaneDecision::WebPkiFallback), _) => "webpki_valid",
        (Some(DaneDecision::NoTlsa), _) => "not_checked",
        (Some(DaneDecision::Failed), _) => "failed",
        (_, Some(GatewayError::InvalidTlsa(_)))
        | (_, Some(GatewayError::Transport(TransportError::DaneFailed))) => "failed",
        _ => "unknown",
    }
}

fn tlsa_records_json(records: &[TlsaRecord]) -> String {
    format!(
        "[{}]",
        records
            .iter()
            .map(tlsa_record_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn tlsa_record_json(record: &TlsaRecord) -> String {
    format!(
        r#"{{"usage":"{}","selector":"{}","matching":"{}","associationDataHex":"{}"}}"#,
        tlsa_usage_name(record.usage),
        tlsa_selector_name(record.selector),
        tlsa_matching_name(record.matching),
        hex_lower(&record.association_data),
    )
}

fn tlsa_usage_name(usage: TlsaUsage) -> &'static str {
    match usage {
        TlsaUsage::PkixTa => "PKIX-TA",
        TlsaUsage::PkixEe => "PKIX-EE",
        TlsaUsage::DaneTa => "DANE-TA",
        TlsaUsage::DaneEe => "DANE-EE",
    }
}

fn tlsa_selector_name(selector: TlsaSelector) -> &'static str {
    match selector {
        TlsaSelector::FullCertificate => "Cert",
        TlsaSelector::SubjectPublicKeyInfo => "SPKI",
    }
}

fn tlsa_matching_name(matching: TlsaMatching) -> &'static str {
    match matching {
        TlsaMatching::Exact => "Exact",
        TlsaMatching::Sha256 => "SHA-256",
        TlsaMatching::Sha512 => "SHA-512",
    }
}

fn dns_protocol_status(events: &[DnsTraceEvent], protocol: &str) -> String {
    let statuses = events
        .iter()
        .filter(|event| event.protocol == protocol)
        .map(|event| event.status.as_str())
        .collect::<Vec<_>>();
    if statuses.is_empty() {
        return "not_attempted".to_owned();
    }
    if statuses.contains(&"ok") {
        return "ok".to_owned();
    }
    if statuses.contains(&"timeout") {
        return "timeout".to_owned();
    }
    statuses.last().copied().unwrap_or("error").to_owned()
}

fn dns_trace_attempts_json(events: &[DnsTraceEvent]) -> String {
    events
        .iter()
        .map(|event| {
            let error = event
                .error
                .as_ref()
                .map(|error| format!(r#""{}""#, json_escape(error)))
                .unwrap_or_else(|| "null".to_owned());
            format!(
                r#"{{"protocol":"{}","server":"{}","status":"{}","elapsedMs":{},"error":{}}}"#,
                event.protocol,
                json_escape(&event.server),
                json_escape(&event.status),
                event.elapsed_ms,
                error,
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn nameserver_candidates_json(events: &[DnsTraceEvent]) -> String {
    let servers = events
        .iter()
        .filter(|event| matches!(event.protocol, "udp53" | "tcp53"))
        .map(|event| event.server.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    format!(
        "[{}]",
        servers
            .into_iter()
            .map(|server| format!(r#""{}""#, json_escape(server)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn dnssec_trace_status(
    resolution: Option<&ResolutionAnswer>,
    error: Option<&GatewayError>,
) -> &'static str {
    if matches!(
        error,
        Some(GatewayError::Resolver(ResolverError::DnssecFailed))
    ) {
        "bogus"
    } else if resolution.map(|answer| answer.secure).unwrap_or(false) {
        "secure"
    } else if resolution.is_some() {
        "unsigned"
    } else {
        "unknown"
    }
}

fn hns_trace_root(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .rsplit('.')
        .next()
        .unwrap_or(host)
        .to_owned()
}

fn hns_proof_details(data_dir: &str, host_or_url: &str) -> String {
    let (host, root_name) = match hns_proof_host_and_root(host_or_url) {
        Ok(value) => value,
        Err(error) => return hns_proof_details_error_json(host_or_url, &error),
    };
    let name_hash = match NameHash::from_name(&root_name) {
        Ok(value) => value,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: None,
                proof_status: "failed",
                cache_status: "invalid_name",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: None,
                error: &format!("invalid HNS name: {error}"),
            });
        }
    };

    let base = Path::new(data_dir).join("hns");
    let resources_path = base.join("resources.sqlite");
    if !resources_path.exists() {
        return hns_proof_details_base_json(HnsProofDetailsJson {
            host: &host,
            root_name: &root_name,
            name_hash: Some(name_hash),
            proof_status: "unavailable",
            cache_status: "resource_cache_missing",
            anchor: None,
            secure: None,
            exists: None,
            records: Vec::new(),
            raw_resource: None,
            current_tip_base: Some(&base),
            error: "resource cache is not initialized",
        });
    }

    let provider = match SqliteResourceValueProvider::open(resources_path) {
        Ok(value) => value,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "error",
                cache_status: "resource_cache_open_failed",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                error: &format!("open resource cache: {error}"),
            });
        }
    };

    let verified = match provider.prove_resource_value(&root_name, name_hash) {
        Ok(value) => value,
        Err(ResolverError::ProofUnavailable) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "unavailable",
                cache_status: "not_cached",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                error: "no cached proof is available for this HNS root",
            });
        }
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "error",
                cache_status: "proof_read_failed",
                anchor: None,
                secure: None,
                exists: None,
                records: Vec::new(),
                raw_resource: None,
                current_tip_base: Some(&base),
                error: &error.to_string(),
            });
        }
    };

    let raw_resource = verified.value.as_deref();
    let records = match ProvenNameRecords::from_verified_resource_value(verified.clone()) {
        Ok(proven) => proven.records,
        Err(error) => {
            return hns_proof_details_base_json(HnsProofDetailsJson {
                host: &host,
                root_name: &root_name,
                name_hash: Some(name_hash),
                proof_status: "invalid_resource",
                cache_status: &proof_cache_status(&base, verified.anchor),
                anchor: verified.anchor,
                secure: Some(verified.secure),
                exists: Some(verified.value.is_some()),
                records: Vec::new(),
                raw_resource,
                current_tip_base: Some(&base),
                error: &format!("decode resource records: {error}"),
            });
        }
    };
    let status = match (verified.secure, verified.value.is_some()) {
        (false, _) => "failed",
        (true, false) => "not_found",
        (true, true) => "verified",
    };

    hns_proof_details_base_json(HnsProofDetailsJson {
        host: &host,
        root_name: &root_name,
        name_hash: Some(name_hash),
        proof_status: status,
        cache_status: &proof_cache_status(&base, verified.anchor),
        anchor: verified.anchor,
        secure: Some(verified.secure),
        exists: Some(verified.value.is_some()),
        records,
        raw_resource,
        current_tip_base: Some(&base),
        error: "",
    })
}

fn hns_proof_host_and_root(host_or_url: &str) -> Result<(String, String), String> {
    let mut value = host_or_url.trim();
    if let Some(rest) = value.strip_prefix("https://") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix("http://") {
        value = rest;
    }
    let authority = value
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or(value)
        .trim();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
        _ => authority,
    }
    .trim_end_matches('.')
    .to_ascii_lowercase();
    if host.is_empty() {
        return Err("missing HNS host".to_owned());
    }
    let root = hns_trace_root(&host).to_ascii_lowercase();
    if root.is_empty() {
        return Err("missing HNS root".to_owned());
    }
    Ok((host, root))
}

fn hns_proof_details_error_json(host_or_url: &str, error: &str) -> String {
    format!(
        r#"{{"host":"{}","name":null,"nameHash":null,"hnsProof":"error","proofStatus":"error","secure":null,"exists":null,"treeRoot":null,"blockHeight":null,"cacheStatus":"invalid_input","resourceValueHex":null,"recordTypes":[],"resourceRecords":[],"currentTip":null,"error":"{}"}}"#,
        json_escape(host_or_url),
        json_escape(error),
    )
}

struct HnsProofDetailsJson<'a> {
    host: &'a str,
    root_name: &'a str,
    name_hash: Option<NameHash>,
    proof_status: &'a str,
    cache_status: &'a str,
    anchor: Option<ResourceValueAnchor>,
    secure: Option<bool>,
    exists: Option<bool>,
    records: Vec<ResourceRecord>,
    raw_resource: Option<&'a [u8]>,
    current_tip_base: Option<&'a Path>,
    error: &'a str,
}

fn hns_proof_details_base_json(details: HnsProofDetailsJson<'_>) -> String {
    let name_hash = details
        .name_hash
        .map(|value| format!(r#""{}""#, value.as_hash()))
        .unwrap_or_else(|| "null".to_owned());
    let tree_root = details
        .anchor
        .map(|value| format!(r#""{}""#, value.tree_root))
        .unwrap_or_else(|| "null".to_owned());
    let block_height = details
        .anchor
        .map(|value| value.height.0.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let secure = json_bool_or_null(details.secure);
    let exists = json_bool_or_null(details.exists);
    let raw_resource = details
        .raw_resource
        .map(|value| format!(r#""{}""#, hex_lower(value)))
        .unwrap_or_else(|| "null".to_owned());
    let record_types = record_types_json(&details.records);
    let records_json = resource_records_json(&details.records);
    let current_tip = details
        .current_tip_base
        .map(current_tip_json)
        .unwrap_or_else(|| "null".to_owned());
    let error = if details.error.is_empty() {
        "null".to_owned()
    } else {
        format!(r#""{}""#, json_escape(details.error))
    };

    format!(
        r#"{{"host":"{}","name":"{}","nameHash":{},"hnsProof":"{}","proofStatus":"{}","secure":{},"exists":{},"treeRoot":{},"blockHeight":{},"cacheStatus":"{}","resourceValueHex":{},"recordTypes":{},"resourceRecords":{},"currentTip":{},"error":{}}}"#,
        json_escape(details.host),
        json_escape(details.root_name),
        name_hash,
        json_escape(details.proof_status),
        json_escape(details.proof_status),
        secure,
        exists,
        tree_root,
        block_height,
        json_escape(details.cache_status),
        raw_resource,
        record_types,
        records_json,
        current_tip,
        error,
    )
}

fn proof_cache_status(base: &Path, anchor: Option<ResourceValueAnchor>) -> String {
    match (anchor, best_synced_header(base).ok()) {
        (None, _) => "no_anchor".to_owned(),
        (Some(anchor), Some(best))
            if anchor.height == best.height && anchor.tree_root == best.header.tree_root =>
        {
            "anchored_to_current_tip".to_owned()
        }
        (Some(_), Some(_)) => "anchored_to_height".to_owned(),
        (Some(_), None) => "anchored_no_current_tip".to_owned(),
    }
}

fn current_tip_json(base: &Path) -> String {
    match best_synced_header(base) {
        Ok(best) => format!(
            r#"{{"height":{},"treeRoot":"{}"}}"#,
            best.height.0, best.header.tree_root,
        ),
        Err(_) => "null".to_owned(),
    }
}

fn json_bool_or_null(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn record_types_json(records: &[ResourceRecord]) -> String {
    let values = records
        .iter()
        .map(|record| record_type_name(&record.record_type))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|record_type| format!(r#""{}""#, json_escape(record_type)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn resource_records_json(records: &[ResourceRecord]) -> String {
    format!(
        "[{}]",
        records
            .iter()
            .map(resource_record_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn resource_record_json(record: &ResourceRecord) -> String {
    format!(
        r#"{{"name":"{}","type":"{}","class":{},"ttl":{},"rdataHex":"{}"}}"#,
        json_escape(&record.name.to_string()),
        json_escape(record_type_name(&record.record_type)),
        record.class,
        record.ttl,
        hex_lower(&record.rdata),
    )
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn record_type_name(record_type: &RecordType) -> &'static str {
    match record_type {
        RecordType::A => "A",
        RecordType::Aaaa => "AAAA",
        RecordType::Ns => "NS",
        RecordType::Ds => "DS",
        RecordType::Txt => "TXT",
        RecordType::Soa => "SOA",
        RecordType::Srv => "SRV",
        RecordType::Rrsig => "RRSIG",
        RecordType::Nsec => "NSEC",
        RecordType::Dnskey => "DNSKEY",
        RecordType::Nsec3 => "NSEC3",
        RecordType::Tlsa => "TLSA",
        RecordType::Svcb => "SVCB",
        RecordType::Https => "HTTPS",
        RecordType::Cname => "CNAME",
        RecordType::Unknown(1) => "GLUE4",
        RecordType::Unknown(2) => "GLUE6",
        RecordType::Unknown(6) => "SYNTH4",
        RecordType::Unknown(7) => "SYNTH6",
        RecordType::Unknown(_) => "UNKNOWN",
    }
}

fn trace_mode(trace_json: &str) -> &'static str {
    if trace_json.contains(r#""mode":"strict""#) {
        "strict"
    } else {
        "compatibility"
    }
}

fn trace_doh_fallback(trace_json: &str) -> &'static str {
    if trace_json.contains(r#""used":true"#) {
        "yes"
    } else {
        "no"
    }
}

fn hns_tls_policy_header(decision: &DaneDecision) -> Option<&'static str> {
    match decision {
        DaneDecision::Matched(_) => Some("dane"),
        DaneDecision::WebPkiFallback => Some("webpki-fallback"),
        DaneDecision::Failed => Some("failed"),
        DaneDecision::NoTlsa => None,
    }
}

fn map_gateway_error(error: &GatewayError) -> (u16, &'static str, &'static str) {
    match error {
        GatewayError::Resolver(ResolverError::UnsupportedBackend) => (
            503,
            "HNS Resolution Unavailable",
            "Rust HNS resolver backend is not ready.",
        ),
        GatewayError::Resolver(ResolverError::ProofUnavailable) => (
            503,
            "HNS Proof Unavailable",
            "No current verified HNS proof is available for this name.",
        ),
        GatewayError::Resolver(ResolverError::NameNotFound) => (
            404,
            "HNS Name Not Found",
            "A verified HNS non-inclusion proof says this name does not exist.",
        ),
        GatewayError::Resolver(ResolverError::NoNameserverAddress) => (
            502,
            "HNS Nameserver Unavailable",
            "No verified nameserver address is available for this HNS delegation.",
        ),
        GatewayError::Resolver(ResolverError::DnsTransport(_)) => (
            502,
            "HNS Nameserver Unavailable",
            "Delegated HNS nameserver transport failed closed.",
        ),
        GatewayError::Resolver(ResolverError::InvalidDnsResponse) => (
            502,
            "HNS Nameserver Response Invalid",
            "Delegated HNS nameserver response was invalid or lacked required secure denial data.",
        ),
        GatewayError::Resolver(ResolverError::DnssecFailed) => (
            502,
            "HNS DNSSEC Validation Failed",
            "Delegated HNS DNSSEC validation failed closed.",
        ),
        GatewayError::Resolver(ResolverError::InvalidName(_)) => {
            (400, "HNS Name Invalid", "Requested HNS name is invalid.")
        }
        GatewayError::Resolver(ResolverError::InvalidResource(_)) => (
            502,
            "HNS Resource Invalid",
            "Verified HNS resource data is malformed or unsupported.",
        ),
        GatewayError::Resolver(ResolverError::ProofNameMismatch) => (
            502,
            "HNS Proof Validation Failed",
            "HNS proof validation failed closed.",
        ),
        GatewayError::InsecureResolution => (
            502,
            "HNS DNSSEC Validation Failed",
            "Secure HNS resolution was required but the resolver returned an insecure result.",
        ),
        GatewayError::NoResolvedAddress => (
            502,
            "HNS Origin Address Missing",
            "Secure HNS resolution did not produce an origin A or AAAA address.",
        ),
        GatewayError::InvalidTlsa(_) | GatewayError::Transport(TransportError::DaneFailed) => (
            502,
            "HNS DANE Validation Failed",
            "DANE/TLSA validation failed closed.",
        ),
        GatewayError::InvalidSvcb(_) | GatewayError::UnsupportedSvcb => (
            502,
            "HNS HTTPS Service Unsupported",
            "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
        ),
        GatewayError::HostResolutionMismatch => (
            400,
            "HNS Request Mismatch",
            "Origin host does not match the HNS resolution name.",
        ),
        GatewayError::Transport(TransportError::UnsupportedTransport) => (
            501,
            "HNS Transport Unsupported",
            "Requested HNS origin transport is not available.",
        ),
        GatewayError::Transport(TransportError::UnsupportedScheme) => (
            501,
            "HNS Scheme Unsupported",
            "Requested HNS origin scheme is not available.",
        ),
        GatewayError::Transport(TransportError::Tls(_)) => (
            502,
            "HNS TLS Failed",
            "Origin TLS negotiation failed closed.",
        ),
        GatewayError::Transport(TransportError::InvalidRequest) => (
            400,
            "HNS Origin Request Invalid",
            "Origin request could not be safely forwarded.",
        ),
        GatewayError::Transport(TransportError::RequestTooLarge) => (
            413,
            "HNS Origin Request Too Large",
            "Origin request body exceeds the configured gateway limit.",
        ),
        GatewayError::Transport(TransportError::UnsupportedTransferEncoding)
        | GatewayError::Transport(TransportError::MalformedResponse) => (
            502,
            "HNS Origin Response Invalid",
            "Origin HTTP response framing failed closed.",
        ),
        GatewayError::Transport(TransportError::UnsupportedUpgrade) => (
            501,
            "HNS Protocol Upgrade Unsupported",
            "HNS WebSocket/HTTP Upgrade must use the native tunnel path and the request failed validation.",
        ),
        GatewayError::Transport(TransportError::ResponseTooLarge) => (
            502,
            "HNS Origin Response Too Large",
            "Origin response exceeds the configured gateway limit.",
        ),
        GatewayError::Transport(TransportError::Io(_)) => (
            502,
            "HNS Origin Transport Failed",
            "Origin connection failed closed.",
        ),
        GatewayError::Transport(TransportError::Http2(_)) => (
            502,
            "HNS HTTP/2 Transport Failed",
            "Origin HTTP/2 exchange failed closed.",
        ),
        GatewayError::Transport(TransportError::Http3(_)) => (
            502,
            "HNS HTTP/3 Transport Failed",
            "Origin HTTP/3 exchange failed closed.",
        ),
        GatewayError::Transport(TransportError::Quic(_)) => (
            502,
            "HNS QUIC Transport Failed",
            "Origin QUIC connection failed closed.",
        ),
        GatewayError::Resolver(ResolverError::CachePoisoned)
        | GatewayError::Resolver(ResolverError::Storage(_))
        | GatewayError::NonLoopbackBind => (
            500,
            "HNS Gateway Storage Error",
            "Local HNS gateway state is unavailable.",
        ),
    }
}

fn plain_response_for_request(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
) -> Vec<u8> {
    let address = gateway_request_address(input);
    plain_response_with_address(status, reason, detail, Some(&address))
}

fn plain_response_for_request_with_trace(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    trace_json: &str,
) -> Vec<u8> {
    let address = gateway_request_address(input);
    plain_response_with_address_and_trace(status, reason, detail, Some(&address), trace_json)
}

fn plain_response_with_address(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
) -> Vec<u8> {
    plain_response_with_address_and_optional_trace(status, reason, detail, address, None)
}

fn plain_response_with_address_and_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    trace_json: &str,
) -> Vec<u8> {
    plain_response_with_address_and_optional_trace(
        status,
        reason,
        detail,
        address,
        Some(trace_json),
    )
}

fn plain_response_with_address_and_optional_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    trace_json: Option<&str>,
) -> Vec<u8> {
    let body = plain_response_body(status, reason, detail, address);
    let mut out = response_head(
        status,
        reason,
        Some("text/plain; charset=utf-8"),
        body.len(),
    );
    if let Some(trace_json) = trace_json {
        out.extend(
            format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes(),
        );
        out.extend(
            format!(
                "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
                trace_doh_fallback(trace_json)
            )
            .as_bytes(),
        );
        out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    }
    out.extend(b"\r\n");
    out.extend(body);
    out
}

fn plain_response_to_file_for_request(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    let address = gateway_request_address(input);
    plain_response_to_file_with_address(status, reason, detail, Some(&address), body_path)
}

fn plain_response_to_file_for_request_with_trace(
    input: &GatewayHttpRequestInput<'_>,
    status: u16,
    reason: &str,
    detail: &str,
    body_path: &Path,
    trace_json: &str,
) -> Result<Vec<u8>, String> {
    let address = gateway_request_address(input);
    plain_response_to_file_with_address_and_trace(
        status,
        reason,
        detail,
        Some(&address),
        body_path,
        trace_json,
    )
}

fn plain_response_to_file_with_address(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
) -> Result<Vec<u8>, String> {
    plain_response_to_file_with_address_and_optional_trace(
        status, reason, detail, address, body_path, None,
    )
}

fn plain_response_to_file_with_address_and_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
    trace_json: &str,
) -> Result<Vec<u8>, String> {
    plain_response_to_file_with_address_and_optional_trace(
        status,
        reason,
        detail,
        address,
        body_path,
        Some(trace_json),
    )
}

fn plain_response_to_file_with_address_and_optional_trace(
    status: u16,
    reason: &str,
    detail: &str,
    address: Option<&str>,
    body_path: &Path,
    trace_json: Option<&str>,
) -> Result<Vec<u8>, String> {
    let body = plain_response_body(status, reason, detail, address);
    if let Some(parent) = body_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create response directory: {error}"))?;
    }
    fs::write(body_path, &body).map_err(|error| format!("write response body: {error}"))?;
    let mut out = response_head(
        status,
        reason,
        Some("text/plain; charset=utf-8"),
        body.len(),
    );
    if let Some(trace_json) = trace_json {
        out.extend(
            format!("{HNS_RESOLVER_MODE_HEADER}: {}\r\n", trace_mode(trace_json)).as_bytes(),
        );
        out.extend(
            format!(
                "{HNS_DOH_FALLBACK_HEADER}: {}\r\n",
                trace_doh_fallback(trace_json)
            )
            .as_bytes(),
        );
        out.extend(format!("{HNS_RESOLUTION_TRACE_HEADER}: {trace_json}\r\n").as_bytes());
    }
    out.extend(b"\r\n");
    Ok(out)
}

fn plain_response_body(status: u16, reason: &str, detail: &str, address: Option<&str>) -> Vec<u8> {
    match address {
        Some(address) => format!("{address}\n{status} {reason}\n{detail}\n").into_bytes(),
        None => format!("{status} {reason}\n{detail}\n").into_bytes(),
    }
}

fn gateway_request_address(input: &GatewayHttpRequestInput<'_>) -> String {
    let scheme = input.scheme.to_ascii_lowercase();
    let port = match (scheme.as_str(), input.port) {
        ("http" | "ws", 80) | ("https" | "wss", 443) => String::new(),
        (_, port) => format!(":{port}"),
    };
    let path = if input.path_and_query.is_empty() {
        "/"
    } else {
        input.path_and_query
    };
    format!("{scheme}://{}{}{}", input.host, port, path)
}

fn response_head(
    status: u16,
    reason: &str,
    content_type: Option<&str>,
    body_len: usize,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {body_len}\r\n"
    )
    .into_bytes();
    if let Some(content_type) = content_type {
        out.extend(format!("Content-Type: {content_type}\r\n").as_bytes());
    }
    out
}

fn run_sync_once(
    data_dir: &str,
    seed_on_empty: bool,
    timeout: Duration,
    resource_cache_limit_bytes: usize,
) -> Result<NativeSyncStatus, String> {
    let base = Path::new(data_dir).join("hns");
    fs::create_dir_all(&base).map_err(|error| format!("create sync directory: {error}"))?;

    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| format!("open header store: {error}"))?;
    let mut chain = HeaderChain::new(header_store);
    if chain
        .best_header()
        .map_err(|error| format!("read best header: {error}"))?
        .is_none()
    {
        chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .map_err(|error| format!("insert genesis header: {error}"))?;
    }
    let mut coordinator = HeaderSyncCoordinator::new(chain);

    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| format!("open peer store: {error}"))?;
    let mut peers = peer_store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    let network = network::mainnet();
    let mut seed_error = None;
    if seed_on_empty && peers.len() < ANDROID_MIN_PEER_TARGET {
        let was_empty = peers.is_empty();
        let source = DnsSeedPeerSource::from_network(&network);
        match peers.seed_from(&source) {
            Ok(inserted) => {
                if inserted > 0 {
                    peer_store
                        .save_manager(&peers)
                        .map_err(|error| format!("save seeded peers: {error}"))?;
                }
            }
            Err(error) => {
                if was_empty {
                    seed_error = Some(error.to_string());
                }
            }
        }
    }

    let runner = HeaderSyncRunner::with_config(
        network,
        TcpHeaderPeerConnector,
        HeaderSyncRunnerConfig {
            preferred_peers: ANDROID_HEADER_SYNC_PEERS,
            max_header_batches_per_peer: ANDROID_HEADER_SYNC_BATCHES_PER_PEER,
            peer_discovery_target: ANDROID_MIN_PEER_TARGET,
            parallel_peer_probes: ANDROID_PARALLEL_PEER_PROBES,
            parallel_header_fetch_peers: ANDROID_PARALLEL_HEADER_FETCH_PEERS,
            peer_height_refresh_interval: ANDROID_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS,
            timeout,
            ..HeaderSyncRunnerConfig::default()
        },
    );
    let result = runner
        .sync_once_parallel_and_persist(
            &mut coordinator,
            &mut peers,
            &peer_store,
            now_unix_seconds(),
        )
        .map_err(|error| format!("sync headers: {error}"))?;
    let best = coordinator
        .chain()
        .best_header()
        .map_err(|error| format!("read synced best header: {error}"))?;
    let now = now_unix_seconds();
    let peer_count = peers.len();
    let peer_groups = peers.address_group_count(now);
    let best_peer_height = best_peer_height(&peers);
    let best_height = best.as_ref().map(|header| header.height.0);
    let estimated_tip_height = estimated_mainnet_tip_height(now);
    let resource_cache_evicted =
        prune_resource_cache_to_best_chain(&base, coordinator.chain())?.saturating_add(
            enforce_resource_cache_limit(&base, resource_cache_limit_bytes)?,
        );
    let (resource_cache_entries, resource_cache_bytes) = resource_cache_stats(&base)?;
    let failed = result.failures.len();
    let status = classify_sync_status(
        result.attempted,
        result.successful,
        result.accepted,
        failed,
        seed_error.is_some(),
        best_height,
        best_peer_height,
    );
    let error = if status == "peer_failed" {
        Some(format!(
            "all {} attempted sync peers failed; see failures",
            result.attempted,
        ))
    } else {
        seed_error
    };

    Ok(NativeSyncStatus {
        status,
        attempted: result.attempted,
        successful: result.successful,
        accepted: result.accepted,
        failed,
        peer_count,
        peer_groups,
        best_height,
        best_peer_height,
        estimated_tip_height,
        resource_cache_entries,
        resource_cache_bytes,
        resource_cache_evicted,
        error,
        failures: result
            .failures
            .into_iter()
            .map(|failure| NativePeerFailure {
                address: failure.address.to_string(),
                stage: failure.stage.as_str(),
                error: failure.error,
            })
            .collect(),
    })
}

fn classify_sync_status(
    attempted: usize,
    successful: usize,
    accepted: usize,
    failed: usize,
    seed_failed: bool,
    best_height: Option<u32>,
    best_peer_height: Option<u32>,
) -> &'static str {
    if successful > 0 && accepted > 0 {
        if is_sync_behind(best_height, best_peer_height)
            || is_sync_target_unknown(best_height, best_peer_height)
        {
            "syncing"
        } else {
            "synced"
        }
    } else if successful > 0 {
        if is_sync_behind(best_height, best_peer_height) {
            "syncing"
        } else {
            "up_to_date"
        }
    } else if attempted > 0 && failed == attempted {
        "peer_failed"
    } else if attempted > 0 {
        "attempted"
    } else if seed_failed {
        "seed_failed"
    } else {
        "idle"
    }
}

fn is_sync_behind(best_height: Option<u32>, best_peer_height: Option<u32>) -> bool {
    matches!((best_height, best_peer_height), (Some(best), Some(peer)) if peer > best)
}

fn is_sync_target_unknown(best_height: Option<u32>, best_peer_height: Option<u32>) -> bool {
    matches!((best_height, best_peer_height), (Some(best), None) if best > 0)
}

fn best_peer_height(peers: &hns_p2p::PeerManager) -> Option<u32> {
    peers
        .iter()
        .map(|peer| peer.last_height.0)
        .filter(|height| *height > 0)
        .max()
}

fn select_live_proof_peers(
    peers: &hns_p2p::PeerManager,
    preferred_count: usize,
    now: u64,
    proof_height: Height,
) -> Vec<SocketAddr> {
    let mut candidates = peers
        .iter()
        .filter(|peer| !peer.is_banned(now) && peer.last_height >= proof_height)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.score
            .cmp(&right.score)
            .then_with(|| right.last_height.cmp(&left.last_height))
            .then_with(|| left.address.cmp(&right.address))
    });
    candidates
        .into_iter()
        .take(preferred_count)
        .map(|peer| peer.address)
        .collect()
}

fn estimated_mainnet_tip_height(now: u64) -> Option<u32> {
    now.checked_sub(MAINNET_GENESIS_TIME)
        .map(|elapsed| elapsed / MAINNET_TARGET_SPACING_SECONDS)
        .and_then(|height| u32::try_from(height).ok())
}

fn read_sync_status(data_dir: &str) -> Result<NativeSyncStatus, String> {
    let base = Path::new(data_dir).join("hns");
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| format!("open header store: {error}"))?;
    let chain = HeaderChain::new(header_store);
    let peer_store = SqlitePeerStore::open(base.join("peers.sqlite"))
        .map_err(|error| format!("open peer store: {error}"))?;
    let peers = peer_store
        .load_manager()
        .map_err(|error| format!("load peer store: {error}"))?;
    let best = chain
        .best_header()
        .map_err(|error| format!("read best header: {error}"))?;
    let now = now_unix_seconds();
    let best_height = best.map(|header| header.height.0);
    let best_peer_height = best_peer_height(&peers);
    let estimated_tip_height = estimated_mainnet_tip_height(now);
    let (resource_cache_entries, resource_cache_bytes) = resource_cache_stats(&base)?;

    Ok(NativeSyncStatus {
        status: classify_cached_sync_status(best_height, best_peer_height),
        attempted: 0,
        successful: 0,
        accepted: 0,
        failed: 0,
        peer_count: peers.len(),
        peer_groups: peers.address_group_count(now),
        best_height,
        best_peer_height,
        estimated_tip_height,
        resource_cache_entries,
        resource_cache_bytes,
        resource_cache_evicted: 0,
        error: None,
        failures: Vec::new(),
    })
}

fn classify_cached_sync_status(
    best_height: Option<u32>,
    best_peer_height: Option<u32>,
) -> &'static str {
    match (best_height, best_peer_height) {
        (Some(best), Some(peer)) if best > 0 && peer <= best => "up_to_date",
        (Some(best), Some(peer)) if peer > best => "syncing",
        (Some(best), None) if best > 0 => "syncing",
        _ => "idle",
    }
}

fn best_synced_header(base: &Path) -> Result<hns_chain::StoredHeader, ResolverError> {
    let header_store = SqliteHeaderStore::open(base.join("headers.sqlite"))
        .map_err(|error| ResolverError::Storage(format!("open header store: {error}")))?;
    let chain = HeaderChain::new(header_store);
    let best = chain
        .best_header()
        .map_err(|error| ResolverError::Storage(format!("read best header: {error}")))?
        .ok_or(ResolverError::ProofUnavailable)?;
    if best.height.0 == 0 {
        return Err(ResolverError::ProofUnavailable);
    }
    Ok(best)
}

fn clear_resolver_cache_inner(data_dir: &str) -> Result<NativeSyncStatus, String> {
    let base = Path::new(data_dir).join("hns");
    fs::create_dir_all(&base).map_err(|error| format!("create sync directory: {error}"))?;
    let path = base.join("resources.sqlite");
    if path.exists() {
        let provider = SqliteResourceValueProvider::open(path)
            .map_err(|error| format!("open resource cache: {error}"))?;
        provider
            .clear()
            .map_err(|error| format!("clear resource cache: {error}"))?;
    }

    let mut status = read_sync_status(data_dir).unwrap_or_else(|_| NativeSyncStatus::empty());
    status.status = "cleared";
    status.resource_cache_entries = 0;
    status.resource_cache_bytes = 0;
    status.resource_cache_evicted = 0;
    Ok(status)
}

fn enforce_resource_cache_limit(base: &Path, max_bytes: usize) -> Result<usize, String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok(0);
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    provider
        .enforce_value_byte_limit(max_bytes)
        .map_err(|error| format!("enforce resource cache limit: {error}"))
}

fn prune_resource_cache_to_best_chain(
    base: &Path,
    chain: &HeaderChain<SqliteHeaderStore>,
) -> Result<usize, String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok(0);
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    let valid_anchors = recent_canonical_resource_anchors(chain)?;
    provider
        .prune_invalid_anchors(&valid_anchors, true)
        .map_err(|error| format!("prune resource cache anchors: {error}"))
}

fn recent_canonical_resource_anchors(
    chain: &HeaderChain<SqliteHeaderStore>,
) -> Result<Vec<ResourceValueAnchor>, String> {
    let Some(best) = chain
        .best_header()
        .map_err(|error| format!("read best header for resource cache anchors: {error}"))?
    else {
        return Ok(Vec::new());
    };
    if best.height.0 == 0 {
        return Ok(Vec::new());
    }

    let first_height = best
        .height
        .0
        .saturating_sub(RESOURCE_PROOF_CACHE_CANONICAL_WINDOW)
        .max(1);
    let mut anchors = Vec::new();
    for height in first_height..=best.height.0 {
        if let Some(header) = chain.canonical_header(Height(height)) {
            anchors.push(ResourceValueAnchor {
                tree_root: header.header.tree_root,
                height: header.height,
            });
        }
    }
    Ok(anchors)
}

fn resource_cache_stats(base: &Path) -> Result<(usize, usize), String> {
    let path = base.join("resources.sqlite");
    if !path.exists() {
        return Ok((0, 0));
    }

    let provider = SqliteResourceValueProvider::open(path)
        .map_err(|error| format!("open resource cache: {error}"))?;
    let stats = provider
        .stats()
        .map_err(|error| format!("read resource cache stats: {error}"))?;
    Ok((stats.entries, stats.value_bytes))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct NativeSyncStatus {
    status: &'static str,
    attempted: usize,
    successful: usize,
    accepted: usize,
    failed: usize,
    peer_count: usize,
    peer_groups: usize,
    best_height: Option<u32>,
    best_peer_height: Option<u32>,
    estimated_tip_height: Option<u32>,
    resource_cache_entries: usize,
    resource_cache_bytes: usize,
    resource_cache_evicted: usize,
    error: Option<String>,
    failures: Vec<NativePeerFailure>,
}

struct NativePeerFailure {
    address: String,
    stage: &'static str,
    error: String,
}

impl NativeSyncStatus {
    fn empty() -> Self {
        Self {
            status: "idle",
            attempted: 0,
            successful: 0,
            accepted: 0,
            failed: 0,
            peer_count: 0,
            peer_groups: 0,
            best_height: None,
            best_peer_height: None,
            estimated_tip_height: None,
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: None,
            failures: Vec::new(),
        }
    }

    fn error(error: String) -> Self {
        Self {
            status: "error",
            attempted: 0,
            successful: 0,
            accepted: 0,
            failed: 0,
            peer_count: 0,
            peer_groups: 0,
            best_height: None,
            best_peer_height: None,
            estimated_tip_height: None,
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: Some(error),
            failures: Vec::new(),
        }
    }

    fn to_json(&self) -> String {
        let best_height = self
            .best_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let best_peer_height = self
            .best_peer_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let estimated_tip_height = self
            .estimated_tip_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let error = self
            .error
            .as_ref()
            .map(|error| format!(r#""{}""#, json_escape(error)))
            .unwrap_or_else(|| "null".to_owned());
        let failures = self
            .failures
            .iter()
            .map(NativePeerFailure::to_json)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"{{"status":"{}","attempted":{},"successful":{},"accepted":{},"failed":{},"peerCount":{},"peerGroups":{},"bestHeight":{},"bestPeerHeight":{},"estimatedTipHeight":{},"resourceCacheEntries":{},"resourceCacheBytes":{},"resourceCacheEvicted":{},"error":{},"failures":[{}]}}"#,
            self.status,
            self.attempted,
            self.successful,
            self.accepted,
            self.failed,
            self.peer_count,
            self.peer_groups,
            best_height,
            best_peer_height,
            estimated_tip_height,
            self.resource_cache_entries,
            self.resource_cache_bytes,
            self.resource_cache_evicted,
            error,
            failures,
        )
    }
}

impl NativePeerFailure {
    fn to_json(&self) -> String {
        format!(
            r#"{{"address":"{}","stage":"{}","error":"{}"}}"#,
            json_escape(&self.address),
            self.stage,
            json_escape(&self.error),
        )
    }
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            character if character.is_control() => {
                format!("\\u{:04x}", character as u32).chars().collect()
            }
            character => vec![character],
        })
        .collect()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeVersion(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    env.new_string(core_version())
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeGatewayHttpResponse(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    body: JByteArray<'_>,
) -> jbyteArray {
    let response = jni_gateway_http_response(
        &mut env,
        JniGatewayHttpRequest {
            data_dir,
            method,
            scheme,
            host,
            port,
            path_and_query,
            header_text,
            body,
        },
    );
    match response.and_then(|bytes| env.byte_array_from_slice(&bytes).ok()) {
        Some(array) => array.into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeGatewayHttpResponseBodyToFile(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    body: JByteArray<'_>,
    body_path: JString<'_>,
) -> jbyteArray {
    let response = jni_gateway_http_response_body_to_file(
        &mut env,
        JniGatewayHttpRequest {
            data_dir,
            method,
            scheme,
            host,
            port,
            path_and_query,
            header_text,
            body,
        },
        body_path,
    );
    match response.and_then(|bytes| env.byte_array_from_slice(&bytes).ok()) {
        Some(array) => array.into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeGatewayHttpUpgradeTunnel(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    client_input: JObject<'_>,
    client_output: JObject<'_>,
) -> jboolean {
    if jni_gateway_http_upgrade_tunnel(
        &mut env,
        data_dir,
        method,
        scheme,
        host,
        port,
        path_and_query,
        header_text,
        client_input,
        client_output,
    ) {
        1
    } else {
        0
    }
}

fn jni_gateway_http_response(
    env: &mut JNIEnv<'_>,
    input: JniGatewayHttpRequest<'_>,
) -> Option<Vec<u8>> {
    let data_dir = env
        .get_string(&input.data_dir)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let method = env
        .get_string(&input.method)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let scheme = env
        .get_string(&input.scheme)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let host = env
        .get_string(&input.host)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let path_and_query = env
        .get_string(&input.path_and_query)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let header_text = env
        .get_string(&input.header_text)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let body = env.convert_byte_array(&input.body).ok()?;
    let port = u16::try_from(input.port).ok()?;
    Some(gateway_http_response(GatewayHttpRequestInput {
        data_dir: &data_dir,
        method: &method,
        scheme: &scheme,
        host: &host,
        port,
        path_and_query: &path_and_query,
        header_text: &header_text,
        body: &body,
    }))
}

fn jni_gateway_http_response_body_to_file(
    env: &mut JNIEnv<'_>,
    input: JniGatewayHttpRequest<'_>,
    body_path: JString<'_>,
) -> Option<Vec<u8>> {
    let data_dir = env
        .get_string(&input.data_dir)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let method = env
        .get_string(&input.method)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let scheme = env
        .get_string(&input.scheme)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let host = env
        .get_string(&input.host)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let path_and_query = env
        .get_string(&input.path_and_query)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let header_text = env
        .get_string(&input.header_text)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let output_path = env
        .get_string(&body_path)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let body = env.convert_byte_array(&input.body).ok()?;
    let port = u16::try_from(input.port).ok()?;
    gateway_http_response_body_to_file(
        GatewayHttpRequestInput {
            data_dir: &data_dir,
            method: &method,
            scheme: &scheme,
            host: &host,
            port,
            path_and_query: &path_and_query,
            header_text: &header_text,
            body: &body,
        },
        Path::new(&output_path),
    )
    .ok()
}

#[allow(clippy::too_many_arguments)]
fn jni_gateway_http_upgrade_tunnel(
    env: &mut JNIEnv<'_>,
    data_dir: JString<'_>,
    method: JString<'_>,
    scheme: JString<'_>,
    host: JString<'_>,
    port: jint,
    path_and_query: JString<'_>,
    header_text: JString<'_>,
    client_input: JObject<'_>,
    client_output: JObject<'_>,
) -> bool {
    let data_dir = match env.get_string(&data_dir) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let method = match env.get_string(&method) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let scheme = match env.get_string(&scheme) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let host = match env.get_string(&host) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let path_and_query = match env.get_string(&path_and_query) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let header_text = match env.get_string(&header_text) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let port = match u16::try_from(port) {
        Ok(port) => port,
        Err(_) => return false,
    };
    let vm = match env.get_java_vm() {
        Ok(vm) => Arc::new(vm),
        Err(_) => return false,
    };
    let client_input = match env.new_global_ref(&client_input) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let client_output = match env.new_global_ref(&client_output) {
        Ok(stream) => stream,
        Err(_) => return false,
    };

    gateway_http_upgrade_tunnel(
        GatewayHttpRequestInput {
            data_dir: &data_dir,
            method: &method,
            scheme: &scheme,
            host: &host,
            port,
            path_and_query: &path_and_query,
            header_text: &header_text,
            body: &[],
        },
        JavaInputStream::new(Arc::clone(&vm), client_input),
        JavaOutputStream::new(vm, client_output),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeDiagnostics(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    env.new_string(diagnostics_json())
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeSyncOnce(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
) -> jstring {
    let status = env
        .get_string(&data_dir)
        .ok()
        .map(|value| sync_once(&value.to_string_lossy()))
        .unwrap_or_else(|| NativeSyncStatus::error("invalid data directory".to_owned()).to_json());

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeSyncStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
) -> jstring {
    let status = env
        .get_string(&data_dir)
        .ok()
        .map(|value| sync_status(&value.to_string_lossy()))
        .unwrap_or_else(|| NativeSyncStatus::error("invalid data directory".to_owned()).to_json());

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeClearResolverCache(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
) -> jstring {
    let status = env
        .get_string(&data_dir)
        .ok()
        .map(|value| clear_resolver_cache(&value.to_string_lossy()))
        .unwrap_or_else(|| NativeSyncStatus::error("invalid data directory".to_owned()).to_json());

    env.new_string(status)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeHnsProofDetails(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    host: JString<'_>,
) -> jstring {
    let details = match (env.get_string(&data_dir), env.get_string(&host)) {
        (Ok(data_dir), Ok(host)) => {
            hns_proof_details(&data_dir.to_string_lossy(), &host.to_string_lossy())
        }
        _ => hns_proof_details_error_json("", "invalid proof detail input"),
    };

    env.new_string(details)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_handshake_browser_net_NativeBridge_nativeLocalTlsCertificate(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    host: JString<'_>,
) -> jbyteArray {
    let bundle = env
        .get_string(&host)
        .ok()
        .and_then(|value| local_tls_certificate_bundle(&value.to_string_lossy()));

    match bundle.and_then(|bytes| env.byte_array_from_slice(&bytes).ok()) {
        Some(array) => array.into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_chain::{HeaderStore, StoredHeader};
    use hns_core::dns::DnsName;
    use hns_core::hash::blake2b_256;
    use hns_core::pow::Chainwork;
    use hns_core::resource::ResourceError;
    use hns_core::{Hash, Height, NameHash};
    use hns_p2p::{Packet, PeerManager, ProofPacket};
    use hns_resolver::{HnsResourceValueProvider, VerifiedResourceValue};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn version_is_stable() {
        assert_eq!(core_version(), "hns-browser-rust-core/0.2.3");
    }

    #[test]
    fn diagnostics_reports_fail_closed_security() {
        assert!(diagnostics_json().contains(r#""securityDefault":"fail-closed""#));
    }

    #[test]
    fn diagnostics_reports_resource_decoder() {
        assert!(diagnostics_json().contains(r#""hns-resource-decoder""#));
    }

    #[test]
    fn diagnostics_reports_verified_resource_handoff() {
        assert!(diagnostics_json().contains(r#""header-canonical-height-index""#));
        assert!(diagnostics_json().contains(r#""header-mainnet-difficulty-retarget""#));
        assert!(diagnostics_json().contains(r#""urkel-proof-value-handoff""#));
        assert!(diagnostics_json().contains(r#""hns-resource-provider-adapter""#));
        assert!(diagnostics_json().contains(r#""hns-memory-resource-provider""#));
        assert!(diagnostics_json().contains(r#""hns-sqlite-resource-provider""#));
        assert!(diagnostics_json().contains(r#""hns-negative-cache""#));
        assert!(diagnostics_json().contains(r#""hns-ttl-cache-lru""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-stats""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-eviction""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-cap-enforcement""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-chain-anchors""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-reorg-invalidation""#));
        assert!(diagnostics_json().contains(r#""hns-resource-cache-current-tip""#));
        assert!(diagnostics_json().contains(r#""hns-delegating-resolver-boundary""#));
        assert!(diagnostics_json().contains(r#""hns-name-state-resource-extraction""#));
        assert!(diagnostics_json().contains(r#""hns-proof-backed-ns-address-hydration""#));
        assert!(diagnostics_json().contains(r#""hns-authoritative-dnssec-delegated-resolver""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-no-data-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-cname-chain""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-referral-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-cname-chain""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-no-data-validation""#));
        assert!(diagnostics_json().contains(r#""gateway-cname-address-routing""#));
        assert!(diagnostics_json().contains(r#""android-actionable-hns-errors""#));
        assert!(diagnostics_json().contains(r#""hns-name-not-found-error""#));
        assert!(diagnostics_json().contains(r#""gateway-hns-address-required""#));
        assert!(diagnostics_json().contains(r#""gateway-tlsa-service-scope""#));
    }

    #[test]
    fn diagnostics_reports_ed25519_dnssec() {
        assert!(diagnostics_json().contains(r#""dnssec-ed25519-verify""#));
    }

    #[test]
    fn diagnostics_reports_sha384_ds_digest() {
        assert!(diagnostics_json().contains(r#""dnssec-ds-sha1""#));
        assert!(diagnostics_json().contains(r#""dnssec-ds-sha384""#));
        assert!(diagnostics_json().contains(r#""dnssec-rsa-sha1-verify""#));
    }

    #[test]
    fn diagnostics_reports_tcp_peer_connection() {
        assert!(diagnostics_json().contains(r#""p2p-tcp-peer-connection""#));
        assert!(diagnostics_json().contains(r#""p2p-static-peer-source""#));
        assert!(diagnostics_json().contains(r#""p2p-dns-seed-source""#));
        assert!(diagnostics_json().contains(r#""p2p-getaddr-peer-discovery""#));
        assert!(diagnostics_json().contains(r#""p2p-discovery-rotation""#));
        assert!(diagnostics_json().contains(r#""p2p-peer-diversity""#));
        assert!(diagnostics_json().contains(r#""p2p-sqlite-peer-store""#));
    }

    #[test]
    fn diagnostics_reports_sync_proof_scheduler() {
        assert!(diagnostics_json().contains(r#""sync-header-runner""#));
        assert!(diagnostics_json().contains(r#""sync-multi-batch-header-runner""#));
        assert!(diagnostics_json().contains(r#""sync-parallel-peer-probing""#));
        assert!(diagnostics_json().contains(r#""sync-ranged-peer-rotation""#));
        assert!(diagnostics_json().contains(r#""sync-proof-scheduler""#));
        assert!(diagnostics_json().contains(r#""android-native-sync-once""#));
        assert!(diagnostics_json().contains(r#""android-sync-status""#));
        assert!(diagnostics_json().contains(r#""android-sync-outcome-status""#));
        assert!(diagnostics_json().contains(r#""android-sync-progress-heights""#));
        assert!(diagnostics_json().contains(r#""android-sync-high-batch-catchup""#));
        assert!(diagnostics_json().contains(r#""android-clear-resolver-cache""#));
        assert!(diagnostics_json().contains(r#""android-persistent-gateway-resolver""#));
        assert!(diagnostics_json().contains(r#""android-gateway-live-proof-fetch""#));
        assert!(diagnostics_json().contains(r#""android-gateway-header-forwarding""#));
        assert!(diagnostics_json().contains(r#""android-gateway-range-forwarding""#));
        assert!(diagnostics_json().contains(r#""android-gateway-body-forwarding""#));
        assert!(diagnostics_json().contains(r#""android-gateway-file-body-stream""#));
        assert!(diagnostics_json().contains(r#""android-webview-hns-intercept""#));
        assert!(diagnostics_json().contains(r#""android-service-worker-hns-intercept""#));
        assert!(diagnostics_json().contains(r#""android-hns-redirect-follow""#));
        assert!(diagnostics_json().contains(r#""android-hns-doh-compat-resolver""#));
        assert!(diagnostics_json().contains(r#""android-random-loopback-proxy-port""#));
    }

    #[test]
    fn diagnostics_reports_websocket_native_tunnel() {
        let diagnostics = diagnostics_json();

        assert!(diagnostics.contains(r#""hns-websocket-native-tunnel""#));
        assert!(diagnostics.contains(r#""http-origin-connection-pooling""#));
        assert!(diagnostics.contains(r#""https-tls-session-resumption""#));
        assert!(diagnostics.contains(r#""https-alt-svc-promotion""#));
    }

    #[test]
    fn diagnostics_reports_origin_transport_framing() {
        assert!(diagnostics_json().contains(r#""http-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http2-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http3-origin-transport""#));
        assert!(diagnostics_json().contains(r#""http-origin-response-framing""#));
        assert!(diagnostics_json().contains(r#""https-rustls-transport""#));
        assert!(diagnostics_json().contains(r#""dane-certificate-chain-policy""#));
        assert!(diagnostics_json().contains(r#""dane-tls-policy""#));
    }

    #[test]
    fn diagnostics_reports_android_connect_certificate_generation() {
        assert!(diagnostics_json().contains(r#""android-local-hns-connect-certs""#));
    }

    #[test]
    fn diagnostics_reports_delegated_gateway_policy() {
        assert!(diagnostics_json().contains(r#""hns-dotted-root-label""#));
        assert!(diagnostics_json().contains(r#""dnssec-delegated-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-child-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""dnssec-nxdomain-name-error-validation""#));
        assert!(diagnostics_json().contains(r#""gateway-delegated-origin-address-lookup""#));
        assert!(diagnostics_json().contains(r#""gateway-origin-address-query""#));
        assert!(diagnostics_json().contains(r#""gateway-https-service-query""#));
        assert!(diagnostics_json().contains(r#""gateway-svcb-alpn-policy""#));
        assert!(diagnostics_json().contains(r#""gateway-actionable-nameserver-errors""#));
    }

    #[test]
    fn local_tls_certificate_bundle_contains_cert_key_and_fingerprint() {
        let bundle = local_tls_certificate_bundle("Welcome.").unwrap();
        let (cert_der, key_der, fingerprint) = parse_local_tls_bundle(&bundle);

        assert!(cert_der.len() > 128);
        assert!(key_der.len() > 64);
        assert_eq!(fingerprint, Sha256::digest(cert_der).as_slice());
    }

    #[test]
    fn local_tls_certificate_bundle_rejects_invalid_hosts() {
        assert!(local_tls_certificate_bundle("").is_none());
        assert!(local_tls_certificate_bundle("127.0.0.1").is_none());
        assert!(local_tls_certificate_bundle("[::1]").is_none());
        assert!(local_tls_certificate_bundle("-bad").is_none());
        assert!(local_tls_certificate_bundle("bad_label").is_none());
    }

    fn parse_local_tls_bundle(bundle: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let cert_len = u32::from_be_bytes(bundle[0..4].try_into().unwrap()) as usize;
        let cert_start = 4;
        let cert_end = cert_start + cert_len;
        let key_len =
            u32::from_be_bytes(bundle[cert_end..cert_end + 4].try_into().unwrap()) as usize;
        let key_start = cert_end + 4;
        let key_end = key_start + key_len;
        let fingerprint_end = key_end + LOCAL_TLS_CERT_FINGERPRINT_BYTES;
        assert_eq!(fingerprint_end, bundle.len());
        (
            &bundle[cert_start..cert_end],
            &bundle[key_start..key_end],
            &bundle[key_end..fingerprint_end],
        )
    }

    #[test]
    fn sync_once_initializes_persistent_stores_without_seed_network() {
        let path = temp_dir_path("sync-once");

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.status, "idle");
        assert_eq!(status.attempted, 0);
        assert_eq!(status.successful, 0);
        assert_eq!(status.accepted, 0);
        assert_eq!(status.failed, 0);
        assert!(status.failures.is_empty());
        assert_eq!(status.peer_count, 0);
        assert_eq!(status.peer_groups, 0);
        assert_eq!(status.best_height, Some(0));
        assert_eq!(status.best_peer_height, None);
        assert_eq!(status.resource_cache_entries, 0);
        assert_eq!(status.resource_cache_bytes, 0);
        assert_eq!(status.resource_cache_evicted, 0);
        assert!(path.join("hns/headers.sqlite").exists());
        assert!(path.join("hns/peers.sqlite").exists());

        let json = sync_status(path.to_str().unwrap());
        assert!(json.contains(r#""status":"idle""#));
        assert!(json.contains(r#""failed":0"#));
        assert!(json.contains(r#""failures":[]"#));
        assert!(json.contains(r#""peerCount":0"#));
        assert!(json.contains(r#""peerGroups":0"#));
        assert!(json.contains(r#""bestHeight":0"#));
        assert!(json.contains(r#""resourceCacheEntries":0"#));
        assert!(json.contains(r#""resourceCacheBytes":0"#));
        assert!(json.contains(r#""resourceCacheEvicted":0"#));

        cleanup_dir(&path);
    }

    #[test]
    fn cached_sync_status_classifier_reports_up_to_date_without_network() {
        assert_eq!(
            classify_cached_sync_status(Some(335_591), Some(335_591)),
            "up_to_date",
        );
        assert_eq!(
            classify_cached_sync_status(Some(335_591), Some(335_590)),
            "up_to_date",
        );
        assert_eq!(
            classify_cached_sync_status(Some(335_590), Some(335_591)),
            "syncing",
        );
        assert_eq!(classify_cached_sync_status(Some(0), Some(0)), "idle");
        assert_eq!(classify_cached_sync_status(Some(10), None), "syncing");
    }

    #[test]
    fn live_proof_peer_selection_ignores_zero_height_failed_peers() {
        let stale: SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let current: SocketAddr = "127.0.0.3:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        for _ in 0..32 {
            peers.record_transient_failure(stale);
        }
        peers.record_success(current, Height(336_034), 1_000);

        let selected = select_live_proof_peers(&peers, 8, 1_100, Height(336_034));

        assert_eq!(selected, vec![current]);
    }

    #[test]
    fn sync_status_json_reports_peer_failures() {
        let status = NativeSyncStatus {
            status: "peer_failed",
            attempted: 1,
            successful: 0,
            accepted: 0,
            failed: 1,
            peer_count: 1,
            peer_groups: 1,
            best_height: Some(0),
            best_peer_height: None,
            estimated_tip_height: Some(335_684),
            resource_cache_entries: 0,
            resource_cache_bytes: 0,
            resource_cache_evicted: 0,
            error: Some("all 1 attempted sync peers failed; see failures".to_owned()),
            failures: vec![NativePeerFailure {
                address: "127.0.0.1:12038".to_owned(),
                stage: "connect",
                error: "connection \"closed\"\n".to_owned(),
            }],
        };

        let json = status.to_json();

        assert!(json.contains(r#""status":"peer_failed""#));
        assert!(json.contains(r#""failed":1"#));
        assert!(json.contains(r#""estimatedTipHeight":335684"#));
        assert!(json.contains(r#""error":"all 1 attempted sync peers failed; see failures""#,));
        assert!(json.contains(
            r#""failures":[{"address":"127.0.0.1:12038","stage":"connect","error":"connection \"closed\"\n"}]"#,
        ));
    }

    #[test]
    fn sync_status_classifier_reports_up_to_date_and_peer_failed() {
        assert_eq!(
            classify_sync_status(4, 1, 0, 3, false, Some(335_591), Some(335_591)),
            "up_to_date",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(335_591), Some(335_591)),
            "synced",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(45_000), Some(335_684)),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 1, 2, 3, false, Some(92_000), None),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 1, 0, 3, false, Some(93_344), Some(335_684)),
            "syncing",
        );
        assert_eq!(
            classify_sync_status(4, 0, 0, 4, false, Some(0), Some(335_684)),
            "peer_failed",
        );
        assert_eq!(
            classify_sync_status(4, 0, 0, 2, false, Some(0), Some(335_684)),
            "attempted",
        );
        assert_eq!(
            classify_sync_status(0, 0, 0, 0, true, None, None),
            "seed_failed",
        );
        assert_eq!(classify_sync_status(0, 0, 0, 0, false, None, None), "idle");
    }

    #[test]
    fn sync_once_enforces_resource_cache_limit_and_clear_removes_cache() {
        let path = temp_dir_path("resource-cache-limit");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        let anchor_root = Hash::new([3; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    "alpha".to_owned(),
                    alpha_hash,
                    vec![1, 2, 3, 4, 5, 6],
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![7, 8])
                    .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let status =
            sync_once_with_options(path.to_str().unwrap(), false, Duration::from_millis(1), 2);

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 1);
        assert_eq!(status.resource_cache_bytes, 2);

        let clear_json = clear_resolver_cache(path.to_str().unwrap());
        assert!(clear_json.contains(r#""status":"cleared""#));
        assert!(clear_json.contains(r#""resourceCacheEntries":0"#));
        assert!(clear_json.contains(r#""resourceCacheBytes":0"#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_prunes_resource_cache_entries_not_on_best_chain() {
        let path = temp_dir_path("resource-cache-reorg");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(hns_core::Hash::new([9; 32]), hns_core::Height(0)),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 0);
        assert_eq!(status.resource_cache_bytes, 0);

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_keeps_resource_cache_entries_on_recent_canonical_chain() {
        let path = temp_dir_path("resource-cache-recent-canonical");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let older_root = Hash::new([3; 32]);
        let current_root = Hash::new([4; 32]);
        let heights = store_canonical_headers_with_tree_roots(&base, &[older_root, current_root]);
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(older_root, heights[0]),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![3])
                    .with_anchor(current_root, heights[1]),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 0);
        assert_eq!(status.resource_cache_entries, 2);
        assert_eq!(status.resource_cache_bytes, 3);

        cleanup_dir(&path);
    }

    #[test]
    fn sync_once_prunes_resource_cache_entries_not_on_recent_canonical_chain() {
        let path = temp_dir_path("resource-cache-stale-tip");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let current_root = Hash::new([4; 32]);
        let current_height = store_best_header_with_tree_root(&base, current_root);
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1, 2])
                    .with_anchor(BlockHeader::mainnet_genesis().tree_root, Height(0)),
            )
            .unwrap();
        resources
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![3])
                    .with_anchor(current_root, current_height),
            )
            .unwrap();

        let status = sync_once_with_options(
            path.to_str().unwrap(),
            false,
            Duration::from_millis(1),
            DEFAULT_RESOURCE_CACHE_LIMIT_BYTES,
        );

        assert_eq!(status.resource_cache_evicted, 1);
        assert_eq!(status.resource_cache_entries, 1);
        assert_eq!(status.resource_cache_bytes, 1);

        cleanup_dir(&path);
    }

    #[test]
    fn hns_proof_details_reports_cached_resource_anchor_and_records() {
        let path = temp_dir_path("proof-details-cached");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([8; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        let resource = owner_glue4_resource(&root_name, [127, 0, 0, 1]);
        resources
            .insert(
                VerifiedResourceValue::inclusion(root_name.clone(), name_hash, resource.clone())
                    .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let json = hns_proof_details(path.to_str().unwrap(), "www.welcome/");

        assert!(json.contains(r#""host":"www.welcome""#));
        assert!(json.contains(r#""name":"welcome""#));
        assert!(json.contains(&format!(r#""nameHash":"{}""#, name_hash.as_hash())));
        assert!(json.contains(r#""proofStatus":"verified""#));
        assert!(json.contains(r#""cacheStatus":"anchored_to_current_tip""#));
        assert!(json.contains(&format!(r#""treeRoot":"{}""#, anchor_root)));
        assert!(json.contains(r#""blockHeight":1"#));
        assert!(json.contains(&format!(r#""resourceValueHex":"{}""#, hex_lower(&resource))));
        assert!(json.contains(r#""recordTypes":["A","NS"]"#));
        assert!(json.contains(r#""type":"NS""#));
        assert!(json.contains(r#""type":"A""#));
        assert!(json.contains(r#""currentTip":{"height":1"#));

        cleanup_dir(&path);
    }

    #[test]
    fn hns_proof_details_reports_missing_resource_cache() {
        let path = temp_dir_path("proof-details-missing-cache");

        let json = hns_proof_details(path.to_str().unwrap(), "missing");

        assert!(json.contains(r#""host":"missing""#));
        assert!(json.contains(r#""name":"missing""#));
        assert!(json.contains(r#""proofStatus":"unavailable""#));
        assert!(json.contains(r#""cacheStatus":"resource_cache_missing""#));
        assert!(json.contains(r#""resourceValueHex":null"#));
        assert!(json.contains(r#""error":"resource cache is not initialized""#));

        cleanup_dir(&path);
    }

    #[test]
    fn sync_status_json_escapes_errors() {
        let json = NativeSyncStatus::error("bad \"path\"\n".to_owned()).to_json();

        assert!(json.contains(r#""status":"error""#));
        assert!(json.contains(r#""error":"bad \"path\"\n""#));
    }

    #[test]
    fn origin_response_suppresses_spoofed_hns_tls_policy_origin_headers() {
        let response = origin_response(OriginResponse {
            status: 200,
            headers: vec![("X-HNS-TLS-Policy".to_owned(), "origin".to_owned())],
            body: b"ok".to_vec(),
            dane_decision: DaneDecision::WebPkiFallback,
            tls_inspection: None,
        });
        let text = String::from_utf8(response).unwrap();

        assert!(!text.contains("X-HNS-TLS-Policy: origin\r\n"));
        assert!(text.contains("X-HNS-TLS-Policy: webpki-fallback\r\n"));
    }

    #[test]
    fn origin_response_reports_hns_resolver_policy_after_tls_policy() {
        let response = origin_response_with_resolver_policy(
            OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::Matched(hns_dane::TlsaUsage::DaneEe),
                tls_inspection: None,
            },
            Some("hns-doh-compat"),
        );
        let text = String::from_utf8(response).unwrap();

        assert!(
            text.contains("X-HNS-TLS-Policy: dane\r\nX-HNS-Resolver-Policy: hns-doh-compat\r\n",)
        );
    }

    #[test]
    fn gateway_headers_strip_internal_strict_mode_control_header() {
        let parsed =
            parse_gateway_headers("Accept: text/html\r\nX-HNS-Browser-Strict-Mode: 1\r\n").unwrap();

        assert!(parsed.strict_hns_mode);
        assert_eq!(
            parsed.headers,
            vec![("Accept".to_owned(), "text/html".to_owned())]
        );
    }

    #[test]
    fn origin_response_includes_resolution_trace_headers() {
        let response = origin_response_with_resolver_policy_and_trace(
            OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::NoTlsa,
                tls_inspection: None,
            },
            None,
            r#"{"mode":"strict","fallback":{"used":false}}"#,
        );
        let text = String::from_utf8(response).unwrap();

        assert!(text.contains("X-HNS-Resolver-Mode: strict\r\n"));
        assert!(text.contains("X-HNS-DoH-Fallback: no\r\n"));
        assert!(text.contains(
            "X-HNS-Resolution-Trace: {\"mode\":\"strict\",\"fallback\":{\"used\":false}}\r\n",
        ));
    }

    #[test]
    fn resolution_trace_reports_authoritative_dns_attempts() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "udp53",
            server: "192.0.2.53:53".to_owned(),
            status: "timeout".to_owned(),
            elapsed_ms: 901,
            error: Some("operation timed out".to_owned()),
        });
        dns_trace.push(DnsTraceEvent {
            protocol: "tcp53",
            server: "192.0.2.53:53".to_owned(),
            status: "transport_error".to_owned(),
            elapsed_ms: 12,
            error: Some("connection refused".to_owned()),
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "nathan.woodburn",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            GatewayResolutionMode::Strict,
            None,
            TlsTraceInput::default(),
            Some(&GatewayError::Resolver(ResolverError::DnsTransport(
                "operation timed out".to_owned(),
            ))),
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(
            trace.contains(r#""authoritativeDns":{"udp53":"timeout","tcp53":"transport_error"}"#)
        );
        assert!(trace.contains(r#""nameserverCandidates":["192.0.2.53:53"]"#));
        assert!(
            trace.contains(r#""protocol":"udp53","server":"192.0.2.53:53","status":"timeout""#)
        );
        assert!(trace.contains(r#""elapsedMs":901"#));
    }

    #[test]
    fn resolution_trace_marks_authoritative_dns_as_delegated() {
        let dns_trace = DnsTraceRecorder::default();
        dns_trace.push(DnsTraceEvent {
            protocol: "udp53",
            server: "192.0.2.53:53".to_owned(),
            status: "ok".to_owned(),
            elapsed_ms: 19,
            error: None,
        });
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "denuoweb",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            GatewayResolutionMode::Compatibility,
            Some(&ResolutionAnswer {
                name: DnsName::from_ascii("denuoweb").unwrap(),
                records: vec![address_record("denuoweb", [35, 212, 156, 128])],
                secure: true,
            }),
            TlsTraceInput::default(),
            None,
            &FallbackMarker::default(),
            &dns_trace,
        );

        assert!(trace.contains(r#""delegation":true"#));
        assert!(trace.contains(r#""resourceRecords":["A"]"#));
        assert!(trace.contains(r#""fallback":{"used":false"#));
    }

    #[test]
    fn resolution_trace_reports_tlsa_and_dane_details() {
        let tlsa = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: vec![0xaa, 0xbb],
        };
        let tls = TlsValidation::hns_compatibility(true, vec![tlsa]);
        let inspection = TlsCertificateInspection {
            end_entity_der: b"cert".to_vec(),
            end_entity_spki_der: b"spki".to_vec(),
            intermediate_der: vec![b"issuer".to_vec()],
            webpki_status: hns_dane::WebPkiStatus::Invalid,
        };
        let trace = resolution_trace_json(
            &GatewayHttpRequestInput {
                data_dir: "/tmp",
                method: "GET",
                scheme: "https",
                host: "nathan.woodburn",
                port: 443,
                path_and_query: "/",
                header_text: "",
                body: &[],
            },
            GatewayResolutionMode::Compatibility,
            None,
            TlsTraceInput {
                validation: Some(&tls),
                decision: Some(&DaneDecision::Matched(TlsaUsage::DaneEe)),
                inspection: Some(&inspection),
            },
            None,
            &FallbackMarker::default(),
            &DnsTraceRecorder::default(),
        );

        assert!(trace.contains(r#""tlsaOwner":"_443._tcp.nathan.woodburn""#));
        assert!(trace.contains(r#""tlsaFound":true"#));
        assert!(trace.contains(r#""dnssecSecure":true"#));
        assert!(trace.contains(
            r#""usage":"DANE-EE","selector":"SPKI","matching":"SHA-256","associationDataHex":"aabb""#
        ));
        assert!(trace.contains(r#""webPkiStatus":"invalid""#));
        assert!(trace.contains(&format!(r#""spkiSha256":"{}""#, sha256_hex(b"spki"))));
        assert!(trace.contains(r#""spkiDerHex":"73706b69""#));
        assert!(trace.contains(r#""intermediateCount":1"#));
        assert!(trace.contains(
            r#""dane":{"decision":"verified","matchedUsage":"DANE-EE","certificateMatch":"pass","webPkiFallback":false}"#
        ));
    }

    #[test]
    fn fallback_resolver_uses_doh_on_nameserver_transport_error() {
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("nathan.woodburn").unwrap(),
            records: vec![address_record("nathan.woodburn", [103, 152, 197, 116])],
            secure: true,
        };
        let resolver = FallbackResolver::new(
            TestResolver::error(|| ResolverError::DnsTransport("closed".to_owned())),
            TestResolver::answer(answer.clone()),
        );

        let resolved = resolver
            .resolve(&ResolutionRequest {
                qname: "nathan.woodburn".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert_eq!(resolved, answer);
    }

    #[test]
    fn fallback_resolver_skips_primary_after_root_fallback() {
        use std::sync::atomic::AtomicUsize;

        let primary_calls = Arc::new(AtomicUsize::new(0));
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("shakeshift").unwrap(),
            records: vec![address_record("shakeshift", [203, 0, 113, 10])],
            secure: true,
        };
        let resolver = FallbackResolver::new(
            CountingErrorResolver {
                calls: primary_calls.clone(),
                error: || ResolverError::DnsTransport("closed".to_owned()),
            },
            TestResolver::answer(answer),
        );

        resolver
            .resolve(&ResolutionRequest {
                qname: "shakeshift".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap();
        resolver
            .resolve(&ResolutionRequest {
                qname: "_443._tcp.shakeshift".to_owned(),
                qtype: RecordType::Tlsa.code(),
            })
            .unwrap();

        assert_eq!(primary_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fallback_resolver_uses_doh_on_proof_unavailable_in_compatibility_mode() {
        let marker = FallbackMarker::default();
        let answer = ResolutionAnswer {
            name: DnsName::from_ascii("welcome").unwrap(),
            records: vec![address_record("welcome", [127, 0, 0, 1])],
            secure: true,
        };
        let resolver = FallbackResolver::with_marker(
            TestResolver::error(|| ResolverError::ProofUnavailable),
            TestResolver::answer(answer.clone()),
            marker.clone(),
        );

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap(),
            answer,
        );
        assert_eq!(marker.reason(), Some("local_hns_proof_unavailable"));
    }

    #[test]
    fn strict_resolver_keeps_proof_errors_fail_closed() {
        let resolver = TestResolver::error(|| ResolverError::ProofUnavailable);

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
    }

    #[test]
    fn doh_response_parser_uses_ad_bit_for_secure_answers() {
        let qname = DnsName::from_ascii("nathan.woodburn").unwrap();
        let answer_record = address_record("nathan.woodburn", [103, 152, 197, 116]);
        let message = DnsMessage {
            header: DnsHeader {
                id: 0x1234,
                flags: DnsFlags::new(0x81a0),
                question_count: 1,
                answer_count: 1,
                authority_count: 0,
                additional_count: 2,
            },
            questions: vec![DnsQuestion {
                name: qname.clone(),
                record_type: RecordType::A,
                class: DNS_CLASS_IN,
            }],
            answers: vec![answer_record.clone()],
            authorities: Vec::new(),
            additionals: vec![
                ResourceRecord {
                    name: DnsName::root(),
                    record_type: RecordType::Unknown(DNS_OPT_RECORD_TYPE),
                    class: DEFAULT_DNS_UDP_PAYLOAD as u16,
                    ttl: DNSSEC_DO_FLAG,
                    rdata: vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
                },
                ResourceRecord {
                    name: DnsName::root(),
                    record_type: RecordType::Unknown(24),
                    class: 255,
                    ttl: 0,
                    rdata: vec![0, 253, 0, 0, 0, 0, 0, 0],
                },
            ],
        };
        let body = message
            .encode(&DnsEncodeConfig {
                max_message_len: 4096,
            })
            .unwrap();

        let answer = doh_answer_from_body(0x1234, &qname, RecordType::A, &body).unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records, vec![answer_record]);
    }

    #[test]
    fn gateway_response_fails_closed_without_resolver_backend() {
        let path = temp_dir_path("gateway-empty");
        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: "welcome",
            port: 80,
            path_and_query: "/",
            header_text: "X-HNS-Browser-Strict-Mode: 1\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 503 HNS Proof Unavailable\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_rejects_malformed_forwarded_headers() {
        let path = temp_dir_path("gateway-bad-headers");
        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: "welcome",
            port: 80,
            path_and_query: "/",
            header_text: "not-a-header\r\n",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(text.ends_with("http://welcome/\n400 Bad Request\nrequest header is malformed\n"));
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_errors_are_mapped_to_actionable_hns_stages() {
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::ProofUnavailable)),
            (
                503,
                "HNS Proof Unavailable",
                "No current verified HNS proof is available for this name.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::NameNotFound)),
            (
                404,
                "HNS Name Not Found",
                "A verified HNS non-inclusion proof says this name does not exist.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::NoNameserverAddress)),
            (
                502,
                "HNS Nameserver Unavailable",
                "No verified nameserver address is available for this HNS delegation.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::DnsTransport(
                "timeout".to_owned(),
            ))),
            (
                502,
                "HNS Nameserver Unavailable",
                "Delegated HNS nameserver transport failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::InvalidDnsResponse)),
            (
                502,
                "HNS Nameserver Response Invalid",
                "Delegated HNS nameserver response was invalid or lacked required secure denial data.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::DnssecFailed)),
            (
                502,
                "HNS DNSSEC Validation Failed",
                "Delegated HNS DNSSEC validation failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Resolver(ResolverError::InvalidResource(
                ResourceError::Malformed,
            ))),
            (
                502,
                "HNS Resource Invalid",
                "Verified HNS resource data is malformed or unsupported.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::InsecureResolution),
            (
                502,
                "HNS DNSSEC Validation Failed",
                "Secure HNS resolution was required but the resolver returned an insecure result.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::NoResolvedAddress),
            (
                502,
                "HNS Origin Address Missing",
                "Secure HNS resolution did not produce an origin A or AAAA address.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::DaneFailed)),
            (
                502,
                "HNS DANE Validation Failed",
                "DANE/TLSA validation failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::UnsupportedSvcb),
            (
                502,
                "HNS HTTPS Service Unsupported",
                "HTTPS/SVCB service binding is malformed or requires unsupported transport policy.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Io(
                "refused".to_owned(),
            ))),
            (
                502,
                "HNS Origin Transport Failed",
                "Origin connection failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Http3(
                "frame error".to_owned(),
            ))),
            (
                502,
                "HNS HTTP/3 Transport Failed",
                "Origin HTTP/3 exchange failed closed.",
            ),
        );
        assert_eq!(
            map_gateway_error(&GatewayError::Transport(TransportError::Quic(
                "handshake failed".to_owned(),
            ))),
            (
                502,
                "HNS QUIC Transport Failed",
                "Origin QUIC connection failed closed.",
            ),
        );
    }

    #[test]
    fn gateway_response_fetches_hns_http_from_persistent_resource_cache() {
        let path = temp_dir_path("gateway-http");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([5; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\nhi") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /path HTTP/1.1\r\n"));
            assert!(request.contains("Content-Type: text/plain\r\n"));
            assert!(request.contains("X-Test: yes\r\n"));
            assert!(request.contains("Content-Length: 2\r\n"));
            assert!(request.ends_with("\r\n\r\nhi"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "POST",
            scheme: "http",
            host: &root_name,
            port,
            path_and_query: "/path",
            header_text: "Content-Type: text/plain\r\nX-Test: yes\r\n",
            body: b"hi",
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\nok"));
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_accepts_recent_canonical_cached_proof() {
        let path = temp_dir_path("gateway-http-recent-proof");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let proof_root = Hash::new([5; 32]);
        let newer_root = Hash::new([6; 32]);
        let heights = store_canonical_headers_with_tree_roots(&base, &[proof_root, newer_root]);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(proof_root, heights[0]),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0_u8; 512];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("GET /recent HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nrecent",
                )
                .unwrap();
        });

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: &root_name,
            port,
            path_and_query: "/recent",
            header_text: "",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\nrecent"));
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_streams_body_to_file_with_fixed_length_head() {
        let path = temp_dir_path("gateway-file-body");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();
        let resources = SqliteResourceValueProvider::open(base.join("resources.sqlite")).unwrap();
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor_root = Hash::new([5; 32]);
        let anchor_height = store_best_header_with_tree_root(&base, anchor_root);
        resources
            .insert(
                VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    owner_glue4_resource(&root_name, [127, 0, 0, 1]),
                )
                .with_anchor(anchor_root, anchor_height),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n4\r\nlive\r\n0\r\n\r\n",
                )
                .unwrap();
        });

        let body_path = path.join("response.body");
        let head = gateway_http_response_body_to_file(
            GatewayHttpRequestInput {
                data_dir: path.to_str().unwrap(),
                method: "GET",
                scheme: "http",
                host: &root_name,
                port,
                path_and_query: "/stream",
                header_text: "",
                body: &[],
            },
            &body_path,
        )
        .unwrap();
        let text = String::from_utf8(head).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 4\r\n"));
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(!text.contains("Transfer-Encoding"));
        assert_eq!(std::fs::read(&body_path).unwrap(), b"live");
        server.join().unwrap();
        cleanup_dir(&path);
    }

    #[test]
    fn gateway_response_fetches_live_proof_on_resource_cache_miss() {
        let path = temp_dir_path("gateway-live-proof");
        let base = path.join("hns");
        std::fs::create_dir_all(&base).unwrap();

        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let value = owner_glue4_resource(&root_name, [127, 0, 0, 1]);
        let name_state_value = name_state_value(&root_name, &value);
        let proof_root = urkel_value_root(name_hash.as_hash(), &name_state_value);
        let proof_height = store_best_header_with_tree_root(&base, proof_root);
        let remote_height = Height(proof_height.0 + 10);

        let proof_payload = urkel_exists_payload(&name_state_value);
        let proof_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proof_address = proof_listener.local_addr().unwrap();
        let proof_server = thread::spawn(move || {
            let (stream, _) = proof_listener.accept().unwrap();
            let mut peer = PeerConnection::new(stream, network::mainnet());
            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_)));
            let version = VersionPacket {
                height: remote_height,
                ..VersionPacket::default()
            };
            peer.send_packet(&Packet::Version(version)).unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();
            match peer.receive_packet().unwrap() {
                Packet::GetProof(request) => {
                    assert_eq!(request.root, proof_root);
                    assert_eq!(request.key, name_hash.as_hash());
                    peer.send_packet(&Packet::Proof(ProofPacket {
                        root: request.root,
                        key: request.key,
                        proof: proof_payload,
                    }))
                    .unwrap();
                }
                other => panic!("unexpected proof peer packet: {other:?}"),
            }
        });

        let peer_store = SqlitePeerStore::open(base.join("peers.sqlite")).unwrap();
        let mut peers = PeerManager::default();
        peers.seed([proof_address]);
        peers.record_observed_height(proof_address, remote_height, now_unix_seconds());
        peer_store.save_manager(&peers).unwrap();

        let origin_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_server = thread::spawn(move || {
            let (mut stream, _) = origin_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0_u8; 512];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("GET /live HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlive")
                .unwrap();
        });

        let response = gateway_http_response(GatewayHttpRequestInput {
            data_dir: path.to_str().unwrap(),
            method: "GET",
            scheme: "http",
            host: &root_name,
            port: origin_port,
            path_and_query: "/live",
            header_text: "",
            body: &[],
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\nlive"));
        let cached = SqliteResourceValueProvider::open(base.join("resources.sqlite"))
            .unwrap()
            .prove_resource_value(&root_name, name_hash)
            .unwrap();
        assert_eq!(cached.value, Some(value));
        assert_eq!(
            cached.anchor,
            Some(ResourceValueAnchor {
                tree_root: proof_root,
                height: proof_height,
            }),
        );
        let peer = peer_store.load_peer(proof_address).unwrap().unwrap();
        assert_eq!(peer.last_height, remote_height);
        proof_server.join().unwrap();
        origin_server.join().unwrap();
        cleanup_dir(&path);
    }

    struct TestResolver {
        outcome: TestResolverOutcome,
    }

    struct CountingErrorResolver {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        error: fn() -> ResolverError,
    }

    enum TestResolverOutcome {
        Answer(ResolutionAnswer),
        Error(fn() -> ResolverError),
    }

    impl TestResolver {
        fn answer(answer: ResolutionAnswer) -> Self {
            Self {
                outcome: TestResolverOutcome::Answer(answer),
            }
        }

        fn error(error: fn() -> ResolverError) -> Self {
            Self {
                outcome: TestResolverOutcome::Error(error),
            }
        }
    }

    impl Resolver for TestResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            match &self.outcome {
                TestResolverOutcome::Answer(answer) => Ok(answer.clone()),
                TestResolverOutcome::Error(error) => Err(error()),
            }
        }
    }

    impl Resolver for CountingErrorResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err((self.error)())
        }
    }

    fn address_record(owner: &str, address: [u8; 4]) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::A,
            class: DNS_CLASS_IN,
            ttl: 20,
            rdata: address.to_vec(),
        }
    }

    fn store_best_header_with_tree_root(base: &std::path::Path, tree_root: Hash) -> Height {
        store_canonical_headers_with_tree_roots(base, &[tree_root])
            .last()
            .copied()
            .unwrap()
    }

    fn store_canonical_headers_with_tree_roots(
        base: &std::path::Path,
        tree_roots: &[Hash],
    ) -> Vec<Height> {
        let genesis_header = BlockHeader::mainnet_genesis();
        let genesis = StoredHeader {
            hash: genesis_header.hash(),
            chainwork: Chainwork::from_bits(genesis_header.bits).unwrap(),
            header: genesis_header,
            height: Height(0),
        };
        let mut headers = vec![genesis.clone()];
        let mut previous = genesis;
        let mut heights = Vec::new();
        for (index, tree_root) in tree_roots.iter().copied().enumerate() {
            let mut header = BlockHeader::mainnet_genesis();
            header.prev_block = previous.hash;
            header.tree_root = tree_root;
            header.time = header.time.saturating_add((index as u64) + 1);
            header.extra_nonce[..4].copy_from_slice(&((index as u32) + 1).to_le_bytes());
            let header_work = Chainwork::from_bits(header.bits).unwrap();
            let stored = StoredHeader {
                hash: header.hash(),
                chainwork: previous.chainwork.checked_add(&header_work),
                header,
                height: Height(previous.height.0 + 1),
            };
            heights.push(stored.height);
            headers.push(stored.clone());
            previous = stored;
        }
        let mut store = SqliteHeaderStore::open(base.join("headers.sqlite")).unwrap();
        for header in &headers {
            store.put_header(header.clone()).unwrap();
        }
        store.replace_canonical_chain(&headers).unwrap();
        heights
    }

    fn urkel_exists_payload(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_le(&mut out, 3 << 14);
        write_u16_le(&mut out, 0);
        write_u16_le(&mut out, value.len() as u16);
        out.extend(value);
        out
    }

    fn urkel_value_root(key: Hash, value: &[u8]) -> Hash {
        let value_hash = blake2b_256(&[value]);
        blake2b_256(&[&[0x00], key.as_bytes(), value_hash.as_bytes()])
    }

    fn owner_glue4_resource(owner: &str, address: [u8; 4]) -> Vec<u8> {
        let mut value = vec![0, 2];
        DnsName::from_ascii(owner)
            .unwrap()
            .encode_wire(&mut value)
            .unwrap();
        value.extend(address);
        value
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

    fn temp_dir_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("android-ffi-{label}-{}-{now}", std::process::id()))
    }

    fn cleanup_dir(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }
}
