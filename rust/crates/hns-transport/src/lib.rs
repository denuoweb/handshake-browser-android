use bytes::{Buf, Bytes};
use hns_dane::{
    DaneCertificateChainValidationInput, DaneDecision, DaneError, DomainTrustMode, TlsaRecord,
    WebPkiStatus, evaluate_policy_with_certificate_chain, extract_spki_der,
};
use http::{HeaderName, HeaderValue, Request as Http2Request};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls::{Error as RustlsError, StreamOwned};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_HTTP11_POOL_PER_ORIGIN: usize = 2;
const MAX_ALT_SVC_AGE_SECS: u64 = 24 * 60 * 60;
const TUNNEL_READ_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginProtocol {
    Http11,
    Http2,
    Http3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub connect_host: Option<String>,
    pub port: u16,
    pub path_and_query: String,
    pub protocol: OriginProtocol,
    pub tls: TlsValidation,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsValidation {
    pub mode: DomainTrustMode,
    pub dnssec_secure: bool,
    pub tlsa_records: Vec<TlsaRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub dane_decision: DaneDecision,
    pub tls_inspection: Option<TlsCertificateInspection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
    pub dane_decision: DaneDecision,
    pub tls_inspection: Option<TlsCertificateInspection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsCertificateInspection {
    pub end_entity_der: Vec<u8>,
    pub end_entity_spki_der: Vec<u8>,
    pub intermediate_der: Vec<Vec<u8>>,
    pub webpki_status: WebPkiStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pub max_request_body_bytes: usize,
    pub max_response_header_bytes: usize,
    pub max_response_body_bytes: usize,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("DANE validation failed")]
    DaneFailed,
    #[error("origin transport is not implemented for requested protocol")]
    UnsupportedTransport,
    #[error("origin scheme is unsupported")]
    UnsupportedScheme,
    #[error("HTTP transfer encoding is unsupported")]
    UnsupportedTransferEncoding,
    #[error("HTTP protocol upgrade is unsupported")]
    UnsupportedUpgrade,
    #[error("origin HTTP/2 error: {0}")]
    Http2(String),
    #[error("origin HTTP/3 error: {0}")]
    Http3(String),
    #[error("origin QUIC error: {0}")]
    Quic(String),
    #[error("origin TLS error: {0}")]
    Tls(String),
    #[error("origin request is invalid")]
    InvalidRequest,
    #[error("origin request body exceeds configured limit")]
    RequestTooLarge,
    #[error("origin response exceeds configured limit")]
    ResponseTooLarge,
    #[error("origin response is malformed")]
    MalformedResponse,
    #[error("origin I/O error: {0}")]
    Io(String),
}

pub trait OriginTransport {
    fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError>;

    fn open_tunnel(&self, _request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
        Err(TransportError::UnsupportedTransport)
    }

    fn fetch_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let response = self.fetch(request)?;
        body.write_all(&response.body).map_err(io_error)?;
        Ok(response.into_head())
    }
}

pub trait ReadWrite: Read + Write + Send {}

impl<T: Read + Write + Send> ReadWrite for T {}

pub struct OriginTunnel {
    pub response_head: Vec<u8>,
    pub stream: Box<dyn ReadWrite>,
    pub dane_decision: DaneDecision,
    pub tls_inspection: Option<TlsCertificateInspection>,
}

pub struct FailClosedTransport;

#[derive(Clone, Debug)]
pub struct TcpHttpTransport {
    connect_timeout: Duration,
    read_timeout: Duration,
    limits: TransportLimits,
    root_store: Arc<RootCertStore>,
    state: Arc<Mutex<TransportState>>,
}

#[derive(Debug, Default)]
struct TransportState {
    http11_pool: HashMap<Http11PoolKey, VecDeque<PooledHttp11Connection>>,
    tls_verifiers: HashMap<String, Arc<DaneServerCertVerifier>>,
    tls_resumption: HashMap<String, Resumption>,
    alt_svc: HashMap<AltSvcKey, AltSvcEndpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Http11PoolKey {
    scheme: String,
    host: String,
    connect_host: String,
    port: u16,
    tls_key: String,
}

#[derive(Debug)]
enum PooledHttp11Connection {
    Plain(TcpStream),
    Tls {
        stream: StreamOwned<ClientConnection, TcpStream>,
        dane_decision: DaneDecision,
        tls_inspection: Option<TlsCertificateInspection>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct AltSvcKey {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct AltSvcEndpoint {
    protocol: OriginProtocol,
    port: u16,
    expires_at: Instant,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 1024 * 1024,
            max_response_header_bytes: 64 * 1024,
            max_response_body_bytes: 8 * 1024 * 1024,
        }
    }
}

impl Default for TcpHttpTransport {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            limits: TransportLimits::default(),
            root_store: Arc::new(default_root_store()),
            state: Arc::new(Mutex::new(TransportState::default())),
        }
    }
}

impl Default for TlsValidation {
    fn default() -> Self {
        Self {
            mode: DomainTrustMode::IcannWebPki,
            dnssec_secure: false,
            tlsa_records: Vec::new(),
        }
    }
}

impl TlsValidation {
    pub fn hns_strict(dnssec_secure: bool, tlsa_records: Vec<TlsaRecord>) -> Self {
        Self {
            mode: DomainTrustMode::HnsStrict,
            dnssec_secure,
            tlsa_records,
        }
    }

    pub fn hns_compatibility(dnssec_secure: bool, tlsa_records: Vec<TlsaRecord>) -> Self {
        Self {
            mode: DomainTrustMode::HnsCompatibility,
            dnssec_secure,
            tlsa_records,
        }
    }
}

impl OriginResponse {
    pub fn into_head(self) -> OriginResponseHead {
        OriginResponseHead {
            status: self.status,
            headers: self.headers,
            body_len: self.body.len(),
            dane_decision: self.dane_decision,
            tls_inspection: self.tls_inspection,
        }
    }
}

impl TcpHttpTransport {
    pub fn new(connect_timeout: Duration, read_timeout: Duration, limits: TransportLimits) -> Self {
        Self {
            connect_timeout,
            read_timeout,
            limits,
            root_store: Arc::new(default_root_store()),
            state: Arc::new(Mutex::new(TransportState::default())),
        }
    }

    pub fn with_root_store(
        connect_timeout: Duration,
        read_timeout: Duration,
        limits: TransportLimits,
        root_store: RootCertStore,
    ) -> Self {
        Self {
            connect_timeout,
            read_timeout,
            limits,
            root_store: Arc::new(root_store),
            state: Arc::new(Mutex::new(TransportState::default())),
        }
    }

    pub fn limits(&self) -> TransportLimits {
        self.limits
    }

    fn fetch_http11(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_http11_to_writer(request, &mut body)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_http11_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let key = self.http11_pool_key(request);
        if let Some(PooledHttp11Connection::Plain(mut stream)) = self.take_http11_connection(&key) {
            if let Ok((head, reusable)) = self.send_plain_http11(&mut stream, request, body) {
                if reusable {
                    self.put_http11_connection(key, PooledHttp11Connection::Plain(stream));
                }
                return Ok(head);
            }
        }

        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let mut stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let (head, reusable) = self.send_plain_http11(&mut stream, request, body)?;
        if reusable {
            self.put_http11_connection(key, PooledHttp11Connection::Plain(stream));
        }
        Ok(head)
    }

    fn fetch_https_http11(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_https_http11_to_writer(request, &mut body)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_https_http11_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let key = self.http11_pool_key(request);
        if let Some(PooledHttp11Connection::Tls {
            mut stream,
            dane_decision,
            tls_inspection,
        }) = self.take_http11_connection(&key)
        {
            if let Ok((mut head, reusable)) = self.send_tls_http11(&mut stream, request, body) {
                head.dane_decision = dane_decision.clone();
                head.tls_inspection = tls_inspection.clone();
                if reusable {
                    self.put_http11_connection(
                        key,
                        PooledHttp11Connection::Tls {
                            stream,
                            dane_decision,
                            tls_inspection,
                        },
                    );
                }
                return Ok(head);
            }
        }

        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let (config, verifier) = self.client_config(request.tls.clone(), Vec::new())?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        verifier.begin_handshake(&request.host);
        let connection = ClientConnection::new(Arc::new(config), server_name).map_err(tls_error)?;
        let mut tls_stream = StreamOwned::new(connection, stream);

        let (mut head, reusable) = self.send_tls_http11(&mut tls_stream, request, body)?;
        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        head.dane_decision = dane_decision.clone();
        head.tls_inspection = tls_inspection.clone();
        if reusable {
            self.put_http11_connection(
                key,
                PooledHttp11Connection::Tls {
                    stream: tls_stream,
                    dane_decision,
                    tls_inspection,
                },
            );
        }
        Ok(head)
    }

    fn fetch_https_http2(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_https_http2_to_writer(request, &mut body)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_https_http2_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(io_error)?;
        runtime.block_on(self.fetch_https_http2_to_writer_async(request, body))
    }

    async fn fetch_https_http2_to_writer_async(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        tokio::time::timeout(
            self.read_timeout,
            self.fetch_https_http2_to_writer_inner(request, body),
        )
        .await
        .map_err(|_| TransportError::Io("HTTP/2 origin request timed out".to_owned()))?
    }

    async fn fetch_https_http2_to_writer_inner(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect_async(connection_host, request.port, self.connect_timeout).await?;

        let (config, verifier) = self.client_config(request.tls.clone(), vec![b"h2".to_vec()])?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        verifier.begin_handshake(&request.host);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(io_error)?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(TransportError::UnsupportedTransport);
        }

        let (mut sender, connection) = h2::client::handshake(tls_stream).await.map_err(h2_error)?;
        let connection_task = tokio::spawn(connection);
        let h2_request = build_http2_request(request)?;
        let end_stream = request.body.is_empty();
        let (response, mut send_stream) = sender
            .send_request(h2_request, end_stream)
            .map_err(h2_error)?;
        if !request.body.is_empty() {
            send_stream
                .send_data(Bytes::copy_from_slice(&request.body), true)
                .map_err(h2_error)?;
        }

        let response = response.await.map_err(h2_error)?;
        let status = response.status().as_u16();
        let headers = http2_response_headers(response.headers())?;
        if transfer_encoding(&headers)?.is_some() {
            return Err(TransportError::MalformedResponse);
        }
        let expected_body_len = content_length(&headers)?;
        let mut response_body = response.into_body();
        let body_len = if response_has_no_body(&request.method, status) {
            0
        } else {
            read_http2_body_to_writer(
                &mut response_body,
                self.limits.max_response_body_bytes,
                body,
            )
            .await?
        };
        if expected_body_len.is_some_and(|expected| expected != body_len) {
            return Err(TransportError::MalformedResponse);
        }
        connection_task.abort();

        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        Ok(OriginResponseHead {
            status,
            headers,
            body_len,
            dane_decision,
            tls_inspection,
        })
    }

    fn fetch_https_http3(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_https_http3_to_writer(request, &mut body)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_https_http3_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(io_error)?;
        runtime.block_on(self.fetch_https_http3_to_writer_async(request, body))
    }

    async fn fetch_https_http3_to_writer_async(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        self.fetch_https_http3_to_writer_inner(request, body).await
    }

    async fn fetch_https_http3_to_writer_inner(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let remote = resolve_socket_addr_async(connection_host, request.port).await?;

        let (config, verifier) = self.client_config(request.tls.clone(), vec![b"h3".to_vec()])?;
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config)
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
            .map_err(io_error)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_config)));

        let connecting = endpoint
            .connect(remote, &request.host)
            .map_err(quic_error)?;
        verifier.begin_handshake(&request.host);
        let connection = http3_timeout(self.connect_timeout, "connect", connecting)
            .await?
            .map_err(quic_error)?;
        let close_connection = connection.clone();
        let quic = h3_quinn::Connection::new(connection);
        let (mut driver, mut sender) = http3_timeout(
            self.read_timeout,
            "connection setup",
            h3::client::builder()
                .max_field_section_size(self.limits.max_response_header_bytes as u64)
                .build(quic),
        )
        .await?
        .map_err(h3_connection_error)?;
        let driver_task =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        let h3_request = build_http2_request(request)?;
        let mut request_stream = http3_timeout(
            self.read_timeout,
            "send request",
            sender.send_request(h3_request),
        )
        .await?
        .map_err(h3_stream_error)?;
        if !request.body.is_empty() {
            http3_timeout(
                self.read_timeout,
                "send request body",
                request_stream.send_data(Bytes::copy_from_slice(&request.body)),
            )
            .await?
            .map_err(h3_stream_error)?;
        }
        http3_timeout(self.read_timeout, "finish request", request_stream.finish())
            .await?
            .map_err(h3_stream_error)?;

        let response = http3_timeout(
            self.read_timeout,
            "receive response headers",
            request_stream.recv_response(),
        )
        .await?
        .map_err(h3_stream_error)?;
        let status = response.status().as_u16();
        let headers = http2_response_headers(response.headers())?;
        if transfer_encoding(&headers)?.is_some() {
            return Err(TransportError::MalformedResponse);
        }
        let expected_body_len = content_length(&headers)?;
        let body_len = if response_has_no_body(&request.method, status) {
            0
        } else {
            http3_timeout(
                self.read_timeout,
                "receive response body",
                read_http3_body_to_writer(
                    &mut request_stream,
                    self.limits.max_response_body_bytes,
                    body,
                ),
            )
            .await??
        };
        if expected_body_len.is_some_and(|expected| expected != body_len) {
            return Err(TransportError::MalformedResponse);
        }

        driver_task.abort();
        close_connection.close(0u32.into(), b"done");

        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        Ok(OriginResponseHead {
            status,
            headers,
            body_len,
            dane_decision,
            tls_inspection,
        })
    }

    fn open_http11_tunnel(&self, request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
        validate_tunnel_request(request, self.limits)?;
        let scheme = tunnel_origin_scheme(&request.scheme)?;
        let request = OriginRequest {
            scheme,
            protocol: OriginProtocol::Http11,
            ..request.clone()
        };
        match request.scheme.as_str() {
            "http" => self.open_plain_http11_tunnel(&request),
            "https" => self.open_tls_http11_tunnel(&request),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }

    fn open_plain_http11_tunnel(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginTunnel, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let mut stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        let response_head = self.send_http11_upgrade(&mut stream, request)?;
        Ok(OriginTunnel {
            response_head,
            stream: Box::new(stream),
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        })
    }

    fn open_tls_http11_tunnel(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginTunnel, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        let (config, verifier) = self.client_config(request.tls.clone(), Vec::new())?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        verifier.begin_handshake(&request.host);
        let connection = ClientConnection::new(Arc::new(config), server_name).map_err(tls_error)?;
        let mut tls_stream = StreamOwned::new(connection, stream);
        let response_head = self.send_http11_upgrade(&mut tls_stream, request)?;
        tls_stream
            .sock
            .set_read_timeout(Some(TUNNEL_READ_TIMEOUT))
            .map_err(io_error)?;
        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        Ok(OriginTunnel {
            response_head,
            stream: Box::new(tls_stream),
            dane_decision,
            tls_inspection,
        })
    }

    fn client_config(
        &self,
        tls: TlsValidation,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<(ClientConfig, Arc<DaneServerCertVerifier>), TransportError> {
        let tls_key = tls_validation_key(&tls);
        let verifier = self.dane_verifier_for(tls.clone(), &tls_key)?;
        let provider = rustls::crypto::ring::default_provider();

        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(tls_error)?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        config.resumption = self.resumption_for(&tls_key, &alpn_protocols)?;
        config.alpn_protocols = alpn_protocols;
        Ok((config, verifier))
    }

    fn dane_verifier_for(
        &self,
        tls: TlsValidation,
        tls_key: &str,
    ) -> Result<Arc<DaneServerCertVerifier>, TransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::Tls("transport state lock is poisoned".to_owned()))?;
        if let Some(verifier) = state.tls_verifiers.get(tls_key) {
            return Ok(Arc::clone(verifier));
        }

        let provider = rustls::crypto::ring::default_provider();
        let webpki = WebPkiServerVerifier::builder_with_provider(
            Arc::clone(&self.root_store),
            Arc::new(provider),
        )
        .build()
        .map_err(|error| TransportError::Tls(error.to_string()))?;
        let verifier = Arc::new(DaneServerCertVerifier::new(webpki, tls));
        state
            .tls_verifiers
            .insert(tls_key.to_owned(), Arc::clone(&verifier));
        Ok(verifier)
    }

    fn resumption_for(
        &self,
        tls_key: &str,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<Resumption, TransportError> {
        let key = format!("{tls_key}|alpn={}", alpn_key(alpn_protocols));
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::Tls("transport state lock is poisoned".to_owned()))?;
        Ok(state
            .tls_resumption
            .entry(key)
            .or_insert_with(|| Resumption::in_memory_sessions(256))
            .clone())
    }

    fn http11_pool_key(&self, request: &OriginRequest) -> Http11PoolKey {
        Http11PoolKey {
            scheme: request.scheme.to_ascii_lowercase(),
            host: request.host.to_ascii_lowercase(),
            connect_host: request
                .connect_host
                .as_deref()
                .unwrap_or(&request.host)
                .to_ascii_lowercase(),
            port: request.port,
            tls_key: tls_validation_key(&request.tls),
        }
    }

    fn take_http11_connection(&self, key: &Http11PoolKey) -> Option<PooledHttp11Connection> {
        self.state
            .lock()
            .ok()?
            .http11_pool
            .get_mut(key)
            .and_then(VecDeque::pop_front)
    }

    fn put_http11_connection(&self, key: Http11PoolKey, connection: PooledHttp11Connection) {
        if let Ok(mut state) = self.state.lock() {
            let pool = state.http11_pool.entry(key).or_default();
            if pool.len() >= MAX_HTTP11_POOL_PER_ORIGIN {
                pool.pop_front();
            }
            pool.push_back(connection);
        }
    }

    fn promoted_request(&self, request: &OriginRequest) -> OriginRequest {
        if !request.scheme.eq_ignore_ascii_case("https")
            || request.protocol == OriginProtocol::Http3
        {
            return request.clone();
        }
        let key = AltSvcKey {
            scheme: "https".to_owned(),
            host: request.host.to_ascii_lowercase(),
            port: request.port,
        };
        let Some(endpoint) = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.alt_svc.get(&key).cloned())
        else {
            return request.clone();
        };
        if endpoint.expires_at <= Instant::now() || endpoint.port != request.port {
            return request.clone();
        }
        let mut promoted = request.clone();
        promoted.protocol = endpoint.protocol;
        promoted
    }

    fn record_alt_svc(&self, request: &OriginRequest, headers: &[(String, String)]) {
        if !request.scheme.eq_ignore_ascii_case("https") {
            return;
        }
        let key = AltSvcKey {
            scheme: "https".to_owned(),
            host: request.host.to_ascii_lowercase(),
            port: request.port,
        };
        let values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("alt-svc"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        if values.is_empty() {
            return;
        }
        if values
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case("clear"))
        {
            if let Ok(mut state) = self.state.lock() {
                state.alt_svc.remove(&key);
            }
            return;
        }
        let Some(endpoint) = selected_alt_svc_endpoint(&values, request.port) else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            state.alt_svc.insert(key, endpoint);
        }
    }

    fn send_plain_http11(
        &self,
        stream: &mut TcpStream,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<(OriginResponseHead, bool), TransportError> {
        let request_bytes = build_http_request(request, true)?;
        stream.write_all(&request_bytes).map_err(io_error)?;
        stream.flush().map_err(io_error)?;
        let (head, reusable) =
            parse_http_response_to_writer_reusable(stream, self.limits, &request.method, body)?;
        self.record_alt_svc(request, &head.headers);
        Ok((head, reusable))
    }

    fn send_tls_http11(
        &self,
        stream: &mut StreamOwned<ClientConnection, TcpStream>,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<(OriginResponseHead, bool), TransportError> {
        let request_bytes = build_http_request(request, true)?;
        stream.write_all(&request_bytes).map_err(io_error)?;
        stream.flush().map_err(io_error)?;
        let (head, reusable) =
            parse_http_response_to_writer_reusable(stream, self.limits, &request.method, body)?;
        self.record_alt_svc(request, &head.headers);
        Ok((head, reusable))
    }

    fn send_http11_upgrade(
        &self,
        stream: &mut impl ReadWrite,
        request: &OriginRequest,
    ) -> Result<Vec<u8>, TransportError> {
        let request_bytes = build_http_upgrade_request(request)?;
        stream.write_all(&request_bytes).map_err(io_error)?;
        stream.flush().map_err(io_error)?;
        let response_head =
            read_header_bytes_including_end(stream, self.limits.max_response_header_bytes)?;
        validate_upgrade_response_head(&response_head)?;
        Ok(response_head)
    }
}

impl OriginTransport for FailClosedTransport {
    fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        Err(TransportError::UnsupportedTransport)
    }
}

impl OriginTransport for TcpHttpTransport {
    fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let request = self.promoted_request(request);
        match (
            request.scheme.to_ascii_lowercase().as_str(),
            request.protocol,
        ) {
            ("http", OriginProtocol::Http11) => self.fetch_http11(&request),
            ("https", OriginProtocol::Http11) => self.fetch_https_http11(&request),
            ("https", OriginProtocol::Http2) => self.fetch_https_http2(&request),
            ("https", OriginProtocol::Http3) => self.fetch_https_http3(&request),
            ("http", _) => Err(TransportError::UnsupportedTransport),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }

    fn open_tunnel(&self, request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
        self.open_http11_tunnel(request)
    }

    fn fetch_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let request = self.promoted_request(request);
        match (
            request.scheme.to_ascii_lowercase().as_str(),
            request.protocol,
        ) {
            ("http", OriginProtocol::Http11) => self.fetch_http11_to_writer(&request, body),
            ("https", OriginProtocol::Http11) => self.fetch_https_http11_to_writer(&request, body),
            ("https", OriginProtocol::Http2) => self.fetch_https_http2_to_writer(&request, body),
            ("https", OriginProtocol::Http3) => self.fetch_https_http3_to_writer(&request, body),
            ("http", _) => Err(TransportError::UnsupportedTransport),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }
}

#[derive(Debug)]
struct DaneServerCertVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    tls: TlsValidation,
    handshakes: Mutex<HashMap<ThreadId, HandshakeCapture>>,
    last_success: Mutex<HashMap<String, HandshakeCapture>>,
}

#[derive(Clone, Debug, Default)]
struct HandshakeCapture {
    server_name: String,
    decision: Option<DaneDecision>,
    inspection: Option<TlsCertificateInspection>,
}

impl DaneServerCertVerifier {
    fn new(webpki: Arc<WebPkiServerVerifier>, tls: TlsValidation) -> Self {
        Self {
            webpki,
            tls,
            handshakes: Mutex::new(HashMap::new()),
            last_success: Mutex::new(HashMap::new()),
        }
    }

    fn begin_handshake(&self, server_name: &str) {
        if let Ok(mut handshakes) = self.handshakes.lock() {
            handshakes.insert(
                std::thread::current().id(),
                HandshakeCapture {
                    server_name: server_name.to_ascii_lowercase(),
                    ..HandshakeCapture::default()
                },
            );
        }
    }

    fn finish_handshake(
        &self,
        server_name: &str,
    ) -> Result<(DaneDecision, Option<TlsCertificateInspection>), TransportError> {
        let capture = self
            .handshakes
            .lock()
            .map_err(|_| TransportError::Tls("TLS handshake lock is poisoned".to_owned()))?
            .remove(&std::thread::current().id());
        if let Some(capture) = capture
            && let Some(decision) = capture.decision
        {
            return Ok((decision, capture.inspection));
        }

        let key = server_name.to_ascii_lowercase();
        let cached = self
            .last_success
            .lock()
            .map_err(|_| TransportError::Tls("TLS handshake cache lock is poisoned".to_owned()))?
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                TransportError::Tls("TLS certificate policy was not evaluated".to_owned())
            })?;
        Ok((
            cached.decision.ok_or_else(|| {
                TransportError::Tls("TLS certificate policy was not evaluated".to_owned())
            })?,
            cached.inspection,
        ))
    }

    fn store_capture(
        &self,
        decision: DaneDecision,
        inspection: TlsCertificateInspection,
    ) -> Result<(), RustlsError> {
        let mut handshakes = self
            .handshakes
            .lock()
            .map_err(|_| RustlsError::General("TLS handshake lock is poisoned".to_owned()))?;
        let capture = handshakes.entry(std::thread::current().id()).or_default();
        capture.decision = Some(decision);
        capture.inspection = Some(inspection);
        let capture = capture.clone();
        let mut last_success = self
            .last_success
            .lock()
            .map_err(|_| RustlsError::General("TLS handshake cache lock is poisoned".to_owned()))?;
        if !capture.server_name.is_empty() {
            last_success.insert(capture.server_name.clone(), capture);
        }
        Ok(())
    }
}

impl ServerCertVerifier for DaneServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let webpki_result = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let webpki_status = if webpki_result.is_ok() {
            WebPkiStatus::Valid
        } else {
            WebPkiStatus::Invalid
        };

        let intermediate_der = intermediates
            .iter()
            .map(|certificate| certificate.as_ref())
            .collect::<Vec<_>>();

        match evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
            mode: self.tls.mode,
            dnssec_secure: self.tls.dnssec_secure,
            tlsa_records: &self.tls.tlsa_records,
            end_entity_der: end_entity.as_ref(),
            intermediate_der: &intermediate_der,
            webpki_status,
        }) {
            Ok(DaneDecision::Failed) => Err(RustlsError::General(
                "DANE certificate association did not match".to_owned(),
            )),
            Ok(decision) => {
                let inspection =
                    tls_certificate_inspection(end_entity, intermediates, webpki_status)?;
                self.store_capture(decision, inspection)?;
                Ok(ServerCertVerified::assertion())
            }
            Err(DaneError::WebPkiFailed) => webpki_result,
            Err(error) => Err(RustlsError::General(format!(
                "DANE policy rejected certificate: {error}"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn default_root_store() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, TransportError> {
    let mut last_error = None;
    let addresses = (host, port).to_socket_addrs().map_err(io_error)?;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error
        .map(io_error)
        .unwrap_or_else(|| TransportError::Io("no resolved socket addresses".to_owned())))
}

async fn connect_async(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<tokio::net::TcpStream, TransportError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(io_error)?
        .collect::<Vec<_>>();
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some(format!("connect to {address} timed out")),
        }
    }

    Err(last_error
        .map(TransportError::Io)
        .unwrap_or_else(|| TransportError::Io("no resolved socket addresses".to_owned())))
}

async fn resolve_socket_addr_async(host: &str, port: u16) -> Result<SocketAddr, TransportError> {
    tokio::net::lookup_host((host, port))
        .await
        .map_err(io_error)?
        .next()
        .ok_or_else(|| TransportError::Io("no resolved socket addresses".to_owned()))
}

fn build_http2_request(request: &OriginRequest) -> Result<Http2Request<()>, TransportError> {
    let authority = host_header(&request.host, request.port, &request.scheme);
    let uri = format!(
        "{}://{}{}",
        request.scheme, authority, request.path_and_query
    )
    .parse::<http::Uri>()
    .map_err(|_| TransportError::InvalidRequest)?;
    let mut h2_request = Http2Request::builder()
        .method(request.method.as_str())
        .uri(uri)
        .body(())
        .map_err(|_| TransportError::InvalidRequest)?;
    {
        let headers = h2_request.headers_mut();
        headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("hns-browser/0.2.4"),
        );
        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("*/*"),
        );
        for (name, value) in &request.headers {
            if is_hop_by_hop_header(name)
                || name.eq_ignore_ascii_case("host")
                || name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| TransportError::InvalidRequest)?;
            let value = HeaderValue::from_str(value).map_err(|_| TransportError::InvalidRequest)?;
            headers.append(name, value);
        }
    }
    Ok(h2_request)
}

fn http2_response_headers(
    headers: &http::HeaderMap<HeaderValue>,
) -> Result<Vec<(String, String)>, TransportError> {
    headers
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str().to_owned(),
                value
                    .to_str()
                    .map_err(|_| TransportError::MalformedResponse)?
                    .to_owned(),
            ))
        })
        .collect()
}

async fn read_http2_body_to_writer(
    stream: &mut h2::RecvStream,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    let mut total = 0usize;
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(h2_error)?;
        total = checked_body_len(total, chunk.len(), limit)?;
        body.write_all(&chunk).map_err(io_error)?;
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(h2_error)?;
    }
    Ok(total)
}

async fn read_http3_body_to_writer<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError>
where
    S: h3::quic::RecvStream,
{
    let mut total = 0usize;
    while let Some(mut chunk) = stream.recv_data().await.map_err(h3_stream_error)? {
        let chunk_len = chunk.remaining();
        total = checked_body_len(total, chunk_len, limit)?;
        let bytes = chunk.copy_to_bytes(chunk_len);
        body.write_all(&bytes).map_err(io_error)?;
    }
    Ok(total)
}

async fn http3_timeout<T>(
    timeout: Duration,
    stage: &'static str,
    future: impl std::future::Future<Output = T>,
) -> Result<T, TransportError> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TransportError::Io(format!("HTTP/3 {stage} timed out")))
}

fn validate_request(
    request: &OriginRequest,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    validate_request_common(request, limits)?;

    if is_protocol_upgrade(&request.headers) {
        return Err(TransportError::UnsupportedUpgrade);
    }

    Ok(())
}

fn validate_tunnel_request(
    request: &OriginRequest,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    validate_request_common(request, limits)?;
    if !is_protocol_upgrade(&request.headers) {
        return Err(TransportError::UnsupportedUpgrade);
    }
    if !request.body.is_empty() {
        return Err(TransportError::InvalidRequest);
    }
    Ok(())
}

fn validate_request_common(
    request: &OriginRequest,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    if !is_http_token(&request.method)
        || !is_valid_host(&request.host)
        || request.port == 0
        || !request.path_and_query.starts_with('/')
        || request
            .path_and_query
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(TransportError::InvalidRequest);
    }

    if let Some(connect_host) = &request.connect_host
        && !is_valid_host(connect_host)
    {
        return Err(TransportError::InvalidRequest);
    }

    if request.body.len() > limits.max_request_body_bytes {
        return Err(TransportError::RequestTooLarge);
    }

    for (name, value) in &request.headers {
        if !is_http_token(name) || value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err(TransportError::InvalidRequest);
        }
    }

    Ok(())
}

fn tunnel_origin_scheme(scheme: &str) -> Result<String, TransportError> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => Ok("http".to_owned()),
        "https" | "wss" => Ok("https".to_owned()),
        _ => Err(TransportError::UnsupportedScheme),
    }
}

fn build_http_request(
    request: &OriginRequest,
    keep_alive: bool,
) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    write!(
        out,
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: hns-browser/0.2.4\r\nAccept: */*\r\n",
        request.method.to_ascii_uppercase(),
        request.path_and_query,
        host_header(&request.host, request.port, &request.scheme),
    )
    .map_err(io_error)?;

    for (name, value) in &request.headers {
        if is_hop_by_hop_header(name)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        write!(out, "{name}: {value}\r\n").map_err(io_error)?;
    }

    let connection = if keep_alive { "keep-alive" } else { "close" };
    if request.body.is_empty() {
        write!(out, "Connection: {connection}\r\n\r\n").map_err(io_error)?;
    } else {
        write!(
            out,
            "Content-Length: {}\r\nConnection: {connection}\r\n\r\n",
            request.body.len(),
        )
        .map_err(io_error)?;
        out.extend(&request.body);
    }

    Ok(out)
}

fn build_http_upgrade_request(request: &OriginRequest) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    write!(
        out,
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: hns-browser/0.2.4\r\nAccept: */*\r\n",
        request.method.to_ascii_uppercase(),
        request.path_and_query,
        host_header(&request.host, request.port, &request.scheme),
    )
    .map_err(io_error)?;

    let mut has_connection_upgrade = false;
    let mut has_upgrade = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("connection") && has_header_token(value, "upgrade") {
            has_connection_upgrade = true;
        }
        if name.eq_ignore_ascii_case("upgrade") {
            has_upgrade = true;
        }
        write!(out, "{name}: {value}\r\n").map_err(io_error)?;
    }
    if !has_connection_upgrade {
        out.extend(b"Connection: Upgrade\r\n");
    }
    if !has_upgrade {
        out.extend(b"Upgrade: websocket\r\n");
    }
    out.extend(b"\r\n");
    Ok(out)
}

fn host_header(host: &str, port: u16, scheme: &str) -> String {
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "https" => 443,
        _ => 80,
    };

    let bracketed_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };

    if port == default_port {
        bracketed_host
    } else {
        format!("{bracketed_host}:{port}")
    }
}

fn parse_http_response_to_writer_reusable(
    stream: &mut impl Read,
    limits: TransportLimits,
    request_method: &str,
    body: &mut dyn Write,
) -> Result<(OriginResponseHead, bool), TransportError> {
    let header_bytes = read_header_bytes(stream, limits.max_response_header_bytes)?;
    let header_text =
        std::str::from_utf8(&header_bytes).map_err(|_| TransportError::MalformedResponse)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(TransportError::MalformedResponse)?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?;
    let status = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?
        .parse::<u16>()
        .map_err(|_| TransportError::MalformedResponse)?;
    if !version.starts_with("HTTP/") || !(100..=999).contains(&status) {
        return Err(TransportError::MalformedResponse);
    }

    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(TransportError::MalformedResponse)?;
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if !is_http_token(&name) {
            return Err(TransportError::MalformedResponse);
        }
        headers.push((name, value));
    }

    let mut self_delimited = response_has_no_body(request_method, status);
    let body_len = if self_delimited {
        0
    } else if let Some(transfer_encoding) = transfer_encoding(&headers)? {
        if content_length(&headers)?.is_some() {
            return Err(TransportError::MalformedResponse);
        }
        if transfer_encoding != [TransferCoding::Chunked] {
            return Err(TransportError::UnsupportedTransferEncoding);
        }
        self_delimited = true;
        read_chunked_body_to_writer(stream, limits.max_response_body_bytes, body)?
    } else if let Some(length) = content_length(&headers)? {
        self_delimited = true;
        read_fixed_body_to_writer(stream, length, limits.max_response_body_bytes, body)?
    } else {
        read_until_eof_to_writer(stream, limits.max_response_body_bytes, body)?
    };
    let reusable =
        version.eq_ignore_ascii_case("HTTP/1.1") && self_delimited && !connection_close(&headers);

    Ok((
        OriginResponseHead {
            status,
            headers,
            body_len,
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        },
        reusable,
    ))
}

fn response_has_no_body(request_method: &str, status: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
}

fn read_header_bytes(stream: &mut impl Read, limit: usize) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];

    while out.len() < limit {
        let read = stream.read(&mut byte).map_err(io_error)?;
        if read == 0 {
            return Err(TransportError::MalformedResponse);
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            out.truncate(out.len() - 4);
            return Ok(out);
        }
    }

    Err(TransportError::ResponseTooLarge)
}

fn read_header_bytes_including_end(
    stream: &mut impl Read,
    limit: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];

    while out.len() < limit {
        let read = stream.read(&mut byte).map_err(io_error)?;
        if read == 0 {
            return Err(TransportError::MalformedResponse);
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            return Ok(out);
        }
    }

    Err(TransportError::ResponseTooLarge)
}

fn validate_upgrade_response_head(response_head: &[u8]) -> Result<(), TransportError> {
    let header_text =
        std::str::from_utf8(response_head).map_err(|_| TransportError::MalformedResponse)?;
    let header_text = header_text
        .strip_suffix("\r\n\r\n")
        .ok_or(TransportError::MalformedResponse)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(TransportError::MalformedResponse)?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?;
    let status = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?
        .parse::<u16>()
        .map_err(|_| TransportError::MalformedResponse)?;
    if !version.starts_with("HTTP/") || status != 101 {
        return Err(TransportError::MalformedResponse);
    }

    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(TransportError::MalformedResponse)?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    if !headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && has_header_token(value, "upgrade")
    }) || !headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket")
    }) {
        return Err(TransportError::MalformedResponse);
    }
    Ok(())
}

fn read_fixed_body_to_writer(
    stream: &mut impl Read,
    length: usize,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    if length > limit {
        return Err(TransportError::ResponseTooLarge);
    }

    copy_exact_body(stream, body, length)?;
    Ok(length)
}

fn read_until_eof_to_writer(
    stream: &mut impl Read,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    let mut total = 0usize;
    let mut buffer = [0u8; 16 * 1024];

    loop {
        let read = stream.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            return Ok(total);
        }
        total = checked_body_len(total, read, limit)?;
        body.write_all(&buffer[..read]).map_err(io_error)?;
    }
}

fn read_chunked_body_to_writer(
    stream: &mut impl Read,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    let mut total = 0usize;

    loop {
        let line = read_crlf_line(stream, 8192)?;
        let size_text = line
            .split(';')
            .next()
            .ok_or(TransportError::MalformedResponse)?
            .trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| TransportError::MalformedResponse)?;

        if size == 0 {
            read_trailers(stream)?;
            return Ok(total);
        }

        total = checked_body_len(total, size, limit)?;
        copy_exact_body(stream, body, size)?;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).map_err(io_error)?;
        if crlf != *b"\r\n" {
            return Err(TransportError::MalformedResponse);
        }
    }
}

fn copy_exact_body(
    stream: &mut impl Read,
    body: &mut dyn Write,
    mut length: usize,
) -> Result<(), TransportError> {
    let mut buffer = [0u8; 16 * 1024];
    while length > 0 {
        let count = length.min(buffer.len());
        stream.read_exact(&mut buffer[..count]).map_err(io_error)?;
        body.write_all(&buffer[..count]).map_err(io_error)?;
        length -= count;
    }
    Ok(())
}

fn checked_body_len(current: usize, chunk: usize, limit: usize) -> Result<usize, TransportError> {
    current
        .checked_add(chunk)
        .filter(|size| *size <= limit)
        .ok_or(TransportError::ResponseTooLarge)
}

fn read_trailers(stream: &mut impl Read) -> Result<(), TransportError> {
    loop {
        if read_crlf_line(stream, 8192)?.is_empty() {
            return Ok(());
        }
    }
}

fn read_crlf_line(stream: &mut impl Read, limit: usize) -> Result<String, TransportError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];

    while out.len() < limit {
        let read = stream.read(&mut byte).map_err(io_error)?;
        if read == 0 {
            return Err(TransportError::MalformedResponse);
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
            return String::from_utf8(out).map_err(|_| TransportError::MalformedResponse);
        }
    }

    Err(TransportError::ResponseTooLarge)
}

fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, TransportError> {
    let mut value = None;
    for (_, header_value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        let parsed = header_value
            .parse::<usize>()
            .map_err(|_| TransportError::MalformedResponse)?;
        if value.is_some_and(|existing| existing != parsed) {
            return Err(TransportError::MalformedResponse);
        }
        value = Some(parsed);
    }
    Ok(value)
}

fn connection_close(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && has_header_token(value, "close")
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferCoding {
    Chunked,
    Unsupported,
}

fn transfer_encoding(
    headers: &[(String, String)],
) -> Result<Option<Vec<TransferCoding>>, TransportError> {
    let mut codings = Vec::new();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
    {
        for coding in value.split(',') {
            let coding = coding.trim();
            if coding.is_empty() {
                return Err(TransportError::MalformedResponse);
            }
            codings.push(if coding.eq_ignore_ascii_case("chunked") {
                TransferCoding::Chunked
            } else {
                TransferCoding::Unsupported
            });
        }
    }

    Ok((!codings.is_empty()).then_some(codings))
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_protocol_upgrade(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade")
            || (name.eq_ignore_ascii_case("connection") && has_header_token(value, "upgrade"))
    })
}

fn has_header_token(value: &str, expected: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case(expected))
}

fn selected_alt_svc_endpoint(values: &[&str], request_port: u16) -> Option<AltSvcEndpoint> {
    let now = Instant::now();
    let mut best = None;
    for value in values {
        for alternative in value.split(',') {
            let alternative = alternative.trim();
            let (protocol, rest) = alternative.split_once('=')?;
            let protocol = protocol.trim().to_ascii_lowercase();
            let protocol = if protocol == "h3" || protocol.starts_with("h3-") {
                OriginProtocol::Http3
            } else if protocol == "h2" {
                OriginProtocol::Http2
            } else {
                continue;
            };
            let authority = rest.trim_start();
            if !authority.starts_with('"') {
                continue;
            }
            let Some(end_quote) = authority[1..].find('"') else {
                continue;
            };
            let authority_value = &authority[1..1 + end_quote];
            let Some(port) = alt_svc_authority_port(authority_value, request_port) else {
                continue;
            };
            if port != request_port {
                continue;
            }
            let params = &authority[1 + end_quote + 1..];
            let max_age = alt_svc_max_age(params).unwrap_or(MAX_ALT_SVC_AGE_SECS);
            if max_age == 0 {
                continue;
            }
            let endpoint = AltSvcEndpoint {
                protocol,
                port,
                expires_at: now + Duration::from_secs(max_age.min(MAX_ALT_SVC_AGE_SECS)),
            };
            if best.as_ref().is_none_or(|current: &AltSvcEndpoint| {
                protocol_rank(endpoint.protocol) > protocol_rank(current.protocol)
            }) {
                best = Some(endpoint);
            }
        }
    }
    best
}

fn alt_svc_authority_port(authority: &str, default_port: u16) -> Option<u16> {
    if authority.is_empty() {
        return Some(default_port);
    }
    if let Some(port_text) = authority.strip_prefix(':') {
        return port_text.parse::<u16>().ok();
    }
    let (_, port_text) = authority.rsplit_once(':')?;
    port_text.parse::<u16>().ok()
}

fn alt_svc_max_age(params: &str) -> Option<u64> {
    params.split(';').find_map(|param| {
        let (name, value) = param.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("ma")
            .then(|| value.trim().trim_matches('"').parse::<u64>().ok())
            .flatten()
    })
}

fn protocol_rank(protocol: OriginProtocol) -> u8 {
    match protocol {
        OriginProtocol::Http3 => 3,
        OriginProtocol::Http2 => 2,
        OriginProtocol::Http11 => 1,
    }
}

fn tls_validation_key(tls: &TlsValidation) -> String {
    let mut out = format!(
        "mode={:?};secure={};records={}",
        tls.mode,
        tls.dnssec_secure,
        tls.tlsa_records.len(),
    );
    for record in &tls.tlsa_records {
        out.push_str(&format!(
            ";{:?}:{:?}:{:?}:",
            record.usage, record.selector, record.matching,
        ));
        append_hash_hex(&mut out, &record.association_data);
    }
    out
}

fn append_hash_hex(out: &mut String, bytes: &[u8]) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    out.push_str(&format!("{:016x}", hasher.finish()));
}

fn alpn_key(alpn_protocols: &[Vec<u8>]) -> String {
    alpn_protocols
        .iter()
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect::<Vec<_>>()
        .join(",")
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'?' | b'#' | b'@' | b' '))
}

fn io_error(error: std::io::Error) -> TransportError {
    TransportError::Io(error.to_string())
}

fn tls_error(error: RustlsError) -> TransportError {
    TransportError::Tls(error.to_string())
}

fn h2_error(error: h2::Error) -> TransportError {
    TransportError::Http2(error.to_string())
}

fn h3_connection_error(error: h3::error::ConnectionError) -> TransportError {
    TransportError::Http3(error.to_string())
}

fn h3_stream_error(error: h3::error::StreamError) -> TransportError {
    TransportError::Http3(error.to_string())
}

fn quic_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::Quic(error.to_string())
}

fn tls_certificate_inspection(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    webpki_status: WebPkiStatus,
) -> Result<TlsCertificateInspection, RustlsError> {
    let end_entity_der = end_entity.as_ref().to_vec();
    let end_entity_spki_der = extract_spki_der(&end_entity_der).map_err(|error| {
        RustlsError::General(format!("TLS certificate inspection failed: {error}"))
    })?;
    let intermediate_der = intermediates
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    Ok(TlsCertificateInspection {
        end_entity_der,
        end_entity_spki_der,
        intermediate_der,
        webpki_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_dane::{TlsaMatching, TlsaSelector, TlsaUsage};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    use std::io::Read;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn fetches_http_origin_response() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: yes\r\n\r\nok".to_vec(),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let response = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(response.dane_decision, DaneDecision::NoTlsa);
        let raw_request = server.request();
        assert!(raw_request.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(raw_request.contains("Host: example.com"));
        assert!(raw_request.contains("Connection: keep-alive"));
    }

    #[test]
    fn http_fetch_waits_longer_than_tunnel_idle_timeout() {
        let server = TestServer::start_delayed(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
            TUNNEL_READ_TIMEOUT + Duration::from_millis(150),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let response = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn decodes_chunked_response_body() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n".to_vec(),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let response = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn streams_response_body_to_writer() {
        let body = vec![b'a'; 128 * 1024];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Test: streamed\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend(&body);
        let server = TestServer::start(response);
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits {
                max_response_body_bytes: body.len(),
                ..TransportLimits::default()
            },
        );
        let mut streamed = Vec::new();

        let head = transport
            .fetch_to_writer(&request(server.address), &mut streamed)
            .unwrap();

        assert_eq!(head.status, 200);
        assert_eq!(head.body_len, body.len());
        assert_eq!(
            head.headers,
            vec![
                ("Content-Length".to_owned(), body.len().to_string()),
                ("X-Test".to_owned(), "streamed".to_owned())
            ]
        );
        assert_eq!(streamed, body);
    }

    #[test]
    fn reuses_http11_origin_connection() {
        let server = PersistentHttp11Server::start(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo".to_vec(),
        ]);
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let first = transport.fetch(&request(server.address)).unwrap();
        let second = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(first.body, b"one");
        assert_eq!(second.body, b"two");
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("Connection: keep-alive\r\n"));
        assert!(requests[1].contains("Connection: keep-alive\r\n"));
    }

    #[test]
    fn promotes_https_same_port_alt_svc_to_http2() {
        let server = TlsTestServer::start_alt_svc_h2();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let first = transport.fetch(&request).unwrap();
        let second = transport.fetch(&request).unwrap();

        assert_eq!(first.body, b"h1");
        assert_eq!(second.body, b"h2");
        let requests = server.requests(2);
        assert!(requests[0].starts_with("h1 GET /path?q=1 HTTP/1.1"));
        assert!(requests[1].starts_with("h2 GET https://example.com:"));
        assert!(requests[1].ends_with("/path?q=1"));
    }

    #[test]
    fn opens_http11_upgrade_tunnel_and_preserves_stream_bytes() {
        let server = UpgradeTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.headers.extend([
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
            (
                "Sec-WebSocket-Key".to_owned(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_owned(),
            ),
            ("Sec-WebSocket-Version".to_owned(), "13".to_owned()),
        ]);

        let mut tunnel = transport.open_tunnel(&request).unwrap();
        tunnel.stream.write_all(b"ping").unwrap();
        tunnel.stream.flush().unwrap();
        let mut echoed = [0u8; 4];
        tunnel.stream.read_exact(&mut echoed).unwrap();

        assert!(tunnel.response_head.starts_with(b"HTTP/1.1 101 "));
        assert_eq!(&echoed, b"ping");
        let raw_request = server.request();
        assert!(raw_request.contains("Connection: Upgrade\r\n"));
        assert!(raw_request.contains("Upgrade: websocket\r\n"));
    }

    #[test]
    fn rejects_unsupported_transfer_encoded_response() {
        let server =
            TestServer::start(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nabc".to_vec());
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::UnsupportedTransferEncoding,
        );
    }

    #[test]
    fn rejects_ambiguous_transfer_encoding_and_content_length() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nok\r\n0\r\n\r\n".to_vec(),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::MalformedResponse,
        );
    }

    #[test]
    fn head_response_never_reads_message_body() {
        let server = TestServer::start(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec());
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.method = "HEAD".to_owned();

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
    }

    #[test]
    fn rewrites_request_content_length_from_body() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request.body = b"hi".to_vec();
        request
            .headers
            .push(("Content-Length".to_owned(), "999".to_owned()));

        let bytes = build_http_request(&request, false).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(!text.contains("Content-Length: 999\r\n"));
        assert!(text.ends_with("\r\n\r\nhi"));
    }

    #[test]
    fn forwards_range_request_header_to_origin() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("Range".to_owned(), "bytes=10-19".to_owned()));
        request
            .headers
            .push(("If-Range".to_owned(), "\"abc\"".to_owned()));

        let text = String::from_utf8(build_http_request(&request, false).unwrap()).unwrap();

        assert!(text.contains("Range: bytes=10-19\r\n"));
        assert!(text.contains("If-Range: \"abc\"\r\n"));
    }

    #[test]
    fn rejects_protocol_upgrade_before_stripping_hop_by_hop_headers() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("Connection".to_owned(), "keep-alive, Upgrade".to_owned()));
        request
            .headers
            .push(("Upgrade".to_owned(), "websocket".to_owned()));

        assert_eq!(
            validate_request(&request, TransportLimits::default()).unwrap_err(),
            TransportError::UnsupportedUpgrade,
        );
    }

    #[test]
    fn rejects_oversized_response_body() {
        let server = TestServer::start(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec());
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits {
                max_response_body_bytes: 2,
                ..TransportLimits::default()
            },
        );

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::ResponseTooLarge,
        );
    }

    #[test]
    fn fetches_https_with_webpki_fallback() {
        let server = TlsTestServer::start();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(server.cert_der.clone()))
            .unwrap();
        let transport = TcpHttpTransport::with_root_store(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
            roots,
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(response.dane_decision, DaneDecision::WebPkiFallback);
        assert!(server.request().starts_with("GET /path?q=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn fetches_https_with_dnssec_tlsa_match() {
        let server = TlsTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneEe)
        );
        let inspection = response.tls_inspection.expect("TLS inspection");
        assert_eq!(inspection.end_entity_der, server.cert_der);
        assert_eq!(
            inspection.end_entity_spki_der,
            extract_spki_der(&inspection.end_entity_der).unwrap(),
        );
        assert_eq!(inspection.intermediate_der.len(), 0);
        assert_eq!(inspection.webpki_status, WebPkiStatus::Invalid);
    }

    #[test]
    fn fetches_https_http2_with_dnssec_tlsa_match() {
        let server = TlsTestServer::start_h2();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http2;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneEe),
        );
        let request_text = server.request();
        assert!(request_text.starts_with("GET https://example.com:"));
        assert!(request_text.ends_with("/path?q=1"));
    }

    #[test]
    fn fetches_https_http3_with_dnssec_tlsa_match() {
        let server = TlsTestServer::start_h3();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http3;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneEe),
        );
        let request_text = server.request();
        assert!(request_text.starts_with("GET https://example.com:"));
        assert!(request_text.ends_with("/path?q=1"));
    }

    #[test]
    fn fetches_https_with_dane_ta_intermediate_match() {
        let server = TlsTestServer::start_with_intermediate();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(
            true,
            vec![tlsa_spki_exact_with_usage(
                server.intermediate_cert_der.as_ref().unwrap(),
                TlsaUsage::DaneTa,
            )],
        );

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneTa)
        );
        let inspection = response.tls_inspection.expect("TLS inspection");
        assert_eq!(inspection.end_entity_der, server.cert_der);
        assert_eq!(inspection.intermediate_der.len(), 1);
        assert_eq!(
            inspection.intermediate_der[0],
            *server.intermediate_cert_der.as_ref().unwrap(),
        );
    }

    #[test]
    fn rejects_insecure_tlsa_https() {
        let server = TlsTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(false, vec![tlsa_spki_exact(&server.cert_der)]);
        let error = transport.fetch(&request).unwrap_err();

        assert!(
            matches!(error, TransportError::Io(_) | TransportError::Tls(_)),
            "{error:?}",
        );
    }

    #[test]
    fn rejects_invalid_https_server_name() {
        let transport = TcpHttpTransport::default();
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        request.scheme = "https".to_owned();
        request.host = "bad host".to_owned();

        assert_eq!(
            transport.fetch(&request).unwrap_err(),
            TransportError::InvalidRequest,
        );
    }

    #[test]
    fn rejects_invalid_request_header() {
        let transport = TcpHttpTransport::default();
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("Bad\r\nHeader".to_owned(), "x".to_owned()));

        assert_eq!(
            transport.fetch(&request).unwrap_err(),
            TransportError::InvalidRequest,
        );
    }

    #[test]
    fn fail_closed_transport_rejects_fetch() {
        assert_eq!(
            FailClosedTransport.fetch(&request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)))),
            Err(TransportError::UnsupportedTransport),
        );
    }

    fn request(address: SocketAddr) -> OriginRequest {
        OriginRequest {
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "example.com".to_owned(),
            connect_host: Some(address.ip().to_string()),
            port: address.port(),
            path_and_query: "/path?q=1".to_owned(),
            protocol: OriginProtocol::Http11,
            tls: TlsValidation::default(),
            headers: vec![("Proxy-Connection".to_owned(), "keep-alive".to_owned())],
            body: Vec::new(),
        }
    }

    fn tlsa_spki_exact(cert_der: &[u8]) -> TlsaRecord {
        tlsa_spki_exact_with_usage(cert_der, TlsaUsage::DaneEe)
    }

    fn tlsa_spki_exact_with_usage(cert_der: &[u8], usage: TlsaUsage) -> TlsaRecord {
        TlsaRecord {
            usage,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Exact,
            association_data: hns_dane::extract_spki_der(cert_der).unwrap(),
        }
    }

    struct TestServer {
        address: SocketAddr,
        request_rx: mpsc::Receiver<String>,
    }

    impl TestServer {
        fn start(response: Vec<u8>) -> Self {
            Self::start_delayed(response, Duration::ZERO)
        }

        fn start_delayed(response: Vec<u8>, delay: Duration) -> Self {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend(&buffer[..read]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                request_tx
                    .send(String::from_utf8_lossy(&request).into_owned())
                    .unwrap();
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                stream.write_all(&response).unwrap();
            });

            Self {
                address,
                request_rx,
            }
        }

        fn request(self) -> String {
            self.request_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        }
    }

    struct PersistentHttp11Server {
        address: SocketAddr,
        request_rx: mpsc::Receiver<String>,
        request_count: usize,
    }

    impl PersistentHttp11Server {
        fn start(responses: Vec<Vec<u8>>) -> Self {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let request_count = responses.len();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                for response in responses {
                    let request = read_test_http_head(&mut stream);
                    request_tx
                        .send(String::from_utf8_lossy(&request).into_owned())
                        .unwrap();
                    stream.write_all(&response).unwrap();
                    stream.flush().unwrap();
                }
            });

            Self {
                address,
                request_rx,
                request_count,
            }
        }

        fn requests(self) -> Vec<String> {
            (0..self.request_count)
                .map(|_| {
                    self.request_rx
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap()
                })
                .collect()
        }
    }

    struct UpgradeTestServer {
        address: SocketAddr,
        request_rx: mpsc::Receiver<String>,
    }

    impl UpgradeTestServer {
        fn start() -> Self {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_test_http_head(&mut stream);
                request_tx
                    .send(String::from_utf8_lossy(&request).into_owned())
                    .unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                    )
                    .unwrap();
                stream.flush().unwrap();
                let mut payload = [0u8; 4];
                stream.read_exact(&mut payload).unwrap();
                stream.write_all(&payload).unwrap();
                stream.flush().unwrap();
            });

            Self {
                address,
                request_rx,
            }
        }

        fn request(self) -> String {
            self.request_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        }
    }

    fn read_test_http_head(stream: &mut impl Read) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend(&buffer[..read]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        request
    }

    struct TlsTestServer {
        address: SocketAddr,
        cert_der: Vec<u8>,
        intermediate_cert_der: Option<Vec<u8>>,
        request_rx: mpsc::Receiver<String>,
    }

    impl TlsTestServer {
        fn start() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            Self::start_with_chain(vec![cert_der.clone()], key_der, cert_der, None)
        }

        fn start_h2() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
            .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec()];

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let (stream, _) = listener.accept().await.unwrap();
                    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                    let stream = acceptor.accept(stream).await.unwrap();
                    let mut connection = h2::server::handshake(stream).await.unwrap();
                    if let Some(request) = connection.accept().await {
                        let (request, mut respond) = request.unwrap();
                        request_tx
                            .send(format!("{} {}", request.method(), request.uri()))
                            .unwrap();
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-length", "2")
                            .header("x-test", "h2")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        send.send_data(Bytes::from_static(b"ok"), true).unwrap();
                        connection.graceful_shutdown();
                        let _ =
                            tokio::time::timeout(Duration::from_millis(100), connection.accept())
                                .await;
                    }
                });
            });

            Self {
                address,
                cert_der,
                intermediate_cert_der: None,
                request_rx,
            }
        }

        fn start_h3() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
            .unwrap();
            config.alpn_protocols = vec![b"h3".to_vec()];

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(config).unwrap(),
            ));
            let (address_tx, address_rx) = mpsc::channel();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let endpoint = quinn::Endpoint::server(
                        server_config,
                        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
                    )
                    .unwrap();
                    address_tx.send(endpoint.local_addr().unwrap()).unwrap();
                    let connecting = endpoint.accept().await.unwrap();
                    let connection = connecting.await.unwrap();
                    let quic = h3_quinn::Connection::new(connection);
                    let mut connection = h3::server::builder().build(quic).await.unwrap();
                    if let Some(request) = connection.accept().await.unwrap() {
                        let handler = tokio::spawn(async move {
                            let (request, mut stream) = request.resolve_request().await.unwrap();
                            request_tx
                                .send(format!("{} {}", request.method(), request.uri()))
                                .unwrap();
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-length", "2")
                                .header("x-test", "h3")
                                .body(())
                                .unwrap();
                            stream.send_response(response).await.unwrap();
                            stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
                            stream.finish().await.unwrap();
                        });
                        let _ = tokio::time::timeout(Duration::from_secs(1), async {
                            while let Ok(Some(_)) = connection.accept().await {
                                // Drive the connection while the spawned request handler writes.
                            }
                        })
                        .await;
                        handler.await.unwrap();
                    }
                });
            });
            let address = address_rx.recv_timeout(Duration::from_secs(1)).unwrap();

            Self {
                address,
                cert_der,
                intermediate_cert_der: None,
                request_rx,
            }
        }

        fn start_alt_svc_h2() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
            .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let config = Arc::new(config);
                let (stream, _) = listener.accept().unwrap();
                let connection = ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut stream = StreamOwned::new(connection, stream);
                let request = read_test_http_head(&mut stream);
                request_tx
                    .send(format!("h1 {}", String::from_utf8_lossy(&request)))
                    .unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nAlt-Svc: h2=\":{}\"; ma=60\r\nConnection: close\r\n\r\nh1",
                            address.port()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stream.flush().unwrap();

                let (stream, _) = listener.accept().unwrap();
                stream.set_nonblocking(true).unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(config);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let stream = tokio::net::TcpStream::from_std(stream).unwrap();
                    let stream = acceptor.accept(stream).await.unwrap();
                    let mut connection = h2::server::handshake(stream).await.unwrap();
                    if let Some(request) = connection.accept().await {
                        let (request, mut respond) = request.unwrap();
                        request_tx
                            .send(format!("h2 {} {}", request.method(), request.uri()))
                            .unwrap();
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-length", "2")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        send.send_data(Bytes::from_static(b"h2"), true).unwrap();
                        connection.graceful_shutdown();
                        let _ =
                            tokio::time::timeout(Duration::from_millis(100), connection.accept())
                                .await;
                    }
                });
            });

            Self {
                address,
                cert_der,
                intermediate_cert_der: None,
                request_rx,
            }
        }

        fn start_with_intermediate() -> Self {
            let mut intermediate_params =
                rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            intermediate_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::DigitalSignature);
            intermediate_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::KeyCertSign);
            intermediate_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::CrlSign);
            let intermediate_key = rcgen::KeyPair::generate().unwrap();
            let intermediate =
                rcgen::CertifiedIssuer::self_signed(intermediate_params, intermediate_key).unwrap();
            let intermediate_cert_der = intermediate.der().to_vec();

            let mut leaf_params =
                rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
            leaf_params.use_authority_key_identifier_extension = true;
            leaf_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::DigitalSignature);
            leaf_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let leaf_cert = leaf_params.signed_by(&leaf_key, &intermediate).unwrap();
            let cert_der = leaf_cert.der().to_vec();
            let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

            Self::start_with_chain(
                vec![cert_der.clone(), intermediate_cert_der.clone()],
                key_der,
                cert_der,
                Some(intermediate_cert_der),
            )
        }

        fn start_with_chain(
            cert_chain_der: Vec<Vec<u8>>,
            key_der: PrivateKeyDer<'static>,
            cert_der: Vec<u8>,
            intermediate_cert_der: Option<Vec<u8>>,
        ) -> Self {
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                cert_chain_der
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect(),
                key_der,
            )
            .unwrap();

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let connection = ServerConnection::new(Arc::new(config)).unwrap();
                let mut stream = StreamOwned::new(connection, stream);
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend(&buffer[..read]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = request_tx.send(String::from_utf8_lossy(&request).into_owned());
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = stream.flush();
            });

            Self {
                address,
                cert_der,
                intermediate_cert_der,
                request_rx,
            }
        }

        fn request(self) -> String {
            self.request_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        }

        fn requests(self, count: usize) -> Vec<String> {
            (0..count)
                .map(|_| {
                    self.request_rx
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap()
                })
                .collect()
        }
    }
}
