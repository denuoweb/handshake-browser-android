use hns_dane::{
    DaneCertificateValidationInput, DaneDecision, DaneError, DomainTrustMode, TlsaRecord,
    WebPkiStatus, evaluate_policy_with_certificate,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls::{Error as RustlsError, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
    pub dane_decision: DaneDecision,
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

pub struct FailClosedTransport;

#[derive(Clone, Debug)]
pub struct TcpHttpTransport {
    connect_timeout: Duration,
    read_timeout: Duration,
    limits: TransportLimits,
    root_store: Arc<RootCertStore>,
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
        }
    }

    pub fn limits(&self) -> TransportLimits {
        self.limits
    }

    fn fetch_http11(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        validate_request(request, self.limits)?;
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let mut stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let request_bytes = build_http_request(request)?;
        stream.write_all(&request_bytes).map_err(io_error)?;
        stream.flush().map_err(io_error)?;
        parse_http_response(&mut stream, self.limits, &request.method)
    }

    fn fetch_http11_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let mut stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let request_bytes = build_http_request(request)?;
        stream.write_all(&request_bytes).map_err(io_error)?;
        stream.flush().map_err(io_error)?;
        parse_http_response_to_writer(&mut stream, self.limits, &request.method, body)
    }

    fn fetch_https_http11(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginResponse, TransportError> {
        validate_request(request, self.limits)?;
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let decision = Arc::new(Mutex::new(None));
        let config = self.client_config(request.tls.clone(), Arc::clone(&decision))?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        let connection = ClientConnection::new(Arc::new(config), server_name).map_err(tls_error)?;
        let mut tls_stream = StreamOwned::new(connection, stream);

        let request_bytes = build_http_request(request)?;
        tls_stream.write_all(&request_bytes).map_err(io_error)?;
        tls_stream.flush().map_err(io_error)?;
        let mut response = parse_http_response(&mut tls_stream, self.limits, &request.method)?;
        response.dane_decision = decision
            .lock()
            .map_err(|_| TransportError::Tls("TLS decision lock is poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| {
                TransportError::Tls("TLS certificate policy was not evaluated".to_owned())
            })?;
        Ok(response)
    }

    fn fetch_https_http11_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let decision = Arc::new(Mutex::new(None));
        let config = self.client_config(request.tls.clone(), Arc::clone(&decision))?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        let connection = ClientConnection::new(Arc::new(config), server_name).map_err(tls_error)?;
        let mut tls_stream = StreamOwned::new(connection, stream);

        let request_bytes = build_http_request(request)?;
        tls_stream.write_all(&request_bytes).map_err(io_error)?;
        tls_stream.flush().map_err(io_error)?;
        let mut response =
            parse_http_response_to_writer(&mut tls_stream, self.limits, &request.method, body)?;
        response.dane_decision = decision
            .lock()
            .map_err(|_| TransportError::Tls("TLS decision lock is poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| {
                TransportError::Tls("TLS certificate policy was not evaluated".to_owned())
            })?;
        Ok(response)
    }

    fn client_config(
        &self,
        tls: TlsValidation,
        decision: Arc<Mutex<Option<DaneDecision>>>,
    ) -> Result<ClientConfig, TransportError> {
        let provider = rustls::crypto::ring::default_provider();
        let webpki = WebPkiServerVerifier::builder_with_provider(
            Arc::clone(&self.root_store),
            Arc::new(provider.clone()),
        )
        .build()
        .map_err(|error| TransportError::Tls(error.to_string()))?;
        let verifier = Arc::new(DaneServerCertVerifier {
            webpki,
            tls,
            decision,
        });

        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(tls_error)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(config)
    }
}

impl OriginTransport for FailClosedTransport {
    fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        Err(TransportError::UnsupportedTransport)
    }
}

impl OriginTransport for TcpHttpTransport {
    fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        if request.protocol != OriginProtocol::Http11 {
            return Err(TransportError::UnsupportedTransport);
        }

        match request.scheme.to_ascii_lowercase().as_str() {
            "http" => self.fetch_http11(request),
            "https" => self.fetch_https_http11(request),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }

    fn fetch_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        if request.protocol != OriginProtocol::Http11 {
            return Err(TransportError::UnsupportedTransport);
        }

        match request.scheme.to_ascii_lowercase().as_str() {
            "http" => self.fetch_http11_to_writer(request, body),
            "https" => self.fetch_https_http11_to_writer(request, body),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }
}

#[derive(Debug)]
struct DaneServerCertVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    tls: TlsValidation,
    decision: Arc<Mutex<Option<DaneDecision>>>,
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

        match evaluate_policy_with_certificate(DaneCertificateValidationInput {
            mode: self.tls.mode,
            dnssec_secure: self.tls.dnssec_secure,
            tlsa_records: &self.tls.tlsa_records,
            cert_der: end_entity.as_ref(),
            webpki_status,
        }) {
            Ok(DaneDecision::Failed) => Err(RustlsError::General(
                "DANE certificate association did not match".to_owned(),
            )),
            Ok(decision) => {
                let mut stored_decision = self.decision.lock().map_err(|_| {
                    RustlsError::General("TLS decision lock is poisoned".to_owned())
                })?;
                *stored_decision = Some(decision);
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

fn validate_request(
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

    if is_protocol_upgrade(&request.headers) {
        return Err(TransportError::UnsupportedUpgrade);
    }

    for (name, value) in &request.headers {
        if !is_http_token(name) || value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err(TransportError::InvalidRequest);
        }
    }

    Ok(())
}

fn build_http_request(request: &OriginRequest) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    write!(
        out,
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: hns-browser/0.1.1\r\nAccept: */*\r\n",
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

    if request.body.is_empty() {
        out.extend(b"Connection: close\r\n\r\n");
    } else {
        write!(
            out,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            request.body.len(),
        )
        .map_err(io_error)?;
        out.extend(&request.body);
    }

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

fn parse_http_response(
    stream: &mut impl Read,
    limits: TransportLimits,
    request_method: &str,
) -> Result<OriginResponse, TransportError> {
    let mut body = Vec::new();
    let head = parse_http_response_to_writer(stream, limits, request_method, &mut body)?;
    Ok(OriginResponse {
        status: head.status,
        headers: head.headers,
        body,
        dane_decision: head.dane_decision,
    })
}

fn parse_http_response_to_writer(
    stream: &mut impl Read,
    limits: TransportLimits,
    request_method: &str,
    body: &mut dyn Write,
) -> Result<OriginResponseHead, TransportError> {
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

    let body_len = if response_has_no_body(request_method, status) {
        0
    } else if let Some(transfer_encoding) = transfer_encoding(&headers)? {
        if content_length(&headers)?.is_some() {
            return Err(TransportError::MalformedResponse);
        }
        if transfer_encoding != [TransferCoding::Chunked] {
            return Err(TransportError::UnsupportedTransferEncoding);
        }
        read_chunked_body_to_writer(stream, limits.max_response_body_bytes, body)?
    } else if let Some(length) = content_length(&headers)? {
        read_fixed_body_to_writer(stream, length, limits.max_response_body_bytes, body)?
    } else {
        read_until_eof_to_writer(stream, limits.max_response_body_bytes, body)?
    };

    Ok(OriginResponseHead {
        status,
        headers,
        body_len,
        dane_decision: DaneDecision::NoTlsa,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use hns_dane::{TlsaMatching, TlsaSelector, TlsaUsage};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    use std::io::Read;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
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
        assert!(raw_request.contains("Connection: close"));
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

        let bytes = build_http_request(&request).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(!text.contains("Content-Length: 999\r\n"));
        assert!(text.ends_with("\r\n\r\nhi"));
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
        TlsaRecord {
            usage: TlsaUsage::DaneEe,
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

    struct TlsTestServer {
        address: SocketAddr,
        cert_der: Vec<u8>,
        request_rx: mpsc::Receiver<String>,
    }

    impl TlsTestServer {
        fn start() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
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
                request_rx,
            }
        }

        fn request(self) -> String {
            self.request_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        }
    }
}
