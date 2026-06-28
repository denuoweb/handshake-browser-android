use hns_core::bytes::ParseError;
use hns_core::dns::{
    DnsName, RecordType, ResourceRecord, SVCB_PARAM_ALPN, SVCB_PARAM_MANDATORY,
    SVCB_PARAM_NO_DEFAULT_ALPN, SVCB_PARAM_PORT, SvcbRecord,
};
use hns_dane::{DaneError, DomainTrustMode, TlsaRecord};
use hns_resolver::{ResolutionAnswer, ResolutionRequest, Resolver, ResolverError, hns_root_label};
use hns_transport::{
    OriginProtocol, OriginRequest, OriginResponse, OriginResponseHead, OriginTransport,
    TransportError,
};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

const MAX_CNAME_CHAIN_LEN: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfig {
    pub bind: SocketAddr,
    pub auth_token: Option<String>,
    pub require_secure_resolution: bool,
    pub hns_https_mode: HnsHttpsMode,
    pub supported_origin_protocols: Vec<OriginProtocol>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HnsHttpsMode {
    Strict,
    Compatibility,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRequest {
    pub origin: OriginRequest,
    pub resolution: ResolutionRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponse {
    pub resolution: ResolutionAnswer,
    pub origin: OriginResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponseHead {
    pub resolution: ResolutionAnswer,
    pub origin: OriginResponseHead,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GatewayError {
    #[error("gateway must bind to loopback")]
    NonLoopbackBind,
    #[error("origin host does not match resolution name")]
    HostResolutionMismatch,
    #[error("resolution is not cryptographically secure")]
    InsecureResolution,
    #[error("HNS resolution did not provide an origin address")]
    NoResolvedAddress,
    #[error("TLSA record is invalid: {0}")]
    InvalidTlsa(#[from] DaneError),
    #[error("HTTPS/SVCB record is invalid: {0}")]
    InvalidSvcb(ParseError),
    #[error("HTTPS/SVCB service binding is unsupported")]
    UnsupportedSvcb,
    #[error("resolver error: {0}")]
    Resolver(#[from] ResolverError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

pub struct Gateway<R, T> {
    config: GatewayConfig,
    resolver: R,
    transport: T,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15_353),
            auth_token: None,
            require_secure_resolution: true,
            hns_https_mode: HnsHttpsMode::Strict,
            supported_origin_protocols: vec![
                OriginProtocol::Http11,
                OriginProtocol::Http2,
                OriginProtocol::Http3,
            ],
        }
    }
}

impl GatewayConfig {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.bind.ip().is_loopback() {
            Ok(())
        } else {
            Err(GatewayError::NonLoopbackBind)
        }
    }
}

impl<R, T> Gateway<R, T>
where
    R: Resolver,
    T: OriginTransport,
{
    pub fn new(config: GatewayConfig, resolver: R, transport: T) -> Result<Self, GatewayError> {
        config.validate()?;
        Ok(Self {
            config,
            resolver,
            transport,
        })
    }

    pub fn handle(&self, request: &GatewayRequest) -> Result<GatewayResponse, GatewayError> {
        let (resolution, origin_request) = self.resolve_origin_request(request)?;
        let origin = self.transport.fetch(&origin_request)?;
        Ok(GatewayResponse { resolution, origin })
    }

    pub fn handle_to_writer(
        &self,
        request: &GatewayRequest,
        body: &mut dyn Write,
    ) -> Result<GatewayResponseHead, GatewayError> {
        let (resolution, origin_request) = self.resolve_origin_request(request)?;
        let origin = self.transport.fetch_to_writer(&origin_request, body)?;
        Ok(GatewayResponseHead { resolution, origin })
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn resolve_origin_request(
        &self,
        request: &GatewayRequest,
    ) -> Result<(ResolutionAnswer, OriginRequest), GatewayError> {
        if !hosts_match(&request.origin.host, &request.resolution.qname) {
            return Err(GatewayError::HostResolutionMismatch);
        }

        let resolution = self.resolver.resolve(&request.resolution)?;
        if self.config.require_secure_resolution && !resolution.secure {
            return Err(GatewayError::InsecureResolution);
        }

        let mut origin_request = request.origin.clone();
        if origin_request.connect_host.is_none() {
            origin_request.connect_host =
                first_resolved_address(&resolution.records, &origin_request.host);
            if origin_request.connect_host.is_none()
                && hns_root_label(&request.resolution.qname).is_ok()
            {
                origin_request.connect_host = self.resolve_origin_address(&origin_request.host)?;
            }
            if origin_request.connect_host.is_none()
                && hns_root_label(&request.resolution.qname).is_ok()
            {
                return Err(GatewayError::NoResolvedAddress);
            }
        }
        if origin_request.scheme.eq_ignore_ascii_case("https") {
            origin_request.tls.mode = self.config.hns_https_mode.domain_trust_mode();
            if !apply_https_service_policy(
                &resolution.records,
                &mut origin_request,
                &self.config.supported_origin_protocols,
            )? {
                self.resolve_https_service_policy(&mut origin_request)?;
            }
            let (tlsa_secure, tlsa_records) =
                self.resolve_tlsa_records(&origin_request.host, origin_request.port)?;
            origin_request.tls.dnssec_secure = tlsa_secure;
            origin_request.tls.tlsa_records = tlsa_records;
        }

        Ok((resolution, origin_request))
    }

    fn resolve_tlsa_records(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(bool, Vec<TlsaRecord>), GatewayError> {
        let Some(request) = tlsa_resolution_request(host, port) else {
            return Ok((false, Vec::new()));
        };
        let answer = self.resolver.resolve(&request)?;
        if self.config.require_secure_resolution && !answer.secure {
            return Err(GatewayError::InsecureResolution);
        }

        Ok((
            answer.secure,
            tlsa_records(&answer.records, &request.qname)?,
        ))
    }

    fn resolve_origin_address(&self, host: &str) -> Result<Option<String>, GatewayError> {
        for qtype in [RecordType::A, RecordType::Aaaa] {
            let request = ResolutionRequest {
                qname: normalize_host(host),
                qtype: qtype.code(),
            };
            let answer = self.resolver.resolve(&request)?;
            if self.config.require_secure_resolution && !answer.secure {
                return Err(GatewayError::InsecureResolution);
            }
            if let Some(address) = first_resolved_address(&answer.records, host) {
                return Ok(Some(address));
            }
        }

        Ok(None)
    }

    fn resolve_https_service_policy(
        &self,
        request: &mut OriginRequest,
    ) -> Result<(), GatewayError> {
        let answer = self.resolver.resolve(&ResolutionRequest {
            qname: normalize_host(&request.host),
            qtype: RecordType::Https.code(),
        })?;
        if self.config.require_secure_resolution && !answer.secure {
            return Err(GatewayError::InsecureResolution);
        }
        apply_https_service_policy(
            &answer.records,
            request,
            &self.config.supported_origin_protocols,
        )?;
        Ok(())
    }
}

impl HnsHttpsMode {
    fn domain_trust_mode(self) -> DomainTrustMode {
        match self {
            HnsHttpsMode::Strict => DomainTrustMode::HnsStrict,
            HnsHttpsMode::Compatibility => DomainTrustMode::HnsCompatibility,
        }
    }
}

fn hosts_match(origin_host: &str, qname: &str) -> bool {
    normalize_host(origin_host) == normalize_host(qname)
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn first_resolved_address(records: &[ResourceRecord], host: &str) -> Option<String> {
    let owner = DnsName::from_ascii(&normalize_host(host)).ok()?;
    resolved_address_for_owner(records, &owner, 0)
}

fn resolved_address_for_owner(
    records: &[ResourceRecord],
    owner: &DnsName,
    depth: usize,
) -> Option<String> {
    if depth > MAX_CNAME_CHAIN_LEN {
        return None;
    }
    records
        .iter()
        .filter(|record| record.name == *owner)
        .find_map(|record| match record.record_type {
            RecordType::A if record.rdata.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
                record.rdata[0],
                record.rdata[1],
                record.rdata[2],
                record.rdata[3],
            ))),
            RecordType::Aaaa if record.rdata.len() == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&record.rdata);
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            _ => None,
        })
        .map(|address| address.to_string())
        .or_else(|| {
            let target = cname_target_for_owner(records, owner)?;
            resolved_address_for_owner(records, &target, depth + 1)
        })
}

fn cname_target_for_owner(records: &[ResourceRecord], owner: &DnsName) -> Option<DnsName> {
    let mut candidates = records
        .iter()
        .filter(|record| record.name == *owner && record.record_type == RecordType::Cname);
    let record = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    let (target, end) = DnsName::parse_wire(&record.rdata, 0).ok()?;
    (end == record.rdata.len()).then_some(target)
}

fn tlsa_resolution_request(host: &str, port: u16) -> Option<ResolutionRequest> {
    let qname = DnsName::from_ascii(&format!("_{port}._tcp.{}", normalize_host(host))).ok()?;
    Some(ResolutionRequest {
        qname: qname.to_string(),
        qtype: RecordType::Tlsa.code(),
    })
}

fn tlsa_records(
    records: &[ResourceRecord],
    service_qname: &str,
) -> Result<Vec<TlsaRecord>, GatewayError> {
    let owner = match DnsName::from_ascii(service_qname) {
        Ok(owner) => owner,
        Err(_) => return Ok(Vec::new()),
    };

    records
        .iter()
        .filter(|record| record.record_type == RecordType::Tlsa && record.name == owner)
        .map(|record| TlsaRecord::parse_rdata(&record.rdata).map_err(GatewayError::from))
        .collect()
}

fn apply_https_service_policy(
    records: &[ResourceRecord],
    request: &mut OriginRequest,
    supported_protocols: &[OriginProtocol],
) -> Result<bool, GatewayError> {
    let Some(service) = selected_https_service(records, &request.host, supported_protocols)? else {
        return Ok(false);
    };

    request.port = service.port.unwrap_or(request.port);
    request.protocol = service.protocol;
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HttpsServicePolicy {
    protocol: OriginProtocol,
    port: Option<u16>,
}

fn selected_https_service(
    records: &[ResourceRecord],
    host: &str,
    supported_protocols: &[OriginProtocol],
) -> Result<Option<HttpsServicePolicy>, GatewayError> {
    let owner =
        DnsName::from_ascii(&normalize_host(host)).map_err(|_| GatewayError::UnsupportedSvcb)?;
    let mut selected = None;
    let mut saw_service = false;

    for record in records
        .iter()
        .filter(|record| record.record_type == RecordType::Https && record.name == owner)
    {
        saw_service = true;
        let svcb = SvcbRecord::from_record(record).map_err(GatewayError::InvalidSvcb)?;
        if svcb.is_alias_mode() {
            return Err(GatewayError::UnsupportedSvcb);
        }
        if svcb.target_name != DnsName::root() && svcb.target_name != owner {
            return Err(GatewayError::UnsupportedSvcb);
        }
        validate_supported_mandatory_params(&svcb)?;

        let Some(protocol) = selected_alpn_protocol(&svcb, supported_protocols)? else {
            continue;
        };
        let candidate = (
            svcb.svc_priority,
            HttpsServicePolicy {
                protocol,
                port: svcb.port().map_err(GatewayError::InvalidSvcb)?,
            },
        );
        if selected
            .as_ref()
            .is_none_or(|(priority, _)| candidate.0 < *priority)
        {
            selected = Some(candidate);
        }
    }

    if let Some((_, policy)) = selected {
        Ok(Some(policy))
    } else if saw_service {
        Err(GatewayError::UnsupportedSvcb)
    } else {
        Ok(None)
    }
}

fn validate_supported_mandatory_params(svcb: &SvcbRecord) -> Result<(), GatewayError> {
    let Some(value) = svcb.param(SVCB_PARAM_MANDATORY) else {
        return Ok(());
    };
    for chunk in value.chunks_exact(2) {
        let key = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !matches!(
            key,
            SVCB_PARAM_ALPN | SVCB_PARAM_NO_DEFAULT_ALPN | SVCB_PARAM_PORT
        ) {
            return Err(GatewayError::UnsupportedSvcb);
        }
    }
    Ok(())
}

fn selected_alpn_protocol(
    svcb: &SvcbRecord,
    supported_protocols: &[OriginProtocol],
) -> Result<Option<OriginProtocol>, GatewayError> {
    let alpn = svcb.alpn_ids().map_err(GatewayError::InvalidSvcb)?;
    if supports_protocol(supported_protocols, OriginProtocol::Http3)
        && alpn.iter().any(|id| is_http3_alpn(id))
    {
        return Ok(Some(OriginProtocol::Http3));
    }
    if supports_protocol(supported_protocols, OriginProtocol::Http2)
        && alpn.iter().any(|id| id.as_slice() == b"h2")
    {
        return Ok(Some(OriginProtocol::Http2));
    }
    if supports_protocol(supported_protocols, OriginProtocol::Http11)
        && (alpn.iter().any(|id| id.as_slice() == b"http/1.1")
            || svcb.param(SVCB_PARAM_NO_DEFAULT_ALPN).is_none())
    {
        return Ok(Some(OriginProtocol::Http11));
    }
    Ok(None)
}

fn supports_protocol(supported_protocols: &[OriginProtocol], protocol: OriginProtocol) -> bool {
    supported_protocols.contains(&protocol)
}

fn is_http3_alpn(id: &[u8]) -> bool {
    id == b"h3" || id.starts_with(b"h3-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_core::dns::{DnsName, RecordType, ResourceRecord};
    use hns_dane::{DaneDecision, DaneError, TlsaMatching, TlsaSelector, TlsaUsage};
    use hns_resolver::{ResolutionAnswer, Resolver};
    use hns_transport::{OriginProtocol, OriginResponse, OriginTransport, TlsValidation};
    use std::sync::{Arc, Mutex};

    struct StaticResolver {
        secure: bool,
        records: Vec<ResourceRecord>,
    }

    struct ScriptedResolver {
        responses: Vec<(ResolutionRequest, ResolutionAnswer)>,
        requests: Arc<Mutex<Vec<ResolutionRequest>>>,
    }

    impl Resolver for StaticResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            Ok(ResolutionAnswer {
                name: DnsName::root(),
                records: self.records.clone(),
                secure: self.secure,
            })
        }
    }

    impl Resolver for ScriptedResolver {
        fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.requests.lock().unwrap().push(request.clone());
            self.responses
                .iter()
                .find(|(candidate, _)| candidate == request)
                .map(|(_, answer)| answer.clone())
                .ok_or(ResolverError::ProofUnavailable)
        }
    }

    struct StaticTransport;

    impl OriginTransport for StaticTransport {
        fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
            Ok(OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::NoTlsa,
            })
        }
    }

    #[derive(Default)]
    struct CapturingTransport {
        last_request: Mutex<Option<OriginRequest>>,
    }

    impl OriginTransport for CapturingTransport {
        fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
            *self.last_request.lock().unwrap() = Some(request.clone());
            Ok(OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::NoTlsa,
            })
        }
    }

    #[test]
    fn rejects_non_loopback_bind() {
        let config = GatewayConfig {
            bind: "0.0.0.0:15353".parse().unwrap(),
            ..GatewayConfig::default()
        };

        assert_eq!(
            config.validate().unwrap_err(),
            GatewayError::NonLoopbackBind
        );
    }

    #[test]
    fn rejects_host_resolution_mismatch() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure(),
            StaticTransport,
        )
        .unwrap();

        let request = request("name", "other");

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::HostResolutionMismatch,
        );
    }

    #[test]
    fn rejects_insecure_resolution_by_default() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::insecure(),
            StaticTransport,
        )
        .unwrap();

        let request = request("name", "name");

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::InsecureResolution,
        );
    }

    #[test]
    fn returns_resolution_and_origin_response() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure_with_address(),
            StaticTransport,
        )
        .unwrap();

        let response = gateway.handle(&request("name", "name")).unwrap();

        assert!(response.resolution.secure);
        assert_eq!(response.origin.status, 200);
    }

    #[test]
    fn rejects_hns_resolution_without_origin_address() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure(),
            StaticTransport,
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::NoResolvedAddress,
        );
    }

    #[test]
    fn rejects_nameserver_glue_as_origin_address() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    ResourceRecord {
                        name: DnsName::from_ascii("name").unwrap(),
                        record_type: RecordType::Ns,
                        class: 1,
                        ttl: 60,
                        rdata: name_rdata("ns1.name"),
                    },
                    ResourceRecord {
                        name: DnsName::from_ascii("ns1.name").unwrap(),
                        record_type: RecordType::A,
                        class: 1,
                        ttl: 60,
                        rdata: vec![127, 0, 0, 1],
                    },
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::NoResolvedAddress,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn passes_resolved_address_to_transport() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![ResourceRecord {
                    name: DnsName::from_ascii("name").unwrap(),
                    record_type: RecordType::A,
                    class: 1,
                    ttl: 60,
                    rdata: vec![127, 0, 0, 1],
                }],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.host, "name");
        assert_eq!(captured.connect_host, Some("127.0.0.1".to_owned()));
    }

    #[test]
    fn resolves_origin_address_after_all_root_records_return_delegation_only() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![ns_record("name", "ns1.name"), ds_record("name")],
                    ),
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.connect_host, Some("127.0.0.1".to_owned()));
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: u16::MAX,
                },
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_443._tcp.name".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn falls_back_to_aaaa_when_delegated_a_has_no_address() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", u16::MAX, true, vec![ds_record("name")]),
                    response("name", RecordType::A.code(), true, vec![]),
                    response(
                        "name",
                        RecordType::Aaaa.code(),
                        true,
                        vec![address_record_v6()],
                    ),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.connect_host, Some("::1".to_owned()));
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| request.qtype)
                .collect::<Vec<_>>(),
            vec![
                u16::MAX,
                RecordType::A.code(),
                RecordType::Aaaa.code(),
                RecordType::Https.code(),
                RecordType::Tlsa.code(),
            ],
        );
    }

    #[test]
    fn passes_cname_resolved_address_to_transport() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    cname_record("name", "edge.name"),
                    ResourceRecord {
                        name: DnsName::from_ascii("edge.name").unwrap(),
                        record_type: RecordType::A,
                        class: 1,
                        ttl: 60,
                        rdata: vec![127, 0, 0, 1],
                    },
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.host, "name");
        assert_eq!(captured.connect_host, Some("127.0.0.1".to_owned()));
    }

    #[test]
    fn selects_http2_from_https_service_alpn() {
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11, OriginProtocol::Http2]),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![
                            address_record(),
                            https_record("name", 1, ".", vec![alpn_param(&[b"h2"])]),
                        ],
                    ),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http2);
        assert_eq!(captured.port, 443);
    }

    #[test]
    fn resolves_https_service_policy_when_initial_answer_is_address_only() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11, OriginProtocol::Http2]),
            ScriptedResolver::new(
                vec![
                    response(
                        "www.name",
                        RecordType::A.code(),
                        true,
                        vec![address_record_for("www.name")],
                    ),
                    response(
                        "www.name",
                        RecordType::Https.code(),
                        true,
                        vec![https_record(
                            "www.name",
                            1,
                            ".",
                            vec![alpn_param(&[b"h2"]), port_param(8443)],
                        )],
                    ),
                    response("_8443._tcp.www.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("www.name", "www.name");
        request.resolution.qtype = RecordType::A.code();

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http2);
        assert_eq!(captured.port, 8443);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "www.name".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "www.name".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_8443._tcp.www.name".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn selects_http3_and_service_port_from_https_service_alpn() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11, OriginProtocol::Http3]),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![
                            address_record(),
                            https_record(
                                "name",
                                1,
                                ".",
                                vec![alpn_param(&[b"h3"]), port_param(8443)],
                            ),
                        ],
                    ),
                    response("_8443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http3);
        assert_eq!(captured.port, 8443);
        assert_eq!(
            requests.lock().unwrap().last().unwrap(),
            &ResolutionRequest {
                qname: "_8443._tcp.name".to_owned(),
                qtype: RecordType::Tlsa.code(),
            },
        );
    }

    #[test]
    fn defaults_to_http11_when_unsupported_alpn_allows_default_protocols() {
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11]),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![
                            address_record(),
                            https_record("name", 1, ".", vec![alpn_param(&[b"h2"])]),
                        ],
                    ),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http11);
        assert_eq!(captured.port, 443);
    }

    #[test]
    fn rejects_https_service_when_no_supported_alpn_remains() {
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11]),
            StaticResolver {
                secure: true,
                records: vec![
                    address_record(),
                    https_record(
                        "name",
                        1,
                        ".",
                        vec![alpn_param(&[b"h2"]), no_default_alpn_param()],
                    ),
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::UnsupportedSvcb,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn rejects_https_service_alias_mode_until_alias_resolution_is_supported() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    address_record(),
                    https_record("name", 0, "alias.name", Vec::new()),
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::UnsupportedSvcb,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn passes_secure_tlsa_records_to_https_transport() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.name",
                        RecordType::Tlsa.code(),
                        true,
                        vec![
                            tlsa_record("_443._tcp.other", vec![3, 1, 0, 0xbb]),
                            tlsa_record("_8443._tcp.name", vec![3, 1, 0, 0xcc]),
                            tlsa_record("_443._tcp.name", vec![3, 1, 0, 0xaa]),
                        ],
                    ),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert!(captured.tls.dnssec_secure);
        assert_eq!(captured.tls.tlsa_records.len(), 1);
        assert_eq!(captured.tls.tlsa_records[0].usage, TlsaUsage::DaneEe);
        assert_eq!(
            captured.tls.tlsa_records[0].selector,
            TlsaSelector::SubjectPublicKeyInfo,
        );
        assert_eq!(captured.tls.tlsa_records[0].matching, TlsaMatching::Exact);
        assert_eq!(captured.tls.tlsa_records[0].association_data, vec![0xaa],);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_443._tcp.name".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn ignores_tlsa_records_for_other_service_owners() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.name",
                        RecordType::Tlsa.code(),
                        true,
                        vec![
                            tlsa_record("_443._tcp.other", vec![3, 1, 0, 0xbb]),
                            tlsa_record("_8443._tcp.name", vec![3, 1, 0, 0xcc]),
                        ],
                    ),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert!(captured.tls.dnssec_secure);
        assert!(captured.tls.tlsa_records.is_empty());
        assert_eq!(captured.tls.mode, DomainTrustMode::HnsStrict);
    }

    #[test]
    fn compatibility_mode_allows_https_transport_webpki_fallback() {
        let gateway = Gateway::new(
            GatewayConfig {
                hns_https_mode: HnsHttpsMode::Compatibility,
                ..GatewayConfig::default()
            },
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.tls.mode, DomainTrustMode::HnsCompatibility);
        assert!(captured.tls.dnssec_secure);
        assert!(captured.tls.tlsa_records.is_empty());
    }

    #[test]
    fn rejects_insecure_tlsa_resolution_by_default() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.name",
                        RecordType::Tlsa.code(),
                        false,
                        vec![tlsa_record("_443._tcp.name", vec![3, 1, 0, 0xaa])],
                    ),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::InsecureResolution,
        );
    }

    #[test]
    fn malformed_tlsa_record_fails_closed() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    address_record(),
                    ResourceRecord {
                        name: DnsName::from_ascii("_443._tcp.name").unwrap(),
                        record_type: RecordType::Tlsa,
                        class: 1,
                        ttl: 60,
                        rdata: vec![3, 1],
                    },
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::InvalidTlsa(DaneError::ShortRecord),
        );
    }

    impl StaticResolver {
        fn secure() -> Self {
            Self {
                secure: true,
                records: Vec::new(),
            }
        }

        fn secure_with_address() -> Self {
            Self {
                secure: true,
                records: vec![address_record()],
            }
        }

        fn insecure() -> Self {
            Self {
                secure: false,
                records: Vec::new(),
            }
        }
    }

    impl ScriptedResolver {
        fn new(
            responses: Vec<(ResolutionRequest, ResolutionAnswer)>,
            requests: Arc<Mutex<Vec<ResolutionRequest>>>,
        ) -> Self {
            Self {
                responses,
                requests,
            }
        }
    }

    fn response(
        qname: &str,
        qtype: u16,
        secure: bool,
        records: Vec<ResourceRecord>,
    ) -> (ResolutionRequest, ResolutionAnswer) {
        (
            ResolutionRequest {
                qname: qname.to_owned(),
                qtype,
            },
            ResolutionAnswer {
                name: DnsName::from_ascii(qname).unwrap(),
                records,
                secure,
            },
        )
    }

    fn address_record() -> ResourceRecord {
        address_record_for("name")
    }

    fn address_record_for(name: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(name).unwrap(),
            record_type: RecordType::A,
            class: 1,
            ttl: 60,
            rdata: vec![127, 0, 0, 1],
        }
    }

    fn address_record_v6() -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii("name").unwrap(),
            record_type: RecordType::Aaaa,
            class: 1,
            ttl: 60,
            rdata: Ipv6Addr::LOCALHOST.octets().to_vec(),
        }
    }

    fn ns_record(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Ns,
            class: 1,
            ttl: 60,
            rdata: name_rdata(target),
        }
    }

    fn ds_record(owner: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Ds,
            class: 1,
            ttl: 60,
            rdata: vec![0x12, 0x34, 13, 2, 0xaa, 0xbb, 0xcc],
        }
    }

    fn tlsa_record(name: &str, rdata: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(name).unwrap(),
            record_type: RecordType::Tlsa,
            class: 1,
            ttl: 60,
            rdata,
        }
    }

    fn https_record(
        owner: &str,
        priority: u16,
        target: &str,
        params: Vec<(u16, Vec<u8>)>,
    ) -> ResourceRecord {
        let mut rdata = Vec::new();
        push_u16(&mut rdata, priority);
        if target == "." {
            DnsName::root()
        } else {
            DnsName::from_ascii(target).unwrap()
        }
        .encode_wire(&mut rdata)
        .unwrap();
        for (key, value) in params {
            push_u16(&mut rdata, key);
            push_u16(&mut rdata, value.len() as u16);
            rdata.extend(value);
        }
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Https,
            class: 1,
            ttl: 60,
            rdata,
        }
    }

    fn alpn_param(ids: &[&[u8]]) -> (u16, Vec<u8>) {
        let mut value = Vec::new();
        for id in ids {
            value.push(id.len() as u8);
            value.extend(*id);
        }
        (SVCB_PARAM_ALPN, value)
    }

    fn port_param(port: u16) -> (u16, Vec<u8>) {
        (SVCB_PARAM_PORT, port.to_be_bytes().to_vec())
    }

    fn no_default_alpn_param() -> (u16, Vec<u8>) {
        (SVCB_PARAM_NO_DEFAULT_ALPN, Vec::new())
    }

    fn gateway_config_with_protocols(protocols: Vec<OriginProtocol>) -> GatewayConfig {
        GatewayConfig {
            supported_origin_protocols: protocols,
            ..GatewayConfig::default()
        }
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_be_bytes());
    }

    fn cname_record(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Cname,
            class: 1,
            ttl: 60,
            rdata: name_rdata(target),
        }
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        DnsName::from_ascii(name)
            .unwrap()
            .encode_wire(&mut out)
            .unwrap();
        out
    }

    fn request(origin_host: &str, qname: &str) -> GatewayRequest {
        GatewayRequest {
            origin: OriginRequest {
                method: "GET".to_owned(),
                scheme: "https".to_owned(),
                host: origin_host.to_owned(),
                connect_host: None,
                port: 443,
                path_and_query: "/".to_owned(),
                protocol: OriginProtocol::Http11,
                tls: TlsValidation::default(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            resolution: ResolutionRequest {
                qname: qname.to_owned(),
                qtype: 1,
            },
        }
    }
}
