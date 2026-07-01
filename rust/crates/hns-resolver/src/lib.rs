use hns_cache::TtlCache;
use hns_core::dns::{
    DnsEncodeConfig, DnsFlags, DnsHeader, DnsMessage, DnsName, DnsQuestion, RecordType,
    ResourceRecord,
};
use hns_core::resource::{ResourceError, decode_handshake_resource_records};
use hns_core::{Hash, Height, NameHash, NameHashError};
use hns_dnssec::{
    DnssecChainLink, DnssecChainValidationInput, DnssecStatus, DnssecTime,
    Nsec3NameErrorValidationInput, Nsec3NoDataValidationInput, NsecNameErrorValidationInput,
    NsecNoDataValidationInput, SignedRrsetValidationInput, validate_dnssec_chain,
    validate_nsec_name_error, validate_nsec_no_data, validate_nsec3_name_error,
    validate_nsec3_no_data, validate_rrset_signature, validate_signed_rrset,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DNS_CLASS_IN: u16 = 1;
const DNS_OPT_RECORD_TYPE: u16 = 41;
const DNSSEC_DO_FLAG: u32 = 0x8000;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const DEFAULT_DNS_UDP_PAYLOAD: usize = 1232;
const DEFAULT_DNS_TCP_MAX_MESSAGE_LEN: usize = 65_535;
const MAX_CNAME_CHAIN_LEN: usize = 8;
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(0x4d00);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameClass {
    Hns,
    Icann,
    Search,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResolutionRequest {
    pub qname: String,
    pub qtype: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionAnswer {
    pub name: DnsName,
    pub records: Vec<ResourceRecord>,
    pub secure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenNameRecords {
    pub root_name: String,
    pub name_hash: NameHash,
    pub records: Vec<ResourceRecord>,
    pub secure: bool,
    pub exists: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedResourceValue {
    pub root_name: String,
    pub name_hash: NameHash,
    pub value: Option<Vec<u8>>,
    pub secure: bool,
    pub anchor: Option<ResourceValueAnchor>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceValueAnchor {
    pub tree_root: Hash,
    pub height: Height,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ResolverError {
    #[error("HNS proof is unavailable")]
    ProofUnavailable,
    #[error("HNS name is invalid: {0}")]
    InvalidName(#[from] NameHashError),
    #[error("HNS proof payload does not match requested name")]
    ProofNameMismatch,
    #[error("HNS name does not exist")]
    NameNotFound,
    #[error("local HNS chain is not current enough to determine current name state")]
    LocalChainNotCurrent,
    #[error("DNSSEC validation failed")]
    DnssecFailed,
    #[error("HNS resource payload is invalid: {0}")]
    InvalidResource(#[from] ResourceError),
    #[error("resolver backend is not implemented")]
    UnsupportedBackend,
    #[error("HNS delegation has no usable nameserver address")]
    NoNameserverAddress,
    #[error("DNS transport failed: {0}")]
    DnsTransport(String),
    #[error("DNS response is invalid")]
    InvalidDnsResponse,
    #[error("resolver cache lock is poisoned")]
    CachePoisoned,
    #[error("resolver storage error: {0}")]
    Storage(String),
}

pub trait Resolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError>;
}

pub trait DelegatedResolver {
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError>;
}

impl<R: Resolver> DelegatedResolver for R {
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        _delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        self.resolve(request)
    }
}

pub trait HnsProofProvider {
    fn prove_name(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError>;
}

pub trait HnsResourceValueProvider {
    fn prove_resource_value(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<VerifiedResourceValue, ResolverError>;
}

pub struct FailClosedResolver;

pub struct ProofBackedResolver<P> {
    proof_provider: P,
}

pub struct DelegatingResolver<P, D> {
    proof_provider: P,
    delegated_resolver: D,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsDelegation {
    pub root_name: String,
    pub owner: DnsName,
    pub records: Vec<ResourceRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTcpDnsTransport {
    pub timeout: Duration,
    pub max_udp_response_len: usize,
    pub max_tcp_message_len: usize,
}

pub struct SystemDnssecVerifier;

pub struct AuthoritativeDnssecResolver<T = UdpTcpDnsTransport, V = SystemDnssecVerifier> {
    transport: T,
    verifier: V,
}

pub trait DnsTransport {
    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError>;

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError>;
}

pub struct DelegatedDnssecValidation<'a> {
    pub dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub dnskey_rrset: &'a [ResourceRecord],
    pub dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub target_rrset: &'a [ResourceRecord],
    pub target_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedDnssecNoDataValidation<'a> {
    pub dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub dnskey_rrset: &'a [ResourceRecord],
    pub dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub query_type: RecordType,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedDnssecNameErrorValidation<'a> {
    pub dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub dnskey_rrset: &'a [ResourceRecord],
    pub dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedChildDnssecValidation<'a> {
    pub parent_dnskey_owner: &'a DnsName,
    pub parent_ds_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_owner: &'a DnsName,
    pub child_ds_rrset: &'a [ResourceRecord],
    pub child_ds_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub target_rrset: &'a [ResourceRecord],
    pub target_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedChildDnssecNoDataValidation<'a> {
    pub parent_dnskey_owner: &'a DnsName,
    pub parent_ds_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_owner: &'a DnsName,
    pub child_ds_rrset: &'a [ResourceRecord],
    pub child_ds_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub query_type: RecordType,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedChildDnssecNameErrorValidation<'a> {
    pub parent_dnskey_owner: &'a DnsName,
    pub parent_ds_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_owner: &'a DnsName,
    pub child_ds_rrset: &'a [ResourceRecord],
    pub child_ds_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub trait DelegatedDnssecVerifier {
    fn validate_positive_rrset(
        &self,
        input: DelegatedDnssecValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_no_data(
        &self,
        input: DelegatedDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_name_error(
        &self,
        _input: DelegatedDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        Ok(false)
    }

    fn validate_child_positive_rrset(
        &self,
        input: DelegatedChildDnssecValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_child_no_data(
        &self,
        input: DelegatedChildDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_child_name_error(
        &self,
        _input: DelegatedChildDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        Ok(false)
    }
}

pub struct ResourceValueProofProvider<P> {
    value_provider: P,
}

#[derive(Default)]
pub struct MemoryResourceValueProvider {
    values: Mutex<HashMap<(String, NameHash), VerifiedResourceValue>>,
}

pub struct SqliteResourceValueProvider {
    connection: Mutex<Connection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceValueCacheStats {
    pub entries: usize,
    pub value_bytes: usize,
}

pub struct CachedResolver<R> {
    inner: R,
    cache: Mutex<TtlCache<ResolutionRequest, CachedResolution>>,
    ttl: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CachedResolution {
    Answer(ResolutionAnswer),
    NameNotFound,
}

impl VerifiedResourceValue {
    pub fn inclusion(root_name: String, name_hash: NameHash, value: Vec<u8>) -> Self {
        Self {
            root_name,
            name_hash,
            value: Some(value),
            secure: true,
            anchor: None,
        }
    }

    pub fn non_inclusion(root_name: String, name_hash: NameHash) -> Self {
        Self {
            root_name,
            name_hash,
            value: None,
            secure: true,
            anchor: None,
        }
    }

    pub fn with_anchor(mut self, tree_root: Hash, height: Height) -> Self {
        self.anchor = Some(ResourceValueAnchor { tree_root, height });
        self
    }
}

impl ProvenNameRecords {
    pub fn from_resource_value(
        root_name: String,
        name_hash: NameHash,
        value: &[u8],
    ) -> Result<Self, ResolverError> {
        let owner =
            DnsName::from_ascii(&root_name).map_err(|_| ResolverError::UnsupportedBackend)?;
        let records = decode_handshake_resource_records(&owner, value)?;
        Ok(Self {
            root_name,
            name_hash,
            records,
            secure: true,
            exists: true,
        })
    }

    pub fn from_verified_resource_value(
        verified: VerifiedResourceValue,
    ) -> Result<Self, ResolverError> {
        let exists = verified.value.is_some();
        let records = match verified.value {
            Some(value) => {
                let owner = DnsName::from_ascii(&verified.root_name)
                    .map_err(|_| ResolverError::UnsupportedBackend)?;
                decode_handshake_resource_records(&owner, &value)?
            }
            None => Vec::new(),
        };

        Ok(Self {
            root_name: verified.root_name,
            name_hash: verified.name_hash,
            records,
            secure: verified.secure,
            exists,
        })
    }
}

impl Resolver for FailClosedResolver {
    fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        Err(ResolverError::UnsupportedBackend)
    }
}

impl Default for UdpTcpDnsTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_udp_response_len: DEFAULT_DNS_UDP_PAYLOAD,
            max_tcp_message_len: DEFAULT_DNS_TCP_MAX_MESSAGE_LEN,
        }
    }
}

impl DnsTransport for UdpTcpDnsTransport {
    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        let bind_addr = match server {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        socket
            .send_to(query, server)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;

        let mut response = vec![0u8; self.max_udp_response_len];
        let (len, source) = socket
            .recv_from(&mut response)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        if source.ip() != server.ip() {
            return Err(ResolverError::InvalidDnsResponse);
        }
        response.truncate(len);
        Ok(response)
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        if query.len() > u16::MAX as usize {
            return Err(ResolverError::InvalidDnsResponse);
        }

        let mut stream = TcpStream::connect_timeout(&server, self.timeout)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;

        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .and_then(|_| stream.write_all(query))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;

        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        let length = u16::from_be_bytes(length) as usize;
        if length > self.max_tcp_message_len {
            return Err(ResolverError::InvalidDnsResponse);
        }

        let mut response = vec![0u8; length];
        stream
            .read_exact(&mut response)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        Ok(response)
    }
}

impl DelegatedDnssecVerifier for SystemDnssecVerifier {
    fn validate_positive_rrset(
        &self,
        input: DelegatedDnssecValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.dnskey_owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            rrset: input.target_rrset,
            rrsig_rrset: input.target_rrsig_rrset,
            now: DnssecTime(now),
        })
        .map_err(|_| ResolverError::DnssecFailed)?;

        Ok(status == DnssecStatus::Secure)
    }

    fn validate_no_data(
        &self,
        input: DelegatedDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.dnskey_owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            rrset: input.dnskey_rrset,
            rrsig_rrset: input.dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_no_data(NsecNoDataValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec_rrset: input.nsec_rrset,
                nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_no_data(Nsec3NoDataValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec3_rrset: input.nsec3_rrset,
                nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_name_error(
        &self,
        input: DelegatedDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.dnskey_owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            rrset: input.dnskey_rrset,
            rrsig_rrset: input.dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                covering_nsec_rrset: input.nsec_rrset,
                covering_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                wildcard_nsec_rrset: input.nsec_rrset,
                wildcard_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_name_error(Nsec3NameErrorValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                closest_encloser_nsec3_rrset: input.nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: input.nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: input.nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_child_positive_rrset(
        &self,
        input: DelegatedChildDnssecValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let link = DnssecChainLink {
            child_dnskey_owner: input.child_dnskey_owner,
            ds_rrset: input.child_ds_rrset,
            ds_rrsig_rrset: input.child_ds_rrsig_rrset,
            child_dnskey_rrset: input.child_dnskey_rrset,
            child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
        };
        let status = validate_dnssec_chain(DnssecChainValidationInput {
            initial_dnskey_owner: input.parent_dnskey_owner,
            initial_ds_rrset: input.parent_ds_rrset,
            initial_dnskey_rrset: input.parent_dnskey_rrset,
            initial_dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            delegation_links: &[link],
            target_rrset: input.target_rrset,
            target_rrsig_rrset: input.target_rrsig_rrset,
            now: DnssecTime(now),
        })
        .map_err(|_| ResolverError::DnssecFailed)?;

        Ok(status == DnssecStatus::Secure)
    }

    fn validate_child_no_data(
        &self,
        input: DelegatedChildDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let parent_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.parent_dnskey_owner,
            ds_rrset: input.parent_ds_rrset,
            dnskey_rrset: input.parent_dnskey_rrset,
            dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            rrset: input.parent_dnskey_rrset,
            rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if parent_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_ds_status = validate_rrset_signature(
            input.parent_dnskey_owner,
            input.parent_dnskey_rrset,
            input.child_ds_rrset,
            input.child_ds_rrsig_rrset,
            now,
        )
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_ds_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.child_dnskey_owner,
            ds_rrset: input.child_ds_rrset,
            dnskey_rrset: input.child_dnskey_rrset,
            dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
            rrset: input.child_dnskey_rrset,
            rrsig_rrset: input.child_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_no_data(NsecNoDataValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec_rrset: input.nsec_rrset,
                nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_no_data(Nsec3NoDataValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec3_rrset: input.nsec3_rrset,
                nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_child_name_error(
        &self,
        input: DelegatedChildDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let parent_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.parent_dnskey_owner,
            ds_rrset: input.parent_ds_rrset,
            dnskey_rrset: input.parent_dnskey_rrset,
            dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            rrset: input.parent_dnskey_rrset,
            rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if parent_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_ds_status = validate_rrset_signature(
            input.parent_dnskey_owner,
            input.parent_dnskey_rrset,
            input.child_ds_rrset,
            input.child_ds_rrsig_rrset,
            now,
        )
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_ds_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.child_dnskey_owner,
            ds_rrset: input.child_ds_rrset,
            dnskey_rrset: input.child_dnskey_rrset,
            dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
            rrset: input.child_dnskey_rrset,
            rrsig_rrset: input.child_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                covering_nsec_rrset: input.nsec_rrset,
                covering_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                wildcard_nsec_rrset: input.nsec_rrset,
                wildcard_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_name_error(Nsec3NameErrorValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                closest_encloser_nsec3_rrset: input.nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: input.nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: input.nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl<T, V> AuthoritativeDnssecResolver<T, V> {
    pub fn new(transport: T, verifier: V) -> Self {
        Self {
            transport,
            verifier,
        }
    }

    pub fn into_parts(self) -> (T, V) {
        (self.transport, self.verifier)
    }
}

impl Default for AuthoritativeDnssecResolver {
    fn default() -> Self {
        Self::new(UdpTcpDnsTransport::default(), SystemDnssecVerifier)
    }
}

impl<T, V> DelegatedResolver for AuthoritativeDnssecResolver<T, V>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        if request.qtype == u16::MAX {
            return Err(ResolverError::UnsupportedBackend);
        }

        let request_name =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let qtype = RecordType::from_code(request.qtype);
        let servers = nameserver_addresses(delegation);
        if servers.is_empty() {
            return Err(ResolverError::NoNameserverAddress);
        }

        let ds_rrset = records_for(&delegation.records, &delegation.owner, RecordType::Ds);
        let mut last_error = None;
        for server in servers {
            match resolve_delegated_from_server(
                &self.transport,
                &self.verifier,
                server,
                delegation,
                &request_name,
                qtype,
                &ds_rrset,
            ) {
                Ok(answer) => return Ok(answer),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or(ResolverError::NoNameserverAddress))
    }
}

impl<P> ProofBackedResolver<P> {
    pub fn new(proof_provider: P) -> Self {
        Self { proof_provider }
    }

    pub fn into_inner(self) -> P {
        self.proof_provider
    }
}

impl<P: HnsProofProvider> Resolver for ProofBackedResolver<P> {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        let request_name =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let root_name = hns_root_label(&request.qname)?;
        let name_hash = NameHash::from_name(&root_name)?;
        let proven = self.proof_provider.prove_name(&root_name, name_hash)?;
        if proven.root_name != root_name || proven.name_hash != name_hash || !proven.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if !proven.exists {
            return Err(ResolverError::NameNotFound);
        }

        let records = filter_records(proven.records, &request_name, request.qtype);

        Ok(ResolutionAnswer {
            name: request_name,
            records,
            secure: true,
        })
    }
}

impl<P, D> DelegatingResolver<P, D> {
    pub fn new(proof_provider: P, delegated_resolver: D) -> Self {
        Self {
            proof_provider,
            delegated_resolver,
        }
    }

    pub fn into_parts(self) -> (P, D) {
        (self.proof_provider, self.delegated_resolver)
    }
}

impl<P, D> Resolver for DelegatingResolver<P, D>
where
    P: HnsProofProvider,
    D: DelegatedResolver,
{
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        let request_name =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let root_name = hns_root_label(&request.qname)?;
        let root_owner =
            DnsName::from_ascii(&root_name).map_err(|_| ResolverError::UnsupportedBackend)?;
        let name_hash = NameHash::from_name(&root_name)?;
        let proven = self.proof_provider.prove_name(&root_name, name_hash)?;
        if proven.root_name != root_name || proven.name_hash != name_hash || !proven.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if !proven.exists {
            return Err(ResolverError::NameNotFound);
        }
        let mut delegation_records = proven.records.clone();

        let direct_records =
            filter_records(delegation_records.clone(), &request_name, request.qtype);
        if (request_name == root_owner && !direct_records.is_empty())
            || root_records_answer_request(&request_name, &root_owner, request.qtype)
            || !has_owner_record(&delegation_records, &root_owner, RecordType::Ns)
        {
            return Ok(ResolutionAnswer {
                name: request_name.clone(),
                records: direct_records,
                secure: true,
            });
        }

        hydrate_hns_nameserver_addresses(
            &self.proof_provider,
            &root_owner,
            &mut delegation_records,
        )?;
        let delegation = HnsDelegation {
            root_name: root_name.clone(),
            owner: root_owner.clone(),
            records: delegation_records.clone(),
        };

        let has_secure_delegation =
            has_owner_record(&delegation_records, &root_owner, RecordType::Ds);
        let mut delegated = self
            .delegated_resolver
            .resolve_delegated(request, &delegation)?;
        if !has_secure_delegation {
            delegated.secure = false;
            return Ok(delegated);
        }
        if !delegated.secure {
            return Err(ResolverError::DnssecFailed);
        }

        Ok(delegated)
    }
}

fn hydrate_hns_nameserver_addresses<P: HnsProofProvider>(
    proof_provider: &P,
    delegation_owner: &DnsName,
    records: &mut Vec<ResourceRecord>,
) -> Result<(), ResolverError> {
    let ns_names = records
        .iter()
        .filter(|record| record.name == *delegation_owner && record.record_type == RecordType::Ns)
        .filter_map(record_name_rdata)
        .fold(Vec::<DnsName>::new(), |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        });

    for ns_name in ns_names {
        if has_owner_record(records, &ns_name, RecordType::A)
            || has_owner_record(records, &ns_name, RecordType::Aaaa)
        {
            continue;
        }

        let Some(ns_root) = ns_name.labels().last().cloned() else {
            continue;
        };
        let name_hash = match NameHash::from_name(&ns_root) {
            Ok(name_hash) => name_hash,
            Err(_) => continue,
        };
        let proven = match proof_provider.prove_name(&ns_root, name_hash) {
            Ok(proven) => proven,
            Err(ResolverError::ProofUnavailable) => continue,
            Err(error) => return Err(error),
        };
        if proven.root_name != ns_root || proven.name_hash != name_hash || !proven.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if !proven.exists {
            continue;
        }

        records.extend(proven.records.into_iter().filter(|record| {
            record.name == ns_name && matches!(record.record_type, RecordType::A | RecordType::Aaaa)
        }));
    }

    Ok(())
}

impl<P> ResourceValueProofProvider<P> {
    pub fn new(value_provider: P) -> Self {
        Self { value_provider }
    }

    pub fn into_inner(self) -> P {
        self.value_provider
    }
}

impl<P: HnsResourceValueProvider> HnsProofProvider for ResourceValueProofProvider<P> {
    fn prove_name(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        let verified = self
            .value_provider
            .prove_resource_value(root_name, name_hash)?;
        if verified.root_name != root_name || verified.name_hash != name_hash || !verified.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        ProvenNameRecords::from_verified_resource_value(verified)
    }
}

impl MemoryResourceValueProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, mut verified: VerifiedResourceValue) -> Result<(), ResolverError> {
        let root_name = normalize_verified_root(&verified.root_name)?;
        verified = normalize_verified_resource_value(verified)?;
        self.values
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .insert((root_name, verified.name_hash), verified);
        Ok(())
    }

    pub fn len(&self) -> Result<usize, ResolverError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .len())
    }

    pub fn is_empty(&self) -> Result<bool, ResolverError> {
        Ok(self.len()? == 0)
    }
}

impl SqliteResourceValueProvider {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ResolverError> {
        let connection =
            Connection::open(path).map_err(|error| ResolverError::Storage(error.to_string()))?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, ResolverError> {
        let connection = Connection::open_in_memory()
            .map_err(|error| ResolverError::Storage(error.to_string()))?;
        Self::from_connection(connection)
    }

    pub fn from_connection(connection: Connection) -> Result<Self, ResolverError> {
        let provider = Self {
            connection: Mutex::new(connection),
        };
        provider.initialize()?;
        Ok(provider)
    }

    pub fn insert(&self, verified: VerifiedResourceValue) -> Result<(), ResolverError> {
        let verified = normalize_verified_resource_value(verified)?;
        let value = verified.value.as_deref();
        let secure = if verified.secure { 1_i64 } else { 0_i64 };
        let proof_tree_root = verified
            .anchor
            .map(|anchor| anchor.tree_root.as_bytes().as_slice().to_vec());
        let proof_height = verified.anchor.map(|anchor| i64::from(anchor.height.0));
        self.connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .execute(
                "
                INSERT INTO verified_resource_values(
                    root_name,
                    name_hash,
                    value,
                    secure,
                    proof_tree_root,
                    proof_height,
                    updated_at_unix
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, unixepoch())
                ON CONFLICT(root_name, name_hash) DO UPDATE SET
                    value = excluded.value,
                    secure = excluded.secure,
                    proof_tree_root = excluded.proof_tree_root,
                    proof_height = excluded.proof_height,
                    updated_at_unix = excluded.updated_at_unix
                ",
                params![
                    verified.root_name.as_str(),
                    verified.name_hash.as_hash().as_bytes().as_slice(),
                    value,
                    secure,
                    proof_tree_root,
                    proof_height,
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn len(&self) -> Result<usize, ResolverError> {
        let count = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .query_row("SELECT COUNT(*) FROM verified_resource_values", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(sqlite_error)?;
        usize::try_from(count).map_err(|error| ResolverError::Storage(error.to_string()))
    }

    pub fn is_empty(&self) -> Result<bool, ResolverError> {
        Ok(self.len()? == 0)
    }

    pub fn stats(&self) -> Result<ResourceValueCacheStats, ResolverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let (entries, value_bytes) = connection
            .query_row(
                "
                SELECT COUNT(*), COALESCE(SUM(COALESCE(length(value), 0)), 0)
                FROM verified_resource_values
                ",
                [],
                |row| {
                    let entries: i64 = row.get(0)?;
                    let value_bytes: i64 = row.get(1)?;
                    Ok((entries, value_bytes))
                },
            )
            .map_err(sqlite_error)?;

        Ok(ResourceValueCacheStats {
            entries: usize::try_from(entries)
                .map_err(|error| ResolverError::Storage(error.to_string()))?,
            value_bytes: usize::try_from(value_bytes)
                .map_err(|error| ResolverError::Storage(error.to_string()))?,
        })
    }

    pub fn total_value_bytes(&self) -> Result<usize, ResolverError> {
        self.stats().map(|stats| stats.value_bytes)
    }

    pub fn enforce_value_byte_limit(&self, max_bytes: usize) -> Result<usize, ResolverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        let mut total = total_value_bytes_in(&transaction)?;
        let mut removed = 0usize;

        while total > max_bytes {
            let Some(entry) = oldest_resource_value_entry(&transaction)? else {
                break;
            };

            transaction
                .execute(
                    "
                    DELETE FROM verified_resource_values
                    WHERE root_name = ?1 AND name_hash = ?2
                    ",
                    params![entry.root_name, entry.name_hash.as_slice()],
                )
                .map_err(sqlite_error)?;
            total = total.saturating_sub(entry.value_bytes);
            removed = removed.saturating_add(1);
        }

        transaction.commit().map_err(sqlite_error)?;
        Ok(removed)
    }

    pub fn anchored_heights(&self) -> Result<Vec<Height>, ResolverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let mut statement = connection
            .prepare(
                "
                SELECT DISTINCT proof_height
                FROM verified_resource_values
                WHERE proof_tree_root IS NOT NULL AND proof_height IS NOT NULL
                ORDER BY proof_height DESC
                ",
            )
            .map_err(sqlite_error)?;
        let heights = statement
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(sqlite_error)?
            .map(|height| {
                let height = height.map_err(sqlite_error)?;
                let height = u32::try_from(height)
                    .map_err(|error| ResolverError::Storage(error.to_string()))?;
                Ok(Height(height))
            })
            .collect::<Result<Vec<_>, ResolverError>>()?;
        Ok(heights)
    }

    pub fn prune_invalid_anchors(
        &self,
        valid_anchors: &[ResourceValueAnchor],
        prune_unanchored: bool,
    ) -> Result<usize, ResolverError> {
        let valid_anchors = valid_anchors.iter().copied().collect::<BTreeSet<_>>();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        let entries = resource_value_anchor_entries(&transaction)?;
        let mut removed = 0usize;

        for entry in entries {
            let remove = match entry.anchor {
                Some(anchor) => !valid_anchors.contains(&anchor),
                None => prune_unanchored,
            };
            if !remove {
                continue;
            }

            transaction
                .execute(
                    "
                    DELETE FROM verified_resource_values
                    WHERE root_name = ?1 AND name_hash = ?2
                    ",
                    params![entry.root_name, entry.name_hash.as_slice()],
                )
                .map_err(sqlite_error)?;
            removed = removed.saturating_add(1);
        }

        transaction.commit().map_err(sqlite_error)?;
        Ok(removed)
    }

    pub fn clear(&self) -> Result<(), ResolverError> {
        self.connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .execute("DELETE FROM verified_resource_values", [])
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn flush(self) -> Result<(), ResolverError> {
        let connection = self
            .connection
            .into_inner()
            .map_err(|_| ResolverError::CachePoisoned)?;
        connection
            .close()
            .map_err(|(_, error)| ResolverError::Storage(error.to_string()))
    }

    fn initialize(&self) -> Result<(), ResolverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        connection
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS verified_resource_values (
                    root_name TEXT NOT NULL,
                    name_hash BLOB NOT NULL,
                    value BLOB,
                    secure INTEGER NOT NULL,
                    proof_tree_root BLOB,
                    proof_height INTEGER,
                    updated_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(root_name, name_hash)
                );
                ",
            )
            .map_err(sqlite_error)?;
        ensure_sqlite_column(&connection, "proof_tree_root", "BLOB")?;
        ensure_sqlite_column(&connection, "proof_height", "INTEGER")?;
        connection
            .execute_batch(
                "
                CREATE INDEX IF NOT EXISTS verified_resource_values_by_anchor
                    ON verified_resource_values(proof_height, proof_tree_root);
                ",
            )
            .map_err(sqlite_error)?;
        Ok(())
    }
}

impl HnsResourceValueProvider for MemoryResourceValueProvider {
    fn prove_resource_value(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<VerifiedResourceValue, ResolverError> {
        let root_name = normalize_verified_root(root_name)?;
        if name_hash != NameHash::from_name(&root_name)? {
            return Err(ResolverError::ProofNameMismatch);
        }

        self.values
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .get(&(root_name, name_hash))
            .cloned()
            .ok_or(ResolverError::ProofUnavailable)
    }
}

impl HnsResourceValueProvider for SqliteResourceValueProvider {
    fn prove_resource_value(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<VerifiedResourceValue, ResolverError> {
        let root_name = normalize_verified_root(root_name)?;
        if name_hash != NameHash::from_name(&root_name)? {
            return Err(ResolverError::ProofNameMismatch);
        }

        self.connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .query_row(
                "
                SELECT name_hash, value, secure, proof_tree_root, proof_height
                FROM verified_resource_values
                WHERE root_name = ?1 AND name_hash = ?2
                ",
                params![root_name, name_hash.as_hash().as_bytes().as_slice()],
                |row| {
                    let hash_bytes: Vec<u8> = row.get(0)?;
                    let value: Option<Vec<u8>> = row.get(1)?;
                    let secure: i64 = row.get(2)?;
                    let proof_tree_root: Option<Vec<u8>> = row.get(3)?;
                    let proof_height: Option<i64> = row.get(4)?;
                    let stored_hash = Hash::from_slice(&hash_bytes).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })?;
                    let anchor = sqlite_anchor(proof_tree_root, proof_height)?;
                    Ok(VerifiedResourceValue {
                        root_name: root_name.clone(),
                        name_hash: NameHash::new(stored_hash),
                        value,
                        secure: secure != 0,
                        anchor,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(ResolverError::ProofUnavailable)
    }
}

impl<R> CachedResolver<R> {
    pub fn new(inner: R, max_entries: usize, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Mutex::new(TtlCache::new(max_entries)),
            ttl,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Resolver> Resolver for CachedResolver<R> {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .get(request)
        {
            return cached.into_result();
        }

        match self.inner.resolve(request) {
            Ok(answer) => {
                self.cache
                    .lock()
                    .map_err(|_| ResolverError::CachePoisoned)?
                    .insert(
                        request.clone(),
                        CachedResolution::Answer(answer.clone()),
                        self.ttl,
                    );
                Ok(answer)
            }
            Err(ResolverError::NameNotFound) => {
                self.cache
                    .lock()
                    .map_err(|_| ResolverError::CachePoisoned)?
                    .insert(request.clone(), CachedResolution::NameNotFound, self.ttl);
                Err(ResolverError::NameNotFound)
            }
            Err(error) => Err(error),
        }
    }
}

impl CachedResolution {
    fn into_result(self) -> Result<ResolutionAnswer, ResolverError> {
        match self {
            Self::Answer(answer) => Ok(answer),
            Self::NameNotFound => Err(ResolverError::NameNotFound),
        }
    }
}

fn normalize_verified_root(root_name: &str) -> Result<String, ResolverError> {
    hns_root_label(root_name)
}

fn normalize_verified_resource_value(
    mut verified: VerifiedResourceValue,
) -> Result<VerifiedResourceValue, ResolverError> {
    let root_name = normalize_verified_root(&verified.root_name)?;
    if verified.name_hash != NameHash::from_name(&root_name)? {
        return Err(ResolverError::ProofNameMismatch);
    }

    verified.root_name = root_name;
    Ok(verified)
}

struct ResourceValueEntry {
    root_name: String,
    name_hash: Vec<u8>,
    value_bytes: usize,
}

struct ResourceValueAnchorEntry {
    root_name: String,
    name_hash: Vec<u8>,
    anchor: Option<ResourceValueAnchor>,
}

fn total_value_bytes_in(connection: &Connection) -> Result<usize, ResolverError> {
    let value_bytes = connection
        .query_row(
            "
            SELECT COALESCE(SUM(COALESCE(length(value), 0)), 0)
            FROM verified_resource_values
            ",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    usize::try_from(value_bytes).map_err(|error| ResolverError::Storage(error.to_string()))
}

fn oldest_resource_value_entry(
    connection: &Connection,
) -> Result<Option<ResourceValueEntry>, ResolverError> {
    connection
        .query_row(
            "
            SELECT root_name, name_hash, COALESCE(length(value), 0)
            FROM verified_resource_values
            ORDER BY updated_at_unix ASC, root_name ASC, name_hash ASC
            LIMIT 1
            ",
            [],
            |row| {
                let root_name: String = row.get(0)?;
                let name_hash: Vec<u8> = row.get(1)?;
                let value_bytes: i64 = row.get(2)?;
                Ok((root_name, name_hash, value_bytes))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|(root_name, name_hash, value_bytes)| {
            Ok(ResourceValueEntry {
                root_name,
                name_hash,
                value_bytes: usize::try_from(value_bytes)
                    .map_err(|error| ResolverError::Storage(error.to_string()))?,
            })
        })
        .transpose()
}

fn resource_value_anchor_entries(
    connection: &Connection,
) -> Result<Vec<ResourceValueAnchorEntry>, ResolverError> {
    let mut statement = connection
        .prepare(
            "
            SELECT root_name, name_hash, proof_tree_root, proof_height
            FROM verified_resource_values
            ",
        )
        .map_err(sqlite_error)?;
    statement
        .query_map([], |row| {
            let root_name: String = row.get(0)?;
            let name_hash: Vec<u8> = row.get(1)?;
            let proof_tree_root: Option<Vec<u8>> = row.get(2)?;
            let proof_height: Option<i64> = row.get(3)?;
            let anchor = sqlite_anchor(proof_tree_root, proof_height)?;
            Ok(ResourceValueAnchorEntry {
                root_name,
                name_hash,
                anchor,
            })
        })
        .map_err(sqlite_error)?
        .map(|entry| entry.map_err(sqlite_error))
        .collect()
}

fn sqlite_anchor(
    proof_tree_root: Option<Vec<u8>>,
    proof_height: Option<i64>,
) -> rusqlite::Result<Option<ResourceValueAnchor>> {
    match (proof_tree_root, proof_height) {
        (Some(root), Some(height)) => {
            let tree_root = Hash::from_slice(&root).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            let height = u32::try_from(height).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?;
            Ok(Some(ResourceValueAnchor {
                tree_root,
                height: Height(height),
            }))
        }
        _ => Ok(None),
    }
}

fn ensure_sqlite_column(
    connection: &Connection,
    column: &str,
    column_type: &str,
) -> Result<(), ResolverError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(verified_resource_values)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if columns.iter().any(|existing| existing == column) {
        return Ok(());
    }

    connection
        .execute_batch(&format!(
            "ALTER TABLE verified_resource_values ADD COLUMN {column} {column_type};"
        ))
        .map_err(sqlite_error)
}

fn sqlite_error(error: rusqlite::Error) -> ResolverError {
    ResolverError::Storage(error.to_string())
}

fn filter_records(
    records: Vec<ResourceRecord>,
    request_name: &DnsName,
    qtype: u16,
) -> Vec<ResourceRecord> {
    if qtype == u16::MAX {
        return records;
    }

    let qtype = RecordType::from_code(qtype);
    records
        .into_iter()
        .filter(|record| record.name == *request_name && record.record_type == qtype)
        .collect()
}

fn root_records_answer_request(request_name: &DnsName, root_owner: &DnsName, qtype: u16) -> bool {
    if request_name != root_owner {
        return false;
    }

    if qtype == u16::MAX {
        return true;
    }

    matches!(
        RecordType::from_code(qtype),
        RecordType::Ds | RecordType::Ns | RecordType::Txt
    )
}

fn has_owner_record(records: &[ResourceRecord], owner: &DnsName, record_type: RecordType) -> bool {
    records
        .iter()
        .any(|record| record.name == *owner && record.record_type == record_type)
}

fn resolve_delegated_from_server<T, V>(
    transport: &T,
    verifier: &V,
    server: SocketAddr,
    delegation: &HnsDelegation,
    request_name: &DnsName,
    qtype: RecordType,
    ds_rrset: &[ResourceRecord],
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let target_response = dns_query(transport, server, request_name, qtype)?;
    let target_rrset = records_for(&target_response.answers, request_name, qtype);

    if ds_rrset.is_empty() {
        return Ok(ResolutionAnswer {
            name: request_name.clone(),
            records: target_rrset,
            secure: false,
        });
    }

    let dnskey_response = dns_query(transport, server, &delegation.owner, RecordType::Dnskey)?;
    let dnskey_rrset = records_for(
        &dnskey_response.answers,
        &delegation.owner,
        RecordType::Dnskey,
    );
    let dnskey_rrsig_rrset = records_for(
        &dnskey_response.answers,
        &delegation.owner,
        RecordType::Rrsig,
    );
    if target_response.header.flags.rcode() == DNS_RCODE_NXDOMAIN {
        return resolve_secure_name_error(
            verifier,
            NameErrorResolutionInput {
                delegation,
                request_name,
                ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                response: &target_response,
                prefix_records: &[],
            },
        );
    }
    if let Some(referral) = child_referral(&target_response, &delegation.owner, request_name) {
        return resolve_secure_child_referral(
            transport,
            verifier,
            ChildReferralResolutionInput {
                parent_delegation: delegation,
                referral,
                request_name,
                qtype,
                parent_ds_rrset: ds_rrset,
                parent_dnskey_rrset: &dnskey_rrset,
                parent_dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
            },
        );
    }
    if target_rrset.is_empty()
        && records_for(&target_response.answers, request_name, RecordType::Cname).is_empty()
    {
        return resolve_secure_no_data(
            verifier,
            NoDataResolutionInput {
                delegation,
                request_name,
                qtype,
                ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                response: &target_response,
                prefix_records: &[],
            },
        );
    }

    if dnskey_rrset.is_empty() || dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }

    resolve_secure_answer_records(SecureAnswerResolutionInput {
        transport,
        verifier,
        server,
        delegation,
        request_name,
        qtype,
        ds_rrset,
        dnskey_rrset: &dnskey_rrset,
        dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
        initial_response: target_response,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChildReferral {
    owner: DnsName,
    ds_rrset: Vec<ResourceRecord>,
    ds_rrsig_rrset: Vec<ResourceRecord>,
    servers: Vec<SocketAddr>,
}

struct ChildReferralResolutionInput<'a> {
    parent_delegation: &'a HnsDelegation,
    referral: ChildReferral,
    request_name: &'a DnsName,
    qtype: RecordType,
    parent_ds_rrset: &'a [ResourceRecord],
    parent_dnskey_rrset: &'a [ResourceRecord],
    parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
}

fn resolve_secure_child_referral<T, V>(
    transport: &T,
    verifier: &V,
    input: ChildReferralResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    if input.parent_dnskey_rrset.is_empty()
        || input.parent_dnskey_rrsig_rrset.is_empty()
        || input.referral.ds_rrset.is_empty()
        || input.referral.ds_rrsig_rrset.is_empty()
    {
        return Err(ResolverError::DnssecFailed);
    }
    if input.referral.servers.is_empty() {
        return Err(ResolverError::NoNameserverAddress);
    }

    let mut last_error = None;
    for &server in &input.referral.servers {
        match resolve_secure_child_from_server(transport, verifier, server, &input) {
            Ok(answer) => return Ok(answer),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or(ResolverError::NoNameserverAddress))
}

fn resolve_secure_child_from_server<T, V>(
    transport: &T,
    verifier: &V,
    server: SocketAddr,
    input: &ChildReferralResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let child_dnskey_response =
        dns_query(transport, server, &input.referral.owner, RecordType::Dnskey)?;
    let child_dnskey_rrset = records_for(
        &child_dnskey_response.answers,
        &input.referral.owner,
        RecordType::Dnskey,
    );
    let child_dnskey_rrsig_rrset = records_for(
        &child_dnskey_response.answers,
        &input.referral.owner,
        RecordType::Rrsig,
    );
    if child_dnskey_rrset.is_empty() || child_dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }

    let target_response = dns_query(transport, server, input.request_name, input.qtype)?;
    resolve_secure_child_answer_records(ChildSecureAnswerResolutionInput {
        transport,
        verifier,
        server,
        referral: input,
        child_dnskey_rrset: &child_dnskey_rrset,
        child_dnskey_rrsig_rrset: &child_dnskey_rrsig_rrset,
        initial_response: target_response,
    })
}

struct ChildSecureAnswerResolutionInput<'a, T, V> {
    transport: &'a T,
    verifier: &'a V,
    server: SocketAddr,
    referral: &'a ChildReferralResolutionInput<'a>,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    initial_response: DnsMessage,
}

fn resolve_secure_child_answer_records<T, V>(
    input: ChildSecureAnswerResolutionInput<'_, T, V>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let mut response = input.initial_response;
    let mut owner = input.referral.request_name.clone();
    let mut cname_records = Vec::new();

    for _ in 0..=MAX_CNAME_CHAIN_LEN {
        let target_rrset = records_for(&response.answers, &owner, input.referral.qtype);
        let cname_rrset = if input.referral.qtype == RecordType::Cname {
            Vec::new()
        } else {
            records_for(&response.answers, &owner, RecordType::Cname)
        };
        if !target_rrset.is_empty() && !cname_rrset.is_empty() {
            return Err(ResolverError::DnssecFailed);
        }

        if !target_rrset.is_empty() {
            validate_secure_child_rrset(
                input.verifier,
                ChildSecureRrsetValidationInput {
                    referral: input.referral,
                    child_dnskey_rrset: input.child_dnskey_rrset,
                    child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &target_rrset,
                    response: &response,
                },
            )?;
            cname_records.extend(target_rrset);
            return Ok(ResolutionAnswer {
                name: input.referral.request_name.clone(),
                records: cname_records,
                secure: true,
            });
        }

        if !cname_rrset.is_empty() {
            validate_secure_child_rrset(
                input.verifier,
                ChildSecureRrsetValidationInput {
                    referral: input.referral,
                    child_dnskey_rrset: input.child_dnskey_rrset,
                    child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &cname_rrset,
                    response: &response,
                },
            )?;
            let next_owner = cname_target(&cname_rrset)?;
            if !dns_name_is_subdomain_or_equal(&next_owner, &input.referral.referral.owner) {
                return Err(ResolverError::DnssecFailed);
            }
            cname_records.extend(cname_rrset);
            owner = next_owner;
            continue;
        }

        if owner != *input.referral.request_name && response.questions[0].name != owner {
            response = dns_query(input.transport, input.server, &owner, input.referral.qtype)?;
            continue;
        }

        if response.header.flags.rcode() == DNS_RCODE_NXDOMAIN {
            return resolve_secure_child_name_error(
                input.verifier,
                ChildNameErrorResolutionInput {
                    referral: input.referral,
                    request_name: &owner,
                    child_dnskey_rrset: input.child_dnskey_rrset,
                    child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                    response: &response,
                    prefix_records: &cname_records,
                },
            );
        }

        return resolve_secure_child_no_data(
            input.verifier,
            ChildNoDataResolutionInput {
                referral: input.referral,
                request_name: &owner,
                qtype: input.referral.qtype,
                child_dnskey_rrset: input.child_dnskey_rrset,
                child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                response: &response,
                prefix_records: &cname_records,
            },
        );
    }

    Err(ResolverError::DnssecFailed)
}

struct ChildSecureRrsetValidationInput<'a> {
    referral: &'a ChildReferralResolutionInput<'a>,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    owner: &'a DnsName,
    rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
}

fn validate_secure_child_rrset<V>(
    verifier: &V,
    input: ChildSecureRrsetValidationInput<'_>,
) -> Result<(), ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    let rrsig_rrset = records_for(&input.response.answers, input.owner, RecordType::Rrsig);
    if rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let secure = verifier.validate_child_positive_rrset(DelegatedChildDnssecValidation {
        parent_dnskey_owner: &input.referral.parent_delegation.owner,
        parent_ds_rrset: input.referral.parent_ds_rrset,
        parent_dnskey_rrset: input.referral.parent_dnskey_rrset,
        parent_dnskey_rrsig_rrset: input.referral.parent_dnskey_rrsig_rrset,
        child_dnskey_owner: &input.referral.referral.owner,
        child_ds_rrset: &input.referral.referral.ds_rrset,
        child_ds_rrsig_rrset: &input.referral.referral.ds_rrsig_rrset,
        child_dnskey_rrset: input.child_dnskey_rrset,
        child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
        target_rrset: input.rrset,
        target_rrsig_rrset: &rrsig_rrset,
    })?;
    if secure {
        Ok(())
    } else {
        Err(ResolverError::DnssecFailed)
    }
}

struct ChildNoDataResolutionInput<'a> {
    referral: &'a ChildReferralResolutionInput<'a>,
    request_name: &'a DnsName,
    qtype: RecordType,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

struct ChildNameErrorResolutionInput<'a> {
    referral: &'a ChildReferralResolutionInput<'a>,
    request_name: &'a DnsName,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

fn resolve_secure_child_no_data<V>(
    verifier: &V,
    input: ChildNoDataResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_for(&proof_records, input.request_name, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let secure = verifier.validate_child_no_data(DelegatedChildDnssecNoDataValidation {
        parent_dnskey_owner: &input.referral.parent_delegation.owner,
        parent_ds_rrset: input.referral.parent_ds_rrset,
        parent_dnskey_rrset: input.referral.parent_dnskey_rrset,
        parent_dnskey_rrsig_rrset: input.referral.parent_dnskey_rrsig_rrset,
        child_dnskey_owner: &input.referral.referral.owner,
        child_ds_rrset: &input.referral.referral.ds_rrset,
        child_ds_rrsig_rrset: &input.referral.referral.ds_rrsig_rrset,
        child_dnskey_rrset: input.child_dnskey_rrset,
        child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
        query_name: input.request_name,
        query_type: input.qtype,
        nsec_rrset: &nsec_rrset,
        nsec_rrsig_rrset: &nsec_rrsig_rrset,
        nsec3_rrset: &nsec3_rrset,
        nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
    })?;
    if !secure {
        return Err(ResolverError::DnssecFailed);
    }

    Ok(ResolutionAnswer {
        name: input.request_name.clone(),
        records: input.prefix_records.to_vec(),
        secure: true,
    })
}

fn resolve_secure_child_name_error<V>(
    verifier: &V,
    input: ChildNameErrorResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    if input.child_dnskey_rrset.is_empty() || input.child_dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_of_type(&proof_records, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    for closest_encloser in
        closest_encloser_candidates(input.request_name, &input.referral.referral.owner)?
    {
        let secure =
            verifier.validate_child_name_error(DelegatedChildDnssecNameErrorValidation {
                parent_dnskey_owner: &input.referral.parent_delegation.owner,
                parent_ds_rrset: input.referral.parent_ds_rrset,
                parent_dnskey_rrset: input.referral.parent_dnskey_rrset,
                parent_dnskey_rrsig_rrset: input.referral.parent_dnskey_rrsig_rrset,
                child_dnskey_owner: &input.referral.referral.owner,
                child_ds_rrset: &input.referral.referral.ds_rrset,
                child_ds_rrsig_rrset: &input.referral.referral.ds_rrsig_rrset,
                child_dnskey_rrset: input.child_dnskey_rrset,
                child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                query_name: input.request_name,
                closest_encloser: &closest_encloser,
                nsec_rrset: &nsec_rrset,
                nsec_rrsig_rrset: &nsec_rrsig_rrset,
                nsec3_rrset: &nsec3_rrset,
                nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
            })?;
        if secure {
            return Ok(ResolutionAnswer {
                name: input.request_name.clone(),
                records: input.prefix_records.to_vec(),
                secure: true,
            });
        }
    }

    Err(ResolverError::DnssecFailed)
}

struct SecureAnswerResolutionInput<'a, T, V> {
    transport: &'a T,
    verifier: &'a V,
    server: SocketAddr,
    delegation: &'a HnsDelegation,
    request_name: &'a DnsName,
    qtype: RecordType,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    initial_response: DnsMessage,
}

fn resolve_secure_answer_records<T, V>(
    input: SecureAnswerResolutionInput<'_, T, V>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let mut response = input.initial_response;
    let mut owner = input.request_name.clone();
    let mut cname_records = Vec::new();

    for _ in 0..=MAX_CNAME_CHAIN_LEN {
        let target_rrset = records_for(&response.answers, &owner, input.qtype);
        let cname_rrset = if input.qtype == RecordType::Cname {
            Vec::new()
        } else {
            records_for(&response.answers, &owner, RecordType::Cname)
        };
        if !target_rrset.is_empty() && !cname_rrset.is_empty() {
            return Err(ResolverError::DnssecFailed);
        }

        if !target_rrset.is_empty() {
            validate_secure_rrset(
                input.verifier,
                SecureRrsetValidationInput {
                    delegation: input.delegation,
                    ds_rrset: input.ds_rrset,
                    dnskey_rrset: input.dnskey_rrset,
                    dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &target_rrset,
                    response: &response,
                },
            )?;
            cname_records.extend(target_rrset);
            return Ok(ResolutionAnswer {
                name: input.request_name.clone(),
                records: cname_records,
                secure: true,
            });
        }

        if !cname_rrset.is_empty() {
            validate_secure_rrset(
                input.verifier,
                SecureRrsetValidationInput {
                    delegation: input.delegation,
                    ds_rrset: input.ds_rrset,
                    dnskey_rrset: input.dnskey_rrset,
                    dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &cname_rrset,
                    response: &response,
                },
            )?;
            let next_owner = cname_target(&cname_rrset)?;
            if !dns_name_is_subdomain_or_equal(&next_owner, &input.delegation.owner) {
                return Err(ResolverError::DnssecFailed);
            }
            cname_records.extend(cname_rrset);
            owner = next_owner;
            continue;
        }

        if owner != *input.request_name && response.questions[0].name != owner {
            response = dns_query(input.transport, input.server, &owner, input.qtype)?;
            continue;
        }

        if response.header.flags.rcode() == DNS_RCODE_NXDOMAIN {
            return resolve_secure_name_error(
                input.verifier,
                NameErrorResolutionInput {
                    delegation: input.delegation,
                    request_name: &owner,
                    ds_rrset: input.ds_rrset,
                    dnskey_rrset: input.dnskey_rrset,
                    dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                    response: &response,
                    prefix_records: &cname_records,
                },
            );
        }

        return resolve_secure_no_data(
            input.verifier,
            NoDataResolutionInput {
                delegation: input.delegation,
                request_name: &owner,
                qtype: input.qtype,
                ds_rrset: input.ds_rrset,
                dnskey_rrset: input.dnskey_rrset,
                dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                response: &response,
                prefix_records: &cname_records,
            },
        );
    }

    Err(ResolverError::DnssecFailed)
}

struct SecureRrsetValidationInput<'a> {
    delegation: &'a HnsDelegation,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    owner: &'a DnsName,
    rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
}

fn validate_secure_rrset<V>(
    verifier: &V,
    input: SecureRrsetValidationInput<'_>,
) -> Result<(), ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    let rrsig_rrset = records_for(&input.response.answers, input.owner, RecordType::Rrsig);
    if rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let secure = verifier.validate_positive_rrset(DelegatedDnssecValidation {
        dnskey_owner: &input.delegation.owner,
        ds_rrset: input.ds_rrset,
        dnskey_rrset: input.dnskey_rrset,
        dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
        target_rrset: input.rrset,
        target_rrsig_rrset: &rrsig_rrset,
    })?;
    if secure {
        Ok(())
    } else {
        Err(ResolverError::DnssecFailed)
    }
}

struct NoDataResolutionInput<'a> {
    delegation: &'a HnsDelegation,
    request_name: &'a DnsName,
    qtype: RecordType,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

struct NameErrorResolutionInput<'a> {
    delegation: &'a HnsDelegation,
    request_name: &'a DnsName,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

fn resolve_secure_no_data<V>(
    verifier: &V,
    input: NoDataResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    if input.dnskey_rrset.is_empty() || input.dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_for(&proof_records, input.request_name, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let secure = verifier.validate_no_data(DelegatedDnssecNoDataValidation {
        dnskey_owner: &input.delegation.owner,
        ds_rrset: input.ds_rrset,
        dnskey_rrset: input.dnskey_rrset,
        dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
        query_name: input.request_name,
        query_type: input.qtype,
        nsec_rrset: &nsec_rrset,
        nsec_rrsig_rrset: &nsec_rrsig_rrset,
        nsec3_rrset: &nsec3_rrset,
        nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
    })?;
    if !secure {
        return Err(ResolverError::DnssecFailed);
    }

    Ok(ResolutionAnswer {
        name: input.request_name.clone(),
        records: input.prefix_records.to_vec(),
        secure: true,
    })
}

fn resolve_secure_name_error<V>(
    verifier: &V,
    input: NameErrorResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    if input.dnskey_rrset.is_empty() || input.dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_of_type(&proof_records, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    for closest_encloser in
        closest_encloser_candidates(input.request_name, &input.delegation.owner)?
    {
        let secure = verifier.validate_name_error(DelegatedDnssecNameErrorValidation {
            dnskey_owner: &input.delegation.owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            query_name: input.request_name,
            closest_encloser: &closest_encloser,
            nsec_rrset: &nsec_rrset,
            nsec_rrsig_rrset: &nsec_rrsig_rrset,
            nsec3_rrset: &nsec3_rrset,
            nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
        })?;
        if secure {
            return Ok(ResolutionAnswer {
                name: input.request_name.clone(),
                records: input.prefix_records.to_vec(),
                secure: true,
            });
        }
    }

    Err(ResolverError::DnssecFailed)
}

fn closest_encloser_candidates(
    query_name: &DnsName,
    zone_owner: &DnsName,
) -> Result<Vec<DnsName>, ResolverError> {
    let query_labels = query_name.labels();
    let zone_labels = zone_owner.labels();
    if query_labels.len() <= zone_labels.len() || !query_labels.ends_with(zone_labels) {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::new();
    for start in 1..=(query_labels.len() - zone_labels.len()) {
        let candidate = DnsName::from_ascii(&query_labels[start..].join("."))
            .map_err(|_| ResolverError::InvalidDnsResponse)?;
        candidates.push(candidate);
    }
    Ok(candidates)
}

fn dns_query<T: DnsTransport>(
    transport: &T,
    server: SocketAddr,
    qname: &DnsName,
    qtype: RecordType,
) -> Result<DnsMessage, ResolverError> {
    let id = next_dns_query_id();
    let query = build_dns_query(id, qname, qtype)?;
    let udp_response = match transport.exchange_udp(server, &query) {
        Ok(response) => response,
        Err(error) if dns_query_should_retry_tcp(&error) => {
            return dns_query_tcp(transport, server, id, qname, qtype, &query);
        }
        Err(error) => return Err(error),
    };
    let response = match parse_dns_response(id, qname, qtype, &udp_response) {
        Ok(response) => response,
        Err(error) if dns_query_should_retry_tcp(&error) => {
            return dns_query_tcp(transport, server, id, qname, qtype, &query);
        }
        Err(error) => return Err(error),
    };
    if response.header.flags.truncated() {
        return dns_query_tcp(transport, server, id, qname, qtype, &query);
    }

    Ok(response)
}

fn dns_query_should_retry_tcp(error: &ResolverError) -> bool {
    matches!(
        error,
        ResolverError::DnsTransport(_) | ResolverError::InvalidDnsResponse
    )
}

fn dns_query_tcp<T: DnsTransport>(
    transport: &T,
    server: SocketAddr,
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    query: &[u8],
) -> Result<DnsMessage, ResolverError> {
    let tcp_response = transport.exchange_tcp(server, query)?;
    let response = parse_dns_response(id, qname, qtype, &tcp_response)?;
    if response.header.flags.truncated() {
        return Err(ResolverError::InvalidDnsResponse);
    }

    Ok(response)
}

fn next_dns_query_id() -> u16 {
    DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

fn build_dns_query(id: u16, qname: &DnsName, qtype: RecordType) -> Result<Vec<u8>, ResolverError> {
    let message = DnsMessage {
        header: DnsHeader {
            id,
            flags: DnsFlags::new(0),
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

fn parse_dns_response(
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    response: &[u8],
) -> Result<DnsMessage, ResolverError> {
    let message = DnsMessage::parse(response).map_err(|_| ResolverError::InvalidDnsResponse)?;
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

    Ok(message)
}

fn nameserver_addresses(delegation: &HnsDelegation) -> Vec<SocketAddr> {
    let ns_names = delegation
        .records
        .iter()
        .filter(|record| record.name == delegation.owner && record.record_type == RecordType::Ns)
        .filter_map(record_name_rdata)
        .fold(Vec::<DnsName>::new(), |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        });

    let mut addresses = Vec::new();
    for ns_name in ns_names {
        for record in delegation
            .records
            .iter()
            .filter(|record| record.name == ns_name)
        {
            let address = match record.record_type {
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
            };
            let Some(address) = address else {
                continue;
            };
            let socket = SocketAddr::new(address, 53);
            if !addresses.contains(&socket) {
                addresses.push(socket);
            }
        }
    }

    addresses
}

fn child_referral(
    response: &DnsMessage,
    parent_owner: &DnsName,
    request_name: &DnsName,
) -> Option<ChildReferral> {
    let owner = response
        .authorities
        .iter()
        .filter(|record| record.record_type == RecordType::Ns)
        .map(|record| record.name.clone())
        .filter(|owner| {
            owner != parent_owner
                && dns_name_is_subdomain_or_equal(owner, parent_owner)
                && dns_name_is_subdomain_or_equal(request_name, owner)
        })
        .max_by_key(|owner| owner.labels().len())?;
    let ns_rrset = records_for(&response.authorities, &owner, RecordType::Ns);
    let ds_rrset = records_for(&response.authorities, &owner, RecordType::Ds);
    let ds_rrsig_rrset = records_for(&response.authorities, &owner, RecordType::Rrsig);
    if ns_rrset.is_empty() || ds_rrset.is_empty() || ds_rrsig_rrset.is_empty() {
        return None;
    }

    Some(ChildReferral {
        owner,
        servers: referral_nameserver_addresses(&ns_rrset, &response.additionals),
        ds_rrset,
        ds_rrsig_rrset,
    })
}

fn referral_nameserver_addresses(
    ns_rrset: &[ResourceRecord],
    additionals: &[ResourceRecord],
) -> Vec<SocketAddr> {
    let ns_names = ns_rrset.iter().filter_map(record_name_rdata).fold(
        Vec::<DnsName>::new(),
        |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        },
    );
    let mut addresses = Vec::new();
    for ns_name in ns_names {
        for record in additionals.iter().filter(|record| record.name == ns_name) {
            let address = match record.record_type {
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
            };
            let Some(address) = address else {
                continue;
            };
            let socket = SocketAddr::new(address, 53);
            if !addresses.contains(&socket) {
                addresses.push(socket);
            }
        }
    }

    addresses
}

fn record_name_rdata(record: &ResourceRecord) -> Option<DnsName> {
    let (name, end) = DnsName::parse_wire(&record.rdata, 0).ok()?;
    (end == record.rdata.len()).then_some(name)
}

fn cname_target(cname_rrset: &[ResourceRecord]) -> Result<DnsName, ResolverError> {
    if cname_rrset.len() != 1 || cname_rrset[0].record_type != RecordType::Cname {
        return Err(ResolverError::DnssecFailed);
    }
    record_name_rdata(&cname_rrset[0]).ok_or(ResolverError::DnssecFailed)
}

fn dns_name_is_subdomain_or_equal(name: &DnsName, parent: &DnsName) -> bool {
    name.labels().ends_with(parent.labels())
}

fn records_for(
    records: &[ResourceRecord],
    owner: &DnsName,
    record_type: RecordType,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| record.name == *owner && record.record_type == record_type)
        .cloned()
        .collect()
}

fn records_of_type(records: &[ResourceRecord], record_type: RecordType) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| record.record_type == record_type)
        .cloned()
        .collect()
}

fn combined_response_records(response: &DnsMessage) -> Vec<ResourceRecord> {
    response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .cloned()
        .collect()
}

pub fn hns_root_label(input: &str) -> Result<String, ResolverError> {
    let trimmed = input
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    let name = DnsName::from_ascii(trimmed).map_err(|_| ResolverError::UnsupportedBackend)?;
    let labels = name.labels();
    let root = labels.last().ok_or(ResolverError::UnsupportedBackend)?;

    NameHash::from_name(root)?;
    Ok(root.to_owned())
}

pub fn classify_name(input: &str) -> NameClass {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return NameClass::Search;
    }

    let host = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();

    let host = host.trim_end_matches('.');

    if host.is_empty() {
        NameClass::Search
    } else if hns_root_label(host).is_ok() && !uses_common_icann_tld(host) {
        NameClass::Hns
    } else {
        NameClass::Icann
    }
}

fn uses_common_icann_tld(host: &str) -> bool {
    let labels = host.trim_end_matches('.').rsplit_once('.');
    let Some((_, tld)) = labels else {
        return false;
    };
    matches!(
        tld.to_ascii_lowercase().as_str(),
        "ai" | "app"
            | "au"
            | "biz"
            | "blog"
            | "br"
            | "ca"
            | "ch"
            | "cloud"
            | "cn"
            | "co"
            | "com"
            | "de"
            | "dev"
            | "edu"
            | "es"
            | "eu"
            | "fr"
            | "gov"
            | "id"
            | "in"
            | "info"
            | "int"
            | "io"
            | "it"
            | "jp"
            | "me"
            | "mil"
            | "name"
            | "net"
            | "nl"
            | "no"
            | "online"
            | "org"
            | "page"
            | "pl"
            | "ru"
            | "se"
            | "site"
            | "store"
            | "tech"
            | "to"
            | "tv"
            | "uk"
            | "us"
            | "xyz"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type DnsRequestLog = Arc<Mutex<Vec<(SocketAddr, String, u16, bool)>>>;
    type DnsValidationLog = Arc<Mutex<Vec<(usize, usize, usize, usize, usize)>>>;
    type DnsResponseMap = HashMap<(String, u16), DnsResponseFixture>;
    type ServerDnsResponseMap = HashMap<(SocketAddr, String, u16), DnsResponseFixture>;

    struct CountingResolver {
        count: AtomicUsize,
    }

    struct CountingNameNotFoundResolver {
        count: AtomicUsize,
    }

    struct StaticProofProvider {
        proven: ProvenNameRecords,
    }

    struct MapProofProvider {
        proven: HashMap<String, ProvenNameRecords>,
    }

    struct StaticValueProvider {
        verified: VerifiedResourceValue,
    }

    struct ScriptedResolver {
        responses: Vec<(ResolutionRequest, ResolutionAnswer)>,
        requests: Arc<Mutex<Vec<ResolutionRequest>>>,
    }

    struct CapturingDelegatedResolver {
        delegations: Arc<Mutex<Vec<HnsDelegation>>>,
    }

    struct ScriptedDnsTransport {
        responses: DnsResponseMap,
        server_responses: ServerDnsResponseMap,
        requests: DnsRequestLog,
        udp_behavior: ScriptedUdpBehavior,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum ScriptedUdpBehavior {
        #[default]
        Normal,
        Truncated,
        TransportError,
        InvalidResponse,
    }

    struct StaticDnssecVerifier {
        positive_valid: bool,
        no_data_valid: bool,
        name_error_valid: bool,
        child_positive_valid: bool,
        child_no_data_valid: bool,
        child_name_error_valid: bool,
        validations: DnsValidationLog,
        no_data_validations: DnsValidationLog,
        name_error_validations: DnsValidationLog,
        child_validations: DnsValidationLog,
        child_no_data_validations: DnsValidationLog,
        child_name_error_validations: DnsValidationLog,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct DnsResponseFixture {
        rcode: u8,
        answers: Vec<ResourceRecord>,
        authorities: Vec<ResourceRecord>,
        additionals: Vec<ResourceRecord>,
    }

    impl Resolver for CountingResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(ResolutionAnswer {
                name: DnsName::root(),
                records: Vec::new(),
                secure: true,
            })
        }
    }

    impl Resolver for CountingNameNotFoundResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::NameNotFound)
        }
    }

    impl HnsProofProvider for StaticProofProvider {
        fn prove_name(
            &self,
            _root_name: &str,
            _name_hash: NameHash,
        ) -> Result<ProvenNameRecords, ResolverError> {
            Ok(self.proven.clone())
        }
    }

    impl HnsProofProvider for MapProofProvider {
        fn prove_name(
            &self,
            root_name: &str,
            name_hash: NameHash,
        ) -> Result<ProvenNameRecords, ResolverError> {
            let proven = self
                .proven
                .get(root_name)
                .cloned()
                .ok_or(ResolverError::ProofUnavailable)?;
            if proven.root_name != root_name || proven.name_hash != name_hash || !proven.secure {
                return Err(ResolverError::ProofNameMismatch);
            }
            Ok(proven)
        }
    }

    impl HnsResourceValueProvider for StaticValueProvider {
        fn prove_resource_value(
            &self,
            _root_name: &str,
            _name_hash: NameHash,
        ) -> Result<VerifiedResourceValue, ResolverError> {
            Ok(self.verified.clone())
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

    impl Resolver for ScriptedResolver {
        fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.requests
                .lock()
                .map_err(|_| ResolverError::CachePoisoned)?
                .push(request.clone());
            self.responses
                .iter()
                .find(|(candidate, _)| candidate == request)
                .map(|(_, answer)| answer.clone())
                .ok_or(ResolverError::ProofUnavailable)
        }
    }

    impl DelegatedResolver for CapturingDelegatedResolver {
        fn resolve_delegated(
            &self,
            request: &ResolutionRequest,
            delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            self.delegations
                .lock()
                .map_err(|_| ResolverError::CachePoisoned)?
                .push(delegation.clone());
            Ok(ResolutionAnswer {
                name: DnsName::from_ascii(&request.qname).unwrap(),
                records: vec![record(
                    DnsName::from_ascii(&request.qname).unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 1],
                )],
                secure: true,
            })
        }
    }

    impl DnsTransport for ScriptedDnsTransport {
        fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            assert_eq!(query.additionals.len(), 1);
            assert_eq!(
                query.additionals[0].record_type,
                RecordType::Unknown(DNS_OPT_RECORD_TYPE)
            );
            assert_eq!(query.additionals[0].ttl, DNSSEC_DO_FLAG);
            self.requests.lock().unwrap().push((
                server,
                question.name.to_string(),
                question.record_type.code(),
                false,
            ));
            match self.udp_behavior {
                ScriptedUdpBehavior::Normal => {}
                ScriptedUdpBehavior::Truncated => {
                    return Ok(dns_response(&query, DnsResponseFixture::default(), true));
                }
                ScriptedUdpBehavior::TransportError => {
                    return Err(ResolverError::DnsTransport("udp failed".to_owned()));
                }
                ScriptedUdpBehavior::InvalidResponse => return Ok(vec![0, 1, 2, 3]),
            }
            let fixture = self
                .server_responses
                .get(&(
                    server,
                    question.name.to_string(),
                    question.record_type.code(),
                ))
                .or_else(|| {
                    self.responses
                        .get(&(question.name.to_string(), question.record_type.code()))
                })
                .cloned()
                .unwrap_or_default();
            Ok(dns_response(&query, fixture, false))
        }

        fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            self.requests.lock().unwrap().push((
                server,
                question.name.to_string(),
                question.record_type.code(),
                true,
            ));
            let fixture = self
                .server_responses
                .get(&(
                    server,
                    question.name.to_string(),
                    question.record_type.code(),
                ))
                .or_else(|| {
                    self.responses
                        .get(&(question.name.to_string(), question.record_type.code()))
                })
                .cloned()
                .unwrap_or_default();
            Ok(dns_response(&query, fixture, false))
        }
    }

    impl DelegatedDnssecVerifier for StaticDnssecVerifier {
        fn validate_positive_rrset(
            &self,
            input: DelegatedDnssecValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.validations.lock().unwrap().push((
                input.ds_rrset.len(),
                input.dnskey_rrset.len(),
                input.dnskey_rrsig_rrset.len(),
                input.target_rrset.len(),
                input.target_rrsig_rrset.len(),
            ));
            Ok(self.positive_valid)
        }

        fn validate_no_data(
            &self,
            input: DelegatedDnssecNoDataValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.no_data_validations.lock().unwrap().push((
                input.ds_rrset.len(),
                input.dnskey_rrset.len(),
                input.dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.no_data_valid)
        }

        fn validate_name_error(
            &self,
            input: DelegatedDnssecNameErrorValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.name_error_validations.lock().unwrap().push((
                input.ds_rrset.len(),
                input.dnskey_rrset.len(),
                input.dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.name_error_valid)
        }

        fn validate_child_positive_rrset(
            &self,
            input: DelegatedChildDnssecValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.child_validations.lock().unwrap().push((
                input.child_ds_rrset.len(),
                input.child_dnskey_rrset.len(),
                input.child_dnskey_rrsig_rrset.len(),
                input.target_rrset.len(),
                input.target_rrsig_rrset.len(),
            ));
            Ok(self.child_positive_valid)
        }

        fn validate_child_no_data(
            &self,
            input: DelegatedChildDnssecNoDataValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.child_no_data_validations.lock().unwrap().push((
                input.child_ds_rrset.len(),
                input.child_dnskey_rrset.len(),
                input.child_dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.child_no_data_valid)
        }

        fn validate_child_name_error(
            &self,
            input: DelegatedChildDnssecNameErrorValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.child_name_error_validations.lock().unwrap().push((
                input.child_ds_rrset.len(),
                input.child_dnskey_rrset.len(),
                input.child_dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.child_name_error_valid)
        }
    }

    #[test]
    fn single_label_is_hns() {
        assert_eq!(classify_name("welcome"), NameClass::Hns);
    }

    #[test]
    fn trailing_dot_single_label_is_hns() {
        assert_eq!(classify_name("welcome."), NameClass::Hns);
    }

    #[test]
    fn service_prefixed_name_extracts_hns_root() {
        assert_eq!(hns_root_label("_443._tcp.welcome").unwrap(), "welcome");
        assert_eq!(hns_root_label("_443._tcp.welcome.2d").unwrap(), "2d");
    }

    #[test]
    fn dotted_name_is_icann() {
        assert_eq!(classify_name("example.com"), NameClass::Icann);
    }

    #[test]
    fn dotted_hns_name_extracts_final_root_label() {
        assert_eq!(hns_root_label("welcome.2d").unwrap(), "2d");
        assert_eq!(classify_name("welcome.2d"), NameClass::Hns);
    }

    #[test]
    fn whitespace_is_search() {
        assert_eq!(classify_name("two words"), NameClass::Search);
    }

    #[test]
    fn cached_resolver_reuses_fresh_answer() {
        let resolver = CachedResolver::new(
            CountingResolver {
                count: AtomicUsize::new(0),
            },
            32,
            Duration::from_secs(60),
        );
        let request = ResolutionRequest {
            qname: "name".to_owned(),
            qtype: 1,
        };

        resolver.resolve(&request).unwrap();
        resolver.resolve(&request).unwrap();

        assert_eq!(resolver.inner.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cached_resolver_reuses_name_not_found() {
        let resolver = CachedResolver::new(
            CountingNameNotFoundResolver {
                count: AtomicUsize::new(0),
            },
            32,
            Duration::from_secs(60),
        );
        let request = ResolutionRequest {
            qname: "missing".to_owned(),
            qtype: 1,
        };

        assert_eq!(
            resolver.resolve(&request).unwrap_err(),
            ResolverError::NameNotFound
        );
        assert_eq!(
            resolver.resolve(&request).unwrap_err(),
            ResolverError::NameNotFound
        );

        assert_eq!(resolver.inner.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn proof_backed_resolver_filters_verified_records() {
        let root_name = "welcome".to_owned();
        let request_name = DnsName::from_ascii("welcome").unwrap();
        let resolver = ProofBackedResolver::new(StaticProofProvider {
            proven: ProvenNameRecords {
                root_name: root_name.clone(),
                name_hash: NameHash::from_name(&root_name).unwrap(),
                records: vec![
                    record(request_name.clone(), RecordType::A, vec![127, 0, 0, 1]),
                    record(request_name.clone(), RecordType::Aaaa, vec![0; 16]),
                    record(
                        DnsName::from_ascii("other").unwrap(),
                        RecordType::A,
                        vec![1, 1, 1, 1],
                    ),
                ],
                secure: true,
                exists: true,
            },
        });

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: "welcome".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert_eq!(answer.name, request_name);
        assert!(answer.secure);
        assert_eq!(
            answer.records,
            vec![record(answer.name, RecordType::A, vec![127, 0, 0, 1])]
        );
    }

    #[test]
    fn proof_backed_resolver_rejects_mismatched_proof_name() {
        let resolver = ProofBackedResolver::new(StaticProofProvider {
            proven: ProvenNameRecords {
                root_name: "other".to_owned(),
                name_hash: NameHash::from_name("other").unwrap(),
                records: Vec::new(),
                secure: true,
                exists: true,
            },
        });

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::ProofNameMismatch,
        );
    }

    #[test]
    fn proof_backed_resolver_reports_verified_non_inclusion() {
        let root_name = "missing".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let resolver = ProofBackedResolver::new(StaticProofProvider {
            proven: ProvenNameRecords {
                root_name: root_name.clone(),
                name_hash,
                records: Vec::new(),
                secure: true,
                exists: false,
            },
        });

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: root_name,
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::NameNotFound,
        );
    }

    #[test]
    fn proven_records_decode_hsd_resource_value() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");

        let proven =
            ProvenNameRecords::from_resource_value(root_name.clone(), name_hash, &value).unwrap();

        assert_eq!(proven.root_name, root_name);
        assert_eq!(proven.name_hash, name_hash);
        assert!(proven.secure);
        assert!(proven.exists);
        assert_eq!(proven.records.len(), 1);
        assert_eq!(
            proven.records[0].name,
            DnsName::from_ascii("welcome").unwrap()
        );
        assert_eq!(proven.records[0].record_type, RecordType::Ns);
        assert_eq!(
            proven.records[0].ttl,
            hns_core::resource::DEFAULT_HANDSHAKE_RESOURCE_TTL
        );
        assert_eq!(proven.records[0].rdata, name_bytes("ns1.welcome"));
    }

    #[test]
    fn proven_records_reject_invalid_resource_value() {
        assert_eq!(
            ProvenNameRecords::from_resource_value(
                "welcome".to_owned(),
                NameHash::from_name("welcome").unwrap(),
                &[1],
            )
            .unwrap_err(),
            ResolverError::InvalidResource(ResourceError::UnsupportedVersion),
        );
    }

    #[test]
    fn resource_value_provider_decodes_verified_inclusion_for_resolver() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");
        let resolver =
            ProofBackedResolver::new(ResourceValueProofProvider::new(StaticValueProvider {
                verified: VerifiedResourceValue::inclusion(root_name.clone(), name_hash, value),
            }));

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::Ns.code(),
            })
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].record_type, RecordType::Ns);
        assert_eq!(answer.records[0].rdata, name_bytes("ns1.welcome"));
    }

    #[test]
    fn delegating_resolver_answers_root_ns_from_hns_proof() {
        let root_name = "welcome".to_owned();
        let request_name = DnsName::from_ascii("welcome").unwrap();
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome")],
                    secure: true,
                    exists: true,
                },
            },
            FailClosedResolver,
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::Ns.code(),
            })
            .unwrap();

        assert_eq!(answer.name, request_name);
        assert!(answer.secure);
        assert_eq!(answer.records, vec![ns_record("welcome", "ns1.welcome")]);
    }

    #[test]
    fn delegating_resolver_delegates_apex_address_with_ds() {
        let root_name = "welcome".to_owned();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome"), ds_record("welcome")],
                    secure: true,
                    exists: true,
                },
            },
            ScriptedResolver::new(
                vec![resolver_response(
                    "welcome",
                    RecordType::A.code(),
                    true,
                    vec![record(
                        DnsName::from_ascii("welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    )],
                )],
                Arc::clone(&requests),
            ),
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].record_type, RecordType::A);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![ResolutionRequest {
                qname: "welcome".to_owned(),
                qtype: RecordType::A.code(),
            }],
        );
    }

    #[test]
    fn delegating_resolver_fails_closed_when_ds_child_is_insecure() {
        let root_name = "welcome".to_owned();
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome"), ds_record("welcome")],
                    secure: true,
                    exists: true,
                },
            },
            ScriptedResolver::new(
                vec![resolver_response(
                    "welcome",
                    RecordType::A.code(),
                    false,
                    Vec::new(),
                )],
                Arc::new(Mutex::new(Vec::new())),
            ),
        );

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: root_name,
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::DnssecFailed,
        );
    }

    #[test]
    fn delegating_resolver_marks_unsigned_delegation_insecure() {
        let root_name = "welcome".to_owned();
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome")],
                    secure: true,
                    exists: true,
                },
            },
            ScriptedResolver::new(
                vec![resolver_response(
                    "welcome",
                    RecordType::A.code(),
                    true,
                    vec![record(
                        DnsName::from_ascii("welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    )],
                )],
                Arc::new(Mutex::new(Vec::new())),
            ),
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(!answer.secure);
        assert_eq!(answer.records.len(), 1);
    }

    #[test]
    fn delegating_resolver_passes_hns_delegation_context() {
        let root_name = "welcome".to_owned();
        let delegations = Arc::new(Mutex::new(Vec::new()));
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![
                        ns_record("welcome", "ns1.welcome"),
                        record(
                            DnsName::from_ascii("ns1.welcome").unwrap(),
                            RecordType::A,
                            vec![127, 0, 0, 1],
                        ),
                        ds_record("welcome"),
                    ],
                    secure: true,
                    exists: true,
                },
            },
            CapturingDelegatedResolver {
                delegations: Arc::clone(&delegations),
            },
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(answer.secure);
        let captured = delegations.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].root_name, "welcome");
        assert_eq!(captured[0].owner, DnsName::from_ascii("welcome").unwrap());
        assert_eq!(captured[0].records.len(), 3);
    }

    #[test]
    fn delegating_resolver_hydrates_out_of_zone_hns_nameserver_address() {
        let root_name = "welcome".to_owned();
        let ns_root_name = "hshub".to_owned();
        let ns_name = DnsName::from_ascii("ns1.hshub").unwrap();
        let delegations = Arc::new(Mutex::new(Vec::new()));
        let mut proven = HashMap::new();
        proven.insert(
            root_name.clone(),
            ProvenNameRecords {
                root_name: root_name.clone(),
                name_hash: NameHash::from_name(&root_name).unwrap(),
                records: vec![ns_record("welcome", "ns1.hshub"), ds_record("welcome")],
                secure: true,
                exists: true,
            },
        );
        proven.insert(
            ns_root_name.clone(),
            ProvenNameRecords {
                root_name: ns_root_name.clone(),
                name_hash: NameHash::from_name(&ns_root_name).unwrap(),
                records: vec![
                    ns_record("hshub", "ns1.hshub"),
                    record(ns_name.clone(), RecordType::A, vec![127, 0, 0, 9]),
                ],
                secure: true,
                exists: true,
            },
        );
        let resolver = DelegatingResolver::new(
            MapProofProvider { proven },
            CapturingDelegatedResolver {
                delegations: Arc::clone(&delegations),
            },
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(answer.secure);
        let captured = delegations.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(
            captured[0]
                .records
                .contains(&record(ns_name, RecordType::A, vec![127, 0, 0, 9],))
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_validates_positive_rrset() {
        let server = SocketAddr::from(([127, 0, 0, 1], 53));
        let validations = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].rdata, vec![127, 0, 0, 1]);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (server, "welcome".to_owned(), RecordType::A.code(), false),
                (
                    server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false
                ),
            ],
        );
        assert_eq!(*validations.lock().unwrap(), vec![(1, 1, 1, 1, 1)]);
    }

    #[test]
    fn authoritative_dnssec_resolver_accepts_secure_nsec_no_data() {
        let validations = Arc::new(Mutex::new(Vec::new()));
        let no_data_validations = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::Aaaa,
                        vec![nsec_record("welcome"), rrsig_record("welcome")],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: true,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::clone(&no_data_validations),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::Aaaa.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
        assert!(validations.lock().unwrap().is_empty());
        assert_eq!(*no_data_validations.lock().unwrap(), vec![(1, 1, 1, 1, 2)]);
    }

    #[test]
    fn authoritative_dnssec_resolver_accepts_secure_nsec_name_error() {
        let validations = Arc::new(Mutex::new(Vec::new()));
        let no_data_validations = Arc::new(Mutex::new(Vec::new()));
        let name_error_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("missing.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NXDOMAIN,
                answers: Vec::new(),
                authorities: vec![
                    nsec_record("alpha.welcome"),
                    nsec_record("z.welcome"),
                    rrsig_record("welcome"),
                ],
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: true,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::clone(&no_data_validations),
                name_error_validations: Arc::clone(&name_error_validations),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "missing.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
        assert!(validations.lock().unwrap().is_empty());
        assert!(no_data_validations.lock().unwrap().is_empty());
        assert_eq!(
            *name_error_validations.lock().unwrap(),
            vec![(1, 1, 1, 2, 2)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_follows_secure_cname_chain() {
        let validations = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            cname_record("welcome", "edge.welcome"),
                            rrsig_record("welcome"),
                            record(
                                DnsName::from_ascii("edge.welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("edge.welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.name, DnsName::from_ascii("welcome").unwrap());
        assert_eq!(answer.records.len(), 2);
        assert_eq!(answer.records[0].record_type, RecordType::Cname);
        assert_eq!(
            answer.records[1].name,
            DnsName::from_ascii("edge.welcome").unwrap()
        );
        assert_eq!(answer.records[1].record_type, RecordType::A);
        assert_eq!(
            *validations.lock().unwrap(),
            vec![(1, 1, 1, 1, 1), (1, 1, 1, 1, 1)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_follows_secure_child_referral() {
        let parent_server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_server = SocketAddr::from(([127, 0, 0, 2], 53));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let child_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("www.sub.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    ns_record("sub.welcome", "ns1.sub.welcome"),
                    ds_record("sub.welcome"),
                    rrsig_record("sub.welcome"),
                ],
                additionals: vec![record(
                    DnsName::from_ascii("ns1.sub.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 2],
                )],
            },
        );
        let mut server_responses = HashMap::new();
        server_responses.insert(
            (
                child_server,
                "sub.welcome".to_owned(),
                RecordType::Dnskey.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("sub.welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![1, 2, 3, 4],
                    ),
                    rrsig_record("sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        server_responses.insert(
            (
                child_server,
                "www.sub.welcome".to_owned(),
                RecordType::A.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("www.sub.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 3],
                    ),
                    rrsig_record("www.sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses,
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: true,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::clone(&child_validations),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "www.sub.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].rdata, vec![127, 0, 0, 3]);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    parent_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
                (
                    parent_server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "sub.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
            ],
        );
        assert_eq!(*child_validations.lock().unwrap(), vec![(1, 1, 1, 1, 1)]);
    }

    #[test]
    fn authoritative_dnssec_resolver_follows_secure_child_cname_chain() {
        let parent_server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_server = SocketAddr::from(([127, 0, 0, 2], 53));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let child_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("www.sub.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    ns_record("sub.welcome", "ns1.sub.welcome"),
                    ds_record("sub.welcome"),
                    rrsig_record("sub.welcome"),
                ],
                additionals: vec![record(
                    DnsName::from_ascii("ns1.sub.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 2],
                )],
            },
        );
        let mut server_responses = HashMap::new();
        server_responses.insert(
            (
                child_server,
                "sub.welcome".to_owned(),
                RecordType::Dnskey.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("sub.welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![1, 2, 3, 4],
                    ),
                    rrsig_record("sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        server_responses.insert(
            (
                child_server,
                "www.sub.welcome".to_owned(),
                RecordType::A.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    cname_record("www.sub.welcome", "edge.sub.welcome"),
                    rrsig_record("www.sub.welcome"),
                    record(
                        DnsName::from_ascii("edge.sub.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 4],
                    ),
                    rrsig_record("edge.sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses,
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: true,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::clone(&child_validations),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "www.sub.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 2);
        assert_eq!(answer.records[0].record_type, RecordType::Cname);
        assert_eq!(answer.records[1].rdata, vec![127, 0, 0, 4]);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    parent_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
                (
                    parent_server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "sub.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
            ],
        );
        assert_eq!(
            *child_validations.lock().unwrap(),
            vec![(1, 1, 1, 1, 1), (1, 1, 1, 1, 1)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_accepts_secure_child_nsec_no_data() {
        let parent_server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_server = SocketAddr::from(([127, 0, 0, 2], 53));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let child_no_data_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("missing.sub.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    ns_record("sub.welcome", "ns1.sub.welcome"),
                    ds_record("sub.welcome"),
                    rrsig_record("sub.welcome"),
                ],
                additionals: vec![record(
                    DnsName::from_ascii("ns1.sub.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 2],
                )],
            },
        );
        let mut server_responses = HashMap::new();
        server_responses.insert(
            (
                child_server,
                "sub.welcome".to_owned(),
                RecordType::Dnskey.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("sub.welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![1, 2, 3, 4],
                    ),
                    rrsig_record("sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        server_responses.insert(
            (
                child_server,
                "missing.sub.welcome".to_owned(),
                RecordType::A.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    nsec_record("missing.sub.welcome"),
                    rrsig_record("missing.sub.welcome"),
                ],
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses,
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: true,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::clone(&child_no_data_validations),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "missing.sub.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    parent_server,
                    "missing.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
                (
                    parent_server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "sub.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "missing.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
            ],
        );
        assert_eq!(
            *child_no_data_validations.lock().unwrap(),
            vec![(1, 1, 1, 1, 2)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_fails_closed_when_verifier_rejects() {
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        assert_eq!(
            resolver
                .resolve_delegated(
                    &ResolutionRequest {
                        qname: "welcome".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    &delegation_with_records(vec![
                        ns_record("welcome", "ns1.welcome"),
                        record(
                            DnsName::from_ascii("ns1.welcome").unwrap(),
                            RecordType::A,
                            vec![127, 0, 0, 1],
                        ),
                        ds_record("welcome"),
                    ]),
                )
                .unwrap_err(),
            ResolverError::DnssecFailed,
        );
    }

    fn authoritative_dnssec_retry_resolver(
        udp_behavior: ScriptedUdpBehavior,
        requests: DnsRequestLog,
    ) -> AuthoritativeDnssecResolver<ScriptedDnsTransport, StaticDnssecVerifier> {
        AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests,
                udp_behavior,
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        )
    }

    fn resolve_welcome_a(
        resolver: &AuthoritativeDnssecResolver<ScriptedDnsTransport, StaticDnssecVerifier>,
    ) -> Result<ResolutionAnswer, ResolverError> {
        resolver.resolve_delegated(
            &ResolutionRequest {
                qname: "welcome".to_owned(),
                qtype: RecordType::A.code(),
            },
            &delegation_with_records(vec![
                ns_record("welcome", "ns1.welcome"),
                record(
                    DnsName::from_ascii("ns1.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 1],
                ),
                ds_record("welcome"),
            ]),
        )
    }

    fn assert_welcome_a_retried_over_tcp(requests: &DnsRequestLog) {
        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|(_, qname, qtype, tcp)| {
            qname == "welcome" && *qtype == RecordType::A.code() && !*tcp
        }));
        assert!(requests.iter().any(|(_, qname, qtype, tcp)| {
            qname == "welcome" && *qtype == RecordType::A.code() && *tcp
        }));
    }

    #[test]
    fn authoritative_dnssec_resolver_retries_truncated_udp_over_tcp() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = authoritative_dnssec_retry_resolver(
            ScriptedUdpBehavior::Truncated,
            Arc::clone(&requests),
        );
        let answer = resolve_welcome_a(&resolver).unwrap();

        assert!(answer.secure);
        assert_welcome_a_retried_over_tcp(&requests);
    }

    #[test]
    fn authoritative_dnssec_resolver_retries_udp_transport_error_over_tcp() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = authoritative_dnssec_retry_resolver(
            ScriptedUdpBehavior::TransportError,
            Arc::clone(&requests),
        );
        let answer = resolve_welcome_a(&resolver).unwrap();

        assert!(answer.secure);
        assert_welcome_a_retried_over_tcp(&requests);
    }

    #[test]
    fn authoritative_dnssec_resolver_retries_invalid_udp_response_over_tcp() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = authoritative_dnssec_retry_resolver(
            ScriptedUdpBehavior::InvalidResponse,
            Arc::clone(&requests),
        );
        let answer = resolve_welcome_a(&resolver).unwrap();

        assert!(answer.secure);
        assert_welcome_a_retried_over_tcp(&requests);
    }

    #[test]
    fn resolver_all_record_query_keeps_synth_address_records() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let value = vec![0, 4, 127, 0, 0, 1];
        let resolver =
            ProofBackedResolver::new(ResourceValueProofProvider::new(StaticValueProvider {
                verified: VerifiedResourceValue::inclusion(root_name.clone(), name_hash, value),
            }));

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: u16::MAX,
            })
            .unwrap();

        assert_eq!(answer.records.len(), 2);
        assert!(
            answer
                .records
                .iter()
                .any(|record| record.record_type == RecordType::A && record.rdata == [127, 0, 0, 1])
        );
    }

    #[test]
    fn resource_value_provider_allows_verified_non_inclusion() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let provider = ResourceValueProofProvider::new(StaticValueProvider {
            verified: VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash),
        });

        let proven = provider.prove_name(&root_name, name_hash).unwrap();

        assert!(proven.secure);
        assert!(!proven.exists);
        assert!(proven.records.is_empty());
    }

    #[test]
    fn resource_value_provider_rejects_mismatched_verified_value() {
        let provider = ResourceValueProofProvider::new(StaticValueProvider {
            verified: VerifiedResourceValue::non_inclusion(
                "other".to_owned(),
                NameHash::from_name("other").unwrap(),
            ),
        });

        assert_eq!(
            provider
                .prove_name("welcome", NameHash::from_name("welcome").unwrap())
                .unwrap_err(),
            ResolverError::ProofNameMismatch,
        );
    }

    #[test]
    fn memory_resource_value_provider_serves_inserted_value() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");
        let values = MemoryResourceValueProvider::new();
        values
            .insert(VerifiedResourceValue::inclusion(
                root_name.clone(),
                name_hash,
                value,
            ))
            .unwrap();
        let resolver = ProofBackedResolver::new(ResourceValueProofProvider::new(values));

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::Ns.code(),
            })
            .unwrap();

        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].rdata, name_bytes("ns1.welcome"));
    }

    #[test]
    fn memory_resource_value_provider_rejects_missing_value() {
        let values = MemoryResourceValueProvider::new();

        assert_eq!(
            values
                .prove_resource_value("welcome", NameHash::from_name("welcome").unwrap())
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
        assert!(values.is_empty().unwrap());
    }

    #[test]
    fn memory_resource_value_provider_rejects_mismatched_hash() {
        let values = MemoryResourceValueProvider::new();

        assert_eq!(
            values
                .insert(VerifiedResourceValue::non_inclusion(
                    "welcome".to_owned(),
                    NameHash::from_name("other").unwrap(),
                ))
                .unwrap_err(),
            ResolverError::ProofNameMismatch,
        );
    }

    #[test]
    fn sqlite_resource_value_provider_persists_inserted_value() {
        let path = temp_db_path("resource-value");
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            values
                .insert(VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    value.clone(),
                ))
                .unwrap();
            assert_eq!(values.len().unwrap(), 1);
            values.flush().unwrap();
        }

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            let verified = values.prove_resource_value(&root_name, name_hash).unwrap();
            assert_eq!(verified.value, Some(value.clone()));

            let resolver = ProofBackedResolver::new(ResourceValueProofProvider::new(values));
            let answer = resolver
                .resolve(&ResolutionRequest {
                    qname: root_name,
                    qtype: RecordType::Ns.code(),
                })
                .unwrap();

            assert_eq!(answer.records.len(), 1);
            assert_eq!(answer.records[0].rdata, name_bytes("ns1.welcome"));
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sqlite_resource_value_provider_persists_non_inclusion() {
        let path = temp_db_path("resource-non-inclusion");
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            values
                .insert(VerifiedResourceValue::non_inclusion(
                    root_name.clone(),
                    name_hash,
                ))
                .unwrap();
            values.flush().unwrap();
        }

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            let verified = values.prove_resource_value(&root_name, name_hash).unwrap();
            assert_eq!(verified.value, None);
            assert!(verified.secure);
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sqlite_resource_value_provider_reports_bytes_and_evicts_oldest_values() {
        let values = SqliteResourceValueProvider::in_memory().unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();

        values
            .insert(VerifiedResourceValue::inclusion(
                "alpha".to_owned(),
                alpha_hash,
                vec![1, 2, 3, 4, 5, 6],
            ))
            .unwrap();
        values
            .insert(VerifiedResourceValue::inclusion(
                "beta".to_owned(),
                beta_hash,
                vec![7, 8],
            ))
            .unwrap();

        assert_eq!(
            values.stats().unwrap(),
            ResourceValueCacheStats {
                entries: 2,
                value_bytes: 8,
            },
        );
        assert_eq!(values.enforce_value_byte_limit(2).unwrap(), 1);

        assert_eq!(
            values.stats().unwrap(),
            ResourceValueCacheStats {
                entries: 1,
                value_bytes: 2,
            },
        );
        assert_eq!(
            values
                .prove_resource_value("alpha", alpha_hash)
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
        assert_eq!(
            values
                .prove_resource_value("beta", beta_hash)
                .unwrap()
                .value,
            Some(vec![7, 8]),
        );

        values.clear().unwrap();
        assert_eq!(
            values.stats().unwrap(),
            ResourceValueCacheStats {
                entries: 0,
                value_bytes: 0,
            },
        );
    }

    #[test]
    fn sqlite_resource_value_provider_persists_and_prunes_anchors() {
        let values = SqliteResourceValueProvider::in_memory().unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        let gamma_hash = NameHash::from_name("gamma").unwrap();
        let valid_anchor = ResourceValueAnchor {
            tree_root: Hash::new([1; 32]),
            height: Height(3),
        };
        let invalid_anchor = ResourceValueAnchor {
            tree_root: Hash::new([2; 32]),
            height: Height(3),
        };

        values
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1])
                    .with_anchor(valid_anchor.tree_root, valid_anchor.height),
            )
            .unwrap();
        values
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![2])
                    .with_anchor(invalid_anchor.tree_root, invalid_anchor.height),
            )
            .unwrap();
        values
            .insert(VerifiedResourceValue::inclusion(
                "gamma".to_owned(),
                gamma_hash,
                vec![3],
            ))
            .unwrap();

        assert_eq!(values.anchored_heights().unwrap(), vec![Height(3)]);
        assert_eq!(
            values.prune_invalid_anchors(&[valid_anchor], true).unwrap(),
            2
        );
        assert_eq!(
            values
                .prove_resource_value("alpha", alpha_hash)
                .unwrap()
                .anchor,
            Some(valid_anchor),
        );
        assert_eq!(
            values.prove_resource_value("beta", beta_hash).unwrap_err(),
            ResolverError::ProofUnavailable,
        );
        assert_eq!(
            values
                .prove_resource_value("gamma", gamma_hash)
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
    }

    #[test]
    fn sqlite_resource_value_provider_migrates_legacy_anchor_columns() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE verified_resource_values (
                    root_name TEXT NOT NULL,
                    name_hash BLOB NOT NULL,
                    value BLOB,
                    secure INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(root_name, name_hash)
                );
                ",
            )
            .unwrap();
        let values = SqliteResourceValueProvider::from_connection(connection).unwrap();
        let root_name = "alpha".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor = ResourceValueAnchor {
            tree_root: Hash::new([3; 32]),
            height: Height(11),
        };

        values
            .insert(
                VerifiedResourceValue::inclusion(root_name.clone(), name_hash, vec![1, 2])
                    .with_anchor(anchor.tree_root, anchor.height),
            )
            .unwrap();

        let stored = values.prove_resource_value(&root_name, name_hash).unwrap();
        assert_eq!(stored.anchor, Some(anchor));
    }

    fn record(name: DnsName, record_type: RecordType, rdata: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name,
            record_type,
            class: 1,
            ttl: 300,
            rdata,
        }
    }

    fn ns_record(owner: &str, target: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Ns,
            name_bytes(target),
        )
    }

    fn ds_record(owner: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Ds,
            vec![0, 1, 8, 2, 0xaa],
        )
    }

    fn rrsig_record(owner: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Rrsig,
            vec![0, 1, 8, 1],
        )
    }

    fn cname_record(owner: &str, target: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Cname,
            name_bytes(target),
        )
    }

    fn nsec_record(owner: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Nsec,
            name_bytes(owner),
        )
    }

    fn delegation_with_records(records: Vec<ResourceRecord>) -> HnsDelegation {
        HnsDelegation {
            root_name: "welcome".to_owned(),
            owner: DnsName::from_ascii("welcome").unwrap(),
            records,
        }
    }

    fn dns_responses(responses: Vec<(&str, RecordType, Vec<ResourceRecord>)>) -> DnsResponseMap {
        responses
            .into_iter()
            .map(|(name, record_type, records)| {
                (
                    (name.to_owned(), record_type.code()),
                    DnsResponseFixture {
                        rcode: DNS_RCODE_NOERROR,
                        answers: records,
                        authorities: Vec::new(),
                        additionals: Vec::new(),
                    },
                )
            })
            .collect()
    }

    fn dns_response(query: &DnsMessage, fixture: DnsResponseFixture, truncated: bool) -> Vec<u8> {
        let flags = (if truncated { 0x8600 } else { 0x8400 }) | fixture.rcode as u16;
        DnsMessage {
            header: DnsHeader {
                id: query.header.id,
                flags: DnsFlags::new(flags),
                question_count: 1,
                answer_count: fixture.answers.len() as u16,
                authority_count: fixture.authorities.len() as u16,
                additional_count: fixture.additionals.len() as u16,
            },
            questions: query.questions.clone(),
            answers: fixture.answers,
            authorities: fixture.authorities,
            additionals: fixture.additionals,
        }
        .encode(&DnsEncodeConfig {
            max_message_len: DEFAULT_DNS_TCP_MAX_MESSAGE_LEN,
        })
        .unwrap()
    }

    fn resolver_response(
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

    fn encode_name(out: &mut Vec<u8>, name: &str) {
        DnsName::from_ascii(name).unwrap().encode_wire(out).unwrap();
    }

    fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_name(&mut out, name);
        out
    }

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hns-resolver-{label}-{}-{now}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup_db_path(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
