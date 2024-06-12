use icann_rdap_common::response::RdapResponse;
use std::any::TypeId;

pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod types;

#[derive(Clone, Copy)]
pub struct GtldParams<'a> {
    pub root: &'a RdapResponse,
    pub parent_type: TypeId,
}

impl<'a> GtldParams<'a> {
    pub fn from_parent(&self, parent_type: TypeId) -> Self {
        GtldParams {
            parent_type,
            root: self.root,
        }
    }

    pub fn next_level(&self) -> Self {
        GtldParams { ..*self }
    }
}

pub trait ToGtld {
    fn to_gtld(&self, params: GtldParams) -> String;
}

impl ToGtld for RdapResponse {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld = String::new();
        let variant_gtld = match &self {
            RdapResponse::Domain(domain) => domain.to_gtld(params),
            RdapResponse::Nameserver(nameserver) => nameserver.to_gtld(params),
            RdapResponse::Network(network) => network.to_gtld(params),
            // NOP
            _ => String::new(),
        };
        gtld.push_str(&variant_gtld);
        gtld
    }
}
