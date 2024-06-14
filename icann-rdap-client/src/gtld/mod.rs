use icann_rdap_common::contact::PostalAddress;
use icann_rdap_common::response::RdapResponse;
use std::any::TypeId;

pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod types;

#[derive(Clone)]
pub struct GtldParams<'a> {
    pub root: &'a RdapResponse,
    pub parent_type: TypeId,
    pub label: String,
}

impl<'a> GtldParams<'a> {
    pub fn from_parent(&mut self, parent_type: TypeId) -> Self {
        GtldParams {
            parent_type,
            root: self.root,
            label: self.label.clone(),
        }
    }

    pub fn next_level(&self) -> Self {
        GtldParams {
            label: self.label.clone(),
            ..*self
        }
    }
}

pub trait ToGtld {
    fn to_gtld(&self, params: &mut GtldParams) -> String;
}

impl ToGtld for RdapResponse {
    fn to_gtld(&self, params: &mut GtldParams) -> String {
        let mut gtld = String::new();
        let variant_gtld = match &self {
            RdapResponse::Domain(domain) => domain.to_gtld(params),
            RdapResponse::Nameserver(nameserver) => nameserver.to_gtld(params),
            // NOP
            _ => String::new(),
        };
        gtld.push_str(&variant_gtld);
        gtld
    }
}

impl ToGtld for PostalAddress {
    fn to_gtld(&self, params: &mut GtldParams) -> String {
        let label = &params.label; // Use the label from params

        let street = self
            .street_parts
            .as_ref()
            .map(|parts| parts.join(" "))
            .unwrap_or_default();
        let city = self.locality.as_deref().unwrap_or("");
        let state = self.region_name.as_deref().unwrap_or("");
        let postal_code = self.postal_code.as_deref().unwrap_or("");
        let country = self.country_code.as_deref().unwrap_or("");

        format!(
            "{} Street: {}\n{} City: {}\n{} State/Province: {}\n{} Postal Code: {}\n{} Country: {}\n",
            label, street, label, city, label, state, label, postal_code, label, country
        )
    }
}
