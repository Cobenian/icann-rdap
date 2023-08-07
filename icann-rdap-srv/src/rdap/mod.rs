use icann_rdap_common::response::{error::Error, RdapResponse};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod ip;
pub mod nameserver;
pub mod response;
pub mod router;

trait ToBootStrap {
    fn to_ip_bootstrap(self, ip_id: &str) -> RdapResponse;
    fn to_domain_bootstrap(self, domain_id: &str) -> RdapResponse;
    fn to_autnum_bootstrap(self, autnum_id: u32) -> RdapResponse;
    fn to_entity_bootstrap(self, entity_id: &str) -> RdapResponse;
    fn to_nameserver_bootstrap(self, nameserver_id: &str) -> RdapResponse;
}

impl ToBootStrap for RdapResponse {
    fn to_ip_bootstrap(self, ip_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(e, "ip", ip_id),
            _ => self,
        }
    }

    fn to_domain_bootstrap(self, domain_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(e, "domain", domain_id),
            _ => self,
        }
    }

    fn to_autnum_bootstrap(self, autnum_id: u32) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => {
                bootstrap_redirect(e, "autnum", &autnum_id.to_string())
            }
            _ => self,
        }
    }

    fn to_entity_bootstrap(self, entity_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(e, "entity", entity_id),
            _ => self,
        }
    }

    fn to_nameserver_bootstrap(self, nameserver_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(e, "nameserver", nameserver_id),
            _ => self,
        }
    }
}

fn bootstrap_redirect(error: Error, path: &str, id: &str) -> RdapResponse {
    let Some(ref notices) = error.common.notices else {return RdapResponse::ErrorResponse(error)};
    let Some(notice) = notices.first() else {return RdapResponse::ErrorResponse(error)};
    let Some(links) = &notice.links else {return RdapResponse::ErrorResponse(error)};
    let Some(link) = links.first() else {return RdapResponse::ErrorResponse(error)};
    let href = format!("{}{path}/{id}", link.href);
    let redirect = Error::redirect().url(href).build();
    RdapResponse::ErrorResponse(redirect)
}
