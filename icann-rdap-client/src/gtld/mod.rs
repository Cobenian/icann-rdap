use crate::request::RequestData;
use std::{any::TypeId, char};

use icann_rdap_common::{check::CheckParams, response::RdapResponse};
use strum::EnumMessage;

// use icann_rdap_common::check::{CheckClass, Checks, CHECK_CLASS_LEN};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod redacted;
pub mod search;
pub mod string;
pub mod table;
pub mod types;

pub trait ToGtld{
  fn to_gtld(&self) -> String;
}

impl ToGtld for RdapResponse {
  fn to_gtld(&self) -> String {
      let mut gtld = String::new();
      let variant_gtld = match &self {
          RdapResponse::Entity(entity) => entity.to_gtld(),
          RdapResponse::Domain(domain) => domain.to_gtld(),
          RdapResponse::Nameserver(nameserver) => nameserver.to_gtld(),
          RdapResponse::Autnum(autnum) => autnum.to_gtld(),
          RdapResponse::Network(network) => network.to_gtld(),
          RdapResponse::DomainSearchResults(results) => results.to_gtld(),
          RdapResponse::EntitySearchResults(results) => results.to_gtld(),
          RdapResponse::NameserverSearchResults(results) => results.to_gtld(),
          RdapResponse::ErrorResponse(error) => error.to_gtld(),
          RdapResponse::Help(help) => help.to_gtld(),
      };
      gtld.push_str(&variant_gtld);
      gtld
  }
}