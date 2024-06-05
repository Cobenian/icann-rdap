use crate::request::RequestData;
use icann_rdap_common::{check::CheckParams, response::RdapResponse};
use std::any::TypeId;
use strum::EnumMessage;

// use icann_rdap_common::check::{CheckClass, Checks, CHECK_CLASS_LEN};

use icann_rdap_common::check::{CheckClass, Checks};

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

pub(crate) const _CODE_INDENT: &str = "    ";

pub(crate) const HR: &str = "\n";

/// Specifies options for generating markdown.
pub struct GtldOptions {
    /// If true, do not use Unicode characters.
    pub no_unicode_chars: bool,

    /// The character used for text styling of bold and italics.
    pub text_style_char: char,

    /// If true, headers use the hash marks or under lines.
    pub hash_headers: bool,

    /// If true, the text_style_char will appear in a justified text.
    pub style_in_justify: bool,
}

impl Default for GtldOptions {
    fn default() -> Self {
        GtldOptions {
            no_unicode_chars: false,
            text_style_char: '*',
            hash_headers: true,
            style_in_justify: false,
        }
    }
}

impl GtldOptions {
    /// Defaults for markdown that looks more like plain text.
    pub fn plain_text() -> Self {
        GtldOptions {
            no_unicode_chars: true,
            text_style_char: '_',
            hash_headers: false,
            style_in_justify: true,
        }
    }
}

#[derive(Clone, Copy)]
pub struct GtldParams<'a> {
    pub root: &'a RdapResponse,
    pub parent_type: TypeId,
    pub check_types: &'a [CheckClass],
    pub req_data: &'a RequestData<'a>,
}

impl<'a> GtldParams<'a> {
    pub fn from_parent(&self, parent_type: TypeId) -> Self {
        GtldParams {
            parent_type,
            root: self.root,
            check_types: self.check_types,
            req_data: self.req_data,
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
            RdapResponse::Entity(entity) => entity.to_gtld(params),
            RdapResponse::Domain(domain) => domain.to_gtld(params),
            RdapResponse::Nameserver(nameserver) => nameserver.to_gtld(params),
            RdapResponse::Autnum(autnum) => autnum.to_gtld(params),
            RdapResponse::Network(network) => network.to_gtld(params),
            RdapResponse::DomainSearchResults(results) => results.to_gtld(params),
            RdapResponse::EntitySearchResults(results) => results.to_gtld(params),
            RdapResponse::NameserverSearchResults(results) => results.to_gtld(params),
            RdapResponse::ErrorResponse(error) => error.to_gtld(params),
            RdapResponse::Help(help) => help.to_gtld(params),
        };
        gtld.push_str(&variant_gtld);
        gtld
    }
}

pub(crate) fn checks_ul(checks: &Checks, params: GtldParams) -> String {
    let mut gtld = String::new();
    checks
        .items
        .iter()
        .filter(|item| params.check_types.contains(&item.check_class))
        .for_each(|item| {
            gtld.push_str(&format!(
                "* {}: {}\n",
                &item.check_class.to_string(),
                item.check
                    .get_message()
                    .expect("Check has no message. Coding error.")
            ))
        });
    gtld
}

pub(crate) trait FromGtld<'a> {
    fn from_gtld(gtld_params: GtldParams<'a>, parent_type: TypeId) -> Self;
    fn from_gtld_no_parent(gtld_params: GtldParams<'a>) -> Self;
}

impl<'a> FromGtld<'a> for CheckParams<'a> {
    fn from_gtld(gtld_params: GtldParams<'a>, parent_type: TypeId) -> Self {
        CheckParams {
            do_subchecks: false,
            root: gtld_params.root,
            parent_type,
        }
    }

    fn from_gtld_no_parent(gtld_params: GtldParams<'a>) -> Self {
        CheckParams {
            do_subchecks: false,
            root: gtld_params.root,
            parent_type: gtld_params.parent_type,
        }
    }
}
