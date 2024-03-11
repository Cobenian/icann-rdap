use std::{net::IpAddr, str::FromStr};

use cidr_utils::cidr::IpInet;
use icann_rdap_common::check::string::StringCheck;
use lazy_static::lazy_static;
use pct_str::{PctString, URIReserved};
use regex::Regex;
use strum_macros::Display;

use crate::RdapClientError;

/// Defines the various types of RDAP lookups and searches.
#[derive(Display, Debug)]
pub enum QueryType {
    #[strum(serialize = "IpV4 Address Lookup")]
    IpV4Addr(String),

    #[strum(serialize = "IpV6 Address Lookup")]
    IpV6Addr(String),

    #[strum(serialize = "IpV4 CIDR Lookup")]
    IpV4Cidr(String),

    #[strum(serialize = "IpV6 CIDR Lookup")]
    IpV6Cidr(String),

    #[strum(serialize = "Autonomous System Number Lookup")]
    AsNumber(String),

    #[strum(serialize = "Domain Lookup")]
    Domain(String),

    #[strum(serialize = "A-Label Domain Lookup")]
    ALable(String),

    #[strum(serialize = "Entity Lookup")]
    Entity(String),

    #[strum(serialize = "Nameserver Lookup")]
    Nameserver(String),

    #[strum(serialize = "Entity Name Search")]
    EntityNameSearch(String),

    #[strum(serialize = "Entity Handle Search")]
    EntityHandleSearch(String),

    #[strum(serialize = "Domain Name Search")]
    DomainNameSearch(String),

    #[strum(serialize = "Domain Nameserver Name Search")]
    DomainNsNameSearch(String),

    #[strum(serialize = "Domain Nameserver IP Address Search")]
    DomainNsIpSearch(String),

    #[strum(serialize = "Nameserver Name Search")]
    NameserverNameSearch(String),

    #[strum(serialize = "Nameserver IP Address Search")]
    NameserverIpSearch(String),

    #[strum(serialize = "Server Help Lookup")]
    Help,

    #[strum(serialize = "Explicit URL")]
    Url(String),
}

impl QueryType {
    pub fn query_url(&self, base_url: &str) -> Result<String, RdapClientError> {
        let base_url = base_url.trim_end_matches('/');
        match self {
            QueryType::IpV4Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::IpV6Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::IpV4Cidr(value) => ip_cidr_query(value, base_url),
            QueryType::IpV6Cidr(value) => ip_cidr_query(value, base_url),
            QueryType::AsNumber(value) => {
                let autnum =
                    value.trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') });
                Ok(format!(
                    "{base_url}/autnum/{}",
                    PctString::encode(autnum.chars(), URIReserved)
                ))
            }
            QueryType::Domain(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::ALable(value) => a_label_query(value, base_url),
            QueryType::Entity(value) => Ok(format!(
                "{base_url}/entity/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::Nameserver(value) => Ok(format!(
                "{base_url}/nameserver/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::EntityNameSearch(value) => search_query(value, "entities?fn", base_url),
            QueryType::EntityHandleSearch(value) => {
                search_query(value, "entities?handle", base_url)
            }
            QueryType::DomainNameSearch(value) => search_query(value, "domains?name", base_url),
            QueryType::DomainNsNameSearch(value) => {
                search_query(value, "domains?nsLdhName", base_url)
            }
            QueryType::DomainNsIpSearch(value) => search_query(value, "domains?nsIp", base_url),
            QueryType::NameserverNameSearch(value) => {
                search_query(value, "nameserver?name=", base_url)
            }
            QueryType::NameserverIpSearch(value) => search_query(value, "nameservers?ip", base_url),
            QueryType::Help => Ok(format!("{base_url}/help")),
            QueryType::Url(url) => Ok(url.to_owned()),
        }
    }
}

fn a_label_query(value: &str, base_url: &str) -> Result<String, RdapClientError> {
    let domain = idna::domain_to_ascii(value).map_err(|_| RdapClientError::InvalidQueryValue)?;
    Ok(format!(
        "{base_url}/domain/{}",
        PctString::encode(domain.chars(), URIReserved),
    ))
}

fn ip_cidr_query(value: &str, base_url: &str) -> Result<String, RdapClientError> {
    let values = value
        .split_once('/')
        .ok_or(RdapClientError::InvalidQueryValue)?;
    Ok(format!(
        "{base_url}/ip/{}/{}",
        PctString::encode(values.0.chars(), URIReserved),
        PctString::encode(values.1.chars(), URIReserved)
    ))
}

fn search_query(value: &str, path_query: &str, base_url: &str) -> Result<String, RdapClientError> {
    Ok(format!(
        "{base_url}/{path_query}={}",
        PctString::encode(value.chars(), URIReserved)
    ))
}

impl FromStr for QueryType {
    type Err = RdapClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // if it looks like a HTTP(S) url
        if s.starts_with("http://") || s.starts_with("https://") {
            return Ok(QueryType::Url(s.to_owned()));
        }

        // if looks like an autnum
        let autnum = s.trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') });
        if let Ok(_autnum) = u32::from_str(autnum) {
            return Ok(QueryType::AsNumber(s.to_owned()));
        }

        // If it's an IP address
        if let Ok(ip_addr) = IpAddr::from_str(s) {
            if ip_addr.is_ipv4() {
                return Ok(QueryType::IpV4Addr(s.to_owned()));
            } else {
                return Ok(QueryType::IpV6Addr(s.to_owned()));
            }
        }

        // if it is a cidr
        if let Ok(ip_cidr) = IpInet::from_str(s) {
            return match ip_cidr {
                IpInet::V4(_) => Ok(QueryType::IpV4Cidr(s.to_owned())),
                IpInet::V6(_) => Ok(QueryType::IpV6Cidr(s.to_owned())),
            };
        }

        // if it looks like a domain name
        if is_domain_name(s) {
            if is_nameserver(s) {
                return Ok(QueryType::Nameserver(s.to_owned()));
            } else {
                return Ok(QueryType::Domain(s.to_owned()));
            }
        }

        // if it is just one word
        if !s.contains(|c: char| c.is_whitespace() || c == '.' || c == ',' || c == '"') {
            return Ok(QueryType::Entity(s.to_owned()));
        }

        // The query type cannot be deteremined.
        Err(RdapClientError::AmbiquousQueryType)
    }
}

fn is_ldh_domain(text: &str) -> bool {
    lazy_static! {
        static ref LDH_DOMAIN_RE: Regex =
            Regex::new(r"^(?i)(\.?[a-zA-Z0-9-]+)*\.[a-zA-Z0-9-]+\.?$").unwrap();
    }
    LDH_DOMAIN_RE.is_match(text)
}

fn is_domain_name(text: &str) -> bool {
    text.contains('.') && text.is_unicode_domain_name()
}

fn is_nameserver(text: &str) -> bool {
    lazy_static! {
        static ref NS_RE: Regex =
            Regex::new(r"^(?i)(ns)[a-zA-Z0-9-]*\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.?$").unwrap();
    }
    NS_RE.is_match(text)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;

    use super::QueryType;

    #[test]
    fn GIVEN_ipv4_WHEN_query_type_from_str_THEN_query_is_ipv4() {
        // GIVEN
        let s = "129.129.1.1";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV4Addr(_)))
    }

    #[test]
    fn GIVEN_ipv6_WHEN_query_type_from_str_THEN_query_is_ipv6() {
        // GIVEN
        let s = "2001::1";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV6Addr(_)))
    }

    #[test]
    fn GIVEN_ipv4_cidr_WHEN_query_type_from_str_THEN_query_is_ipv4_cidr() {
        // GIVEN
        let s = "129.129.1.1/8";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV4Cidr(_)))
    }

    #[test]
    fn GIVEN_ipv6_cidr_WHEN_query_type_from_str_THEN_query_is_ipv6_cidr() {
        // GIVEN
        let s = "2001::1/20";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV6Cidr(_)))
    }

    #[test]
    fn GIVEN_number_WHEN_query_type_from_str_THEN_query_is_autnum() {
        // GIVEN
        let s = "16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumber(_)))
    }

    #[test]
    fn GIVEN_as_followed_by_number_WHEN_query_type_from_str_THEN_query_is_autnum() {
        // GIVEN
        let s = "as16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumber(_)))
    }

    #[rstest]
    #[case("example.com")]
    #[case("foo.example.com")]
    #[case("snark.fail")]
    #[case("ns.fail")]
    #[case(".com")]
    fn GIVEN_domain_name_WHEN_query_type_from_str_THEN_query_is_domain(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Domain(_)))
    }

    #[rstest]
    #[case("ns.example.com")]
    #[case("ns1.example.com")]
    #[case("NS1.example.com")]
    fn GIVEN_name_server_WHEN_query_type_from_str_THEN_query_is_nameserver(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Nameserver(_)))
    }

    #[test]
    fn GIVEN_single_word_WHEN_query_type_from_str_THEN_query_is_entity() {
        // GIVEN
        let s = "foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        let q = q.unwrap();
        assert!(matches!(q, QueryType::Entity(_)))
    }

    #[rstest]
    #[case("https://example.com")]
    #[case("http://foo.example.com")]
    fn GIVEN_url_WHEN_query_type_from_str_THEN_query_is_url(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Url(_)))
    }

    #[rstest]
    #[case("ns.foo_bar.com")]
    #[case("ns.foo bar.com")]
    fn GIVEN_bad_input_WHEN_query_type_from_str_THEN_error(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(q.is_err());
    }
}
