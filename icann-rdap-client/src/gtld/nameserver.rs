use super::{GtldParams, ToGtld};
use icann_rdap_common::response::nameserver::Nameserver;

impl ToGtld for Nameserver {
    fn to_gtld(&self, _params: &mut GtldParams) -> String {
        let mut gtld = String::new();
        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Name Server: {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Name Server: {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Name Server: {handle}")
        } else {
            "Name Server: ".to_string()
        };
        gtld.push_str(&header_text);
        gtld.push('\n');
        gtld
    }
}
