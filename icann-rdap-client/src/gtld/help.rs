use std::any::TypeId;
//
use icann_rdap_common::response::help::Help;
use super::{GtldParams, ToGtld};

impl ToGtld for Help {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld = String::new();
        gtld.push_str(&self.common.to_gtld(params.from_parent(TypeId::of::<Help>())));
        gtld.push_str("\n");
        gtld.push('\n');
        gtld
    }
}
