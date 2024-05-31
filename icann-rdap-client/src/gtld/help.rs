use std::any::TypeId;
//
use super::{GtldParams, ToGtld};
use icann_rdap_common::response::help::Help;

impl ToGtld for Help {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld = String::new();
        gtld.push_str(
            &self
                .common
                .to_gtld(params.from_parent(TypeId::of::<Help>())),
        );
        gtld.push_str("\n");
        gtld.push('\n');
        gtld
    }
}
