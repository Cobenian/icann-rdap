use icann_rdap_common::response::error::Error;
use std::any::TypeId;

// use super::ToGtld;
use super::{GtldParams, ToGtld};

impl ToGtld for Error {
    fn to_gtld(&self, params: GtldParams) -> String {
        let _typeid = TypeId::of::<Error>();
        let mut gtld = String::new();
        gtld.push_str(
            &self
                .common
                .to_gtld(params.from_parent(TypeId::of::<Error>())),
        );
        gtld.push_str("\n");
        gtld.push('\n');
        gtld
    }
}
