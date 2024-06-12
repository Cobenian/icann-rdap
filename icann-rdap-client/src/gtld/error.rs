use icann_rdap_common::response::error::Error;
use super::{GtldParams, ToGtld};

impl ToGtld for Error {
    fn to_gtld(&self, _params: GtldParams) -> String {
        let gtld = String::new();
        gtld
    }
}
