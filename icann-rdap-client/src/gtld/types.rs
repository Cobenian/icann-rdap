use icann_rdap_common::response::types::Common;
use super::{ToGtld, GtldParams};

impl ToGtld for Common {
    fn to_gtld(&self, _params: GtldParams) -> String {
        let  gtld = String::new();
        gtld
    }
}
