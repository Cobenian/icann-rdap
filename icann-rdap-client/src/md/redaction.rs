// use std::any::TypeId;

use icann_rdap_common::response::redaction::{Redaction, RedactionResults};

use super::{
    // string::StringUtil,
    // table::{
    // MultiPartTable, ToMpTable
    // },
    // types::checks_to_table,
    // FromMd,
    MdParams,
    ToMd,
    // HR,
};

// XXX todo implement this
impl ToMd for Redaction {
    fn to_md(&self, _params: MdParams) -> String {
        String::new()
    }
}

// XXX todo implement this
impl ToMd for RedactionResults {
    fn to_md(&self, _params: MdParams) -> String {
        String::new()
    }
}
