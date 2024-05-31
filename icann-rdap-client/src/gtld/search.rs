use std::any::TypeId;

use icann_rdap_common::response::search::{
    DomainSearchResults, EntitySearchResults, NameserverSearchResults,
};

use super::{GtldParams, ToGtld};

impl ToGtld for DomainSearchResults {
    fn to_gtld(&self, params: GtldParams) -> String {
        let typeid = TypeId::of::<DomainSearchResults>();
        let mut gtld = String::new();
        gtld.push_str(&self.common.to_gtld(params.from_parent(typeid)));
        self.results.iter().for_each(|result| {
            gtld.push_str(&result.to_gtld(GtldParams {
                parent_type: typeid,
                ..params
            }))
        });
        gtld.push('\n');
        gtld
    }
}

impl ToGtld for NameserverSearchResults {
    fn to_gtld(&self, params: GtldParams) -> String {
        let typeid = TypeId::of::<NameserverSearchResults>();
        let mut gtld: String = String::new();
        gtld.push_str(&self.common.to_gtld(params.from_parent(typeid)));
        self.results.iter().for_each(|result| {
            gtld.push_str(&result.to_gtld(GtldParams {
                parent_type: typeid,
                ..params
            }))
        });
        gtld.push('\n');
        gtld
    }
}

impl ToGtld for EntitySearchResults {
    fn to_gtld(&self, params: GtldParams) -> String {
        let typeid = TypeId::of::<EntitySearchResults>();
        let mut gtld = String::new();
        gtld.push_str(&self.common.to_gtld(params.from_parent(typeid)));
        self.results.iter().for_each(|result| {
            gtld.push_str(&result.to_gtld(GtldParams {
                parent_type: typeid,
                ..params
            }))
        });
        gtld.push('\n');
        gtld
    }
}
