// use std::any::TypeId;

use std::any::TypeId;

use icann_rdap_common::{
    check::{CheckParams, GetSubChecks},
    response::redacted::{Redacted, RedactedResults},
};

// use super::types::{events_to_table, links_to_table, public_ids_to_table};
// use super::FromMd;

// use super::{
//     // string::StringUtil,
//     table::{
//         MultiPartTable,
//         ToMpTable
//     },
//     types::checks_to_table,
//     FromMd,
//     MdParams,
//     ToMd,
//     HR,
// };

use crate::md::{types::checks_to_table, FromMd};

// use super::types::{events_to_table, links_to_table, public_ids_to_table};
// use super::FromMd;
use super::{
    // string::StringListUtil,
    string::StringUtil,
    table::MultiPartTable,
    // types::checks_to_table,
    MdParams,
    ToMd,
    // HR,
};

// Add the `tracing` crate as a dependency
use tracing::debug;

// XXX todo implement this
impl ToMd for Redacted {
    // fn to_md(&self, _params: MdParams) -> String {
    //     String::new()
    // }
    fn to_md(&self, params: MdParams) -> String {
        debug!("Redacted::to_md");
        let typeid = TypeId::of::<Redacted>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = "Redacted".to_string();

        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();

        // identifiers
        table = table
            .header_ref(&"reason")
            .and_data_ref(&"prePath", &self.pre_path)
            .and_data_ref(&"postPath", &self.post_path)
            .and_data_ref(&"pathLang", &self.path_lang)
            .and_data_ref(&"replacementPath", &self.replacement_path)
            // .and_data_ref(&"method", &Some(self.method))
            ;
        // if let Some(public_ids) = &self.public_ids {
        //     table = public_ids_to_table(public_ids, table);
        // }

        // common object stuff
        // table = self.object_common.add_to_mptable(table, params);

        // checks
        let check_params = CheckParams::from_md(params, typeid);
        let mut checks = self.common.get_sub_checks(check_params);
        checks.push(self.get_checks(check_params));
        table = checks_to_table(checks, table, params);

        // render table
        md.push_str(&table.to_md(params));

        // // variants require a custom table
        // if let Some(variants) = &self.variants {
        //     md.push_str(&do_variants(variants, params))
        // }

        // // secure dns
        // if let Some(secure_dns) = &self.secure_dns {
        //     md.push_str(&do_secure_dns(secure_dns, params))
        // }

        // // remarks
        // md.push_str(&self.object_common.remarks.to_md(params.from_parent(typeid)));

        // // only other object classes from here
        // md.push_str(HR);

        // // entities
        // md.push_str(
        //     &self
        //         .object_common
        //         .entities
        //         .to_md(params.from_parent(typeid)),
        // );

        // // nameservers
        // if let Some(nameservers) = &self.nameservers {
        //     nameservers
        //         .iter()
        //         .for_each(|ns| md.push_str(&ns.to_md(params.next_level())));
        // }

        // // network
        // if let Some(network) = &self.network {
        //     md.push_str(&network.to_md(params.next_level()));
        // }

        md.push('\n');
        md
    }
}

// XXX todo implement this
impl ToMd for RedactedResults {
    fn to_md(&self, _params: MdParams) -> String {
        String::new()
    }
}
