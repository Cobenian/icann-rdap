use std::any::TypeId;

use crate::md::{types::checks_to_table, FromMd};
use icann_rdap_common::{
    check::{CheckParams, GetSubChecks},
    response::redacted::Redacted,
};

use super::{string::StringUtil, table::MultiPartTable, MdParams, ToMd};

// Save this until we decide which we like more.
// multi table version
// impl ToMd for Redacted {
//     fn to_md(&self, params: MdParams) -> String {
//         // debug!("Redacted::to_md");
//         let typeid = TypeId::of::<Redacted>();
//         let mut md = String::new();
//         md.push_str(&self.common.to_md(params.from_parent(typeid)));

//         // header
//         let header_text = "Redacted".to_string();

//         md.push_str(&header_text.to_header(params.heading_level, params.options));

//         // multipart data
//         let mut table = MultiPartTable::new();

//         table = table
//             .header_ref(&"Fields")
//             .and_data_ref(
//                 &"name",
//                 &self.name.description.as_ref().map(|s| s.clone()).or(self
//                     .name
//                     .type_field
//                     .as_ref()
//                     .map(|s| s.clone())),
//             )
//             .and_data_ref(&"prePath", &self.pre_path)
//             .and_data_ref(&"postPath", &self.post_path)
//             .and_data_ref(&"replacementPath", &self.replacement_path)
//             .and_data_ref(&"pathLang", &self.path_lang)
//             .and_data_ref(&"method", &self.method.as_ref().map(|m| m.to_string()))
//             .and_data_ref(&"reason", &self.reason.as_ref().map(|m| m.to_string()));
//         // checks
//         let check_params = CheckParams::from_md(params, typeid);
//         let mut checks = self.common.get_sub_checks(check_params);
//         checks.push(self.get_checks(check_params));
//         table = checks_to_table(checks, table, params);
//         // render table
//         md.push_str(&table.to_md(params));
//         md.push('\n');
//         md
//     }
// }

impl ToMd for &[Redacted] {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Redacted>();
        let mut md = String::new();

        // header
        let header_text = "Redacted".to_string();
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();
        table = table.header_ref(&"Fields");

        for (index, redacted) in self.iter().enumerate() {
            // just hardcode the ** for now to make redaction blue
            table = table.and_data_ref(&"**Redaction**", &Some((index + 1).to_string()));

            table = table
                .and_data_ref(
                    &"name",
                    &redacted
                        .name
                        .description
                        .as_ref()
                        .map(|s| s.clone())
                        .or(redacted.name.type_field.as_ref().map(|s| s.clone())),
                )
                .and_data_ref(&"prePath", &redacted.pre_path)
                .and_data_ref(&"postPath", &redacted.post_path)
                .and_data_ref(&"replacementPath", &redacted.replacement_path)
                .and_data_ref(&"pathLang", &redacted.path_lang)
                .and_data_ref(&"method", &redacted.method.as_ref().map(|m| m.to_string()))
                .and_data_ref(&"reason", &redacted.reason.as_ref().map(|m| m.to_string()));

            // checks
            let check_params = CheckParams::from_md(params, typeid);
            let mut checks = redacted.common.get_sub_checks(check_params);
            checks.push(redacted.get_checks(check_params));
            table = checks_to_table(checks, table, params);
        }

        // render table
        md.push_str(&table.to_md(params));
        md.push('\n');
        md
    }
}
