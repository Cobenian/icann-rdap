use std::any::TypeId;

use crate::md::{types::checks_to_table, FromMd};
use icann_rdap_common::{
    check::{CheckParams, GetSubChecks},
    response::redacted::Redacted,
};

use super::{string::StringUtil, table::MultiPartTable, MdParams, ToMd};

impl ToMd for Redacted {
    fn to_md(&self, params: MdParams) -> String {
        // debug!("Redacted::to_md");
        let typeid = TypeId::of::<Redacted>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = "Redacted".to_string();

        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();

        table = table
            .header_ref(&"Fields")
            .and_data_ref(&"name", &self.name.description)
            .and_data_ref(&"prePath", &self.pre_path)
            .and_data_ref(&"postPath", &self.post_path)
            .and_data_ref(&"replacementPath", &self.replacement_path)
            .and_data_ref(&"pathLang", &self.path_lang)
            .and_data_ref(&"method", &self.method.as_ref().map(|m| m.to_string()))
            .and_data_ref(&"reason", &self.reason.as_ref().map(|m| m.to_string()));
        // checks
        let check_params = CheckParams::from_md(params, typeid);
        let mut checks = self.common.get_sub_checks(check_params);
        checks.push(self.get_checks(check_params));
        table = checks_to_table(checks, table, params);
        // render table
        md.push_str(&table.to_md(params));
        md.push('\n');
        md
    }
}
