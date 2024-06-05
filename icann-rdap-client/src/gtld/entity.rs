use super::{GtldParams, ToGtld};
use icann_rdap_common::response::entity::Entity;
use std::any::TypeId;

impl ToGtld for Entity {
    fn to_gtld(&self, params: GtldParams) -> String {
        let typeid = TypeId::of::<Entity>();
        let mut gtld = String::new();
        gtld.push_str(&self.common.to_gtld(params.from_parent(typeid)));

        // header
        let header_text = if let Some(roles) = &self.roles {
            roles.first().unwrap_or(&String::default()).clone()
        } else {
            "Entity".to_string()
        };
        gtld.push_str(&header_text);

        gtld.push('\n');
        gtld
    }
}

impl ToGtld for Option<Vec<Entity>> {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut md = String::new();
        if let Some(entities) = &self {
            entities
                .iter()
                .for_each(|entity| md.push_str(&entity.to_gtld(params.next_level())));
        }
        md
    }
}

impl ToGtld for Vec<Entity> {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut md = String::new();
        self.iter()
            .for_each(|entity| md.push_str(&entity.to_gtld(params.next_level())));
        md
    }
}

// impl ToMpTable for Option<Vec<PostalAddress>> {
//     fn add_to_mptable(&self, mut table: MultiPartTable, params: MdParams) -> MultiPartTable {
//         if let Some(addrs) = self {
//             for addr in addrs {
//                 table = addr.add_to_mptable(table, params);
//             }
//         }
//         table
//     }
// }

// impl ToMpTable for PostalAddress {
//     fn add_to_mptable(&self, mut table: MultiPartTable, _params: MdParams) -> MultiPartTable {
//         if self.contexts.is_some() && self.preference.is_some() {
//             table = table.data(
//                 &"Address",
//                 format!(
//                     "{} (pref: {})",
//                     self.contexts.as_ref().unwrap().join(" "),
//                     self.preference.unwrap()
//                 ),
//             );
//         } else if self.contexts.is_some() {
//             table = table.data(&"Address", self.contexts.as_ref().unwrap().join(" "));
//         } else if self.preference.is_some() {
//             table = table.data(
//                 &"Address",
//                 format!("preference: {}", self.preference.unwrap()),
//             );
//         } else {
//             table = table.data(&"Address", "");
//         }
//         if let Some(street_parts) = &self.street_parts {
//             table = table.data_ul_ref(&"Street", street_parts.iter().collect());
//         }
//         if let Some(locality) = &self.locality {
//             table = table.data_ref(&"Locality", locality);
//         }
//         if self.region_name.is_some() && self.region_code.is_some() {
//             table = table.data(
//                 &"Region",
//                 format!(
//                     "{} ({})",
//                     self.region_name.as_ref().unwrap(),
//                     self.region_code.as_ref().unwrap()
//                 ),
//             );
//         } else if let Some(region_name) = &self.region_name {
//             table = table.data_ref(&"Region", region_name);
//         } else if let Some(region_code) = &self.region_code {
//             table = table.data_ref(&"Region", region_code);
//         }
//         if self.country_name.is_some() && self.country_code.is_some() {
//             table = table.data(
//                 &"Country",
//                 format!(
//                     "{} ({})",
//                     self.country_name.as_ref().unwrap(),
//                     self.country_code.as_ref().unwrap()
//                 ),
//             );
//         } else if let Some(country_name) = &self.country_name {
//             table = table.data_ref(&"Country", country_name);
//         } else if let Some(country_code) = &self.country_code {
//             table = table.data_ref(&"Country", country_code);
//         }
//         if let Some(postal_code) = &self.postal_code {
//             table = table.data_ref(&"Postal Code", postal_code);
//         }
//         if let Some(full_address) = &self.full_address {
//             let parts = full_address.split('\n').collect::<Vec<&str>>();
//             for (i, p) in parts.iter().enumerate() {
//                 table = table.data_ref(&i.to_string(), p);
//             }
//         }
//         table
//     }
// }

// impl ToMpTable for Option<NameParts> {
//     fn add_to_mptable(&self, mut table: MultiPartTable, _params: MdParams) -> MultiPartTable {
//         if let Some(parts) = self {
//             if let Some(prefixes) = &parts.prefixes {
//                 table = table.data(&"Honorifics", prefixes.join(", "));
//             }
//             if let Some(given_names) = &parts.given_names {
//                 table = table.data_ul(&"Given Names", given_names.to_vec());
//             }
//             if let Some(middle_names) = &parts.middle_names {
//                 table = table.data_ul(&"Middle Names", middle_names.to_vec());
//             }
//             if let Some(surnames) = &parts.surnames {
//                 table = table.data_ul(&"Surnames", surnames.to_vec());
//             }
//             if let Some(suffixes) = &parts.suffixes {
//                 table = table.data(&"Suffixes", suffixes.join(", "));
//             }
//         }
//         table
//     }
// }
