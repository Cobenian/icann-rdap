
use std::any::TypeId;

// use icann_rdap_common::response::types::{
//     Common, Event, Link, Links, Notices, ObjectCommon, PublicId, Remarks,
// };

use icann_rdap_common::response::types::{
    Common, Link, Links, Notices, Remarks,
};

use icann_rdap_common::response::types::{NoticeOrRemark, RdapConformance};
use strum::EnumMessage;

use icann_rdap_common::check::{
    CheckParams, GetChecks,
};

// use icann_rdap_common::check::{
//     CheckClass, CheckItem, CheckParams, Checks, GetChecks, CHECK_CLASS_LEN,
// };

// use super::string::{StringListUtil, StringUtil};
use super::{checks_ul, GtldParams};
use super::{FromGtld, ToGtld};

impl ToGtld for RdapConformance {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld= String::new();
        gtld.push_str(
            &format!(
                "{} Conformance Claims",
                params.req_data.source_host.to_string()
            )
            .to_string(),
        );
        self.iter().for_each(|s| {
          gtld.push_str(&format!(
                "* {}\n",
                s.0.replace('_', " ")
                    .to_string()
            ))
        });
        self.get_checks(CheckParams::from_gtld_no_parent(params))
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
              gtld.push_str(&format!(
                    "* {}: {}\n",
                    item.check_class.to_string().to_string(),
                    item.check
                        .get_message()
                        .expect("Check has no message. Coding error.")
                ))
            });
            gtld.push('\n');
            gtld
    }
}

impl ToGtld for Links {
    fn to_gtld(&self, gtldparams: GtldParams) -> String {
        let mut gtld= String::new();
        self.iter()
            .for_each(|link| gtld.push_str(&link.to_gtld(gtldparams)));
        gtld
    }
}

impl ToGtld for Link {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld= String::new();
        if let Some(title) = &self.title {
          gtld.push_str(&format!("* {title}: "));
        } else {
          gtld.push_str("* Link: ")
        };
        if let Some(rel) = &self.rel {
          gtld.push_str(&format!("[{rel}] "));
        };
        gtld.push_str(&self.href.to_owned().to_string());
        gtld.push(' ');
        if let Some(media_type) = &self.media_type {
          gtld.push_str(&format!("of type '{media_type}' "));
        };
        if let Some(media) = &self.media {
          gtld.push_str(&format!("to be used with {media} ",));
        };
        if let Some(value) = &self.value {
          gtld.push_str(&format!("for {value} ",));
        };
        if let Some(hreflang) = &self.hreflang {
          gtld.push_str(&format!("in languages {}", hreflang.join(", ")));
        };
        gtld.push('\n');
        let checks = self.get_checks(CheckParams::from_gtld(params, TypeId::of::<Link>()));
        gtld.push_str(&checks_ul(&checks, params));
        gtld.push('\n');
        gtld
    }
}

impl ToGtld for Notices {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld= String::new();
        self.iter()
            .for_each(|notice| gtld.push_str(&notice.0.to_gtld(params)));
          gtld
    }
}

impl ToGtld for Remarks {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld= String::new();
        self.iter()
            .for_each(|remark| gtld.push_str(&remark.0.to_gtld(params)));
          gtld
    }
}

impl ToGtld for Option<Remarks> {
    fn to_gtld(&self, params: GtldParams) -> String {
        if let Some(remarks) = &self {
            remarks.to_gtld(params)
        } else {
            String::new()
        }
    }
}

impl ToGtld for NoticeOrRemark {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld= String::new();
        if let Some(title) = &self.title {
          gtld.push_str(&format!("{}\n", title.to_string()));
        };
        self.description
            .iter()
            .for_each(|s| gtld.push_str(&format!("> {}\n\n", s.trim())));
        self.get_checks(CheckParams::from_gtld(params, TypeId::of::<NoticeOrRemark>()))
            .items
            .iter()
            .filter(|item| params.check_types.contains(&item.check_class))
            .for_each(|item| {
              gtld.push_str(&format!(
                    "* {}: {}\n",
                    &item.check_class.to_string().to_string(),
                    item.check
                        .get_message()
                        .expect("Check has no message. Coding error.")
                ))
            });
        if let Some(links) = &self.links {
            links
                .iter()
                .for_each(|link| gtld.push_str(&link.to_gtld(params)));
        }
        gtld.push('\n');
        gtld
    }
}

impl ToGtld for Common {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld= String::new();
        let not_empty = self.rdap_conformance.is_some() || self.notices.is_some();
        if not_empty {
          gtld.push('\n');
          gtld.push_str("\n");
            let header_text = format!(
                "Response from {} at {}",
                params.req_data.source_type,
                params.req_data.source_host.to_string()
            );
            gtld.push_str(&header_text.to_string());
        };
        if let Some(rdap_conformance) = &self.rdap_conformance {
          gtld.push_str(&rdap_conformance.to_gtld(params));
        };
        if let Some(notices) = &self.notices {
          gtld.push_str(&"Server Notices".to_string());
          gtld.push_str(&notices.to_gtld(params));
        }
        if not_empty {
          gtld.push_str("\n");
        };
        gtld
    }
}

// impl ToMpTable for ObjectCommon {
//     fn add_to_mptable(&self, mut table: MultiPartTable, params: GtldParams) -> MultiPartTable {
//         if self.status.is_some() || self.port_43.is_some() {
//             table = table.header_ref(&"Information");

//             // Status
//             if let Some(status) = &self.status {
//                 let values = status.iter().map(|v| v.0.as_str()).collect::<Vec<&str>>();
//                 table = table.data_ul(&"Status", values.make_list_all_title_case());
//             }

//             // Port 43
//             table = table.and_data_ref(&"Whois", &self.port_43);
//         }

//         // Events
//         if let Some(events) = &self.events {
//             table = events_to_table(events, table, "Events", params);
//         }

//         // Links
//         if let Some(links) = &self.links {
//             table = links_to_table(links, table, "Links");
//         }

//         // TODO Checks
//         table
//     }
// }

// pub(crate) fn public_ids_to_table(
//     publid_ids: &[PublicId],
//     mut table: MultiPartTable,
// ) -> MultiPartTable {
//     for pid in publid_ids {
//         table = table.data_ref(&pid.id_type, &pid.identifier);
//     }
//     table
// }

// pub(crate) fn events_to_table(
//     events: &[Event],
//     mut table: MultiPartTable,
//     header_name: &str,
//     params: GtldParams,
// ) -> MultiPartTable {
//     table = table.header_ref(&header_name.to_string());
//     for event in events {
//         let event_date = &event
//             .event_date
//             .to_owned()
//             .unwrap_or("????".to_string())
//             .format_date_time(params)
//             .unwrap_or_default();
//         let mut ul: Vec<&String> = vec![event_date];
//         if let Some(event_actor) = &event.event_actor {
//             ul.push(event_actor);
//         }
//         table = table.data_ul_ref(&event.event_action.to_owned().to_words_title_case(), ul);
//     }
//     table
// }

// pub(crate) fn links_to_table(
//     links: &[Link],
//     mut table: MultiPartTable,
//     header_name: &str,
// ) -> MultiPartTable {
//     table = table.header_ref(&header_name.to_string());
//     for link in links {
//         if let Some(title) = &link.title {
//             table = table.data_ref(&"Title", &title.trim());
//         };
//         let rel = link
//             .rel
//             .as_ref()
//             .unwrap_or(&"Link".to_string())
//             .to_title_case();
//         let mut ul: Vec<&String> = vec![&link.href];
//         if let Some(media_type) = &link.media_type {
//             ul.push(media_type)
//         };
//         if let Some(media) = &link.media {
//             ul.push(media)
//         };
//         if let Some(value) = &link.value {
//             ul.push(value)
//         };
//         let hreflang_s;
//         if let Some(hreflang) = &link.hreflang {
//             hreflang_s = hreflang.join(", ");
//             ul.push(&hreflang_s)
//         };
//         table = table.data_ul_ref(&rel, ul);
//     }
//     table
// }

// pub(crate) fn checks_to_table(
//     checks: Vec<Checks>,
//     mut table: MultiPartTable,
//     params: GtldParams,
// ) -> MultiPartTable {
//     let mut filtered_checks: Vec<CheckItem> = checks
//         .into_iter()
//         .flat_map(|checks| checks.items)
//         .filter(|item| params.check_types.contains(&item.check_class))
//         .collect();

//     if !filtered_checks.is_empty() {
//         filtered_checks.sort();
//         filtered_checks.dedup();
//         table = table.header_ref(&"Checks");

//         // Informational
//         let class = CheckClass::Informational;
//         let ul: Vec<String> = filtered_checks
//             .iter()
//             .filter(|item| item.check_class == class)
//             .map(|item| item.check.get_message().unwrap_or_default().to_owned())
//             .collect();
//         table = table.data_ul_ref(
//             &&class
//                 .to_string()
//                 .to_right_em(*CHECK_CLASS_LEN, params.options),
//             ul.iter().collect(),
//         );

//         // Specification Warning
//         let class = CheckClass::SpecificationWarning;
//         let ul: Vec<String> = filtered_checks
//             .iter()
//             .filter(|item| item.check_class == class)
//             .map(|item| item.check.get_message().unwrap_or_default().to_owned())
//             .collect();
//         table = table.data_ul_ref(
//             &class
//                 .to_string()
//                 .to_right_em(*CHECK_CLASS_LEN, params.options),
//             ul.iter().collect(),
//         );

//         // Specification Error
//         let class = CheckClass::SpecificationError;
//         let ul: Vec<String> = filtered_checks
//             .iter()
//             .filter(|item| item.check_class == class)
//             .map(|item| item.check.get_message().unwrap_or_default().to_owned())
//             .collect();
//         table = table.data_ul_ref(
//             &&class
//                 .to_string()
//                 .to_right_em(*CHECK_CLASS_LEN, params.options),
//             ul.iter().collect(),
//         );
//     }

//     table
// }
