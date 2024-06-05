use super::{
    table::{MultiPartTable, ToGtldTable},
    GtldParams, ToGtld,
};
// use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};
use icann_rdap_common::response::domain::Domain;
use std::any::TypeId;

impl ToGtld for Domain {
    fn to_gtld(&self, params: GtldParams) -> String {
        let _typeid = TypeId::of::<Domain>();
        let mut gtld = String::new();
        // gtld.push_str(&self.common.to_gtld(params.from_parent(typeid)));
        gtld.push_str("\n\n");

        // header
        let domain_name = if let Some(unicode_name) = &self.unicode_name {
            format!("Domain Name: {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Domain Name: {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Domain Name: {handle}")
        } else {
            "Domain Name: ".to_string()
        };
        gtld.push_str(&domain_name);
        gtld.push('\n');

        // Domain ID
        let domain_id = if let Some(handle) = &self.object_common.handle {
            format!("Registry Domain ID: {handle}")
        } else {
            "Registry Domain ID:".to_string()
        };
        gtld.push_str(&domain_id);
        gtld.push('\n');

        // Date Time for Registry
        if let Some(events) = &self.object_common.events {
            for event in events {
                //"last changed"
                if event.event_action == "last changed" {
                    if let Some(event_date) = &event.event_date {
                        gtld.push_str(&format!("Updated Date: {}\n", event_date));
                    }
                }
                //registration
                if event.event_action == "registration" {
                    if let Some(event_date) = &event.event_date {
                        gtld.push_str(&format!("Creation Date: {}\n", event_date));
                    }
                }
                //expiration
                if event.event_action == "expiration" {
                    if let Some(event_date) = &event.event_date {
                        gtld.push_str(&format!("Registry Expiry Date: {}\n", event_date));
                    }
                }
            }
        }

        let mut table = MultiPartTable::new();
        // // common object stuff
        table = self.object_common.add_to_gtldtable(table, params);
        // dbg!(&self.object_common);
        // gtltd.push_str(&self.object_common.to_gtld(params.from_parent(typeid)));

        gtld.push_str(&table.to_gtld(params));

        // variants require a custom table
        // if let Some(variants) = &self.variants {
        //     gtld.push_str(&do_variants(variants))
        // }

        // // secure dns
        // if let Some(secure_dns) = &self.secure_dns {
        //     gtld.push_str(&do_secure_dns(secure_dns))
        // }

        // remarks
        // gtld.push_str(&self.object_common.remarks.to_gtld(params.from_parent(typeid)));

        // only other object classes from here
        // gtld.push_str("\n");

        // // entities
        // gtld.push_str(
        //     &self
        //         .object_common
        //         .entities
        //         .to_gtld(params.from_parent(typeid)),
        // );
        // for entity in &self.object_common.entities {
        //     gtld.push_str(&entity.to_gtld(params));
        //     gtld.push('\n');
        // }
        // dump out self.object_common.entities
        // dbg!(&self.object_common.entities);
        let mut registrar_name = String::new();
        let mut registrar_iana_id = String::new();
        let mut abuse_contact_email = String::new();
        let mut abuse_contact_phone = String::new();

        if let Some(entities) = &self.object_common.entities {
            for entity in entities {
                if let Some(roles) = &entity.roles {
                    for role in roles {
                        if role.as_str() == "registrar" {
                            if let Some(vcard_array) = &entity.vcard_array {
                                if let Some(properties) = vcard_array[1].as_array() {
                                    for property in properties {
                                        if let Some(property) = property.as_array() {
                                            if property[0].as_str().unwrap_or("") == "fn" {
                                                registrar_name =
                                                    property[3].as_str().unwrap_or("").to_string();
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(public_ids) = &entity.public_ids {
                                for public_id in public_ids {
                                    if public_id.id_type.as_str() == "IANA Registrar ID" {
                                        registrar_iana_id = public_id.identifier.clone();
                                    }
                                }
                            }
                        } else if role.as_str() == "abuse" {
                            if let Some(vcard_array) = &entity.vcard_array {
                                if let Some(properties) = vcard_array[1].as_array() {
                                    for property in properties {
                                        if let Some(property) = property.as_array() {
                                            if property[0].as_str().unwrap_or("") == "tel" {
                                                abuse_contact_phone =
                                                    property[3].as_str().unwrap_or("").to_string();
                                            } else if property[0].as_str().unwrap_or("") == "email"
                                            {
                                                abuse_contact_email =
                                                    property[3].as_str().unwrap_or("").to_string();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let formatted_data = format!(
            "Registrar: {}\nRegistrar IANA ID: {}\nRegistrar Abuse Contact Email: {}\nRegistrar Abuse Contact Phone: {}\n",
            registrar_name, registrar_iana_id, abuse_contact_email, abuse_contact_phone
        );

        gtld.push_str(&formatted_data);

        // nameservers
        if let Some(nameservers) = &self.nameservers {
            nameservers
                .iter()
                .for_each(|ns| gtld.push_str(&ns.to_gtld(params.next_level())));
        }

        // // network
        if let Some(network) = &self.network {
            gtld.push_str(&network.to_gtld(params.next_level()));
        }

        // secure dns
        if let Some(secure_dns) = &self.secure_dns {
            if secure_dns.delegation_signed.unwrap_or(false) {
                gtld.push_str("DNSSEC: signedDelegation\n");
                if let Some(ds_data) = &secure_dns.ds_data {
                    for ds in ds_data {
                        if let (Some(key_tag), Some(algorithm), Some(digest_type), Some(digest)) =
                            (ds.key_tag, ds.algorithm, ds.digest_type, ds.digest.as_ref())
                        {
                            gtld.push_str(&format!(
                                "DNSSEC DS Data: {} {} {} {}\n",
                                key_tag, algorithm, digest_type, digest
                            ));
                        }
                    }
                }
            }
        }

        // // redacted
        // if let Some(redacted) = &self.object_common.redacted {
        //     gtld.push_str(&redacted.as_slice().to_gtld(params.from_parent(typeid)));
        // }
        gtld.push_str(
            "URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n",
        );
        if let Some(events) = &self.object_common.events {
            for event in events {
                if event.event_action == "last update of RDAP database" {
                    if let Some(event_date) = &event.event_date {
                        gtld.push_str(&format!(
                            ">>> Last update of RDAP database: {} <<<\n",
                            event_date
                        ));
                    }
                    break;
                }
            }
        }

        // strip out any double newlines and keep just one new line
        gtld = gtld.replace("\n\n", "\n");
        gtld
    }
}

// fn do_variants(variants: &[Variant]) -> String {
//     let mut gtld = String::new();
//     gtld.push_str()
//     md.push_str(&format!(
//         "|:-:|\n|{}|\n",
//         "Domain Variants".to_right_bold(8, params.options)
//     ));
//     md.push_str("|:-:|:-:|:-:|\n|Relations|IDN Table|Variant Names|\n");
//     variants.iter().for_each(|v| {
//         md.push_str(&format!(
//             "|{}|{}|{}|",
//             v.relation
//                 .as_deref()
//                 .unwrap_or_default()
//                 .make_title_case_list(),
//             v.idn_table.as_deref().unwrap_or_default(),
//             v.variant_names
//                 .as_deref()
//                 .unwrap_or_default()
//                 .iter()
//                 .map(|dv| format!(
//                     "ldh: '{}' utf:'{}'",
//                     dv.ldh_name.as_deref().unwrap_or_default(),
//                     dv.unicode_name.as_deref().unwrap_or_default()
//                 ))
//                 .collect::<Vec<String>>()
//                 .join(", "),
//         ))
//     });
//     md.push_str("|\n");
//     md
// }

// fn do_secure_dns(secure_dns: &SecureDns, params: MdParams) -> String {
//     let mut md = String::new();
//     // multipart data
//     let mut table = MultiPartTable::new();

//     table = table
//         .header_ref(&"DNSSEC Information")
//         .and_data_ref(
//             &"Zone Signed",
//             &secure_dns.zone_signed.map(|b| b.to_string()),
//         )
//         .and_data_ref(
//             &"Delegation Signed",
//             &secure_dns.delegation_signed.map(|b| b.to_string()),
//         )
//         .and_data_ref(
//             &"Max Sig Life",
//             &secure_dns.max_sig_life.map(|u| u.to_string()),
//         );

//     if let Some(ds_data) = &secure_dns.ds_data {
//         for (i, ds) in ds_data.iter().enumerate() {
//             let header = format!("DS Data ({i})");
//             table = table
//                 .header_ref(&header)
//                 .and_data_ref(&"Key Tag", &ds.key_tag.map(|k| k.to_string()))
//                 .and_data_ref(&"Algorithm", &dns_algorithm(&ds.algorithm))
//                 .and_data_ref(&"Digest", &ds.digest)
//                 .and_data_ref(&"Digest Type", &dns_digest_type(&ds.digest_type));
//             if let Some(events) = &ds.events {
//                 let ds_header = format!("DS ({i}) Events");
//                 table = events_to_table(events, table, &ds_header, params);
//             }
//             if let Some(links) = &ds.links {
//                 let ds_header = format!("DS ({i}) Links");
//                 table = links_to_table(links, table, &ds_header);
//             }
//         }
//     }

//     if let Some(key_data) = &secure_dns.key_data {
//         for (i, key) in key_data.iter().enumerate() {
//             let header = format!("Key Data ({i})");
//             table = table
//                 .header_ref(&header)
//                 .and_data_ref(&"Flags", &key.flags.map(|k| k.to_string()))
//                 .and_data_ref(&"Protocol", &key.protocol.map(|a| a.to_string()))
//                 .and_data_ref(&"Public Key", &key.public_key)
//                 .and_data_ref(&"Algorithm", &dns_algorithm(&key.algorithm));
//             if let Some(events) = &key.events {
//                 let key_header = format!("Key ({i}) Events");
//                 table = events_to_table(events, table, &key_header, params);
//             }
//             if let Some(links) = &key.links {
//                 let key_header = format!("Key ({i}) Links");
//                 table = links_to_table(links, table, &key_header);
//             }
//         }
//     }

//     // render table
//     md.push_str(&table.to_md(params));
//     md
// }

// fn dns_algorithm(alg: &Option<u8>) -> Option<String> {
//     alg.map(|alg| {
//         DnsAlgorithmType::mnemonic(alg).map_or(format!("{alg} - Unassigned or Reserved"), |a| {
//             format!("{alg} - {a}")
//         })
//     })
// }

// fn dns_digest_type(dt: &Option<u8>) -> Option<String> {
//     dt.map(|dt| {
//         DnsDigestType::mnemonic(dt).map_or(format!("{dt} - Unassigned or Reserved"), |a| {
//             format!("{dt} - {a}")
//         })
//     })
// }
