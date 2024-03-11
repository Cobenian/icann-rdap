use std::any::TypeId;

use icann_rdap_common::dns_types::{DnsAlgorithmType, DnsDigestType};
use icann_rdap_common::response::domain::{Domain, SecureDns, Variant};

use icann_rdap_common::check::{CheckParams, GetChecks, GetSubChecks};

use super::types::{events_to_table, links_to_table, public_ids_to_table};
use super::FromMd;
use super::{
    string::StringListUtil,
    string::StringUtil,
    table::{MultiPartTable, ToMpTable},
    types::checks_to_table,
    MdParams, ToMd, HR,
};

use serde_json::Value;
use jsonpath_lib as jsonpath;
// use serde_json::json;


// This is phase one of this ... it's utter BS, of course, but it's a start
fn redact_if_empty(value: &Option<String>) -> Option<String> {
    match value {
        Some(s) if !s.is_empty() => Some(s.clone()),
        _ => Some("REDACTED".to_string()),
    }
}

// this is phase two, we need to find the jsonPath to a key in the structure
fn get_json_path(json: &Value, path: String, target_key: &str) -> Option<String> {
    match json {
        Value::Object(map) => {
            for (key, value) in map {
                let new_path = if path.is_empty() {
                    format!("$.{}", key)
                } else {
                    format!("{}.{}", path, key)
                };
                if key == target_key {
                    return Some(new_path);
                }
                if let Some(found_path) = get_json_path(value, new_path, target_key) {
                    return Some(found_path);
                }
            }
        }
        Value::Array(arr) => {
            for (i, value) in arr.iter().enumerate() {
                let new_path = format!("{}[{}]", path, i);
                if let Some(found_path) = get_json_path(value, new_path, target_key) {
                    return Some(found_path);
                }
            }
        }
        _ => (),
    }
    None
}

// This is phase 2.5 where we did it only for the domain structure

// pub fn get_json_paths(domain: &Domain) -> Result<(Vec<(String, String)>, Vec<(String, String)>), serde_json::Error> {
//     // Serialize the domain to a JSON string
//     let json = serde_json::to_string(domain)?;

//     // Deserialize the JSON string back into a Value
//     let value: Value = serde_json::from_str(&json)?;

//     // Initialize two empty Vecs to store the results
//     let mut root_paths = Vec::new();
//     let mut redacted_paths = Vec::new();

//     // Recursively explore the JSON Value to find all paths
//     explore_paths(&value, "".to_string(), &mut root_paths, &mut redacted_paths);

//     Ok((root_paths, redacted_paths))
// }

// fn explore_paths(value: &Value, current_path: String, root_paths: &mut Vec<(String, String)>, redacted_paths: &mut Vec<(String, String)>) {
//     match value {
//         Value::Object(map) => {
//             for (key, value) in map {
//                 let new_path = if current_path.is_empty() {
//                     format!("$.{}", key)
//                 } else {
//                     format!("{}.{}", current_path, key)
//                 };
//                 if new_path.starts_with("$.redacted") && ["prePath", "postPath"].contains(&key.as_str()) {
//                     let right_hand_side = value.as_str().unwrap_or("").to_string();
//                     redacted_paths.push((key.clone(), right_hand_side));
//                 } else if !new_path.starts_with("$.redacted") {
//                     root_paths.push((key.clone(), new_path.clone()));
//                 }
//                 explore_paths(value, new_path, root_paths, redacted_paths);
//             }
//         }
//         Value::Array(vec) => {
//             for (index, value) in vec.iter().enumerate() {
//                 let new_path = format!("{}[{}]", current_path, index);
//                 explore_paths(value, new_path, root_paths, redacted_paths);
//             }
//         }
//         _ => {}
//     }
// }

pub fn get_json_paths(domain: &Domain) -> Result<(Vec<String>, Vec<String>), serde_json::Error> {
    // Serialize the domain to a JSON string
    let json = serde_json::to_string(domain)?;

    // Deserialize the JSON string back into a Value
    let value: Value = serde_json::from_str(&json)?;

    // Initialize two empty Vecs to store the results
    let mut pre_paths = Vec::new();
    let mut post_paths = Vec::new();

    // Recursively explore the JSON Value to find all paths
    explore_paths(&value, "".to_string(), &mut pre_paths, &mut post_paths);

    Ok((pre_paths, post_paths))
}

fn explore_paths(value: &Value, current_path: String, pre_paths: &mut Vec<String>, post_paths: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let new_path = if current_path.is_empty() {
                    format!("$.{}", key)
                } else {
                    format!("{}.{}", current_path, key)
                };
                if new_path.starts_with("$.redacted") && value.is_string() {
                    if key == "prePath" {
                        pre_paths.push(value.as_str().unwrap().to_string());
                    } else if key == "postPath" {
                        post_paths.push(value.as_str().unwrap().to_string());
                    }
                }
                explore_paths(value, new_path, pre_paths, post_paths);
            }
        }
        Value::Array(vec) => {
            for (index, value) in vec.iter().enumerate() {
                let new_path = format!("{}[{}]", current_path, index);
                explore_paths(value, new_path, pre_paths, post_paths);
            }
        }
        _ => {}
    }
}



fn filter_existing_paths(redacted_paths: Vec<String>, domain: &Domain) -> Result<Vec<String>, serde_json::Error> {
    // Serialize the domain to a JSON string
    let json_string = serde_json::to_string_pretty(domain)?;
    // Pretty-print out the json string
    // println!("[ADEBUG] JSON String: {}", json_string);

    // Parse the JSON string into a Value
    let json_value: Value = serde_json::from_str(&json_string)?;

    // Select all entities
    let entities = jsonpath::select(&json_value, "$.entities[*]").unwrap();

    // Filter entities based on their roles
    let administrative_entities: Vec<&Value> = entities.iter()
        .cloned()
        .filter(|entity| entity["roles"][0] == "administrative")
        .collect();

    let billing_entities: Vec<&Value> = entities.iter()
        .cloned()
        .filter(|entity| entity["roles"][0] == "billing")
        .collect();

    let registrant_entities: Vec<&Value> = entities.iter()
        .cloned()
        .filter(|entity| entity["roles"][0] == "registrant")
        .collect();

    println!("[ADEBUG] Administrative entities: {:?}", administrative_entities);
    println!("[ADEBUG] Billing entities: {:?}", billing_entities);
    println!("[ADEBUG] Registrant entities: {:?}", registrant_entities);

    // Find the paths that exist in the Domain JSON as well
    let existing_paths: Vec<String> = redacted_paths.into_iter()
        .filter(|path| {
            println!("[ADEBUG] Trying Path: {},", path);
            let result = jsonpath::select(&json_value, &format!("{}", path));
            println!("[ADEBUG] Result: {:?}", result);
            result.is_ok()
        })
        .collect();

    Ok(existing_paths)
}

// for the keys and json paths of the domain only
fn explore_kjp(value: &Value, current_path: String, kjp: &mut Vec<(String, String)>, in_redacted: bool) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let new_path = if current_path.is_empty() {
                    format!("$.{}", key)
                } else {
                    format!("{}.{}", current_path, key)
                };
                let new_in_redacted = in_redacted || key == "redacted";
                if !new_in_redacted {
                    kjp.push((key.clone(), new_path.clone()));
                }
                explore_kjp(value, new_path, kjp, new_in_redacted);
            }
        }
        Value::Array(vec) => {
            for (index, value) in vec.iter().enumerate() {
                let new_path = format!("{}[{}]", current_path, index);
                if !in_redacted {
                    kjp.push((index.to_string(), new_path.clone()));
                }
                explore_kjp(value, new_path, kjp, in_redacted);
            }
        }
        _ => {}
    }
}

pub fn get_domain_kjp(domain: &Domain) -> Result<Vec<(String, String)>, serde_json::Error> {
    let json = serde_json::to_string(domain)?;
    let value: Value = serde_json::from_str(&json)?;
    let mut kjp = Vec::new();
    explore_kjp(&value, "".to_string(), &mut kjp, false);
    Ok(kjp)
}



impl ToMd for Domain {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Domain>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // We have access to the redaction we _could_ look up the fields here

        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Domain {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Domain {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Domain {handle}")
        } else {
            "Domain".to_string()
        };

        // Here is our test code for the get_json_path function
        // uncomment and check for the json renamed structure!
        //
        // let domain = self;
        // let json = serde_json::to_value(&domain).unwrap();
        // println!("json: {:?}", json);
        // let target_key = "ldhName"; // Replace this with your actual target key
        // let path = get_json_path(&json, String::new(), target_key);
        // match path {
        //     Some(path) => println!("Path to {}: {}", target_key, path),
        //     None => println!("{} not found", target_key),
        // }
        // once we have the path we have to see if the path matches the json path for
        // THAT specific value in the redaction

        // XXX Phase 3: ideally we throw 'self' (the domain) and the redaction at a library that
        // figures this stuff out and then when we print the object to the table
        // the domain can look up the redaction and print the redacted value if it exists

        // iterate over all the pub struct fields in the domain and call get_json_path on them and put all the responses in a big map
        // then we can use that map to look up the redaction for each field and print the redacted value if it exists
        // let (root_paths, redacted_paths) = match get_json_paths(&self) {
        //     Ok((root_paths, redacted_paths)) => (root_paths, redacted_paths),
        //     Err(err) => {
        //         eprintln!("Error: {}", err);
        //         return String::new(); // or any other appropriate error handling
        //     }
        // };
        
        // println!("Root paths:");
        // for (key, value) in root_paths {
        //     println!("{}: {}", key, value);
        // }
        
        // println!("\nRedacted paths:");
        // for (key, value) in redacted_paths {
        //     println!("{}: {}", key, value);
        // }
        let (mut pre_paths, post_paths) = match get_json_paths(&self) {
            Ok((pre_paths, post_paths)) => (pre_paths, post_paths),
            Err(err) => {
                eprintln!("Error: {}", err);
                return String::new(); // or any other appropriate error handling
            }
        };
        
        pre_paths.extend(post_paths);
        pre_paths.sort();
        pre_paths.dedup();
        
        println!("Combined Redacted Paths:");
        for path in &pre_paths {
            println!("{}", path);
        }
        let redacted_paths = pre_paths;

        let domain_key_and_jsonpaths = match get_domain_kjp(&self) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Error getting domain key and JSON paths: {}", e);
                return; // or handle the error in some other way
            }
        };
        println!("Domain Key and JSON Paths:");
        
        for (key, value) in &domain_key_and_jsonpaths {
            println!("{}: {}", key, value);
        }
        

        // multipart data
        let mut table = MultiPartTable::new();

        
        // identifiers
        table = table
            .header_ref(&"Identifiers")
            .and_data_ref(&"LDH Name", &redact_if_empty(&self.ldh_name))
            .and_data_ref(&"Unicode Name", &redact_if_empty(&self.unicode_name))
            .and_data_ref(&"Handle", &redact_if_empty(&self.object_common.handle));
        if let Some(public_ids) = &self.public_ids {
            table = public_ids_to_table(public_ids, table);
        }
        // common object stuff
        table = self.object_common.add_to_mptable(table, params);

        // checks
        let check_params = CheckParams::from_md(params, typeid);
        let mut checks = self.object_common.get_sub_checks(check_params);
        checks.push(self.get_checks(check_params));
        table = checks_to_table(checks, table, params);

        // render table
        md.push_str(&table.to_md(params));

        // variants require a custom table
        if let Some(variants) = &self.variants {
            md.push_str(&do_variants(variants, params))
        }

        // secure dns
        if let Some(secure_dns) = &self.secure_dns {
            md.push_str(&do_secure_dns(secure_dns, params))
        }

        // remarks
        md.push_str(&self.object_common.remarks.to_md(params.from_parent(typeid)));

        // only other object classes from here
        md.push_str(HR);

        // entities
        md.push_str(
            &self
                .object_common
                .entities
                .to_md(params.from_parent(typeid)),
        );

        // nameservers
        if let Some(nameservers) = &self.nameservers {
            nameservers
                .iter()
                .for_each(|ns| md.push_str(&ns.to_md(params.next_level())));
        }

        // network
        if let Some(network) = &self.network {
            md.push_str(&network.to_md(params.next_level()));
        }

        // redacted
        if let Some(redacted) = &self.object_common.redacted {
            md.push_str(&redacted.as_slice().to_md(params.from_parent(typeid)));
        }

        md.push('\n');
        md
    }
}

fn do_variants(variants: &[Variant], params: MdParams) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "|:-:|\n|{}|\n",
        "Domain Variants".to_right_bold(8, params.options)
    ));
    md.push_str("|:-:|:-:|:-:|\n|Relations|IDN Table|Variant Names|\n");
    variants.iter().for_each(|v| {
        md.push_str(&format!(
            "|{}|{}|{}|",
            v.relation
                .as_deref()
                .unwrap_or_default()
                .make_title_case_list(),
            v.idn_table.as_deref().unwrap_or_default(),
            v.variant_names
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|dv| format!(
                    "ldh: '{}' utf:'{}'",
                    dv.ldh_name.as_deref().unwrap_or_default(),
                    dv.unicode_name.as_deref().unwrap_or_default()
                ))
                .collect::<Vec<String>>()
                .join(", "),
        ))
    });
    md.push_str("|\n");
    md
}

fn do_secure_dns(secure_dns: &SecureDns, params: MdParams) -> String {
    let mut md = String::new();
    // multipart data
    let mut table = MultiPartTable::new();

    table = table
        .header_ref(&"DNSSEC Information")
        .and_data_ref(
            &"Zone Signed",
            &secure_dns.zone_signed.map(|b| b.to_string()),
        )
        .and_data_ref(
            &"Delegation Signed",
            &secure_dns.delegation_signed.map(|b| b.to_string()),
        )
        .and_data_ref(
            &"Max Sig Life",
            &secure_dns.max_sig_life.map(|u| u.to_string()),
        );

    if let Some(ds_data) = &secure_dns.ds_data {
        for (i, ds) in ds_data.iter().enumerate() {
            let header = format!("DS Data ({i})");
            table = table
                .header_ref(&header)
                .and_data_ref(&"Key Tag", &ds.key_tag.map(|k| k.to_string()))
                .and_data_ref(&"Algorithm", &dns_algorithm(&ds.algorithm))
                .and_data_ref(&"Digest", &ds.digest)
                .and_data_ref(&"Digest Type", &dns_digest_type(&ds.digest_type));
            if let Some(events) = &ds.events {
                let ds_header = format!("DS ({i}) Events");
                table = events_to_table(events, table, &ds_header, params);
            }
            if let Some(links) = &ds.links {
                let ds_header = format!("DS ({i}) Links");
                table = links_to_table(links, table, &ds_header);
            }
        }
    }

    if let Some(key_data) = &secure_dns.key_data {
        for (i, key) in key_data.iter().enumerate() {
            let header = format!("Key Data ({i})");
            table = table
                .header_ref(&header)
                .and_data_ref(&"Flags", &key.flags.map(|k| k.to_string()))
                .and_data_ref(&"Protocol", &key.protocol.map(|a| a.to_string()))
                .and_data_ref(&"Public Key", &key.public_key)
                .and_data_ref(&"Algorithm", &dns_algorithm(&key.algorithm));
            if let Some(events) = &key.events {
                let key_header = format!("Key ({i}) Events");
                table = events_to_table(events, table, &key_header, params);
            }
            if let Some(links) = &key.links {
                let key_header = format!("Key ({i}) Links");
                table = links_to_table(links, table, &key_header);
            }
        }
    }

    // render table
    md.push_str(&table.to_md(params));
    md
}

fn dns_algorithm(alg: &Option<u8>) -> Option<String> {
    alg.map(|alg| {
        DnsAlgorithmType::mnemonic(alg).map_or(format!("{alg} - Unassigned or Reserved"), |a| {
            format!("{alg} - {a}")
        })
    })
}

fn dns_digest_type(dt: &Option<u8>) -> Option<String> {
    dt.map(|dt| {
        DnsDigestType::mnemonic(dt).map_or(format!("{dt} - Unassigned or Reserved"), |a| {
            format!("{dt} - {a}")
        })
    })
}
