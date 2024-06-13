use super::{GtldParams, ToGtld};
use icann_rdap_common::response::domain::Domain;
use icann_rdap_common::response::domain::SecureDns;
use icann_rdap_common::response::entity::Entity;
use icann_rdap_common::response::nameserver::Nameserver;
use icann_rdap_common::response::network::Network;
use icann_rdap_common::response::types::Event;
use icann_rdap_common::response::types::StatusValue;

impl ToGtld for Domain {
    fn to_gtld(&self, params: GtldParams) -> String {
        let mut gtld = String::new();

        gtld.push_str("\n\n");
        // Domain Name
        let domain_name = format_domain_name(self);
        gtld.push_str(&domain_name);
        gtld.push('\n');

        // Domain ID
        let domain_id = format_domain_id(self.object_common.handle.as_ref());
        gtld.push_str(&domain_id);
        gtld.push('\n');

        // Date Time for Registry
        let date_info = format_registry_dates(&self.object_common.events);
        gtld.push_str(&date_info);

        // Common Object Stuff
        let domain_info =
            format_domain_info(&self.object_common.status, &self.object_common.port_43);
        gtld.push_str(&domain_info);

        // dump out self.object_common.entities
        // dbg!(&self.object_common.entities);
        let (formatted_data, _) = extract_registrar_and_abuse_info(&self.object_common.entities);
        gtld.push_str(&formatted_data);

        // nameservers and network
        let additional_info =
            format_nameservers_and_network(&self.nameservers, &self.network, &params);
        gtld.push_str(&additional_info);

        // secure dns
        let dnssec_info = format_dnssec_info(&self.secure_dns);
        gtld.push_str(&dnssec_info);

        gtld.push_str(
            "URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n",
        );

        // last update info
        format_last_update_info(&self.object_common.events, &mut gtld);

        // Keep it clean and strip out any double newlines that may have crept in
        gtld = gtld.replace("\n\n", "\n");
        gtld
    }
}

fn format_domain_name(domain: &Domain) -> String {
    if let Some(unicode_name) = &domain.unicode_name {
        format!("Domain Name: {unicode_name}")
    } else if let Some(ldh_name) = &domain.ldh_name {
        format!("Domain Name: {ldh_name}")
    } else if let Some(handle) = &domain.object_common.handle {
        format!("Domain Name: {handle}")
    } else {
        "Domain Name: ".to_string()
    }
}

fn format_domain_id(handle: Option<&String>) -> String {
    if let Some(handle) = handle {
        format!("Registry Domain ID: {handle}")
    } else {
        "Registry Domain ID:".to_string()
    }
}

fn format_registry_dates(events: &Option<Vec<Event>>) -> String {
    let mut formatted_dates = String::new();
    if let Some(events) = events {
        for event in events {
            match event.event_action.as_str() {
                "last changed" => {
                    if let Some(event_date) = &event.event_date {
                        formatted_dates.push_str(&format!("Updated Date: {}\n", event_date));
                    }
                }
                "registration" => {
                    if let Some(event_date) = &event.event_date {
                        formatted_dates.push_str(&format!("Creation Date: {}\n", event_date));
                    }
                }
                "expiration" => {
                    if let Some(event_date) = &event.event_date {
                        formatted_dates
                            .push_str(&format!("Registry Expiry Date: {}\n", event_date));
                    }
                }
                _ => {}
            }
        }
    }
    formatted_dates
}

fn format_domain_info(status: &Option<Vec<StatusValue>>, port_43: &Option<String>) -> String {
    let mut info = String::new();
    if let Some(status) = status {
        for value in status {
            info.push_str(&format!("Domain Status: {}\n", value.to_string()));
        }
    }
    if let Some(port_43) = port_43 {
        if !port_43.is_empty() {
            info.push_str(&format!("Registrar Whois Server: {}\n", port_43));
        }
    }
    info
}

fn format_nameservers_and_network(
    nameservers: &Option<Vec<Nameserver>>,
    network: &Option<Network>,
    params: &GtldParams,
) -> String {
    let mut gtld = String::new();

    if let Some(nameservers) = nameservers {
        nameservers
            .iter()
            .for_each(|ns| gtld.push_str(&ns.to_gtld(params.next_level())));
    }

    if let Some(network) = network {
        gtld.push_str(&network.to_gtld(params.next_level()));
    }

    gtld
}

fn format_dnssec_info(secure_dns: &Option<SecureDns>) -> String {
    let mut dnssec_info = String::new();

    if let Some(secure_dns) = secure_dns {
        if secure_dns.delegation_signed.unwrap_or(false) {
            dnssec_info.push_str("DNSSEC: signedDelegation\n");
            if let Some(ds_data) = &secure_dns.ds_data {
                for ds in ds_data {
                    if let (Some(key_tag), Some(algorithm), Some(digest_type), Some(digest)) =
                        (ds.key_tag, ds.algorithm, ds.digest_type, ds.digest.as_ref())
                    {
                        dnssec_info.push_str(&format!(
                            "DNSSEC DS Data: {} {} {} {}\n",
                            key_tag, algorithm, digest_type, digest
                        ));
                    }
                }
            }
        }
    }

    dnssec_info
}

fn format_last_update_info(events: &Option<Vec<Event>>, gtld: &mut String) {
    if let Some(events) = events {
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
}

// here there be Dragons
// Step 1: Define the new function
fn extract_registrar_and_abuse_info(entities: &Option<Vec<Entity>>) -> (String, String) {
    let mut registrar_name = String::new();
    let mut registrar_iana_id = String::new();
    let mut abuse_contact_email = String::new();
    let mut abuse_contact_phone = String::new();
    let mut registrar_adr = String::new();
    let mut formatted_data = String::new();

    let mut tech_name = String::new();
    let mut tech_adr = String::new();

    let mut admin_name = String::new();
    let mut admin_adr = String::new();

    let mut registrant_name = String::new();
    let mut registrant_adr = String::new();

    if let Some(entities) = entities {
        for entity in entities {
            if let Some(roles) = &entity.roles {
                for role in roles {
                    if role.as_str() == "registrar" {
                        // dbg!(&entity.vcard_array);
                        if let Some(vcard_array) = &entity.vcard_array {
                            for vcard in vcard_array.iter() {
                                if let Some(properties) = vcard.as_array() {
                                    for property in properties {
                                        if let Some(property) = property.as_array() {
                                            if property[0].as_str().unwrap_or("") == "fn" {
                                                registrar_name =
                                                    property[3].as_str().unwrap_or("").to_string();
                                            }
                                        }
                                        if property[0].as_str().unwrap_or("") == "adr" {
                                            if let Some(address_components) = property[3].as_array()
                                            {
                                                registrar_adr = format_address_with_label(
                                                    address_components,
                                                    "Registrar",
                                                );
                                            }
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
                        if let Some(entities) = &entity.object_common.entities {
                            for entity in entities {
                                if let Some(roles) = &entity.roles {
                                    for role in roles {
                                        if role.as_str() == "abuse" {
                                            if let Some(vcard_array) = &entity.vcard_array {
                                                if let Some(properties) = vcard_array[1].as_array()
                                                {
                                                    for property in properties {
                                                        if let Some(property) = property.as_array()
                                                        {
                                                            if property[0].as_str().unwrap_or("")
                                                                == "tel"
                                                            {
                                                                abuse_contact_phone = property[3]
                                                                    .as_str()
                                                                    .unwrap_or("")
                                                                    .to_string();
                                                            } else if property[0]
                                                                .as_str()
                                                                .unwrap_or("")
                                                                == "email"
                                                            {
                                                                abuse_contact_email = property[3]
                                                                    .as_str()
                                                                    .unwrap_or("")
                                                                    .to_string();
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } // end if abuse
                                    }
                                }
                            }
                        }
                    } // if the role is registrar
                    if role.as_str() == "technical" {
                        println!("Technical: FOUND!\n");
                        dbg!(&entity.vcard_array);
                        if let Some(vcard_array) = &entity.vcard_array {
                            for vcard in vcard_array.iter() {
                                if let Some(properties) = vcard.as_array() {
                                    for property in properties {
                                        if let Some(property) = property.as_array() {
                                            if property[0].as_str().unwrap_or("") == "fn" {
                                                tech_name =
                                                    property[3].as_str().unwrap_or("").to_string();
                                            }
                                        }
                                        if property[0].as_str().unwrap_or("") == "adr" {
                                            if let Some(address_components) = property[3].as_array()
                                            {
                                                tech_adr = format_address_with_label(
                                                    address_components,
                                                    "Technical",
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if role.as_str() == "administrative" {
                        println!("Administrative: FOUND!\n");
                        dbg!(&entity.vcard_array);
                        if let Some(vcard_array) = &entity.vcard_array {
                            for vcard in vcard_array.iter() {
                                if let Some(properties) = vcard.as_array() {
                                    for property in properties {
                                        if let Some(property) = property.as_array() {
                                            if property[0].as_str().unwrap_or("") == "fn" {
                                                admin_name =
                                                    property[3].as_str().unwrap_or("").to_string();
                                            }
                                        }
                                        if property[0].as_str().unwrap_or("") == "adr" {
                                            if let Some(address_components) = property[3].as_array()
                                            {
                                                admin_adr = format_address_with_label(
                                                    address_components,
                                                    "Admin",
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if role.as_str() == "registrant" {
                        println!("Registrant: FOUND!\n");
                        dbg!(&entity.vcard_array);
                        if let Some(vcard_array) = &entity.vcard_array {
                            for vcard in vcard_array.iter() {
                                if let Some(properties) = vcard.as_array() {
                                    for property in properties {
                                        if let Some(property) = property.as_array() {
                                            if property[0].as_str().unwrap_or("") == "org" {
                                                registrant_name =
                                                    property[3].as_str().unwrap_or("").to_string();
                                            }
                                        }
                                        if property[0].as_str().unwrap_or("") == "adr" {
                                            if let Some(address_components) = property[3].as_array()
                                            {
                                                registrant_adr = format_address_with_label(
                                                    address_components,
                                                    "Registrant",
                                                );
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
    }

    // Combine all pieces of information into the formatted_data string
    if !registrar_name.is_empty() {
        formatted_data += &format!("Registrar: {}\n", registrar_name);
    }
    if !registrar_iana_id.is_empty() {
        formatted_data += &format!("Registrar IANA ID: {}\n", registrar_iana_id);
    }
    if !registrar_adr.is_empty() {
        formatted_data += &registrar_adr;
    }
    if !abuse_contact_email.is_empty() {
        formatted_data += &format!("Registrar Abuse Contact Email: {}\n", abuse_contact_email);
    }
    if !abuse_contact_phone.is_empty() {
        formatted_data += &format!("Registrar Abuse Contact Phone: {}\n", abuse_contact_phone);
    }

    if !tech_name.is_empty() {
        formatted_data += &format!("Tech Name: {}\n", tech_name);
    }
    if !tech_adr.is_empty() {
        formatted_data += &tech_adr;
    }

    if !admin_name.is_empty() {
        formatted_data += &format!("Admin Name: {}\n", admin_name);
    }
    if !admin_adr.is_empty() {
        formatted_data += &admin_adr;
    }

    if !registrant_name.is_empty() {
        formatted_data += &format!("Registrant Name: {}\n", registrant_name);
    }
    if !registrant_adr.is_empty() {
        formatted_data += &registrant_adr;
    }

    // Return the formatted data
    (formatted_data, String::new()) // Adjust according to actual needs
}

fn format_address_with_label(address_components: &Vec<serde_json::Value>, label: &str) -> String {
    if address_components.len() < 7 {
        return String::new();
    }

    let street_end_index = address_components.len() - 4;
    let street = address_components[0..street_end_index]
        .iter()
        .filter_map(|s| s.as_str())
        .collect::<Vec<&str>>()
        .join(" ");
    let city = address_components
        .get(street_end_index)
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let state = address_components
        .get(street_end_index + 1)
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let postal_code = address_components
        .get(street_end_index + 2)
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let country = address_components
        .get(street_end_index + 3)
        .and_then(|s| s.as_str())
        .unwrap_or("");

    format!(
        "{} Street: {}\n{} City: {}\n{} State/Province: {}\n{} Postal Code: {}\n{} Country: {}\n",
        label, street, label, city, label, state, label, postal_code, label, country
    )
}
