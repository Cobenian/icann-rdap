use super::{GtldParams, ToGtld};
use icann_rdap_common::contact::PostalAddress;
use icann_rdap_common::response::domain::Domain;
use icann_rdap_common::response::domain::SecureDns;
use icann_rdap_common::response::entity::Entity;
use icann_rdap_common::response::nameserver::Nameserver;
use icann_rdap_common::response::network::Network;
use icann_rdap_common::response::types::{Event, StatusValue};

impl ToGtld for Domain {
    fn to_gtld(&self, params: &mut GtldParams) -> String {
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

        // registrar and abuse/tech/admin/registrant info
        let (formatted_data, _) =
            extract_registrar_and_abuse_info(params, &self.object_common.entities);
        gtld.push_str(&formatted_data);

        // nameservers and network
        let additional_info =
            format_nameservers_and_network(&self.nameservers, &self.network, params);
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
    params: &mut GtldParams,
) -> String {
    let mut gtld = String::new();

    if let Some(nameservers) = nameservers {
        nameservers
            .iter()
            .for_each(|ns| gtld.push_str(&ns.to_gtld(params)));
    }

    if let Some(network) = network {
        gtld.push_str(&network.to_gtld(params));
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

fn format_address_with_label(
    params: &mut GtldParams,
    address_components: &Vec<serde_json::Value>,
) -> String {
    let postal_address = PostalAddress::builder()
        .street_parts(
            address_components
                .get(2)
                .and_then(|v| v.as_str())
                .map_or_else(|| Vec::new(), |s| vec![s.to_string()]),
        )
        .locality(
            address_components
                .get(3)
                .and_then(|v| v.as_str())
                .map_or_else(|| String::new(), String::from),
        )
        .region_name(
            address_components
                .get(4)
                .and_then(|v| v.as_str())
                .map_or_else(|| String::new(), String::from),
        )
        .country_name(
            address_components
                .get(6)
                .and_then(|v| v.as_str())
                .map_or_else(|| String::new(), String::from),
        )
        .country_code(
            address_components
                .get(6)
                .and_then(|v| v.as_str())
                .map_or_else(|| String::new(), String::from),
        )
        .postal_code(
            address_components
                .get(5)
                .and_then(|v| v.as_str())
                .map_or_else(|| String::new(), String::from),
        )
        .build();

    postal_address.to_gtld(params).to_string()
}

struct RoleInfo {
    name: String,
    org: String,
    url: String,
    adr: String,
}

fn extract_registrar_and_abuse_info(
    params: &mut GtldParams,
    entities: &Option<Vec<Entity>>,
) -> (String, String) {
    let mut front_formatted_data = String::new();
    let mut formatted_data = String::new();

    if let Some(entities) = entities {
        for entity in entities {
            if let Some(roles) = &entity.roles {
                for role in roles {
                    match role.as_str() {
                        "registrar" => {
                            if let Some(vcard_array) = &entity.vcard_array {
                                let role_info = extract_role_info(role, vcard_array, params);
                                // Now use role_info to append to formatted_data
                                if !role_info.name.is_empty() {
                                    front_formatted_data +=
                                        &format!("{}: {}\n", cfl(role), role_info.name);
                                }
                                if !role_info.org.is_empty() {
                                    front_formatted_data +=
                                        &format!("{} Organization: {}\n", cfl(role), role_info.org);
                                }
                                if !role_info.url.is_empty() {
                                    front_formatted_data +=
                                        &format!("{} URL: {}\n", cfl(role), role_info.url);
                                }
                                if !role_info.adr.is_empty() {
                                    front_formatted_data += &role_info.adr;
                                }
                            }
                            // Special Sauce for Registrar IANA ID and Abuse Contact
                            if let Some(public_ids) = &entity.public_ids {
                                for public_id in public_ids {
                                    if public_id.id_type.as_str() == "IANA Registrar ID" {
                                        if !public_id.identifier.is_empty() {
                                            front_formatted_data += &format!(
                                                "Registrar IANA ID: {}\n",
                                                public_id.identifier.clone()
                                            );
                                        }
                                    }
                                }
                            }
                            append_abuse_contact_info(entity, &mut front_formatted_data);
                        }
                        "technical" | "administrative" | "registrant" => {
                            if let Some(vcard_array) = &entity.vcard_array {
                                let role_info = extract_role_info(role, vcard_array, params);
                                // Now use role_info to append to formatted_data
                                if !role_info.name.is_empty() {
                                    formatted_data +=
                                        &format!("{} Name: {}\n", cfl(role), role_info.name);
                                }
                                if !role_info.org.is_empty() {
                                    formatted_data +=
                                        &format!("{} Organization: {}\n", cfl(role), role_info.org);
                                }
                                if !role_info.adr.is_empty() {
                                    formatted_data += &role_info.adr;
                                }
                            }
                        }
                        _ => {} // Are there any roles we are missing?
                    }
                }
            }
        }
    }

    front_formatted_data += &formatted_data;
    (front_formatted_data, String::new())
}

fn extract_role_info(
    role: &str,
    vcard_array: &Vec<serde_json::Value>,
    params: &mut GtldParams,
) -> RoleInfo {
    let mut name = String::new();
    let mut org = String::new();
    let mut url = String::new();
    let mut adr = String::new();

    let label = match role {
        "registrar" => "Registrar",
        "technical" => "Technical",
        "administrative" => "Admin",
        "registrant" => "Registrant",
        _ => "",
    };
    params.label = label.to_string();

    for vcard in vcard_array.iter() {
        if let Some(properties) = vcard.as_array() {
            for property in properties {
                if let Some(property) = property.as_array() {
                    match property[0].as_str().unwrap_or("") {
                        "fn" => name = property[3].as_str().unwrap_or("").to_string(),
                        "url" => url = property[3].as_str().unwrap_or("").to_string(),
                        "org" => org = property[3].as_str().unwrap_or("").to_string(),
                        "adr" => {
                            if let Some(address_components) = property[3].as_array() {
                                adr = format_address_with_label(params, address_components);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    RoleInfo {
        name,
        org,
        url,
        adr,
    }
}

fn append_abuse_contact_info(entity: &Entity, front_formatted_data: &mut String) {
    if let Some(entities) = &entity.object_common.entities {
        for entity in entities {
            if let Some(roles) = &entity.roles {
                for role in roles {
                    if role.as_str() == "abuse" {
                        if let Some(vcard_array) = &entity.vcard_array {
                            if let Some(properties) = vcard_array[1].as_array() {
                                for property in properties {
                                    if let Some(property) = property.as_array() {
                                        if property[0].as_str().unwrap_or("") == "tel" {
                                            let abuse_contact_phone =
                                                property[3].as_str().unwrap_or("").to_string();
                                            if !abuse_contact_phone.is_empty() {
                                                front_formatted_data.push_str(&format!(
                                                    "Registrar Abuse Contact Phone: {}\n",
                                                    abuse_contact_phone
                                                ));
                                            }
                                        } else if property[0].as_str().unwrap_or("") == "email" {
                                            let abuse_contact_email =
                                                property[3].as_str().unwrap_or("").to_string();
                                            if !abuse_contact_email.is_empty() {
                                                front_formatted_data.push_str(&format!(
                                                    "Registrar Abuse Contact Email: {}\n",
                                                    abuse_contact_email
                                                ));
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
}

// capitalize first letter
fn cfl(s: &str) -> String {
    s.char_indices()
        .next()
        .map(|(i, c)| c.to_uppercase().collect::<String>() + &s[i + 1..])
        .unwrap_or_else(|| String::new())
}
