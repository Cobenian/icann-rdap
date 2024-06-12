use super::{GtldParams, ToGtld};
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

        // Common Object Stuff
        // let mut table = MultiPartTable::new();
        // table = self.object_common.add_to_gtldtable(table, params);
        // gtld.push_str(&table.to_gtld(params));
        // Common Object Stuff
        if let Some(status) = &self.object_common.status {
            for value in status {
                gtld.push_str(&format!("Domain Status: {}\n", value.0));
            }
        }
        if let Some(port_43) = &self.object_common.port_43 {
            if !port_43.is_empty() {
                gtld.push_str(&format!("Registrar Whois Server: {}\n", port_43));
            }
        }

        // dump out self.object_common.entities
        // dbg!(&self.object_common.entities);
        let mut registrar_name = String::new();
        let mut registrar_iana_id = String::new();
        let mut abuse_contact_email = String::new();
        let mut abuse_contact_phone = String::new();
        let mut registrar_adr = String::new();

        if let Some(entities) = &self.object_common.entities {
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
                                                    registrar_name = property[3]
                                                        .as_str()
                                                        .unwrap_or("")
                                                        .to_string();
                                                }
                                            }
                                            if property[0].as_str().unwrap_or("") == "adr" {
                                                if let Some(address_components) =
                                                    property[3].as_array()
                                                {
                                                    if address_components.len() >= 7 {
                                                        // Ensure there are at least 7 elements
                                                        // Include all elements before city as part of the street address
                                                        let street_end_index =
                                                            address_components.len() - 4; // Exclude city, state, postal code, and country
                                                        let street = address_components
                                                            [0..street_end_index]
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
                                                        registrar_adr = format!(
                                                            "Registrar Street: {}\nRegistrar City: {}\nRegistrar State/Province: {}\nRegistrar Postal Code: {}\nRegistrar Country: {}\n",
                                                            street, city, state, postal_code, country
                                                        );
                                                    }
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
                                                    if let Some(properties) =
                                                        vcard_array[1].as_array()
                                                    {
                                                        for property in properties {
                                                            if let Some(property) =
                                                                property.as_array()
                                                            {
                                                                if property[0]
                                                                    .as_str()
                                                                    .unwrap_or("")
                                                                    == "tel"
                                                                {
                                                                    abuse_contact_phone = property
                                                                        [3]
                                                                    .as_str()
                                                                    .unwrap_or("")
                                                                    .to_string();
                                                                } else if property[0]
                                                                    .as_str()
                                                                    .unwrap_or("")
                                                                    == "email"
                                                                {
                                                                    abuse_contact_email = property
                                                                        [3]
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
                            // dbg!(&entity.vcard_array);

                            //
                        }
                        if role.as_str() == "administrative" {
                            println!("Administrative: FOUND!\n");
                            // dbg!(&entity.vcard_array);

                            //
                        }
                        if role.as_str() == "registrant" {
                            println!("Registrant: FOUND!\n");
                            // dbg!(&entity.vcard_array);

                            //
                        }
                    }
                }
            }
        }

        // format the registrar and abuse contact data
        let mut formatted_data = String::new();

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
