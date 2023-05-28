use std::{net::IpAddr, path::PathBuf};

use clap::{Parser, ValueEnum};
use icann_rdap_common::{
    check::{traverse_checks, CheckClass, CheckParams, GetChecks},
    response::RdapResponse,
    VERSION,
};
use icann_rdap_srv::{
    config::{data_dir, debug_config_vars, LOG},
    error::RdapServerError,
    storage::data::{trigger_reload, trigger_update, NetworkIdType, Template},
};
use ipnet::IpNet;
use serde_json::Value;
use tracing::{debug, error, warn};
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about)]
/// This program moves RDAP files into storage. Files are checked for validity
/// before moving them.
struct Cli {
    /// Directory containg RDAP JSON files.
    #[arg()]
    directory: Option<String>,

    /// Check type.
    ///
    /// Specifies the type of checks to conduct on the RDAP
    /// files. These are RDAP specific checks and not
    /// JSON validation which is done automatically. This
    /// argument may be specified multiple times to include
    /// multiple check types. If no check types are given,
    /// all check types are used.
    #[arg(short = 'C', long, required = false, value_enum)]
    check_type: Vec<CheckTypeArg>,

    /// Update storage.
    ///
    /// If true, storage is updated.
    #[arg(long, required = false, conflicts_with = "reload")]
    update: bool,

    /// Reload storage.
    ///
    /// If true, storage is completely reloaded.
    #[arg(long, required = false, conflicts_with = "update")]
    reload: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CheckTypeArg {
    /// Checks for specification warnings.
    SpecWarn,

    /// Checks for specficiation errors.
    SpecError,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RdapServerError> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    debug_config_vars();

    let check_types = if cli.check_type.is_empty() {
        vec![
            CheckClass::SpecificationWarning,
            CheckClass::SpecificationError,
        ]
    } else {
        cli.check_type
            .iter()
            .map(|c| match c {
                CheckTypeArg::SpecWarn => CheckClass::SpecificationWarning,
                CheckTypeArg::SpecError => CheckClass::SpecificationError,
            })
            .collect::<Vec<CheckClass>>()
    };

    let data_dir = data_dir();

    if let Some(directory) = cli.directory {
        do_validate_then_move(&directory, &check_types, &data_dir).await?;
    }

    // signal update or reload
    if cli.reload {
        trigger_reload(&data_dir).await?;
    } else if cli.update {
        trigger_update(&data_dir).await?;
    };

    Ok(())
}

async fn do_validate_then_move(
    directory: &str,
    check_types: &[CheckClass],
    data_dir: &str,
) -> Result<(), RdapServerError> {
    // validate files
    let src_path = PathBuf::from(directory);
    if !src_path.exists() || !src_path.is_dir() {
        error!(
            "Source Directory {} does not exist or is not a directory.",
            src_path.to_string_lossy()
        );
        return Err(RdapServerError::Config(
            "Source directory does not exist or is not a directory.".to_string(),
        ));
    };

    let mut entries = tokio::fs::read_dir(src_path.clone()).await?;
    let mut errors_found = false;
    while let Some(entry) = entries.next_entry().await? {
        let entry = entry.path();
        let contents = tokio::fs::read_to_string(&entry).await?;
        if entry.extension().map_or(false, |ext| ext == "template") {
            errors_found |= verify_rdap_template(&contents, &entry.to_string_lossy(), check_types)?;
        } else if entry.extension().map_or(false, |ext| ext == "json") {
            errors_found |= verify_rdap(&contents, &entry.to_string_lossy(), check_types)?;
        }
    }
    if errors_found {
        return Err(RdapServerError::ErrorOnChecks);
    }

    // if all files validate, then move them
    let dest_path = PathBuf::from(&data_dir);
    if !dest_path.exists() || !dest_path.is_dir() {
        warn!(
            "Destination Directory {} does not exist or is not a directory.",
            dest_path.to_string_lossy()
        );
        return Err(RdapServerError::Config(
            "Destination directory does not exist or is not a directory.".to_string(),
        ));
    };
    let mut entries = tokio::fs::read_dir(src_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let source = entry.path();
        let mut dest = dest_path.clone();
        dest.push(source.file_name().expect("cannot get source file name"));
        tokio::fs::copy(source, dest).await?;
    }
    Ok(())
}

/// Verifies the RDAP JSON file.
fn verify_rdap(
    contents: &str,
    path_name: &str,
    check_types: &[CheckClass],
) -> Result<bool, RdapServerError> {
    let mut errors_found = false;
    debug!("verifying {path_name}");
    let json = serde_json::from_str::<Value>(contents);
    if let Ok(value) = json {
        let rdap = RdapResponse::try_from(value);
        if let Ok(rdap) = rdap {
            if check_rdap(rdap, check_types) {
                errors_found = true;
            }
        } else {
            error!("Non RDAP file at {}", path_name.to_owned());
            errors_found = true;
        }
    } else {
        error!("Non JSON file at {}", path_name.to_owned());
        errors_found = true;
    };
    Ok(errors_found)
}

fn check_rdap(rdap: RdapResponse, check_types: &[CheckClass]) -> bool {
    let checks = rdap.get_checks(CheckParams {
        do_subchecks: true,
        root: &rdap,
        parent_type: rdap.get_type(),
    });
    traverse_checks(
        &checks,
        check_types,
        None,
        &mut |struct_tree, check_item| error!("{struct_tree} -> {check_item}"),
    )
}

/// Verifies the template files.
fn verify_rdap_template(
    contents: &str,
    path_name: &str,
    check_types: &[CheckClass],
) -> Result<bool, RdapServerError> {
    let mut errors_found = false;
    debug!("processing {path_name} template");
    let json = serde_json::from_str::<Template>(contents);
    if let Ok(value) = json {
        match value {
            Template::Domain { domain, ids } => {
                for id in ids {
                    debug!("verifying domain from template for {id:?}");
                    let mut domain = domain.clone();
                    domain.ldh_name = Some(id.ldh_name);
                    if let Some(unicode_name) = id.unicode_name {
                        domain.unicode_name = Some(unicode_name);
                    };
                    errors_found |= check_rdap(RdapResponse::Domain(domain), check_types);
                }
            }
            Template::Entity { entity, ids } => {
                for id in ids {
                    debug!("verifying entity from template for {id:?}");
                    let mut entity = entity.clone();
                    entity.object_common.handle = Some(id.handle);
                    errors_found |= check_rdap(RdapResponse::Entity(entity), check_types);
                }
            }
            Template::Nameserver { nameserver, ids } => {
                for id in ids {
                    debug!("verifying dding nameserver from template for {id:?}");
                    let mut nameserver = nameserver.clone();
                    nameserver.ldh_name = Some(id.ldh_name);
                    if let Some(unicode_name) = id.unicode_name {
                        nameserver.unicode_name = Some(unicode_name);
                    };
                    errors_found |= check_rdap(RdapResponse::Nameserver(nameserver), check_types);
                }
            }
            Template::Autnum { autnum, ids } => {
                for id in ids {
                    debug!("verifying autnum from template for {id:?}");
                    let mut autnum = autnum.clone();
                    autnum.start_autnum = Some(id.start_autnum);
                    autnum.end_autnum = Some(id.end_autnum);
                    errors_found |= check_rdap(RdapResponse::Autnum(autnum), check_types);
                }
            }
            Template::Network { network, ids } => {
                for id in ids {
                    debug!("verifying network from template for {id:?}");
                    let mut network = network.clone();
                    match id.network_id {
                        NetworkIdType::Cidr(cidr) => match cidr {
                            IpNet::V4(v4) => {
                                network.start_address = Some(v4.network().to_string());
                                network.end_address = Some(v4.broadcast().to_string());
                                network.ip_version = Some("v4".to_string());
                            }
                            IpNet::V6(v6) => {
                                network.start_address = Some(v6.network().to_string());
                                network.end_address = Some(v6.broadcast().to_string());
                                network.ip_version = Some("v6".to_string());
                            }
                        },
                        NetworkIdType::Range {
                            start_address,
                            end_address,
                        } => {
                            let addr: IpAddr = start_address.parse()?;
                            if addr.is_ipv4() {
                                network.ip_version = Some("v4".to_string());
                            } else {
                                network.ip_version = Some("v6".to_string());
                            }
                            network.start_address = Some(start_address);
                            network.end_address = Some(end_address);
                        }
                    }
                    errors_found |= check_rdap(RdapResponse::Network(network), check_types);
                }
            }
        };
    } else {
        error!("Non JSON template file at {}", path_name.to_owned());
        errors_found = true;
    }
    Ok(errors_found)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        crate::Cli::command().debug_assert()
    }
}
