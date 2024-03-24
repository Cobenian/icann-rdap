use icann_rdap_common::check::traverse_checks;
use icann_rdap_common::check::CheckClass;
use icann_rdap_common::check::CheckParams;
use icann_rdap_common::check::GetChecks;
use tracing::error;
use tracing::info;

use icann_rdap_client::{
    md::{MdOptions, MdParams, ToMd},
    query::{qtype::QueryType, request::ResponseData},
    request::{RequestData, RequestResponse, RequestResponses, SourceType},
};
use icann_rdap_common::{media_types::RDAP_MEDIA_TYPE, response::RdapResponse};
use reqwest::Client;
use termimad::{crossterm::style::Color::*, Alignment, MadSkin};

use crate::bootstrap::get_base_url;
use crate::bootstrap::BootstrapType;
use crate::error::CliError;
use crate::request::do_request;

// Awful hackery
extern crate jsonpath_lib as jsonpath;
use jsonpath::replace_with;
use jsonpath_rust::{JsonPathFinder, JsonPathInst};
use regex::Regex;
use serde_json::{json, Value};
use std::str::FromStr;

// Define the enum
#[derive(Debug, PartialEq)]
pub enum ResultType {
    Removed1,
    Empty1,
    Empty2,
    Replaced1,
    Removed2,
    Replaced2,
    Replaced3,
    Removed3,
    Removed4,
    Removed5,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OutputType {
    /// Results are rendered as Markdown in the terminal using ANSI terminal capabilities.
    RenderedMarkdown,

    /// Results are rendered as Markdown in plain text.
    Markdown,

    /// Results are output as RDAP JSON.
    Json,

    /// Results are output as Pretty RDAP JSON.
    PrettyJson,

    /// RDAP JSON with extra information.
    JsonExtra,
}

pub(crate) struct ProcessingParams {
    pub bootstrap_type: BootstrapType,
    pub output_type: OutputType,
    pub check_types: Vec<CheckClass>,
    pub error_on_checks: bool,
    pub no_cache: bool,
    pub max_cache_age: u32,
}

pub(crate) async fn do_query<'a, W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    match query_type {
        QueryType::IpV4Addr(_)
        | QueryType::IpV6Addr(_)
        | QueryType::IpV4Cidr(_)
        | QueryType::IpV6Cidr(_)
        | QueryType::AsNumber(_) => {
            do_inr_query(query_type, processing_params, client, write).await
        }
        QueryType::Domain(_) | QueryType::DomainNameSearch(_) => {
            do_domain_query(query_type, processing_params, client, write).await
        }
        _ => do_basic_query(query_type, processing_params, None, client, write).await,
    }
}

async fn do_domain_query<'a, W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let mut transactions = RequestResponses::new();
    let base_url = get_base_url(&processing_params.bootstrap_type, client, query_type).await?;
    let response = do_request(&base_url, query_type, processing_params, client).await;
    match response {
        Ok(response) => {
            let source_host = response.http_data.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                source_host: &source_host,
                source_type: SourceType::DomainRegistry,
            };
            let replaced_rdap = replace_redacted_items(response.rdap.clone());
            let replaced_data = ResponseData {
                rdap: replaced_rdap,
                // copy other fields from `response`
                ..response.clone()
            };
            transactions = do_output(
                processing_params,
                &req_data,
                &replaced_data,
                write,
                transactions,
            )?;
            let regr_source_host;
            let regr_req_data: RequestData;
            if let Some(url) = get_related_link(&response.rdap).first() {
                info!("Querying domain name from registrar.");
                let query_type = QueryType::Url(url.to_string());
                let registrar_response =
                    do_request(&base_url, &query_type, processing_params, client).await;
                match registrar_response {
                    Ok(registrar_response) => {
                        regr_source_host = registrar_response.http_data.host;
                        regr_req_data = RequestData {
                            req_number: 2,
                            source_host: &regr_source_host,
                            source_type: SourceType::DomainRegistrar,
                        };
                        transactions = do_output(
                            processing_params,
                            &regr_req_data,
                            &response,
                            write,
                            transactions,
                        )?;
                    }
                    Err(error) => return Err(error),
                }
            }
            do_final_output(processing_params, write, transactions)?;
        }
        Err(error) => return Err(error),
    };
    Ok(())
}

async fn do_inr_query<'a, W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let mut transactions = RequestResponses::new();
    let base_url = get_base_url(&processing_params.bootstrap_type, client, query_type).await?;
    let response = do_request(&base_url, query_type, processing_params, client).await;
    match response {
        Ok(response) => {
            let source_host = response.http_data.host.to_owned();
            let req_data = RequestData {
                req_number: 1,
                source_host: &source_host,
                source_type: SourceType::RegionalInternetRegistry,
            };
            let replaced_rdap = replace_redacted_items(response.rdap.clone());
            let replaced_data = ResponseData {
                rdap: replaced_rdap,
                // copy other fields from `response`
                ..response.clone()
            };
            transactions = do_output(
                processing_params,
                &req_data,
                &replaced_data,
                write,
                transactions,
            )?;
            do_final_output(processing_params, write, transactions)?;
        }
        Err(error) => return Err(error),
    };
    Ok(())
}

async fn do_basic_query<'a, W: std::io::Write>(
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    req_data: Option<&'a RequestData<'a>>,
    client: &Client,
    write: &mut W,
) -> Result<(), CliError> {
    let mut transactions = RequestResponses::new();
    let base_url = get_base_url(&processing_params.bootstrap_type, client, query_type).await?;
    let response = do_request(&base_url, query_type, processing_params, client).await;
    match response {
        Ok(response) => {
            let source_host = response.http_data.host.to_owned();
            let req_data = if let Some(meta) = req_data {
                RequestData {
                    req_number: meta.req_number + 1,
                    source_host: meta.source_host,
                    source_type: SourceType::UncategorizedRegistry,
                }
            } else {
                RequestData {
                    req_number: 1,
                    source_host: &source_host,
                    source_type: SourceType::UncategorizedRegistry,
                }
            };
            let replaced_rdap = replace_redacted_items(response.rdap.clone());
            let replaced_data = ResponseData {
                rdap: replaced_rdap,
                // copy other fields from `response`
                ..response.clone()
            };
            transactions = do_output(
                processing_params,
                &req_data,
                &replaced_data,
                write,
                transactions,
            )?;
            do_final_output(processing_params, write, transactions)?;
        }
        Err(error) => return Err(error),
    };
    Ok(())
}

fn do_output<'a, W: std::io::Write>(
    processing_params: &ProcessingParams,
    req_data: &'a RequestData,
    response: &'a ResponseData,
    write: &mut W,
    mut transactions: RequestResponses<'a>,
) -> Result<RequestResponses<'a>, CliError> {
    match processing_params.output_type {
        OutputType::RenderedMarkdown => {
            let mut skin = MadSkin::default_dark();
            skin.set_headers_fg(Yellow);
            skin.headers[1].align = Alignment::Center;
            skin.headers[2].align = Alignment::Center;
            skin.headers[3].align = Alignment::Center;
            skin.headers[4].compound_style.set_fg(DarkGreen);
            skin.headers[5].compound_style.set_fg(Magenta);
            skin.headers[6].compound_style.set_fg(Cyan);
            skin.headers[7].compound_style.set_fg(Red);
            skin.bold.set_fg(DarkBlue);
            skin.italic.set_fg(Red);
            skin.quote_mark.set_fg(DarkBlue);
            skin.table.set_fg(DarkGreen);
            skin.table.align = Alignment::Center;
            skin.inline_code.set_fgbg(Cyan, Reset);
            skin.write_text_on(
                write,
                &response.rdap.to_md(MdParams {
                    heading_level: 1,
                    root: &response.rdap,
                    parent_type: response.rdap.get_type(),
                    check_types: &processing_params.check_types,
                    options: &MdOptions::default(),
                    req_data,
                }),
            )?;
        }
        OutputType::Markdown => {
            writeln!(
                write,
                "{}",
                response.rdap.to_md(MdParams {
                    heading_level: 1,
                    root: &response.rdap,
                    parent_type: response.rdap.get_type(),
                    check_types: &processing_params.check_types,
                    options: &MdOptions {
                        text_style_char: '_',
                        style_in_justify: true,
                        ..MdOptions::default()
                    },
                    req_data,
                })
            )?;
        }
        _ => {} // do nothing
    };

    let checks = response.rdap.get_checks(CheckParams {
        do_subchecks: true,
        root: &response.rdap,
        parent_type: response.rdap.get_type(),
    });

    let req_res = RequestResponse {
        checks,
        req_data,
        res_data: response,
    };
    transactions.push(req_res);
    Ok(transactions)
}

fn do_final_output<W: std::io::Write>(
    processing_params: &ProcessingParams,
    write: &mut W,
    transactions: RequestResponses<'_>,
) -> Result<(), CliError> {
    match processing_params.output_type {
        OutputType::Json => {
            for req_res in &transactions {
                writeln!(
                    write,
                    "{}",
                    serde_json::to_string(&req_res.res_data.rdap).unwrap()
                )?;
            }
        }
        OutputType::PrettyJson => {
            for req_res in &transactions {
                writeln!(
                    write,
                    "{}",
                    serde_json::to_string_pretty(&req_res.res_data.rdap).unwrap()
                )?;
            }
        }
        OutputType::JsonExtra => {
            writeln!(write, "{}", serde_json::to_string(&transactions).unwrap())?
        }
        _ => {} // do nothing
    };

    let mut checks_found = false;
    // we don't want to error on informational
    let error_check_types: Vec<CheckClass> = processing_params
        .check_types
        .iter()
        .filter(|ct| *ct != &CheckClass::Informational)
        .copied()
        .collect();
    for req_res in &transactions {
        let found = traverse_checks(
            &req_res.checks,
            &error_check_types,
            None,
            &mut |struct_tree, check_item| {
                if processing_params.error_on_checks {
                    error!("{struct_tree} -> {check_item}")
                }
            },
        );
        if found {
            checks_found = true
        }
    }
    if checks_found && processing_params.error_on_checks {
        return Err(CliError::ErrorOnChecks);
    }

    Ok(())
}

fn get_related_link(rdap_response: &RdapResponse) -> Vec<&str> {
    if let Some(links) = rdap_response.get_links() {
        let urls: Vec<&str> = links
            .iter()
            .filter(|l| {
                if let Some(rel) = &l.rel {
                    if let Some(media_type) = &l.media_type {
                        rel.eq_ignore_ascii_case("related")
                            && media_type.eq_ignore_ascii_case(RDAP_MEDIA_TYPE)
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .map(|l| l.href.as_str())
            .collect::<Vec<&str>>();
        urls
    } else {
        Vec::new()
    }
}

fn replace_redacted_items(rdap: RdapResponse) -> RdapResponse {
    let rdap_json = serde_json::to_string(&rdap).unwrap();
    let mut v: Value = serde_json::from_str(&rdap_json).unwrap();
    let jps: Vec<(String, Value, String)> = get_redacted_paths_for_object(&v, "".to_string());
    let json_paths: Vec<String> = get_pre_and_post_paths(jps);

    let mut to_change = check_json_paths(v.clone(), json_paths.into_iter().collect());
    // println!("TO CHANGE: {:?}", to_change);
    let removed_paths = filter_and_extract_paths(&mut to_change, ResultType::Removed1);
    // println!("REMOVED PATHS: {:?}", removed_paths);

    let redact_paths = find_paths_to_redact(&to_change);
    // dbg!(&redact_paths);

    // there is something there, highlight it with *<someting>*, if it is "", put *REDACTED* in there
    for path in redact_paths {
        let json_path = &path;
        match replace_with(v.clone(), json_path, &mut |v| match v.as_str() {
            Some("") => Some(json!("*REDACTED*")),
            Some(s) => Some(json!(format!("*{}*", s))),
            _ => Some(json!("*REDACTED*")),
        }) {
            Ok(val) => v = val,
            Err(e) => {
                eprintln!("Error replacing value: {}", e);
            }
        }
    }

    // Add the missing filed
    for path in &removed_paths {
        // dbg!(&path);
        add_field(
            &mut v,
            path,
            serde_json::Value::String("*REDACTED*".to_string()),
        );
    }

    // Now we have to convert the modified Value back to RdapResponse
    let modified_rdap: RdapResponse = serde_json::from_value(v.clone()).unwrap();
    modified_rdap
}

fn find_paths_to_redact(checks: &[(ResultType, String, String)]) -> Vec<String> {
    checks
        .iter()
        .filter(|(status, _, _)| {
            matches!(
                *status,
                ResultType::Empty1
                    | ResultType::Empty2
                    | ResultType::Replaced1
                    | ResultType::Removed1
            )
        })
        .map(|(_, _, found_path)| found_path.clone())
        .collect()
}

fn check_json_paths(u: Value, paths: Vec<String>) -> Vec<(ResultType, String, String)> {
    let mut results = Vec::new();

    for path in paths {
        let path = path.trim_matches('"'); // Remove double quotes
        match JsonPathInst::from_str(path) {
            Ok(json_path) => {
                let finder = JsonPathFinder::new(Box::new(u.clone()), Box::new(json_path));
                let matches = finder.find_as_path();

                if let Value::Array(paths) = matches {
                    if paths.is_empty() {
                        results.push((ResultType::Removed1, path.to_string(), "".to_string()));
                    } else {
                        for path_value in paths {
                            if let Value::String(found_path) = path_value {
                                let no_value = Value::String("NO_VALUE".to_string());
                                let re = Regex::new(r"\.\[|\]").unwrap();
                                let json_pointer = found_path
                                    .trim_start_matches('$')
                                    .replace('.', "/")
                                    .replace("['", "/")
                                    .replace("']", "")
                                    .replace('[', "/")
                                    .replace(']', "")
                                    .replace("//", "/");
                                let json_pointer = re.replace_all(&json_pointer, "/").to_string();
                                let value_at_path = u.pointer(&json_pointer).unwrap_or(&no_value);
                                if value_at_path.is_string() {
                                    let str_value = value_at_path.as_str().unwrap_or("");
                                    if str_value == "NO_VALUE" {
                                        results.push((
                                            ResultType::Empty1,
                                            path.to_string(),
                                            found_path,
                                        ));
                                    } else if str_value.is_empty() {
                                        results.push((
                                            ResultType::Empty2,
                                            path.to_string(),
                                            found_path,
                                        ));
                                    } else {
                                        results.push((
                                            ResultType::Replaced1,
                                            path.to_string(),
                                            found_path,
                                        ));
                                    }
                                } else if value_at_path.is_null() {
                                    results.push((
                                        ResultType::Removed2,
                                        path.to_string(),
                                        found_path,
                                    ));
                                } else if value_at_path.is_array() {
                                    results.push((
                                        ResultType::Replaced2,
                                        path.to_string(),
                                        found_path,
                                    ));
                                } else if value_at_path.is_object() {
                                    results.push((
                                        ResultType::Replaced3,
                                        path.to_string(),
                                        found_path,
                                    ));
                                } else {
                                    results.push((
                                        ResultType::Removed3,
                                        path.to_string(),
                                        found_path,
                                    ));
                                }
                            } else {
                                results.push((
                                    ResultType::Removed4,
                                    path.to_string(),
                                    "".to_string(),
                                ));
                            }
                        }
                    }
                } else {
                    results.push((ResultType::Removed5, path.to_string(), "".to_string()));
                }
            }
            Err(e) => {
                println!("Failed to parse JSON path '{}': {}", path, e);
            }
        }
    }
    // dbg!(&results);
    results
}

fn get_redacted_paths_for_object(
    obj: &Value,
    current_path: String,
) -> Vec<(String, Value, String)> {
    match obj {
        Value::Object(map) => {
            let mut paths = vec![];
            for (key, value) in map {
                let new_path = if current_path.is_empty() {
                    format!("$.{}", key)
                } else {
                    format!("{}.{}", current_path, key)
                };
                // dbg!(&key, &value, &new_path);
                paths.push((key.clone(), value.clone(), new_path.clone()));
                paths.extend(get_redacted_paths_for_object(value, new_path));
            }
            paths
        }
        Value::Array(arr) => arr
            .iter()
            .enumerate()
            .flat_map(|(i, value)| {
                let new_path = format!("{}[{}]", current_path, i);
                get_redacted_paths_for_object(value, new_path)
            })
            .collect(),
        _ => vec![],
    }
}

fn get_pre_and_post_paths(paths: Vec<(String, Value, String)>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|(key, _, _)| key == "prePath" || key == "postPath")
        .filter_map(|(_, value, _)| value.as_str().map(|s| s.to_string()))
        .collect()
}

// adds a field to the JSON object
fn add_field(json: &mut Value, path: &str, new_value: Value) {
    // If the path contains '@' or '?(', return without modifying the JSON
    if path.contains('@') || path.contains("?(") {
        return;
    }

    // println!("Adding field: {} -> {}", path, new_value);
    let path = path.trim_start_matches("$."); // strip the $. prefix
    let parts: Vec<&str> = path.split('.').collect();
    let last = parts.last().unwrap();

    // set the current to the incoming JSON
    let mut current = json;

    for part in &parts[0..parts.len() - 1] {
        let array_parts: Vec<&str> = part.split('[').collect();
        dbg!(&array_parts);
        if array_parts.len() > 1 {
            let index = usize::from_str(array_parts[1].trim_end_matches(']')).unwrap();
            current = &mut current[array_parts[0]][index];
        } else {
            current = &mut current[*part];
        }
    }

    // if it is an array then set it there
    if last.contains('[') {
        let array_parts: Vec<&str> = last.split('[').collect();
        let index = usize::from_str(array_parts[1].trim_end_matches(']')).unwrap();
        current[array_parts[0]][index] = new_value;
    } else {
        // otherwise set it as a field
        current[*last] = new_value;
    }
}

// Filter out the paths that we need to handle explicitly elsewhere and return them
fn filter_and_extract_paths(
    to_change: &mut Vec<(ResultType, String, String)>,
    filter: ResultType,
) -> Vec<String> {
    let mut extracted_paths = vec![];

    to_change.retain(|(key, path, _)| {
        if key == &filter {
            extracted_paths.push(path.clone());
            false
        } else {
            true
        }
    });

    extracted_paths
}
