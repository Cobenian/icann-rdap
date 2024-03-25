extern crate jsonpath_lib as jsonpath;
use jsonpath::replace_with;
use jsonpath_rust::{JsonPathFinder, JsonPathInst};
use regex::Regex;
use response::RdapResponse;
use serde_json::{json, Value};
use std::str::FromStr;

use crate::response;

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

pub fn replace_redacted_items(rdap: RdapResponse) -> RdapResponse {
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

pub fn find_paths_to_redact(checks: &[(ResultType, String, String)]) -> Vec<String> {
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

pub fn check_json_paths(u: Value, paths: Vec<String>) -> Vec<(ResultType, String, String)> {
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

// Checks the redaction in the object and returns the json paths that we need
pub fn get_redacted_paths_for_object(
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

// pull the JSON paths from prePath and postPath
pub fn get_pre_and_post_paths(paths: Vec<(String, Value, String)>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|(key, _, _)| key == "prePath" || key == "postPath")
        .filter_map(|(_, value, _)| value.as_str().map(|s| s.to_string()))
        .collect()
}

// Adds a field to the JSON object
pub fn add_field(json: &mut Value, path: &str, new_value: Value) {
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
pub fn filter_and_extract_paths(
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

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use serde_json::Value;

    use crate::utils::*;

    #[test]
    fn GIVEN_redaction_in_json_WHEN_added_correctly_THEN_success() {
        // GIVEN
        let json = r#"
          {"rdapConformance":["rdap_level_0","redacted"],"objectClassName":"domain","handle":"XXX","ldhName":"example1.com","links":[{"value":"https://example.com/rdap/domain/example1.com","rel":"self","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"},{"value":"https://example.com/rdap/domain/example1.com","rel":"related","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"}],"redacted":[{"name":{"description":"Registry Domain ID"},"prePath":"$.handle","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}},{"name":{"description":"Registry Domain ID"},"prePath":"$.unicodeName","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}}]}
          "#;

        // WHEN
        let mut v: Value = serde_json::from_str(json).unwrap();
        let jps: Vec<(String, Value, String)> = get_redacted_paths_for_object(&v, "".to_string());
        let json_paths: Vec<String> = get_pre_and_post_paths(jps);
        let mut to_change = check_json_paths(v.clone(), json_paths.into_iter().collect());
        let removed_paths = filter_and_extract_paths(&mut to_change, ResultType::Removed1);
        let redact_paths = find_paths_to_redact(&to_change);

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
        for path in &removed_paths {
            // dbg!(&path);
            add_field(
                &mut v,
                path,
                serde_json::Value::String("*REDACTED*".to_string()),
            );
        }

        // THEN
        // comparse the json with the expected json
        let expected_json = r#"
          {"rdapConformance":["rdap_level_0","redacted"],"objectClassName":"domain","unicodeName": "*REDACTED*", "handle":"*XXX*","ldhName":"example1.com","links":[{"value":"https://example.com/rdap/domain/example1.com","rel":"self","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"},{"value":"https://example.com/rdap/domain/example1.com","rel":"related","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"}],"redacted":[{"name":{"description":"Registry Domain ID"},"prePath":"$.handle","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}},{"name":{"description":"Registry Domain ID"},"prePath":"$.unicodeName","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}}]}
          "#;

        assert_eq!(
            v,
            serde_json::from_str::<serde_json::Value>(expected_json).unwrap()
        );
        // assert_eq!(v, serde_json::from_str(expected_json).unwrap());
    }
}
