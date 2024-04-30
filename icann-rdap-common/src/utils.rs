extern crate jsonpath_lib as jsonpath;
use jsonpath::replace_with;
use jsonpath_rust::{JsonPathFinder, JsonPathInst};
use regex::Regex;
use response::RdapResponse;
use serde_json::{json, Value};
use std::str::FromStr;

use crate::response;

// These are the different types of results that we can get from the JSON path checks
#[derive(Debug, PartialEq, Clone)]
pub enum ResultType {
    Empty1, // (*) what we found in the value paths array was a string but has no value (yes, this is a little weird, but does exist) `Redaction by Empty Value`
    Empty2, // (*) what we found in the value paths array was a string but it is an empty string `Redaction by Empty Value`
    Replaced1, // (*) what we found in the value paths array was a string and it does have a value `Redaction by Partial Value` and/or `Redaction by Replacement Value`
    Replaced2, // what we found in the value paths array was _another_ array (have never found this)
    Replaced3, // what we found in the value paths array was an object (have never found this)
    Removed1, // (*) paths array is empty, finder.find_as_path() found nothing `Redaction by Removal`
    Removed2, // value in paths array is null (have never found this)
    Removed3, // fall through, value in paths array is not anything else (have never found this)
    Removed4, // what we found was not a JSON::Value::string (have never found this)
    Removed5, // what finder.find_as_path() returned was not a Value::Array (have never found this, could possibly be an error)
}

#[derive(Debug, Clone)]
pub struct RedactedObject {
    pub name: Value,
    pub pre_path: Option<String>,
    pub post_path: Option<String>,
    pub final_path: Option<String>,
    pub final_path_exists: bool,
    pub path_lang: Value,
    pub replacement_path: Option<String>,
    pub method: Value,
    pub reason: Value,
    pub result_type: Option<ResultType>,
}

// this is our public entry point
pub fn replace_redacted_items(orignal_response: RdapResponse) -> RdapResponse {
    let rdap_json = serde_json::to_string(&orignal_response).unwrap();
    let mut v: Value = serde_json::from_str(&rdap_json).unwrap();
    let mut response = orignal_response; // Initialize with the original response

    // if there are any redactions we need to do some modifications
    if let Some(redacted_array) = v["redacted"].as_array() {
        let result = parse_redacted_array(&v, redacted_array);
        // dbg!(&result);

        for redacted_object in result {
            println!("Processing redacted_object...");
            if redacted_object.final_path_exists {
                println!("final_path_exists is true");
                if let Some(final_path) = redacted_object.final_path {
                    println!("Found final_path: {}", final_path);
                    dbg!(&final_path);
                    match replace_with(v.clone(), &final_path, &mut |v| {
                        println!("Replacing value...");
                        if v.is_string() {
                            match v.as_str() {
                                Some("") => {
                                    println!("Value is an empty string");
                                    Some(json!("*REDACTED*"))
                                }
                                Some(s) => {
                                    println!("Value is a string: {}", s);
                                    Some(json!(format!("*{}*", s)))
                                }
                                _ => {
                                    println!("Value is a non-string");
                                    Some(json!("*REDACTED*"))
                                }
                            }
                        }
                        // the real question is what do we do with these types of values?
                        else if v.is_null() {
                            println!("Value is null");
                            Some(json!(null))
                        } else if v.is_boolean() {
                            // what do we do?
                            println!("Value is a boolean");
                            Some(json!(false))
                        } else if v.is_number() {
                            // what do we do?
                            println!("Value is a number");
                            Some(json!(0))
                        } else if v.is_array() {
                            // what do we do?
                            println!("Value is an array");
                            Some(json!([]))
                        } else if v.is_object() {
                            // what do we do?
                            println!("Value is an object");
                            Some(json!({}))
                        } else {
                            // Handle non-string values here /// mon dieu! we cannot set this to a string!
                            println!("Value is not a string");
                            Some(json!("*NON-STRING VALUE*"))
                        }
                    }) {
                        Ok(val) => {
                            println!("Successfully replaced value");
                            v = val; // No need to declare `v` as mutable again
                        }
                        Err(e) => {
                            println!("Error replacing value: {}", e);
                        }
                    }
                }
            } else {
                println!("final_path_exists is false");
            }
        }
        // find all the replacementValues and replace them with the value in the replacementPath

        response = serde_json::from_value(v).unwrap();
    }

    // Return the response
    response
}

// everything else below this line is internal to the module

fn parse_redacted_array(v: &Value, redacted_array: &Vec<Value>) -> Vec<RedactedObject> {
    let mut result: Vec<RedactedObject> = Vec::new();

    for item in redacted_array {
        let item_map = item.as_object().unwrap();
        let pre_path = item_map
            .get("prePath")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let post_path = item_map
            .get("postPath")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // we need set a final_path here, prefer pre over the post
        let final_path = pre_path.clone().or(post_path.clone());
        let mut redacted_object = RedactedObject {
            name: Value::String(String::from("")), // Set to empty string initially
            pre_path: pre_path,
            post_path: post_path,
            final_path: final_path.clone(),
            final_path_exists: false, // Set to false initially
            path_lang: item_map
                .get("pathLang")
                .unwrap_or(&Value::String(String::from("")))
                .clone(),
            replacement_path: item_map
                .get("replacementPath")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            method: item_map
                .get("method")
                .unwrap_or(&Value::String(String::from("")))
                .clone(),
            reason: Value::String(String::from("")), // Set to empty string initially
            result_type: None,                       // Set to None initially
        };

        // Check if the "name" field is an object
        if let Some(Value::Object(name_map)) = item_map.get("name") {
            // If the "name" field contains a "description" or "type" field, use it to replace the "name" field in the RedactedObject
            if let Some(name_value) = name_map.get("description").or_else(|| name_map.get("type")) {
                redacted_object.name = name_value.clone();
            }
        }

        // Check if the "reason" field is an object
        if let Some(Value::Object(reason_map)) = item_map.get("reason") {
            // If the "reason" field contains a "description" or "type" field, use it to replace the "reason" field in the RedactedObject
            if let Some(reason_value) = reason_map
                .get("description")
                .or_else(|| reason_map.get("type"))
            {
                redacted_object.reason = reason_value.clone();
            }
        }

        // here is our sanity checking
        if let Some(_final_path_str) = final_path {
            redacted_object = set_result_type_from_json_path(v.clone(), redacted_object);
            match redacted_object.result_type {
                // if you are changing what is considered a "valid" path, you need to change this
                Some(ResultType::Empty1)
                | Some(ResultType::Empty2)
                | Some(ResultType::Replaced1) => {
                    redacted_object.final_path_exists = true;
                }
                _ => {
                    redacted_object.final_path_exists = false;
                }
            }
        }

        result.push(redacted_object);
    }

    result
}

pub fn set_result_type_from_json_path(u: Value, mut item: RedactedObject) -> RedactedObject {
    if let Some(path) = item.final_path.as_deref() {
        let path = path.trim_matches('"'); // Remove double quotes
        match JsonPathInst::from_str(path) {
            Ok(json_path) => {
                let finder = JsonPathFinder::new(Box::new(u.clone()), Box::new(json_path));
                let matches = finder.find_as_path();

                if let Value::Array(paths) = matches {
                    if paths.is_empty() {
                        item.result_type = Some(ResultType::Removed1);
                    } else {
                        for path_value in paths {
                            if let Value::String(found_path) = path_value {
                                item.final_path = Some(found_path.clone()); // Assign found_path to final_path
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
                                        item.result_type = Some(ResultType::Empty1);
                                    } else if str_value.is_empty() {
                                        item.result_type = Some(ResultType::Empty2);
                                    } else {
                                        item.result_type = Some(ResultType::Replaced1);
                                    }
                                } else if value_at_path.is_null() {
                                    item.result_type = Some(ResultType::Removed2);
                                } else if value_at_path.is_array() {
                                    item.result_type = Some(ResultType::Replaced2);
                                } else if value_at_path.is_object() {
                                    item.result_type = Some(ResultType::Replaced3);
                                } else {
                                    item.result_type = Some(ResultType::Removed3);
                                }
                            } else {
                                item.result_type = Some(ResultType::Removed4);
                            }
                        }
                    }
                } else {
                    item.result_type = Some(ResultType::Removed5);
                }
            }
            Err(e) => {
                println!("Failed to parse JSON path '{}': {}", path, e);
            }
        }
    }
    item
}

pub fn check_valid_json_path(u: Value, path: &str) -> bool {
    match JsonPathInst::from_str(path) {
        Ok(json_path) => {
            let finder = JsonPathFinder::new(Box::new(u.clone()), Box::new(json_path));
            let matches = finder.find_as_path();

            if let Value::Array(paths) = matches {
                if !paths.is_empty() {
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
                                    // This is where Empty1 would be
                                    return true;
                                } else if str_value.is_empty() {
                                    // This is where Empty2 would be
                                    return true;
                                } else {
                                    // This is where Replaced1 would be
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            false
        }
        Err(_) => false,
    }
}

// old stuff
pub fn find_paths_to_redact(checks: &[(ResultType, String, String)]) -> Vec<String> {
    checks
        .iter()
        .filter(|(status, _, _)| {
            matches!(
                *status,
                ResultType::Empty1 | ResultType::Empty2 | ResultType::Replaced1 // | ResultType::Removed1 - We no longer can do this, the edge cases make this impossible
            )
        })
        .map(|(_, _, found_path)| found_path.clone())
        .collect()
}

pub fn check_json_paths(u: Value, data: Vec<RedactedObject>) -> Vec<RedactedObject> {
    let mut results = Vec::new();

    for mut item in data {
        let path = item
            .pre_path
            .as_deref()
            .unwrap_or(item.replacement_path.as_deref().unwrap())
            .trim_matches('"'); // Remove double quotes
        match JsonPathInst::from_str(path) {
            Ok(json_path) => {
                let finder = JsonPathFinder::new(Box::new(u.clone()), Box::new(json_path));
                let matches = finder.find_as_path();

                if let Value::Array(paths) = matches {
                    if paths.is_empty() {
                        item.result_type = Some(ResultType::Removed1);
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
                                        item.result_type = Some(ResultType::Empty1);
                                    } else if str_value.is_empty() {
                                        item.result_type = Some(ResultType::Empty2);
                                    } else {
                                        item.result_type = Some(ResultType::Replaced1);
                                    }
                                } else if value_at_path.is_null() {
                                    item.result_type = Some(ResultType::Removed2);
                                } else if value_at_path.is_array() {
                                    item.result_type = Some(ResultType::Replaced2);
                                } else if value_at_path.is_object() {
                                    item.result_type = Some(ResultType::Replaced3);
                                } else {
                                    item.result_type = Some(ResultType::Removed3);
                                }
                            } else {
                                item.result_type = Some(ResultType::Removed4);
                            }
                        }
                    }
                } else {
                    item.result_type = Some(ResultType::Removed5);
                }
            }
            Err(e) => {
                println!("Failed to parse JSON path '{}': {}", path, e);
            }
        }
        results.push(item);
    }
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
        let rdap: RdapResponse = serde_json::from_str(json).unwrap();
        let modified_rdap = replace_redacted_items(rdap);

        // THEN
        // compare the json with the expected json
        let expected_json = r#"
          {"rdapConformance":["rdap_level_0","redacted"],"objectClassName":"domain","handle":"*XXX*","ldhName":"example1.com","links":[{"value":"https://example.com/rdap/domain/example1.com","rel":"self","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"},{"value":"https://example.com/rdap/domain/example1.com","rel":"related","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"}],"redacted":[{"name":{"description":"Registry Domain ID"},"prePath":"$.handle","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}},{"name":{"description":"Registry Domain ID"},"prePath":"$.unicodeName","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}}]}
          "#;

        let expected_rdap: RdapResponse = serde_json::from_str(expected_json).unwrap();

        assert_eq!(modified_rdap, expected_rdap);
    }
}
