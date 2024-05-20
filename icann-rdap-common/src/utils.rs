use std::str::FromStr;

use jsonpath::replace_with;
use jsonpath_lib as jsonpath;
use jsonpath_rust::{JsonPathFinder, JsonPathInst};
use serde_json::{json, Value};

use crate::response;
use response::RdapResponse;

// These are the different types of results that we can get from the JSON path checks
#[derive(Debug, PartialEq, Clone)]
pub enum ResultType {
    StringNoValue, // (*) what we found in the value paths array was a string but has no value (yes, this is a little weird, but does exist) `Redaction by Empty Value`
    EmptyString, // (*) what we found in the value paths array was a string but it is an empty string `Redaction by Empty Value`
    PartialString, // (*) what we found in the value paths array was a string and it does have a value `Redaction by Partial Value` and/or `Redaction by Replacement Value`
    Array, // what we found in the value paths array was _another_ array (have never found this w/ redactions done correctly)
    Object, // what we found in the value paths array was an object (have never found this w/ redactions done correctly)
    Removed, // (*) paths array is empty, finder.find_as_path() found nothing `Redaction by Removal`
    FoundNull, // value in paths array is null (have never found this w/ redactions done correctly)
    FoundNothing, // fall through, value in paths array is not anything else (have never found this w/ redactions done correctly)
    FoundUnknown, // what we found was not a JSON::Value::string (have never found this w/ redactions done correctly)
    FoundPathReturnedBadValue, // what finder.find_as_path() returned was not a Value::Array (have never found this, could possibly be an error)
}

#[derive(Debug, Clone)]
pub struct RedactedObject {
    pub name: Value,                     // Get the description's name or type
    pub path_index_count: i32,           // how many paths does the json resolve to?
    pub pre_path: Option<String>,        // the prePath
    pub post_path: Option<String>,       // the postPath
    pub original_path: Option<String>,   // the original path that was put into the redaction
    pub final_path: Vec<Option<String>>, // a vector of the paths where we put a partialValue or emptyValue
    pub do_final_path_subsitution: bool, // if we are modifying anything or not
    pub path_lang: Value, // the path_lang they put in, these may be used in the future
    pub replacement_path: Option<String>,
    pub method: Value,                         // the method they are using
    pub reason: Value,                         // the reason
    pub result_type: Vec<Option<ResultType>>,  // a vec of our own internal Results we found
    pub redaction_type: Option<RedactionType>, //
}

// This isn't just based on the string type that is in the redaction method, but also based on the result type above
#[derive(Debug, PartialEq, Clone)]
pub enum RedactionType {
    EmptyValue,
    PartialValue,
    ReplacementValue,
    Removal,
    Unknown,
}

// this is our public entry point
pub fn replace_redacted_items(orignal_response: RdapResponse) -> RdapResponse {
    // convert the RdapResponse to a string
    let rdap_json = serde_json::to_string(&orignal_response).unwrap();
    // convert the string to a JSON Value
    let mut rdap_json_response: Value = serde_json::from_str(&rdap_json).unwrap();
    // Initialize the final response with the original response
    let mut response = orignal_response;
    // pull the redacted array out of the JSON
    let redacted_array_option = rdap_json_response["redacted"].as_array().cloned();

    // if there are any redactions we need to do some modifications
    if let Some(ref redacted_array) = redacted_array_option {
        parse_redacted_json(&mut rdap_json_response, Some(redacted_array));
        // convert the Value back to a RdapResponse
        response = serde_json::from_value(rdap_json_response).unwrap();
    } // END if there are redactions

    // send the response back so we can display it to the client
    response
}

fn parse_redacted_json(
    rdap_json_response: &mut serde_json::Value,
    redacted_array_option: Option<&Vec<serde_json::Value>>,
) {
    if let Some(redacted_array) = redacted_array_option {
        let redactions = parse_redacted_array(rdap_json_response, redacted_array);
        // Loop through the RedactedObjects
        for redacted_object in redactions {
            dbg!("Processing redacted_object...");
            dbg!(&redacted_object);
            // If we have determined we are doing some kind of substitution
            if redacted_object.do_final_path_subsitution {
                dbg!("final_path_exists is true");
                if !redacted_object.final_path.is_empty() {
                    let path_count = redacted_object.path_index_count as usize;
                    for path_index_count in 0..path_count {
                        let final_path_option = &redacted_object.final_path[path_index_count];
                        let result_type = &redacted_object.result_type[path_index_count];
                        dbg!(
                            "Processing final_path: {:?}, result_type: {:?}",
                            final_path_option,
                            result_type
                        );
                        if let Some(final_path) = final_path_option {
                            dbg!("Found final_path: {}", final_path);
                            dbg!(final_path);
                            // This is a replacement and we SHOULD NOT be doing this until it is sorted out.
                            // For experimental reasons though, we shall continue.
                            if let Some(redaction_type) = &redacted_object.redaction_type {
                                if *redaction_type == RedactionType::ReplacementValue {
                                    dbg!("we have a replacement value");
                                    // dbg!(&redacted_object);

                                    // let replacement_path_str;

                                    // if let Some(replacement_path) =
                                    //     redacted_object.replacement_path.as_ref()
                                    // {
                                    //     dbg!("Replacement path: {}", replacement_path);
                                    //     replacement_path_str =
                                    //         convert_to_json_pointer_path(replacement_path);
                                    // } else {
                                    //     dbg!("CONTINUE b/c replacement not found");
                                    //     continue;
                                    // }

                                    // dbg!(&replacement_path_str);

                                    // let final_replacement_value = match rdap_json_response
                                    //     .pointer(&replacement_path_str)
                                    // {
                                    //     Some(value) => {
                                    //         dbg!("Pointer Found replacement value: {:?}", value);
                                    //         value
                                    //     }
                                    //     None => {
                                    //         dbg!("CONTINUE b/c final_path not found");
                                    //         continue;
                                    //     }
                                    // };
                                    // dbg!(&final_replacement_value);

                                    // // Unwrap final_path and replacement_path to get a String and then get a reference to the String to get a &str
                                    // let final_path = redacted_object
                                    //     // .final_path
                                    //     .final_path[path_index_count]
                                    //     .as_ref()
                                    //     .expect("final_path is None");

                                    // // With the redaction I am saying that I am replacing the value at the prePath with the value from the replacementPath.
                                    // // So, in essence, it is a copy. replacementPath = source, prePath = target.
                                    // match replace_with(
                                    //     rdap_json_response.clone(),
                                    //     final_path,
                                    //     &mut |_| Some(json!(final_replacement_value)),
                                    // ) {
                                    //     Ok(new_v) => {
                                    //         *rdap_json_response = new_v;
                                    //         dbg!("Replaced value at replacement_path");
                                    //     }
                                    //     Err(e) => {
                                    //         dbg!("Failed to replace value at replacement_path: ");
                                    //         dbg!(e);
                                    //     }
                                    //} // end match replace_with
                                } else if *redaction_type == RedactionType::EmptyValue
                                    || *redaction_type == RedactionType::PartialValue
                                {
                                    dbg!("we have an empty or partial value");
                                    // dbg!(&redacted_object);

                                    // convert the final_path to a json pointer path
                                    let final_path_str = convert_to_json_pointer_path(final_path);

                                    // grab the value at the end point of the JSON path
                                    let final_value =
                                        match rdap_json_response.pointer(&final_path_str) {
                                            Some(value) => {
                                                dbg!("Pointer Found value: {:?}", value);
                                                value.clone()
                                            }
                                            None => {
                                                dbg!("CONTINUE b/c final_path not found");
                                                continue;
                                            }
                                        };

                                    dbg!("Final path: {:?}", final_path);
                                    // actually do the replace_with
                                    let replaced_json = replace_with(
                                        rdap_json_response.clone(),
                                        final_path,
                                        &mut |x| {
                                            dbg!("Replacing value...");
                                            // STRING ONLY! This is the only spot where we are ACTUALLY replacing or updating something
                                            if x.is_string() {
                                                match x.as_str() {
                                                    Some("") => {
                                                        dbg!("Value is an empty string");
                                                        Some(json!("*REDACTED*"))
                                                    }
                                                    Some(s) => {
                                                        dbg!("Value is a string: {}", s);
                                                        Some(json!(format!("*{}*", s)))
                                                    }
                                                    _ => {
                                                        dbg!("Value is a non-string");
                                                        Some(json!("*REDACTED*"))
                                                    }
                                                }
                                            } else if x.is_null() {
                                                dbg!("Value is null");
                                                Some(final_value.clone()) // copy the found value back to it
                                            } else if x.is_boolean() {
                                                dbg!("Value is a boolean");
                                                Some(final_value.clone()) // copy the found value back to it
                                            } else if x.is_number() {
                                                dbg!("Value is a number");
                                                Some(final_value.clone()) // copy the found value back to it
                                            } else if x.is_array() {
                                                dbg!("Value is an array");
                                                Some(final_value.clone()) // copy the found value back to it
                                            } else if x.is_object() {
                                                dbg!("Value is an object");
                                                Some(final_value.clone()) // copy the found value back to it
                                            } else {
                                                dbg!("Value is not a string");
                                                Some(final_value.clone()) // copy the found value back to it
                                            }
                                        },
                                    );
                                    // Now we check if we did something
                                    match replaced_json {
                                        Ok(new_v) => {
                                            *rdap_json_response = new_v; // we replaced something so now we need to update the response
                                            dbg!("Replaced value at empty or partial path");
                                        }
                                        _ => {
                                            // Do nothing but debug out b/c we need to investigate why this is happening
                                            dbg!(
                                                "Failed to replace value at empty or partial path - WHY?"
                                            );
                                        }
                                    } // end match replace_with
                                    dbg!("End match replace with...");
                                } else {
                                    dbg!("other type of object - we did nothing with it");
                                } // end if replacementValue
                                  // You can now use result_type here
                                dbg!("Result type: {:?}", result_type);
                            } // end if redaction_type
                        } // end if final_path_option
                    } // end for each path_index_count
                } // end !redacted_object.final_path.is_empty()
            } // end if we are doing final_path_subsitution or not
        } // end for each redacted_object
    } else {
        // there is no redacted array to do anything with
    }
}

// This cleans it up into a json pointer which is what we need to use to get the value
fn convert_to_json_pointer_path(path: &str) -> String {
    let pointer_path = path
        .trim_start_matches('$')
        .replace('.', "/")
        .replace("['", "/")
        .replace("']", "")
        .replace('[', "/")
        .replace(']', "")
        .replace("//", "/");
    dbg!(&pointer_path);
    pointer_path
}

fn parse_redacted_array(
    rdap_json_response: &Value,
    redacted_array: &Vec<Value>,
) -> Vec<RedactedObject> {
    let mut list_of_redactions: Vec<RedactedObject> = Vec::new();

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
        // this is the original_path given to us
        let original_path = pre_path.clone().or(post_path.clone());
        let mut redacted_object = RedactedObject {
            name: Value::String(String::from("")), // Set to empty string initially
            path_index_count: 0,                   // Set to 0 initially
            pre_path,
            post_path,
            original_path,
            final_path: Vec::new(), // final path we are doing something with
            do_final_path_subsitution: false, // flag whether we ACTUALLY doing something or not
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
            result_type: Vec::new(), // Set to an empty Vec<Option<ResultType>> initially
            redaction_type: None,    // Set to None initially
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

        // this has to happen here, before everything else
        redacted_object =
            set_result_type_from_json_path(rdap_json_response.clone(), &mut redacted_object);

        // check the method and result_type to determine the redaction_type
        if let Some(method) = redacted_object.method.as_str() {
            // we don't just assume you are what you say you are...
            match method {
                "emptyValue" => {
                    if !redacted_object.result_type.is_empty() {
                        // I have relaxed the rules around this one, so we can have partialValue as well counts, so if someone has inadvertently added a partialValue to an emptyValue, it will still be redacted
                        if redacted_object.result_type.iter().all(|result_type| {
                            matches!(
                                result_type,
                                Some(ResultType::StringNoValue)
                                    | Some(ResultType::EmptyString)
                                    | Some(ResultType::PartialString)
                            )
                        }) {
                            redacted_object.redaction_type = Some(RedactionType::EmptyValue);
                        } else {
                            redacted_object.redaction_type = Some(RedactionType::Unknown);
                        }
                    } else {
                        // the result_type is empty, so we don't know what it is
                        redacted_object.redaction_type = Some(RedactionType::Unknown);
                    }
                }
                "partialValue" => {
                    if !redacted_object.result_type.is_empty() {
                        if redacted_object.result_type.iter().all(|result_type| {
                            // matches!(result_type, Some(ResultType::PartialString))
                            matches!(
                                result_type,
                                Some(ResultType::StringNoValue)
                                    | Some(ResultType::EmptyString)
                                    | Some(ResultType::PartialString)
                            )
                        }) {
                            redacted_object.redaction_type = Some(RedactionType::PartialValue);
                        } else {
                            redacted_object.redaction_type = Some(RedactionType::Unknown);
                        }
                    } else {
                        // the result_type is empty, so we don't know what it is
                        redacted_object.redaction_type = Some(RedactionType::Unknown);
                    }
                }
                "replacementValue" => {
                    if !redacted_object.result_type.is_empty() {
                        if redacted_object.result_type.iter().all(|result_type| {
                            matches!(result_type, Some(ResultType::PartialString))
                        }) {
                            if redacted_object.replacement_path.is_some()
                                && !redacted_object
                                    .replacement_path
                                    .as_ref()
                                    .unwrap()
                                    .is_empty()
                                && (redacted_object.pre_path.is_some()
                                    && !redacted_object.pre_path.as_ref().unwrap().is_empty()
                                    || redacted_object.post_path.is_some()
                                        && !redacted_object.post_path.as_ref().unwrap().is_empty())
                            {
                                redacted_object.redaction_type =
                                    Some(RedactionType::ReplacementValue);
                            } else if redacted_object.replacement_path.is_none()
                                && (redacted_object.pre_path.is_some()
                                    && !redacted_object.pre_path.as_ref().unwrap().is_empty()
                                    || redacted_object.post_path.is_some()
                                        && !redacted_object.post_path.as_ref().unwrap().is_empty())
                            {
                                // this logic is really a partial value
                                redacted_object.redaction_type = Some(RedactionType::PartialValue);
                            } else {
                                redacted_object.redaction_type = Some(RedactionType::Unknown);
                            }
                        } else {
                            redacted_object.redaction_type = Some(RedactionType::Unknown);
                        }
                    } else {
                        // the result_type is empty, so we don't know what it is
                        redacted_object.redaction_type = Some(RedactionType::Unknown);
                    }
                }
                "removal" => {
                    if !redacted_object.result_type.is_empty() {
                        if redacted_object
                            .result_type
                            .iter()
                            .all(|result_type| matches!(result_type, Some(ResultType::Removed)))
                        {
                            // they were all removals so mark it as such
                            redacted_object.redaction_type = Some(RedactionType::Removal);
                        } else {
                            redacted_object.redaction_type = Some(RedactionType::Unknown);
                        }
                    } else {
                        // the result_type is empty, so we don't know what it is
                        redacted_object.redaction_type = Some(RedactionType::Unknown);
                    }
                }
                _ => {
                    // what they put in doesn't match any of the accepted values
                    redacted_object.redaction_type = Some(RedactionType::Unknown);
                }
            }
        } else {
            // the method was not a string, just mark it as Unknown
            redacted_object.redaction_type = Some(RedactionType::Unknown);
        }

        // now we need to check if we need to do the final path substitution
        match redacted_object.redaction_type {
            // if you are changing what you're going to subsitute on, you need to change this.
            Some(RedactionType::EmptyValue) | Some(RedactionType::PartialValue) => {
                // | Some(RedactionType::ReplacementValue) => {
                redacted_object.do_final_path_subsitution = true;
            }
            _ => {
                redacted_object.do_final_path_subsitution = false;
            }
        }

        // put the redacted_object into the list of them
        list_of_redactions.push(redacted_object);
    }

    list_of_redactions
}

// we are setting our own internal ResultType for each item that is found in the jsonPath
pub fn set_result_type_from_json_path(u: Value, item: &mut RedactedObject) -> RedactedObject {
    if let Some(path) = item.original_path.as_deref() {
        let path = path.trim_matches('"'); // Remove double quotes
        match JsonPathInst::from_str(path) {
            Ok(json_path) => {
                let finder = JsonPathFinder::new(Box::new(u.clone()), Box::new(json_path));
                let matches = finder.find_as_path();

                if let Value::Array(paths) = matches {
                    if paths.is_empty() {
                        item.result_type.push(Some(ResultType::Removed));
                    } else {
                        // get the length of paths
                        let len = paths.len();
                        dbg!("PXP Found {} paths", len);
                        // set the path_index_length to the length of the paths
                        item.path_index_count = len as i32;
                        dbg!(&paths);
                        for path_value in paths {
                            if let Value::String(found_path) = path_value {
                                item.final_path.push(Some(found_path.clone())); // Push found_path to final_path on the redacted object
                                let no_value = Value::String("NO_VALUE".to_string());
                                let json_pointer = convert_to_json_pointer_path(&found_path);
                                let value_at_path = u.pointer(&json_pointer).unwrap_or(&no_value);
                                if value_at_path.is_string() {
                                    let str_value = value_at_path.as_str().unwrap_or("");
                                    if str_value == "NO_VALUE" {
                                        item.result_type.push(Some(ResultType::StringNoValue));
                                        dbg!("!! Value at path is NO_VALUE");
                                    } else if str_value.is_empty() {
                                        item.result_type.push(Some(ResultType::EmptyString));
                                        dbg!("!! Value at path is an empty string");
                                    } else {
                                        item.result_type.push(Some(ResultType::PartialString));
                                        dbg!("!! Value at path is a string: {}", str_value);
                                    }
                                } else if value_at_path.is_null() {
                                    dbg!("!! Value at path is null");
                                    item.result_type.push(Some(ResultType::FoundNull));
                                } else if value_at_path.is_array() {
                                    dbg!("!! Value at path is an array");
                                    item.result_type.push(Some(ResultType::Array));
                                } else if value_at_path.is_object() {
                                    dbg!("!! Value at path is an object");
                                    item.result_type.push(Some(ResultType::Object));
                                } else {
                                    dbg!("!! Value at path is not a string - FoundNothing");
                                    item.result_type.push(Some(ResultType::FoundNothing));
                                }
                            } else {
                                dbg!("!! Value at path is not a string - FoundUnknown");
                                item.result_type.push(Some(ResultType::FoundUnknown));
                            }
                        }
                    }
                } else {
                    dbg!("!! Finder.find_as_path() returned a bad value");
                    item.result_type
                        .push(Some(ResultType::FoundPathReturnedBadValue));
                }
            }
            Err(e) => {
                dbg!("Failed to parse JSON path '{}': {}", path, e);
            }
        }
    }
    item.clone()
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::utils::*;
    use serde_json::Value;
    use std::error::Error;
    use std::fs::File;
    use std::io::Read;

    fn process_redacted_file(file_path: &str) -> Result<String, Box<dyn Error>> {
        let mut file = File::open(file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // this has to be setup very specifically, just like replace_redacted_items is setup.
        let mut rdap_json_response: Value = serde_json::from_str(&contents)?;
        let redacted_array_option = rdap_json_response["redacted"].as_array().cloned();
        // we are testing parse_redacted_json here -- just the JSON transforms
        parse_redacted_json(&mut rdap_json_response, redacted_array_option.as_ref());

        let pretty_json = serde_json::to_string_pretty(&rdap_json_response)?;
        println!("{}", pretty_json);
        Ok(pretty_json)
    }

    #[test]
    fn test_process_empty_value() {
        let expected_output =
            std::fs::read_to_string("src/test_files/example-1_empty_value-expected.json").unwrap();
        let output = process_redacted_file("src/test_files/example-1_empty_value.json").unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_process_partial_value() {
        let expected_output =
            std::fs::read_to_string("src/test_files/example-2_partial_value-expected.json")
                .unwrap();
        let output = process_redacted_file("src/test_files/example-2_partial_value.json").unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_process_dont_replace_number() {
        let expected_output = std::fs::read_to_string(
            "src/test_files/example-3-dont_replace_redaction_of_a_number.json",
        )
        .unwrap();
        // we don't need an expected for this one, it should remain unchanged
        let output = process_redacted_file(
            "src/test_files/example-3-dont_replace_redaction_of_a_number.json",
        )
        .unwrap();
        assert_eq!(output, expected_output);
    }
}
