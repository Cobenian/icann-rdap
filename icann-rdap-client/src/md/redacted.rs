use std::str::FromStr;

use icann_rdap_common::response::redacted::Redacted;
use jsonpath::replace_with;
use jsonpath_lib as jsonpath;
use jsonpath_rust::{JsonPathFinder, JsonPathInst};
use serde_json::{json, Map, Value};

use super::{string::StringUtil, table::MultiPartTable, MdOptions, MdParams, ToMd};
use icann_rdap_common::response::RdapResponse;

impl ToMd for &[Redacted] {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();

        // header
        let header_text = "Redacted".to_string();
        md.push_str(&header_text.to_header(params.heading_level, params.options));

        // multipart data
        let mut table = MultiPartTable::new();
        table = table.header_ref(&"Fields");

        for (index, redacted) in self.iter().enumerate() {
            let options = MdOptions {
                text_style_char: '*',
                ..Default::default()
            };

            // make the name bold
            let name = "Redaction";
            let b_name = name.to_bold(&options);
            // build the table
            table = table.and_data_ref(&b_name, &Some((index + 1).to_string()));

            // Get the data itself
            let name_data = redacted
                .name
                .description
                .clone()
                .or(redacted.name.type_field.clone());
            let method_data = redacted.method.as_ref().map(|m| m.to_string());
            let reason_data = redacted.reason.as_ref().map(|m| m.to_string());

            // Special case the 'column' fields
            table = table
                .and_data_ref(&"name".to_title_case(), &name_data)
                .and_data_ref(&"prePath".to_title_case(), &redacted.pre_path)
                .and_data_ref(&"postPath".to_title_case(), &redacted.post_path)
                .and_data_ref(
                    &"replacementPath".to_title_case(),
                    &redacted.replacement_path,
                )
                .and_data_ref(&"pathLang".to_title_case(), &redacted.path_lang)
                .and_data_ref(&"method".to_title_case(), &method_data)
                .and_data_ref(&"reason".to_title_case(), &reason_data);

            // we don't have these right now but if we put them in later we will need them
            // let check_params = CheckParams::from_md(params, typeid);
            // let mut checks = redacted.object_common.get_sub_checks(check_params);
            // checks.push(redacted.get_checks(check_params));
            // table = checks_to_table(checks, table, params);
        }

        // render table
        md.push_str(&table.to_md(params));
        md.push('\n');
        md
    }
}

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
    NotAString,                // if it's not a string, we can't do anything with it
}

// This isn't just based on the string type that is in the redaction method, but also based on the result type above
#[derive(Debug, PartialEq, Clone)]
pub enum ActionType {
    SubstituteEmptyValue,
    SubstitutePartialValue,
    DoNothing,
}

#[derive(Debug, Clone)]
pub struct RedactedInfo {
    pub paths_found_count: i32,    // how many paths does the json resolve to?
    pub post_path: Option<String>, // the postPath
    pub original_path: Option<String>, // the original path that was put into the redaction
    pub final_path: Vec<Option<String>>, // a vector of the paths where we put a partialValue or emptyValue
    pub do_substitution: bool,           // if we are modifying anything or not
    pub method: Value,                   // the method they are using
    pub result_type: Vec<Option<ResultType>>, // a vec of our own internal Results we found
    pub action_type: Option<ActionType>, //
}

// this is our public entry point
pub fn replace_redacted_items(orignal_response: RdapResponse) -> RdapResponse {
    // convert the RdapResponse to a string
    let rdap_json = serde_json::to_string(&orignal_response).unwrap();

    // check if the "redacted" string is in the JSON string
    if !rdap_json.contains("\"redacted\"") {
        // If there are no redactions, return the original response
        return orignal_response;
    }

    // convert the string to a JSON Value
    let mut rdap_json_response: Value = serde_json::from_str(&rdap_json).unwrap();
    // Initialize the final response with the original response
    let mut response = orignal_response;
    // pull the redacted array out of the JSON
    let redacted_array_option = rdap_json_response["redacted"].as_array().cloned();

    // if there are any redactions we need to do some modifications
    if let Some(redacted_array) = redacted_array_option {
        // Check if "redacted" is an array and has more than one element
        if !redacted_array.is_empty() {
            parse_redacted_json(&mut rdap_json_response, Some(&redacted_array));
            // convert the Value back to a RdapResponse
            response = serde_json::from_value(rdap_json_response).unwrap();
        }
    } // END if there are redactions

    // send the response back so we can display it to the client
    response
}

fn replace_json_value(
    rdap_json_response: &mut serde_json::Value,
    final_path: &str,
    final_value: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    replace_with(rdap_json_response.clone(), final_path, &mut |x| {
        if x.is_string() {
            match x.as_str() {
                Some("") => Some(json!("*REDACTED*")),
                Some(s) => Some(json!(format!("*{}*", s))),
                _ => Some(json!("*REDACTED*")),
            }
        } else {
            Some(final_value.clone())
        }
    })
    .map_err(|e| e.into())
}

fn parse_redacted_json(
    rdap_json_response: &mut serde_json::Value,
    redacted_array_option: Option<&Vec<serde_json::Value>>,
) {
    if let Some(redacted_array) = redacted_array_option {
        let redactions = parse_redacted_array(rdap_json_response, redacted_array);
        // Loop through the RedactedObjects
        for redacted_object in redactions {
            // If we have determined we are doing some kind of substitution
            if redacted_object.do_substitution && !redacted_object.final_path.is_empty() {
                let path_count = redacted_object.paths_found_count as usize;
                for path_index_count in 0..path_count {
                    let final_path_option = &redacted_object.final_path[path_index_count];
                    if let Some(final_path) = final_path_option {
                        // This is a replacement and we SHOULD NOT be doing this until it is sorted out.
                        if let Some(redaction_type) = &redacted_object.action_type {
                            if *redaction_type == ActionType::SubstituteEmptyValue
                                || *redaction_type == ActionType::SubstitutePartialValue
                            {
                                // convert the final_path to a json pointer path
                                let final_path_str = convert_to_json_pointer_path(final_path);
                                // grab the value at the end point of the JSON path
                                let final_value = match rdap_json_response.pointer(&final_path_str)
                                {
                                    Some(value) => value.clone(),
                                    None => {
                                        continue;
                                    }
                                };

                                // actually do the replace_with
                                let replaced_json = replace_json_value(
                                    rdap_json_response,
                                    final_path,
                                    &final_value,
                                );
                                // Now we check if we did something
                                match replaced_json {
                                    Ok(new_v) => {
                                        *rdap_json_response = new_v; // we replaced something so now we need to update the response
                                    }
                                    _ => {
                                        // Do nothing but we need to investigate why this is happening
                                    }
                                } // end match replace_with
                            } // end if doing partialValue or emptyValue
                        } // end if redaction_type
                    } // end if final_path_option
                } // end for each path_index_count
            } // end if final_path
        } // end loop over redactions
    } // end if there is a redacted array
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
    pointer_path
}

fn create_redacted_info_object(item_map: &Map<String, Value>) -> RedactedInfo {
    let post_path = item_map
        .get("postPath")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    // this is the original_path given to us
    let original_path = post_path.clone();

    let redacted_object = RedactedInfo {
        paths_found_count: 0, // Set to 0 initially
        post_path,
        original_path,
        final_path: Vec::new(), // final path we are doing something with
        do_substitution: false, // flag whether we ACTUALLY doing something or not
        method: item_map
            .get("method")
            .unwrap_or(&Value::String(String::from("")))
            .clone(),
        result_type: Vec::new(), // Set to an empty Vec<Option<ResultType>> initially
        action_type: None,       // Set to None initially
    };

    redacted_object
}

fn set_final_path_substitution(redacted_object: &mut RedactedInfo) {
    match redacted_object.action_type {
        Some(ActionType::SubstituteEmptyValue) | Some(ActionType::SubstitutePartialValue) => {
            redacted_object.do_substitution = true;
        }
        _ => {
            redacted_object.do_substitution = false;
        }
    }
}

fn set_action_type(redacted_object: &mut RedactedInfo) {
    let is_valid_result_type = |result_type: &Option<ResultType>| {
        matches!(
            result_type,
            Some(ResultType::StringNoValue)
                | Some(ResultType::EmptyString)
                | Some(ResultType::PartialString)
        )
    };

    let which_action_type = |redaction_type: ActionType, redacted_object: &mut RedactedInfo| {
        if !redacted_object.result_type.is_empty()
            && redacted_object.result_type.iter().all(is_valid_result_type)
        {
            redacted_object.action_type = Some(redaction_type);
        } else {
            redacted_object.action_type = Some(ActionType::DoNothing);
        }
    };

    match redacted_object.method.as_str() {
        Some("emptyValue") => which_action_type(ActionType::SubstituteEmptyValue, redacted_object),
        Some("partialValue") => {
            which_action_type(ActionType::SubstitutePartialValue, redacted_object)
        }
        _ => redacted_object.action_type = Some(ActionType::DoNothing),
    }
}

fn parse_redacted_array(
    rdap_json_response: &Value,
    redacted_array: &Vec<Value>,
) -> Vec<RedactedInfo> {
    let mut list_of_redactions: Vec<RedactedInfo> = Vec::new();

    for item in redacted_array {
        let item_map = item.as_object().unwrap();
        let mut redacted_object = create_redacted_info_object(item_map);

        // this has to happen here, before everything else
        redacted_object = set_result_type(rdap_json_response.clone(), &mut redacted_object);

        // check the method and result_type to determine the redaction_type
        set_action_type(&mut redacted_object);

        // now we need to check if we need to do the final path substitution
        set_final_path_substitution(&mut redacted_object);

        // put the redacted_object into the list of them
        list_of_redactions.push(redacted_object);
    }

    list_of_redactions
}

fn process_paths(u: &Value, paths: Vec<Value>, item: &mut RedactedInfo, no_value: &Value) {
    for path_value in paths {
        if let Value::String(found_path) = path_value {
            item.final_path.push(Some(found_path.clone())); // Push found_path to final_path on the redacted object
            let json_pointer = convert_to_json_pointer_path(&found_path);
            let value_at_path = u.pointer(&json_pointer).unwrap_or(no_value);
            if value_at_path.is_string() {
                let str_value = value_at_path.as_str().unwrap_or("");
                if str_value == "NO_VALUE" {
                    item.result_type.push(Some(ResultType::StringNoValue));
                } else if str_value.is_empty() {
                    item.result_type.push(Some(ResultType::EmptyString));
                } else {
                    item.result_type.push(Some(ResultType::PartialString));
                }
                continue;
            }
        }
        item.result_type.push(Some(ResultType::NotAString));
    }
}

fn process_json_path(u: Value, json_path: JsonPathInst, item: &mut RedactedInfo) {
    let finder = JsonPathFinder::new(Box::new(u.clone()), Box::new(json_path));
    let matches = finder.find_as_path();

    if let Value::Array(paths) = matches {
        if paths.is_empty() {
            item.result_type.push(Some(ResultType::Removed));
        } else {
            // get the length of paths
            let len = paths.len();
            // set the path_index_length to the length of the paths
            item.paths_found_count = len as i32;
            let no_value = Value::String("NO_VALUE".to_string()); // Moved outside the loop
            process_paths(&u, paths, item, &no_value);
        }
    } else {
        item.result_type.push(Some(ResultType::NotAString));
    }
}

// we are setting our own internal ResultType for each item that is found in the jsonPath
pub fn set_result_type(u: Value, item: &mut RedactedInfo) -> RedactedInfo {
    if let Some(path) = item.original_path.as_deref() {
        match JsonPathInst::from_str(path) {
            Ok(json_path) => process_json_path(u, json_path, item),
            Err(_e) => {
                // siliently fail???
                // dbg!("Failed to parse JSON path '{}': {}", path, e);
            }
        }
    }
    item.clone()
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
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
        crate::md::redacted::parse_redacted_json(
            &mut rdap_json_response,
            redacted_array_option.as_ref(),
        );

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
