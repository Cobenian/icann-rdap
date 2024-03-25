// #![allow(non_snake_case)]

// use crate::test_jig::TestJig;
// use rstest::rstest;

// extern crate jsonpath_lib as jsonpath;
// use jsonpath::replace_with;
// use jsonpath_rust::{JsonPathFinder, JsonPathInst};
// use regex::Regex;
// use serde_json::{json, Value};
// use std::str::FromStr;

// use utils::{
//     add_field, check_json_paths, filter_and_extract_paths, find_paths_to_redact,
//     get_pre_and_post_paths, get_redacted_paths_for_object, ResultType,
// };

// async fn GIVEN_redaction_in_json_WHEN_added_correctly_THEN_success() {
//     // GIVEN
//     let json = r#"
//   {"rdapConformance":["rdap_level_0","redacted"],"objectClassName":"domain","handle":"XXX","ldhName":"example1.com","links":[{"value":"https://example.com/rdap/domain/example1.com","rel":"self","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"},{"value":"https://example.com/rdap/domain/example1.com","rel":"related","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"}],"redacted":[{"name":{"description":"Registry Domain ID"},"prePath":"$.handle","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}},{"name":{"description":"Registry Domain ID"},"prePath":"$.unicodeName","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}}]}
//   "#;

//     // WHEN
//     let mut v: Value = serde_json::from_str(json).unwrap();
//     let jps: Vec<(String, Value, String)> = get_redacted_paths_for_object(&v, "".to_string());
//     let json_paths: Vec<String> = get_pre_and_post_paths(jps);
//     let mut to_change = check_json_paths(v.clone(), json_paths.into_iter().collect());
//     let removed_paths = filter_and_extract_paths(&mut to_change, ResultType::Removed1);
//     let redact_paths = find_paths_to_redact(&to_change);

//     for path in redact_paths {
//         let json_path = &path;
//         match replace_with(v.clone(), json_path, &mut |v| match v.as_str() {
//             Some("") => Some(json!("*REDACTED*")),
//             Some(s) => Some(json!(format!("*{}*", s))),
//             _ => Some(json!("*REDACTED*")),
//         }) {
//             Ok(val) => v = val,
//             Err(e) => {
//                 eprintln!("Error replacing value: {}", e);
//             }
//         }
//     }
//     for path in &removed_paths {
//         // dbg!(&path);
//         add_field(
//             &mut v,
//             path,
//             serde_json::Value::String("*REDACTED*".to_string()),
//         );
//     }

//     // THEN
//     // comparse the json with the expected json
//     let expected_json = r#"
//   {"rdapConformance":["rdap_level_0","redacted"],"objectClassName":"domain","unicodeName": "*REDACTED*", "handle":"*XXX*","ldhName":"example1.com","links":[{"value":"https://example.com/rdap/domain/example1.com","rel":"self","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"},{"value":"https://example.com/rdap/domain/example1.com","rel":"related","href":"https://example.com/rdap/domain/example1.com","type":"application/rdap+json"}],"redacted":[{"name":{"description":"Registry Domain ID"},"prePath":"$.handle","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}},{"name":{"description":"Registry Domain ID"},"prePath":"$.unicodeName","pathLang":"jsonpath","method":"removal","reason":{"type":"Server policy"}}]}
//   "#;

//     assert_eq!(v, serde_json::from_str(expected_json).unwrap());
// }
