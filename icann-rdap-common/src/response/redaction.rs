// These are my first initial thoughts on how we _might_ structure a redacted member according to 
// draft-ietf-regext-rdap-redacted-16
// I'm not saying this is correct, but let's get something down to get things started.


use serde::{Deserialize, Serialize};

// Probably going need these soon!
// use super::{
//   types::{to_option_status, Common, Link, ObjectCommon},
//   GetSelfLink, RdapResponseError, SelfLink, ToChild,
// };

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Name {
    description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Reason {
  #[serde(rename = "description")]
  pub description: Option<String>,

  #[serde(rename = "type")]
  pub type_field: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Method {
    Removal,
    EmptyValue,
    PartialValue,
    ReplacementValue,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Redaction {

  #[serde[rename = "name"]]
  pub name: Name,

  #[serde[rename = "reason"]]
  pub reason: Option<Reason>,

  #[serde[rename = "prePath"]]
  pub pre_path: Option<String>,
  
  #[serde[rename = "postPath"]]
  pub post_path: Option<String>,
  
  #[serde[rename = "pathLang"]]
  pub path_lang: Option<String>,

  #[serde[rename = "replacementPath"]]
  pub replacement_path: Option<String>,

  #[serde(rename = "method")]
  pub method: Method,
  

}

impl Default for Name {
  fn default() -> Self {
      Self {
          description: String::default(),
          // provide default values for the fields of Name
      }
  }
}

impl Default for Reason {
  fn default() -> Self {
      Self {
          description: None,
          type_field: None,
          // provide default values for the fields of Reason
      }
  }
}

impl Default for Method {
  fn default() -> Self {
      Self::Removal // or whatever default you want
  }
}

impl Redaction {
  pub fn new() -> Self {
      Self {
          name: Name::default(),
          reason: Some(Reason::default()),
          pre_path: None,
          post_path: None,
          path_lang: None,
          replacement_path: None,
          method: Method::default(),
      }
  }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn GIVEN_redaction_WHEN_deserialize_THEN_success() {
        //todo: acutally do this deserialization test, not just test the language
        // GIVEN
        let mut name = Redaction::new();
        name.name = Name { description: "foo".to_string() };

        // WHEN
        let mut redaction = name;
        redaction.reason = Some(Reason::default());
        redaction.pre_path = Some("$.handle".to_string());
        redaction.post_path = Some("$.entities[?(@.roles[0]=='registrant".to_string());
        redaction.path_lang = Some("jsonpath".to_string());
        redaction.replacement_path = Some("$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]".to_string());
        redaction.method = Method::Removal;

        // THEN
        assert_eq!(redaction.name.description, "foo");
        assert_eq!(redaction.pre_path, Some("$.handle".to_string()));
        assert_eq!(redaction.post_path, Some("$.entities[?(@.roles[0]=='registrant".to_string()));
        assert_eq!(redaction.path_lang, Some("jsonpath".to_string()));
        assert_eq!(redaction.replacement_path, Some("$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]".to_string()));
        assert_eq!(redaction.method, Method::Removal);
    }
}

