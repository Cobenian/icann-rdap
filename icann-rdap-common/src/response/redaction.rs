// These are my first initial thoughts on how we _might_ structure a redacted member according to 
// draft-ietf-regext-rdap-redacted-16
// I'm not saying this is correct, but let's get something down to get things started.

// use buildstructor::Builder;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Name {
    description: String,
}

#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
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
          // provide default values for the fields of Name
      }
  }
}

impl Default for Reason {
  fn default() -> Self {
      Self {
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
          reason: Reason::default(),
          pre_path: None,
          post_path: None,
          path_lang: None,
          replacement_path: None,
          method: Method::default(),
      }
  }
}

// No, don't actually do this. Magic Fairyland right now. Tests to come soon
// fn main() {
// let redaction = Redaction::new()
//     .name( Name { description: "foo".to_string()}) // replace with actual value
//     .reason(Reason::default()) // replace with actual value
//     .pre_path(Some("$.handle".to_string())) // just fake values for now
//     .post_path(Some("$.entities[?(@.roles[0]=='registrant".to_string())) // we wouldn't have both pre_path and post_path, but I'm just showing both here
//     .path_lang(Some("jsonpath".to_string())) 
//     .replacement_path(Some("$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]".to_string())) // again 
//     .method(Method::Removal); // let's get the default value
// }

