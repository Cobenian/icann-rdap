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
    description: String,
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
  pub reason: Reason,

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