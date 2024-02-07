// These are my first initial thoughts on how we _might_ structure a redacted member according to
// draft-ietf-regext-rdap-redacted-16
// I'm not saying this is correct, but let's get something down to get things started.

use std::any::TypeId;

use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use crate::check::{items, Checks};

use super::types::Common;

// Probably going need these soon!
// use super::{
//   types::{to_option_status, Common, Link, ObjectCommon},
//   GetSelfLink, RdapResponseError, SelfLink, ToChild,
// };

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Name {
    #[serde(rename = "description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default)]
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

impl Name {
    // Getter for `description`
    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    // Getter for `type_`
    pub fn type_(&self) -> Option<&String> {
        self.type_.as_ref()
    }
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
pub struct Redacted {
    #[serde(flatten)]
    pub common: Common,

    // Required
    #[serde[rename = "name"]]
    pub name: Name,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde[rename = "reason"]]
    pub reason: Option<Reason>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde[rename = "prePath"]]
    pub pre_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde[rename = "postPath"]]
    pub post_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde[rename = "pathLang"]]
    pub path_lang: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde[rename = "replacementPath"]]
    pub replacement_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "method")]
    pub method: Option<Method>,
}

impl Default for Name {
    fn default() -> Self {
        Self {
            description: Some(String::default()),
            type_: None,
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
        Self::Removal // according to IETF draft this is the default
    }
}

impl Redacted {
    pub fn new() -> Self {
        Self {
            name: Name::default(),
            reason: Some(Reason::default()),
            pre_path: None,
            post_path: None,
            path_lang: None,
            replacement_path: None,
            method: Some(Method::default()),
            common: Common::builder().build(), // we have to have this appease the compiler but we ARE common now?? wtf?
                                               // common: Common::level0_with_options().extension("redacted").build(),
        }
    }

    pub fn get_checks(
        &self,
        _check_params: crate::check::CheckParams<'_>,
    ) -> crate::check::Checks<'_> {
        Checks {
            struct_name: "RDAP Conformance",
            items: Vec::new(),
            sub_checks: Vec::new(),
        }
    }

    pub fn get_type(&self) -> std::any::TypeId {
        TypeId::of::<Redacted>()
    }
}

/// Represents RDAP nameserver search results.
#[derive(Serialize, Deserialize, Builder, Clone, PartialEq, Debug, Eq)]
pub struct RedactedResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "redacted")]
    pub results: Vec<Redacted>,
}

#[buildstructor::buildstructor]
impl RedactedResults {
    #[builder(entry = "basic")]
    pub fn new_empty() -> Self {
        Self {
            common: Common::builder().build(),
            results: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn GIVEN_redaction_WHEN_set_THEN_success() {
        // this is a just to test that I set up the structures correctly
        // Should you change them, this will fail
        // GIVEN
        let mut name = Redacted::new();
        name.name = Name {
            description: Some("Registry Domain ID".to_string()),
            type_: None,
        };

        // WHEN
        let mut redacted = name;
        redacted.reason = Some(Reason::default());
        redacted.pre_path = Some("$.handle".to_string());
        redacted.post_path = Some("$.entities[?(@.roles[0]=='registrant".to_string());
        redacted.path_lang = Some("jsonpath".to_string());
        redacted.replacement_path = Some(
            "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                .to_string(),
        );
        redacted.method = Some(Method::Removal);

        // THEN
        assert_eq!(
            redacted.name.description,
            Some("Registry Domain ID".to_string())
        );
        assert_eq!(redacted.pre_path, Some("$.handle".to_string()));
        assert_eq!(
            redacted.post_path,
            Some("$.entities[?(@.roles[0]=='registrant".to_string())
        );
        assert_eq!(redacted.path_lang, Some("jsonpath".to_string()));
        assert_eq!(
            redacted.replacement_path,
            Some(
                "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                    .to_string()
            )
        );
        assert_eq!(redacted.method, Some(Method::Removal));
    }

    #[test]
    fn GIVEN_redaction_WHEN_deserialize_THEN_success() {
        //this is the actual serialization test
        // GIVEN
        let expected = r#"
        {
          "name": {
            "description": "Registry Domain ID"
          },
          "prePath": "$.handle",
          "pathLang": "jsonpath",
          "postPath": "$.entities[?(@.roles[0]=='registrant",
          "replacementPath": "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]",
          "method": "removal",
          "reason": {
            "description": "Server policy"
          }
        }
        "#;

        let mut name: Redacted = Redacted::new();
        name.name = Name {
            description: Some("Registry Domain ID".to_string()),
            type_: None,
        };

        let reason: Reason = Reason {
            description: Some("Server policy".to_string()),
            type_field: None,
        };

        // WHEN
        let mut sample_redact: Redacted = name;
        sample_redact.pre_path = Some("$.handle".to_string());
        sample_redact.path_lang = Some("jsonpath".to_string());
        sample_redact.post_path = Some("$.entities[?(@.roles[0]=='registrant".to_string());
        sample_redact.replacement_path = Some(
            "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                .to_string(),
        );
        sample_redact.method = Some(Method::Removal);
        sample_redact.reason = Some(reason);

        let actual: Result<Redacted, serde_json::Error> =
            serde_json::from_str::<Redacted>(expected);

        // THEN
        let actual: Redacted = actual.unwrap();
        assert_eq!(actual, sample_redact); // sanity check
        assert_eq!(
            actual.name.description,
            Some("Registry Domain ID".to_string())
        );
        assert_eq!(actual.pre_path, Some("$.handle".to_string()));
        assert_eq!(
            actual.post_path,
            Some("$.entities[?(@.roles[0]=='registrant".to_string())
        );
        assert_eq!(actual.path_lang, Some("jsonpath".to_string()));
        assert_eq!(
            actual.replacement_path,
            Some(
                "$.entities[?(@.roles[0]=='registrant')].vcardArray[1][?(@[0]=='contact-uri')]"
                    .to_string()
            )
        );
        assert_eq!(actual.method, Some(Method::Removal));
    }
}
