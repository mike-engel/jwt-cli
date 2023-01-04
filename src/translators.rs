use crate::utils::parse_duration_string;
use chrono::{TimeZone, Utc};
use clap::ValueEnum;
use serde_derive::{Deserialize, Serialize};
use serde_json::{from_str, Value};
use std::collections::BTreeMap;

pub mod decode;
pub mod encode;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadItem(pub String, pub Value);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload(pub BTreeMap<String, Value>);

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, ValueEnum)]
pub enum SupportedTypes {
    JWT,
}

impl PayloadItem {
    pub fn from_string_with_name(val: Option<&String>, name: &str) -> Option<PayloadItem> {
        match val {
            Some(value) => match from_str(value) {
                Ok(json_value) => Some(PayloadItem(name.to_string(), json_value)),
                Err(_) => match from_str(format!("\"{}\"", value).as_str()) {
                    Ok(json_value) => Some(PayloadItem(name.to_string(), json_value)),
                    Err(_) => None,
                },
            },
            _ => None,
        }
    }

    // If the value is defined as systemd.time, converts the defined duration into a UNIX timestamp
    pub fn from_timestamp_with_name(
        val: Option<&String>,
        name: &str,
        now: i64,
    ) -> Option<PayloadItem> {
        if let Some(timestamp) = val {
            if timestamp.parse::<u64>().is_err() {
                let duration = parse_duration_string(timestamp);
                if let Ok(parsed_duration) = duration {
                    let seconds = parsed_duration + now;
                    return PayloadItem::from_string_with_name(Some(&seconds.to_string()), name);
                }
            }
        }

        PayloadItem::from_string_with_name(val, name)
    }
}

impl Payload {
    pub fn from_payloads(payloads: Vec<PayloadItem>) -> Payload {
        let mut payload = BTreeMap::new();

        for PayloadItem(k, v) in payloads {
            payload.insert(k, v);
        }

        Payload(payload)
    }

    pub fn convert_timestamps(&mut self) {
        let timestamp_claims: Vec<String> = vec!["iat".into(), "nbf".into(), "exp".into()];

        for (key, value) in self.0.iter_mut() {
            if timestamp_claims.contains(key) && value.is_number() {
                *value = match value.as_i64() {
                    Some(timestamp) => Utc.timestamp(timestamp, 0).to_rfc3339().into(),
                    None => value.clone(),
                }
            }
        }
    }
}
