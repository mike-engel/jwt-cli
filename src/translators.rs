use crate::utils::parse_duration_string;
use chrono::{FixedOffset, Local, TimeZone, Utc};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeFormat {
    /// Displays UTC (+00:00)
    UTC,
    /// Displays your local timezone
    Local,
    /// Displays a fixed timezone
    Fixed(i32),
}

impl PayloadItem {
    pub fn from_string_with_name(val: Option<&String>, name: &str) -> Option<PayloadItem> {
        match val {
            Some(value) => match from_str(value) {
                Ok(json_value) => Some(PayloadItem(name.to_string(), json_value)),
                Err(_) => match from_str(format!("\"{value}\"").as_str()) {
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

    pub fn convert_timestamps(&mut self, offset: TimeFormat) {
        let timestamp_claims: Vec<String> = vec!["iat".into(), "nbf".into(), "exp".into()];

        for (key, value) in self.0.iter_mut() {
            if timestamp_claims.contains(key) && value.is_number() {
                *value = match value.as_i64() {
                    Some(timestamp) => match offset {
                        TimeFormat::UTC => Utc.timestamp_opt(timestamp, 0).unwrap().to_rfc3339(),
                        TimeFormat::Local => {
                            Local.timestamp_opt(timestamp, 0).unwrap().to_rfc3339()
                        }
                        TimeFormat::Fixed(secs) => FixedOffset::east_opt(secs)
                            .unwrap()
                            .timestamp_opt(timestamp, 0)
                            .unwrap()
                            .to_rfc3339(),
                    }
                    .into(),
                    None => value.clone(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_item_from_string_with_name() {
        let string = String::from("that");
        let result = PayloadItem::from_string_with_name(Some(&string), "this");
        let expected = Some(PayloadItem("this".to_string(), serde_json::json!("that")));

        assert_eq!(result, expected);
    }

    #[test]
    fn payload_item_from_none_with_name() {
        let result = PayloadItem::from_string_with_name(None, "this");

        assert_eq!(result, None);
    }

    #[test]
    fn payload_from_payload_items() {
        let payload_item_one =
            PayloadItem::from_string_with_name(Some(&String::from("that")), "this").unwrap();
        let payload_item_two =
            PayloadItem::from_string_with_name(Some(&String::from("yolo")), "full").unwrap();
        let payloads = vec![payload_item_one, payload_item_two];
        let result = Payload::from_payloads(payloads);
        let payload = result.0;

        println!("{:?}", payload.keys());
        assert!(payload.contains_key("this"));
        assert!(payload.contains_key("full"));
        assert_eq!(payload["this"], serde_json::json!("that"));
        assert_eq!(payload["full"], serde_json::json!("yolo"));
    }
}
