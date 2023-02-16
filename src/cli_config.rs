use crate::translators::{PayloadItem, SupportedTypes, TimeFormat};
use crate::utils::parse_duration_string;
use chrono::format::{parse, Parsed, StrftimeItems};
use clap::{Parser, Subcommand, ValueEnum};
use jsonwebtoken::Algorithm;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(name = "jwt")]
#[clap(about, version, author)]
#[clap(propagate_version = true)]

pub struct App {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Encode new JWTs
    Encode(EncodeArgs),

    /// Decode a JWT
    Decode(DecodeArgs),
}

#[derive(Debug, Clone, Parser)]
pub struct EncodeArgs {
    /// the algorithm to use for signing the JWT
    #[clap(long = "alg", short = 'A')]
    #[clap(value_enum)]
    #[clap(default_value = "HS256")]
    pub algorithm: SupportedAlgorithms,

    /// the kid to place in the header
    #[clap(long = "kid", short = 'k')]
    #[clap(value_parser)]
    pub kid: Option<String>,

    /// the type of token being encoded
    #[clap(name = "type")]
    #[clap(long = "typ", short = 't')]
    #[clap(value_enum)]
    pub typ: Option<SupportedTypes>,

    /// the json payload to encode
    #[clap(index = 1)]
    #[clap(value_parser)]
    pub json: Option<String>,

    /// a key=value pair to add to the payload
    #[clap(long = "payload", short = 'P')]
    #[clap(value_parser = is_payload_item)]
    pub payload: Option<Vec<Option<PayloadItem>>>,

    /// the time the token should expire, in seconds or a systemd.time string
    #[clap(long = "exp", short = 'e')]
    #[clap(num_args = 0..=1)]
    #[clap(require_equals = true)]
    #[clap(value_parser = is_timestamp_or_duration)]
    #[clap(default_value = None)]
    #[clap(default_missing_value = "+30m")]
    pub expires: Option<String>,

    /// the issuer of the token
    #[clap(long = "iss", short = 'i')]
    #[clap(value_parser)]
    pub issuer: Option<String>,

    /// the subject of the token
    #[clap(long = "sub", short = 's')]
    #[clap(value_parser)]
    pub subject: Option<String>,

    /// the audience of the token
    #[clap(long = "aud", short = 'a')]
    #[clap(value_parser)]
    pub audience: Option<String>,

    /// the jwt id of the token
    #[clap(long = "jti")]
    #[clap(value_parser)]
    pub jwt_id: Option<String>,

    /// the time the JWT should become valid, in seconds or a systemd.time string
    #[clap(long = "nbf", short = 'n')]
    #[clap(value_parser = is_timestamp_or_duration)]
    pub not_before: Option<String>,

    /// prevent an iat claim from being automatically added
    #[clap(long)]
    #[clap(value_parser)]
    pub no_iat: bool,

    /// the secret to sign the JWT with. Prefix with @ to read from a file or b64: to use base-64 encoded bytes
    #[clap(long, short = 'S')]
    #[clap(value_parser)]
    pub secret: String,

    /// The path of the file to write the result to (suppresses default standard output)
    #[clap(long = "out", short = 'o')]
    #[clap(value_parser)]
    pub output_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Parser)]
pub struct DecodeArgs {
    /// The JWT to decode. Provide '-' to read from STDIN.
    #[clap(index = 1)]
    #[clap(value_parser)]
    pub jwt: String,

    /// The algorithm used to sign the JWT
    #[clap(long = "alg", short = 'A')]
    #[clap(value_enum)]
    #[clap(default_value = "HS256")]
    #[clap(value_parser)]
    pub algorithm: SupportedAlgorithms,

    /// Display unix timestamps as ISO 8601 dates [default: UTC] [possible values: UTC, Local, Offset (e.g. -02:00)]
    #[clap(long = "date")]
    #[clap(aliases = &["dates", "time"])]
    #[clap(num_args = 0..=1)]
    #[clap(require_equals = true)]
    #[clap(value_parser = time_format)]
    #[clap(default_value = None)]
    #[clap(default_missing_value = "UTC")]
    pub time_format: Option<TimeFormat>,

    /// The secret to validate the JWT with. Prefix with @ to read from a file or b64: to use base-64 encoded bytes
    #[clap(long = "secret", short = 'S')]
    #[clap(default_value = "")]
    #[clap(value_parser)]
    pub secret: String,

    /// Render the decoded JWT as JSON
    #[clap(long = "json", short = 'j')]
    #[clap(value_parser)]
    pub json: bool,

    /// Ignore token expiration date (`exp` claim) during validation
    #[clap(long = "ignore-exp")]
    #[clap(value_parser)]
    pub ignore_exp: bool,

    /// The path of the file to write the result to (suppresses default standard output, implies JSON format)
    #[clap(long = "out", short = 'o')]
    #[clap(value_parser)]
    pub output_path: Option<PathBuf>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "UPPERCASE")]
pub enum SupportedAlgorithms {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    EdDSA,
}

fn is_payload_item(val: &str) -> Result<Option<PayloadItem>, String> {
    let item: Vec<&str> = val.split('=').collect();

    match item.len() {
        2 => Ok(PayloadItem::from_string_with_name(
            Some(&String::from(item[1])),
            item[0],
        )),
        _ => Err(String::from(
            "payloads must have a key and value in the form key=value",
        )),
    }
}

fn is_timestamp_or_duration(val: &str) -> Result<String, String> {
    match val.parse::<i64>() {
        Ok(_) => Ok(val.into()),
        Err(_) => match parse_duration_string(val) {
            Ok(_) => Ok(val.into()),
            Err(_) => Err(String::from(
                "must be a UNIX timestamp or systemd.time string",
            )),
        },
    }
}

fn time_format(arg: &str) -> Result<TimeFormat, String> {
    match arg.to_uppercase().as_str() {
        "UTC" => Ok(TimeFormat::UTC),
        "LOCAL" => Ok(TimeFormat::Local),
        _ => {
            let mut parsed = Parsed::new();
            match parse(&mut parsed, arg, StrftimeItems::new("%#z")) {
                Ok(_) => match parsed.offset {
                    Some(offset) => Ok(TimeFormat::Fixed(offset)),
                    None => panic!("Should have been able to parse the offset"),
                },
                Err(_) => Err(String::from(
                    "must be one of `Local`, `UTC` or an offset (-02:00)",
                )),
            }
        }
    }
}

pub fn translate_algorithm(alg: &SupportedAlgorithms) -> Algorithm {
    match alg {
        SupportedAlgorithms::HS256 => Algorithm::HS256,
        SupportedAlgorithms::HS384 => Algorithm::HS384,
        SupportedAlgorithms::HS512 => Algorithm::HS512,
        SupportedAlgorithms::RS256 => Algorithm::RS256,
        SupportedAlgorithms::RS384 => Algorithm::RS384,
        SupportedAlgorithms::RS512 => Algorithm::RS512,
        SupportedAlgorithms::PS256 => Algorithm::PS256,
        SupportedAlgorithms::PS384 => Algorithm::PS384,
        SupportedAlgorithms::PS512 => Algorithm::PS512,
        SupportedAlgorithms::ES256 => Algorithm::ES256,
        SupportedAlgorithms::ES384 => Algorithm::ES384,
        SupportedAlgorithms::EdDSA => Algorithm::EdDSA,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_payload_item() {
        assert!(is_payload_item("this=that").is_ok());
    }

    #[test]
    fn is_invalid_payload_item() {
        assert!(is_payload_item("this").is_err());
        assert!(is_payload_item("this=that=yolo").is_err());
        assert!(is_payload_item("this-that_yolo").is_err());
    }

    #[test]
    fn is_valid_timestamp_or_duration() {
        assert!(is_timestamp_or_duration("2").is_ok());
        assert!(is_timestamp_or_duration("39874398").is_ok());
        assert!(is_timestamp_or_duration("12h").is_ok());
        assert!(is_timestamp_or_duration("1 day -1 hour").is_ok());
        assert!(is_timestamp_or_duration("+30 min").is_ok());
    }

    #[test]
    fn is_invalid_timestamp_or_duration() {
        assert!(is_timestamp_or_duration("yolo").is_err());
        assert!(is_timestamp_or_duration("2398ybdfiud93").is_err());
        assert!(is_timestamp_or_duration("1 day -1 hourz").is_err());
    }

    #[test]
    fn is_valid_time_format() {
        assert_eq!(time_format("local"), Ok(TimeFormat::Local));
        assert_eq!(time_format("LoCaL"), Ok(TimeFormat::Local));
        assert_eq!(time_format("utc"), Ok(TimeFormat::UTC));
        assert_eq!(time_format("+03:00"), Ok(TimeFormat::Fixed(10800)));
        assert_eq!(time_format("+03:30"), Ok(TimeFormat::Fixed(12600)));
    }

    #[test]
    fn is_invalid_time_format() {
        assert!(time_format("yolo").is_err());
        assert!(time_format("2398ybdfiud93").is_err());
        assert!(time_format("+3").is_err());
    }
}
