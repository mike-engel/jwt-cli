use crate::cli_config::{translate_algorithm, EncodeArgs};
use crate::translators::{Payload, PayloadItem};
use crate::utils::{slurp_file, write_file, JWTError, JWTResult};
use atty::Stream;
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine as _;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{from_str, Value};
use std::io;
use std::path::PathBuf;

fn create_header(alg: Algorithm, kid: Option<&String>) -> Header {
    let mut header = Header::new(alg);

    header.kid = kid.map(|k| k.to_owned());

    header
}

pub fn encoding_key_from_secret(alg: &Algorithm, secret_string: &str) -> JWTResult<EncodingKey> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());
                Ok(EncodingKey::from_secret(&secret))
            } else if secret_string.starts_with("b64:") {
                Ok(EncodingKey::from_secret(
                    &base64_engine
                        .decode(secret_string.chars().skip(4).collect::<String>())
                        .unwrap(),
                ))
            } else {
                Ok(EncodingKey::from_secret(secret_string.as_bytes()))
            }
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            if !&secret_string.starts_with('@') {
                return Err(JWTError::Internal(format!(
                    "Secret for {alg:?} must be a file path starting with @",
                )));
            }

            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => {
                    EncodingKey::from_rsa_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
                }
                false => Ok(EncodingKey::from_rsa_der(&secret)),
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            if !&secret_string.starts_with('@') {
                return Err(JWTError::Internal(format!(
                    "Secret for {alg:?} must be a file path starting with @"
                )));
            }

            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => {
                    EncodingKey::from_ec_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
                }
                false => Ok(EncodingKey::from_ec_der(&secret)),
            }
        }
        Algorithm::EdDSA => {
            if !&secret_string.starts_with('@') {
                return Err(JWTError::Internal(format!(
                    "Secret for {alg:?} must be a file path starting with @",
                )));
            }

            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => {
                    EncodingKey::from_ed_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
                }
                false => Ok(EncodingKey::from_ed_der(&secret)),
            }
        }
    }
}

pub fn encode_token(arguments: &EncodeArgs) -> JWTResult<String> {
    let algorithm = translate_algorithm(&arguments.algorithm);
    let header = create_header(algorithm, arguments.kid.as_ref());
    let custom_payloads = arguments.payload.clone();
    let custom_payload = arguments
        .json
        .as_ref()
        .map(|value| {
            if value != "-" {
                return String::from(value);
            }

            let mut buffer = String::new();

            io::stdin()
                .read_line(&mut buffer)
                .expect("STDIN was not valid UTF-8");

            buffer
        })
        .map(|raw_json| match from_str(&raw_json) {
            Ok(Value::Object(json_value)) => json_value
                .into_iter()
                .map(|(json_key, json_val)| Some(PayloadItem(json_key, json_val)))
                .collect(),
            _ => panic!("Invalid JSON provided!"),
        });
    let now = Utc::now().timestamp();
    let expires = PayloadItem::from_timestamp_with_name(arguments.expires.as_ref(), "exp", now);
    let not_before =
        PayloadItem::from_timestamp_with_name(arguments.not_before.as_ref(), "nbf", now);
    let issued_at = match arguments.no_iat {
        true => None,
        false => PayloadItem::from_timestamp_with_name(Some(&now.to_string()), "iat", now),
    };
    let issuer = PayloadItem::from_string_with_name(arguments.issuer.as_ref(), "iss");
    let subject = PayloadItem::from_string_with_name(arguments.subject.as_ref(), "sub");
    let audience = PayloadItem::from_string_with_name(arguments.audience.as_ref(), "aud");
    let jwt_id = PayloadItem::from_string_with_name(arguments.jwt_id.as_ref(), "jti");
    let mut maybe_payloads: Vec<Option<PayloadItem>> = vec![
        issued_at, expires, issuer, subject, audience, jwt_id, not_before,
    ];

    maybe_payloads.append(&mut custom_payloads.unwrap_or_default());
    maybe_payloads.append(&mut custom_payload.unwrap_or_default());

    let payloads = maybe_payloads.into_iter().flatten().collect();
    let Payload(claims) = Payload::from_payloads(payloads);

    encoding_key_from_secret(&algorithm, &arguments.secret).and_then(|secret| {
        encode(&header, &claims, &secret).map_err(jsonwebtoken::errors::Error::into)
    })
}

pub fn print_encoded_token(
    token: JWTResult<String>,
    output_path: &Option<PathBuf>,
) -> JWTResult<()> {
    match (output_path.as_ref(), token) {
        (Some(path), Ok(jwt)) => {
            write_file(path, jwt.as_bytes());
            println!("Wrote jwt to file {}", path.display());
        }
        (None, Ok(jwt)) => {
            if atty::is(Stream::Stdout) {
                println!("{jwt}");
            } else {
                print!("{jwt}");
            };
        }
        (_, Err(err)) => {
            bunt::eprintln!("{$red+bold}Something went awry creating the jwt{/$}\n");
            eprintln!("{err}");
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_jwt_header_with_kid() {
        let algorithm = Algorithm::HS256;
        let kid = String::from("yolo");
        let result = create_header(algorithm, Some(&kid));
        let mut expected = Header::new(algorithm);

        expected.kid = Some(kid);

        assert_eq!(result, expected);
    }

    #[test]
    fn creates_jwt_header_without_kid() {
        let algorithm = Algorithm::HS256;
        let kid = None;
        let result = create_header(algorithm, kid);
        let mut expected = Header::new(algorithm);

        expected.kid = kid.map(|k| k.to_string());

        assert_eq!(result, expected);
    }
}
