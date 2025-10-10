use crate::cli_config::{translate_algorithm, EncodeArgs};
use crate::translators::{Claims, Payload, PayloadItem};
use crate::utils::{get_secret_from_file_or_input, write_file, JWTError, JWTResult, SecretType};
use atty::Stream;
use chrono::Utc;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{from_str, Value};
use std::io;
use std::path::PathBuf;

fn create_header(alg: Algorithm, kid: Option<&String>, no_typ: bool) -> Header {
    let mut header = Header::new(alg);

    header.kid = kid.map(|k| k.to_owned());

    if no_typ {
        header.typ = None;
    }

    header
}

pub fn encoding_key_from_secret(alg: &Algorithm, secret_string: &str) -> JWTResult<EncodingKey> {
    let (secret, file_type) = get_secret_from_file_or_input(alg, secret_string);

    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => match file_type {
            SecretType::Plain => Ok(EncodingKey::from_secret(&secret)),
            SecretType::B64 => EncodingKey::from_base64_secret(std::str::from_utf8(&secret)?)
                .map_err(jsonwebtoken::errors::Error::into),
            _ => Err(JWTError::Internal(format!(
                "Invalid secret file type for {alg:?}"
            ))),
        },
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => match file_type {
            SecretType::Pem => {
                EncodingKey::from_rsa_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
            }
            SecretType::Der => Ok(EncodingKey::from_rsa_der(&secret)),
            _ => Err(JWTError::Internal(format!(
                "Invalid secret file type for {alg:?}"
            ))),
        },
        Algorithm::ES256 | Algorithm::ES384 => match file_type {
            SecretType::Pem => {
                EncodingKey::from_ec_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
            }
            SecretType::Der => Ok(EncodingKey::from_ec_der(&secret)),
            _ => Err(JWTError::Internal(format!(
                "Invalid secret file type for {alg:?}"
            ))),
        },
        Algorithm::EdDSA => match file_type {
            SecretType::Pem => {
                EncodingKey::from_ed_pem(&secret).map_err(jsonwebtoken::errors::Error::into)
            }
            SecretType::Der => Ok(EncodingKey::from_ed_der(&secret)),
            SecretType::Nkey => {
                let secret_str = std::str::from_utf8(&secret)?;
                let seed_bytes = crate::utils::nkey_to_ed25519_seed(secret_str.trim())?;

                use ed25519_dalek::SigningKey;
                let signing_key = SigningKey::from_bytes(&seed_bytes.try_into().map_err(|_| {
                    JWTError::Internal("Invalid seed length for Ed25519".to_string())
                })?);

                let pkcs8_pem = signing_key.to_pkcs8_pem(Default::default()).map_err(|e| {
                    JWTError::Internal(format!("Failed to convert to PKCS#8 PEM: {}", e))
                })?;

                EncodingKey::from_ed_pem(pkcs8_pem.as_bytes())
                    .map_err(jsonwebtoken::errors::Error::into)
            }
            _ => Err(JWTError::Internal(format!(
                "Invalid secret file type for {alg:?}"
            ))),
        },
    }
}

pub fn encode_token(arguments: &EncodeArgs) -> JWTResult<String> {
    let algorithm = translate_algorithm(&arguments.algorithm);
    let header = create_header(algorithm, arguments.kid.as_ref(), arguments.no_typ);
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
    let claims = match arguments.keep_payload_order {
        true => Claims::OrderKept(payloads),
        false => {
            let Payload(_claims) = Payload::from_payloads(payloads);
            Claims::Reordered(_claims)
        }
    };

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
        let result = create_header(algorithm, Some(&kid), false);
        let mut expected = Header::new(algorithm);

        expected.kid = Some(kid);

        assert_eq!(result, expected);
    }

    #[test]
    fn creates_jwt_header_without_kid() {
        let algorithm = Algorithm::HS256;
        let kid = None;
        let result = create_header(algorithm, kid, false);
        let mut expected = Header::new(algorithm);

        expected.kid = kid.map(|k| k.to_string());

        assert_eq!(result, expected);
    }

    #[test]
    fn creates_jwt_header_without_typ() {
        let algorithm = Algorithm::HS256;
        let kid = None;
        let result = create_header(algorithm, kid, true);
        let mut expected = Header::new(algorithm);

        expected.kid = kid.map(|k| k.to_string());
        expected.typ = None;

        assert_eq!(result, expected);
    }
}
