use crate::cli_config::{translate_algorithm, DecodeArgs};
use crate::translators::Payload;
use crate::utils::slurp_file;
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine as _;
use jsonwebtoken::errors::{ErrorKind, Result as JWTResult};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Header, TokenData, Validation};
use serde_derive::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::io;
use std::process::exit;

#[derive(Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TokenOutput {
    header: Header,
    payload: Payload,
}

impl TokenOutput {
    fn new(data: TokenData<Payload>) -> Self {
        TokenOutput {
            header: data.header,
            payload: data.claims,
        }
    }
}

pub fn decoding_key_from_secret(alg: &Algorithm, secret_string: &str) -> JWTResult<DecodingKey> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());
                Ok(DecodingKey::from_secret(&secret))
            } else if secret_string.starts_with("b64:") {
                Ok(DecodingKey::from_secret(
                    &base64_engine
                        .decode(secret_string.chars().skip(4).collect::<String>())
                        .unwrap(),
                ))
            } else {
                Ok(DecodingKey::from_secret(secret_string.as_bytes()))
            }
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => DecodingKey::from_rsa_pem(&secret),
                false => Ok(DecodingKey::from_rsa_der(&secret)),
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => DecodingKey::from_ec_pem(&secret),
                false => Ok(DecodingKey::from_ec_der(&secret)),
            }
        }
        Algorithm::EdDSA => {
            panic!("EdDSA is not implemented yet!");
        }
    }
}

pub fn decode_token(
    arguments: &DecodeArgs,
) -> (
    JWTResult<TokenData<Payload>>,
    JWTResult<TokenData<Payload>>,
    OutputFormat,
) {
    let algorithm = translate_algorithm(&arguments.algorithm);
    let secret = match arguments.secret.len() {
        0 => None,
        _ => Some(decoding_key_from_secret(&algorithm, &arguments.secret)),
    };
    let jwt = match arguments.jwt.as_str() {
        "-" => {
            let mut buffer = String::new();

            io::stdin()
                .read_line(&mut buffer)
                .expect("STDIN was not valid UTF-8");

            buffer
        }
        _ => arguments.jwt.clone(),
    }
    .trim()
    .to_owned();

    let mut secret_validator = Validation::new(algorithm);

    secret_validator.leeway = 1000;
    secret_validator.validate_exp = !arguments.ignore_exp;

    let mut insecure_validator = secret_validator.clone();
    let insecure_decoding_key = DecodingKey::from_secret("".as_ref());

    insecure_validator.insecure_disable_signature_validation();

    let token_data =
        decode::<Payload>(&jwt, &insecure_decoding_key, &insecure_validator).map(|mut token| {
            if arguments.iso_dates {
                token.claims.convert_timestamps();
            }

            token
        });

    (
        match secret {
            Some(secret_key) => decode::<Payload>(&jwt, &secret_key.unwrap(), &secret_validator),
            None => decode::<Payload>(&jwt, &insecure_decoding_key, &insecure_validator),
        },
        token_data,
        if arguments.json {
            OutputFormat::Json
        } else {
            OutputFormat::Text
        },
    )
}

pub fn print_decoded_token(
    validated_token: JWTResult<TokenData<Payload>>,
    token_data: JWTResult<TokenData<Payload>>,
    format: OutputFormat,
) {
    if let Err(err) = &validated_token {
        match err.kind() {
            ErrorKind::InvalidToken => {
                bunt::println!("{$red+bold}The JWT provided is invalid{/$}")
            }
            ErrorKind::InvalidSignature => {
                bunt::eprintln!("{$red+bold}The JWT provided has an invalid signature{/$}")
            }
            ErrorKind::InvalidRsaKey(_) => {
                bunt::eprintln!("{$red+bold}The secret provided isn't a valid RSA key{/$}")
            }
            ErrorKind::InvalidEcdsaKey => {
                bunt::eprintln!("{$red+bold}The secret provided isn't a valid ECDSA key{/$}")
            }
            ErrorKind::ExpiredSignature => {
                bunt::eprintln!("{$red+bold}The token has expired (or the `exp` claim is not set). This error can be ignored via the `--ignore-exp` parameter.{/$}")
            }
            ErrorKind::InvalidIssuer => {
                bunt::println!("{$red+bold}The token issuer is invalid{/$}")
            }
            ErrorKind::InvalidAudience => {
                bunt::eprintln!("{$red+bold}The token audience doesn't match the subject{/$}")
            }
            ErrorKind::InvalidSubject => {
                bunt::eprintln!("{$red+bold}The token subject doesn't match the audience{/$}")
            }
            ErrorKind::ImmatureSignature => bunt::eprintln!(
                "{$red+bold}The `nbf` claim is in the future which isn't allowed{/$}"
            ),
            ErrorKind::InvalidAlgorithm => bunt::eprintln!(
                "{$red+bold}The JWT provided has a different signing algorithm than the one you \
									 provided{/$}",
            ),
            _ => bunt::eprintln!(
                "{$red+bold}The JWT provided is invalid because{/$} {:?}",
                err
            ),
        };
    }

    match (format, token_data) {
        (OutputFormat::Json, Ok(token)) => {
            println!("{}", to_string_pretty(&TokenOutput::new(token)).unwrap())
        }
        (_, Ok(token)) => {
            bunt::println!("\n{$bold}Token header\n------------{/$}");
            println!("{}\n", to_string_pretty(&token.header).unwrap());
            bunt::println!("{$bold}Token claims\n------------{/$}");
            println!("{}", to_string_pretty(&token.claims).unwrap());
        }
        (_, Err(_)) => exit(1),
    }

    exit(match validated_token {
        Err(_) => 1,
        Ok(_) => 0,
    })
}
