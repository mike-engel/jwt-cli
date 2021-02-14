use atty::Stream;
use chrono::Utc;
use clap::{arg_enum, crate_authors, crate_version, App, Arg, ArgMatches, SubCommand};
use jsonwebtoken::errors::{ErrorKind, Result as JWTResult};
use jsonwebtoken::{
    dangerous_insecure_decode, decode, encode, Algorithm, DecodingKey, EncodingKey, Header,
    TokenData, Validation,
};
use serde_derive::{Deserialize, Serialize};
use serde_json::{from_str, to_string_pretty, Value};
use std::collections::BTreeMap;
use std::process::exit;
use std::{fs, io};
use term_painter::Attr::*;
use term_painter::Color::*;
use term_painter::ToStyle;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PayloadItem(String, Value);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Payload(BTreeMap<String, Value>);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TokenOutput {
    header: Header,
    payload: Payload,
}

arg_enum! {
    #[derive(Debug, PartialEq)]
    enum SupportedAlgorithms {
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512,
        ES256,
        ES384,
    }
}

arg_enum! {
    enum SupportedTypes {
        JWT
    }
}

#[derive(Debug, PartialEq)]
enum OutputFormat {
    Text,
    JSON,
}

impl PayloadItem {
    fn from_string(val: Option<&str>) -> Option<PayloadItem> {
        match val {
            Some(item) => Some(PayloadItem::split_payload_item(item)),
            None => None,
        }
    }

    fn from_string_with_name(val: Option<&str>, name: &str) -> Option<PayloadItem> {
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
    fn from_timestamp_with_name(val: Option<&str>, name: &str, now: i64) -> Option<PayloadItem> {
        if let Some(timestamp) = val {
            if timestamp.parse::<u64>().is_err() {
                let duration = parse_duration::parse(timestamp);
                if let Ok(parsed_duration) = duration {
                    let seconds = parsed_duration.as_secs() + now as u64;
                    return PayloadItem::from_string_with_name(Some(&seconds.to_string()), name);
                }
            }
        }

        PayloadItem::from_string_with_name(val, name)
    }

    fn split_payload_item(p: &str) -> PayloadItem {
        let split: Vec<&str> = p.split('=').collect();
        let (name, value) = (split[0], split[1]);
        let payload_item = PayloadItem::from_string_with_name(Some(value), name);

        payload_item.unwrap()
    }
}

impl Payload {
    fn from_payloads(payloads: Vec<PayloadItem>) -> Payload {
        let mut payload = BTreeMap::new();

        for PayloadItem(k, v) in payloads {
            payload.insert(k, v);
        }

        Payload(payload)
    }
}

impl SupportedAlgorithms {
    fn from_string(alg: &str) -> SupportedAlgorithms {
        match alg {
            "HS256" => SupportedAlgorithms::HS256,
            "HS384" => SupportedAlgorithms::HS384,
            "HS512" => SupportedAlgorithms::HS512,
            "RS256" => SupportedAlgorithms::RS256,
            "RS384" => SupportedAlgorithms::RS384,
            "RS512" => SupportedAlgorithms::RS512,
            "ES256" => SupportedAlgorithms::ES256,
            "ES384" => SupportedAlgorithms::ES384,
            _ => SupportedAlgorithms::HS256,
        }
    }
}

impl TokenOutput {
    fn new(data: TokenData<Payload>) -> Self {
        TokenOutput {
            header: data.header,
            payload: data.claims,
        }
    }
}

fn config_options<'a, 'b>() -> App<'a, 'b> {
    App::new("jwt")
        .about("Encode and decode JWTs from the command line. RSA and ECDSA encryption currently only supports keys in DER format")
        .version(crate_version!())
        .author(crate_authors!())
        .subcommand(
            SubCommand::with_name("encode")
                .about("Encode new JWTs")
                .arg(
                    Arg::with_name("algorithm")
                        .help("the algorithm to use for signing the JWT")
                        .takes_value(true)
                        .long("alg")
                        .short("A")
                        .possible_values(&SupportedAlgorithms::variants())
                        .default_value("HS256"),
                ).arg(
                    Arg::with_name("kid")
                        .help("the kid to place in the header")
                        .takes_value(true)
                        .long("kid")
                        .short("k"),
                ).arg(
                    Arg::with_name("type")
                        .help("the type of token being encoded")
                        .takes_value(true)
                        .long("typ")
                        .short("t")
                        .possible_values(&SupportedTypes::variants()),
                ).arg(
                    Arg::with_name("json")
                        .help("the json payload to encode")
                        .index(1)
                        .required(false),
                ).arg(
                    Arg::with_name("payload")
                        .help("a key=value pair to add to the payload")
                        .number_of_values(1)
                        .multiple(true)
                        .takes_value(true)
                        .long("payload")
                        .short("P")
                        .validator(is_payload_item),
                ).arg(
                    Arg::with_name("expires")
                        .help("the time the token should expire, in seconds or systemd.time string")
                        .default_value("+30 min")
                        .takes_value(true)
                        .long("exp")
                        .short("e")
                        .validator(is_timestamp_or_duration),
                ).arg(
                    Arg::with_name("issuer")
                        .help("the issuer of the token")
                        .takes_value(true)
                        .long("iss")
                        .short("i"),
                ).arg(
                    Arg::with_name("subject")
                        .help("the subject of the token")
                        .takes_value(true)
                        .long("sub")
                        .short("s"),
                ).arg(
                    Arg::with_name("audience")
                        .help("the audience of the token")
                        .takes_value(true)
                        .long("aud")
                        .short("a")
                ).arg(
                    Arg::with_name("not_before")
                        .help("the time the JWT should become valid, in seconds or systemd.time string")
                        .takes_value(true)
                        .long("nbf")
                        .short("n")
                        .validator(is_timestamp_or_duration),
                ).arg(
                    Arg::with_name("secret")
                        .help("the secret to sign the JWT with. Can be prefixed with @ to read from a binary file")
                        .takes_value(true)
                        .long("secret")
                        .short("S")
                        .required(true),
                ),
        ).subcommand(
            SubCommand::with_name("decode")
                .about("Decode a JWT")
                .arg(
                    Arg::with_name("jwt")
                        .help("the jwt to decode")
                        .index(1)
                        .required(true),
                ).arg(
                    Arg::with_name("algorithm")
                        .help("the algorithm to use for signing the JWT")
                        .takes_value(true)
                        .long("alg")
                        .short("A")
                        .possible_values(&SupportedAlgorithms::variants())
                        .default_value("HS256"),
                ).arg(
                    Arg::with_name("secret")
                        .help("the secret to validate the JWT with. Can be prefixed with @ to read from a binary file")
                        .takes_value(true)
                        .long("secret")
                        .short("S")
                        .default_value(""),
                ).arg(
                    Arg::with_name("json")
                        .help("render decoded JWT as JSON")
                        .long("json")
                        .short("j"),
                ),
        )
}

fn is_timestamp_or_duration(val: String) -> Result<(), String> {
    match i64::from_str_radix(&val, 10) {
        Ok(_) => Ok(()),
        Err(_) => match parse_duration::parse(&val) {
            Ok(_) => Ok(()),
            Err(_) => Err(String::from(
                "must be a UNIX timestamp or systemd.time string",
            )),
        },
    }
}

fn is_payload_item(val: String) -> Result<(), String> {
    let split: Vec<&str> = val.split('=').collect();

    match split.len() {
        2 => Ok(()),
        _ => Err(String::from(
            "payloads must have a key and value in the form key=value",
        )),
    }
}

fn warn_unsupported(matches: &ArgMatches) {
    if matches.value_of("type").is_some() {
        println!("Sorry, `typ` isn't supported quite yet!");
    }
}

fn translate_algorithm(alg: SupportedAlgorithms) -> Algorithm {
    match alg {
        SupportedAlgorithms::HS256 => Algorithm::HS256,
        SupportedAlgorithms::HS384 => Algorithm::HS384,
        SupportedAlgorithms::HS512 => Algorithm::HS512,
        SupportedAlgorithms::RS256 => Algorithm::RS256,
        SupportedAlgorithms::RS384 => Algorithm::RS384,
        SupportedAlgorithms::RS512 => Algorithm::RS512,
        SupportedAlgorithms::ES256 => Algorithm::ES256,
        SupportedAlgorithms::ES384 => Algorithm::ES384,
    }
}

fn create_header(alg: Algorithm, kid: Option<&str>) -> Header {
    let mut header = Header::new(alg);

    header.kid = kid.map(str::to_string);

    header
}

fn create_validations(alg: Algorithm) -> Validation {
    Validation {
        leeway: 1000,
        algorithms: vec![alg],
        ..Default::default()
    }
}

fn slurp_file(file_name: &str) -> Vec<u8> {
    fs::read(file_name).unwrap_or_else(|_| panic!("Unable to read file {}", file_name))
}

fn encoding_key_from_secret(alg: &Algorithm, secret_string: &str) -> JWTResult<EncodingKey> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(EncodingKey::from_secret(secret_string.as_bytes()))
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => EncodingKey::from_rsa_pem(&secret),
                false => Ok(EncodingKey::from_rsa_der(&secret)),
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => EncodingKey::from_ec_pem(&secret),
                false => Ok(EncodingKey::from_ec_der(&secret)),
            }
        }
        _ => panic!("Unsupported algorithm!"),
    }
}

fn decoding_key_from_secret(
    alg: &Algorithm,
    secret_string: &str,
) -> JWTResult<DecodingKey<'static>> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(secret_string.as_bytes()).into_static())
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => DecodingKey::from_rsa_pem(&secret).map(DecodingKey::into_static),
                false => Ok(DecodingKey::from_rsa_der(&secret).into_static()),
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());

            match secret_string.ends_with(".pem") {
                true => DecodingKey::from_ec_pem(&secret).map(DecodingKey::into_static),
                false => Ok(DecodingKey::from_ec_der(&secret).into_static()),
            }
        }
        _ => panic!("Unsupported algorithm!"),
    }
}

fn encode_token(matches: &ArgMatches) -> JWTResult<String> {
    let algorithm = translate_algorithm(SupportedAlgorithms::from_string(
        matches.value_of("algorithm").unwrap(),
    ));
    let kid = matches.value_of("kid");
    let header = create_header(algorithm, kid);
    let custom_payloads: Option<Vec<Option<PayloadItem>>> =
        matches.values_of("payload").map(|maybe_payloads| {
            maybe_payloads
                .map(|p| PayloadItem::from_string(Some(p)))
                .collect()
        });
    let custom_payload = matches
        .value_of("json")
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
    let expires = PayloadItem::from_timestamp_with_name(matches.value_of("expires"), "exp", now);
    let not_before =
        PayloadItem::from_timestamp_with_name(matches.value_of("not_before"), "nbf", now);
    let issued_at = PayloadItem::from_timestamp_with_name(Some(&now.to_string()), "iat", now);
    let issuer = PayloadItem::from_string_with_name(matches.value_of("issuer"), "iss");
    let subject = PayloadItem::from_string_with_name(matches.value_of("subject"), "sub");
    let audience = PayloadItem::from_string_with_name(matches.value_of("audience"), "aud");
    let mut maybe_payloads: Vec<Option<PayloadItem>> =
        vec![issued_at, expires, issuer, subject, audience, not_before];

    maybe_payloads.append(&mut custom_payloads.unwrap_or_default());
    maybe_payloads.append(&mut custom_payload.unwrap_or_default());

    let payloads = maybe_payloads
        .into_iter()
        .filter(Option::is_some)
        .map(Option::unwrap)
        .collect();
    let Payload(claims) = Payload::from_payloads(payloads);

    encoding_key_from_secret(&algorithm, matches.value_of("secret").unwrap())
        .and_then(|secret| encode(&header, &claims, &secret))
}

fn decode_token(
    matches: &ArgMatches,
) -> (
    JWTResult<TokenData<Payload>>,
    JWTResult<TokenData<Payload>>,
    OutputFormat,
) {
    let algorithm = translate_algorithm(SupportedAlgorithms::from_string(
        matches.value_of("algorithm").unwrap(),
    ));
    let secret = match matches.value_of("secret").map(|s| (s, !s.is_empty())) {
        Some((secret, true)) => Some(decoding_key_from_secret(&algorithm, &secret)),
        _ => None,
    };
    let jwt = matches
        .value_of("jwt")
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
        .unwrap()
        .trim()
        .to_owned();

    let secret_validator = create_validations(algorithm);

    (
        match secret {
            Some(secret_key) => decode::<Payload>(&jwt, &secret_key.unwrap(), &secret_validator),
            None => dangerous_insecure_decode::<Payload>(&jwt),
        },
        dangerous_insecure_decode::<Payload>(&jwt),
        if matches.is_present("json") {
            OutputFormat::JSON
        } else {
            OutputFormat::Text
        },
    )
}

fn print_encoded_token(token: JWTResult<String>) {
    match token {
        Ok(jwt) => {
            if atty::is(Stream::Stdout) {
                println!("{}", jwt);
            } else {
                print!("{}", jwt);
            }
            exit(0);
        }
        Err(err) => {
            eprintln!(
                "{}",
                Red.bold().paint("Something went awry creating the jwt\n")
            );
            eprintln!("{}", err);
            exit(1);
        }
    }
}

fn print_decoded_token(
    validated_token: JWTResult<TokenData<Payload>>,
    token_data: JWTResult<TokenData<Payload>>,
    format: OutputFormat,
) {
    if let Err(err) = &validated_token {
        match err.kind() {
            ErrorKind::InvalidToken => {
                println!("{}", Red.bold().paint("The JWT provided is invalid"))
            }
            ErrorKind::InvalidSignature => eprintln!(
                "{}",
                Red.bold()
                    .paint("The JWT provided has an invalid signature",)
            ),
            ErrorKind::InvalidRsaKey => eprintln!(
                "{}",
                Red.bold()
                    .paint("The secret provided isn't a valid RSA key",)
            ),
            ErrorKind::InvalidEcdsaKey => eprintln!(
                "{}",
                Red.bold()
                    .paint("The secret provided isn't a valid ECDSA key",)
            ),
            ErrorKind::ExpiredSignature => {
                if let Ok(token) = &token_data {
                    if token.claims.0.contains_key("exp") {
                        println!("{}", Red.bold().paint("The token has expired"))
                    }
                }
            }
            ErrorKind::InvalidIssuer => {
                println!("{}", Red.bold().paint("The token issuer is invalid"))
            }
            ErrorKind::InvalidAudience => eprintln!(
                "{}",
                Red.bold()
                    .paint("The token audience doesn't match the subject",)
            ),
            ErrorKind::InvalidSubject => eprintln!(
                "{}",
                Red.bold()
                    .paint("The token subject doesn't match the audience",)
            ),
            ErrorKind::ImmatureSignature => eprintln!(
                "{}",
                Red.bold()
                    .paint("The `nbf` claim is in the future which isn't allowed",)
            ),
            ErrorKind::InvalidAlgorithm => eprintln!(
                "{}",
                Red.bold().paint(
                    "The JWT provided has a different signing algorithm than the one you \
                     provided",
                )
            ),
            _ => eprintln!(
                "{} {:?}",
                Red.bold().paint("The JWT provided is invalid because"),
                err
            ),
        };
    }

    match (format, token_data) {
        (OutputFormat::JSON, Ok(token)) => {
            println!("{}", to_string_pretty(&TokenOutput::new(token)).unwrap())
        }
        (_, Ok(token)) => {
            println!("\n{}", Plain.bold().paint("Token header\n------------"));
            println!("{}\n", to_string_pretty(&token.header).unwrap());
            println!("{}", Plain.bold().paint("Token claims\n------------"));
            println!("{}", to_string_pretty(&token.claims).unwrap());
        }
        (_, Err(_)) => exit(1),
    }

    exit(match validated_token {
        Err(_) => 1,
        Ok(_) => 0,
    })
}

fn main() {
    let matches = config_options().get_matches();

    match matches.subcommand() {
        ("encode", Some(encode_matches)) => {
            warn_unsupported(&encode_matches);

            let token = encode_token(&encode_matches);

            print_encoded_token(token);
        }
        ("decode", Some(decode_matches)) => {
            let (validated_token, token_data, format) = decode_token(&decode_matches);

            print_decoded_token(validated_token, token_data, format);
        }
        _ => (),
    }
}
