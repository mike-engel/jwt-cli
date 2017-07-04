extern crate chrono;
#[macro_use]
extern crate clap;
extern crate jsonwebtoken as jwt;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate term_painter;

use chrono::{Duration, Utc};
use clap::{App, Arg, ArgMatches, SubCommand};
use jwt::{Algorithm, decode, encode, Header, TokenData, Validation};
use jwt::errors::{Error, ErrorKind, Result as JWTResult};
use serde_json::{to_string_pretty, to_value, Value};
use std::collections::BTreeMap;
use term_painter::ToStyle;
use term_painter::Color::*;
use term_painter::Attr::*;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PayloadItem(String, Value);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Payload(BTreeMap<String, Value>);

arg_enum!{
    #[derive(Debug, PartialEq)]
    enum SupportedAlgorithms {
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512
    }
}

arg_enum!{
    enum SupportedTypes {
        JWT
    }
}

impl PayloadItem {
    fn from_string(val: Option<&str>) -> Option<PayloadItem> {
        if val.is_some() {
            Some(PayloadItem::split_payload_item(val.unwrap()))
        } else {
            None
        }
    }

    fn from_string_with_name(val: Option<&str>, name: &str) -> Option<PayloadItem> {
        match val {
            Some(value) => {
                match to_value(value) {
                    Ok(json_value) => Some(PayloadItem(name.to_string(), json_value)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn from_int_with_name(val: Option<&str>, name: &str) -> Option<PayloadItem> {
        match val {
            Some(value) => {
                match i64::from_str_radix(&value, 10) {
                    Ok(int_value) => {
                        match to_value(int_value) {
                            Ok(json_value) => Some(PayloadItem(name.to_string(), json_value)),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn split_payload_item(p: &str) -> PayloadItem {
        let split: Vec<&str> = p.split('=').collect();
        let (name, value) = (split[0], split[1]);

        PayloadItem(name.to_string(), to_value(value).unwrap_or(Value::Null))
    }
}

impl Payload {
    fn from_payloads(payloads: Vec<PayloadItem>) -> Payload {
        let mut payload = BTreeMap::new();
        let iat = json!(Utc::now().timestamp());
        let exp = json!((Utc::now() + Duration::minutes(30)).timestamp());

        for PayloadItem(k, v) in payloads {
            payload.insert(k, v);
        }

        payload.insert("iat".to_string(), iat);

        if !payload.contains_key("exp") {
            payload.insert("exp".to_string(), exp);
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
            _ => SupportedAlgorithms::HS256,
        }
    }
}

fn config_options<'a, 'b>() -> App<'a, 'b> {
    App::new("jwt")
        .about("Encode and decode JWTs from the command line")
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
                )
                .arg(
                    Arg::with_name("kid")
                        .help("the kid to place in the header")
                        .takes_value(true)
                        .long("kid")
                        .short("k"),
                )
                .arg(
                    Arg::with_name("type")
                        .help("the type of token being encoded")
                        .takes_value(true)
                        .long("typ")
                        .short("t")
                        .possible_values(&SupportedTypes::variants()),
                )
                .arg(
                    Arg::with_name("payload")
                        .help("a key=value pair to add to the payload")
                        .multiple(true)
                        .takes_value(true)
                        .long("payload")
                        .short("P")
                        .validator(is_payload_item),
                )
                .arg(
                    Arg::with_name("expires")
                        .help("the time the token should expire, in seconds")
                        .takes_value(true)
                        .long("exp")
                        .short("e")
                        .validator(is_num),
                )
                .arg(
                    Arg::with_name("issuer")
                        .help("the issuer of the token")
                        .takes_value(true)
                        .long("iss")
                        .short("i"),
                )
                .arg(
                    Arg::with_name("subject")
                        .help("the subject of the token")
                        .takes_value(true)
                        .long("sub")
                        .short("s"),
                )
                .arg(
                    Arg::with_name("audience")
                        .help("the audience of the token")
                        .takes_value(true)
                        .long("aud")
                        .short("a")
                        .requires("principal"),
                )
                .arg(
                    Arg::with_name("principal")
                        .help("the principal of the token")
                        .takes_value(true)
                        .long("prn")
                        .short("p")
                        .requires("audience"),
                )
                .arg(
                    Arg::with_name("not_before")
                        .help("the time the JWT should become valid, in seconds")
                        .takes_value(true)
                        .long("nbf")
                        .short("n")
                        .validator(is_num),
                )
                .arg(
                    Arg::with_name("secret")
                        .help("the secret to sign the JWT with")
                        .takes_value(true)
                        .long("secret")
                        .short("S")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("decode")
                .about("Decode a JWT")
                .arg(
                    Arg::with_name("jwt")
                        .help("the jwt to decode")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name("algorithm")
                        .help("the algorithm to use for signing the JWT")
                        .takes_value(true)
                        .long("alg")
                        .short("A")
                        .possible_values(&SupportedAlgorithms::variants())
                        .default_value("HS256"),
                )
                .arg(
                    Arg::with_name("secret")
                        .help("the secret to sign the JWT with")
                        .takes_value(true)
                        .long("secret")
                        .short("S")
                        .required(true),
                ),
        )
}

fn is_num(val: String) -> Result<(), String> {
    let parse_result = i64::from_str_radix(&val, 10);

    match parse_result {
        Ok(_) => Ok(()),
        Err(_) => Err(String::from("expires must be an integer")),
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
    }
}

fn create_header(alg: &Algorithm, kid: Option<&str>) -> Header {
    let mut header = Header::new(alg.clone());

    header.kid = kid.map(|k| k.to_string());

    header
}

fn create_validations(alg: Algorithm) -> Validation {
    Validation {
        leeway: 1000,
        algorithms: Some(vec![alg]),
        ..Default::default()
    }
}

fn encode_token(matches: &ArgMatches) -> JWTResult<String> {
    let algorithm = translate_algorithm(SupportedAlgorithms::from_string(
        matches.value_of("algorithm").unwrap(),
    ));
    let kid = matches.value_of("kid");
    let header = create_header(&algorithm, kid);
    let custom_payloads: Option<Vec<Option<PayloadItem>>> = matches.values_of("payload").map(|maybe_payloads| {
        maybe_payloads
            .map(|p| PayloadItem::from_string(Some(p)))
            .collect()
    });
    let expires = PayloadItem::from_int_with_name(matches.value_of("expires"), "exp");
    let issuer = PayloadItem::from_string_with_name(matches.value_of("issuer"), "iss");
    let subject = PayloadItem::from_string_with_name(matches.value_of("subject"), "sub");
    let audience = PayloadItem::from_string_with_name(matches.value_of("audience"), "aud");
    let principal = PayloadItem::from_string_with_name(matches.value_of("principal"), "prn");
    let not_before = PayloadItem::from_int_with_name(matches.value_of("not_before"), "nbf");
    let mut maybe_payloads: Vec<Option<PayloadItem>> = vec![expires, issuer, subject, audience, principal, not_before];

    maybe_payloads.append(&mut custom_payloads.unwrap_or(Vec::new()));

    let payloads = maybe_payloads
        .into_iter()
        .filter(|p| p.is_some())
        .map(|p| p.unwrap())
        .collect();
    let Payload(claims) = Payload::from_payloads(payloads);
    let secret = matches.value_of("secret").unwrap().as_bytes();

    encode(&header, &claims, secret.as_ref())
}

fn decode_token(matches: &ArgMatches) -> JWTResult<TokenData<Payload>> {
    let algorithm = translate_algorithm(SupportedAlgorithms::from_string(
        matches.value_of("algorithm").unwrap(),
    ));
    let secret = matches.value_of("secret").unwrap().as_bytes();
    let jwt = matches.value_of("jwt").unwrap().to_string();
    let validations = create_validations(algorithm);

    decode::<Payload>(&jwt, secret.as_ref(), &validations)
}

fn print_encoded_token(token: JWTResult<String>) {
    match token {
        Ok(jwt) => {
            println!("{}", Cyan.bold().paint("Success! Here's your token\n"));
            println!("{}", jwt);
        }
        Err(err) => {
            println!(
                "{}",
                Red.bold().paint("Something went awry creating the jwt\n")
            );
            println!("{}", err);
        }
    }
}

fn print_decoded_token(token_data: JWTResult<TokenData<Payload>>) {
    match token_data {
        Ok(TokenData { header, claims }) => {
            println!("{}\n", Cyan.bold().paint("Looks like a valid JWT!"));
            println!("{}", Plain.bold().paint("Token header\n------------"));
            println!("{}\n", to_string_pretty(&header).unwrap());
            println!("{}", Plain.bold().paint("Token claims\n------------"));
            println!("{}", to_string_pretty(&claims).unwrap());
        }
        Err(Error(err, _)) => {
            match err {
                ErrorKind::InvalidToken => println!("The JWT provided is invalid"),
                ErrorKind::InvalidSignature => println!("The JWT provided has an invalid signature"),
                ErrorKind::InvalidKey => println!("The secret provided isn't a valid RSA key"),
                ErrorKind::ExpiredSignature => println!("The token has expired"),
                ErrorKind::InvalidIssuer => println!("The token issuer is invalid"),
                ErrorKind::InvalidAudience => println!("The token audience doesn't match the subject"),
                ErrorKind::InvalidSubject => println!("The token subject doesn't match the audience"),
                ErrorKind::InvalidIssuedAt => println!("The issued at claim is in the future which isn't allowed"),
                ErrorKind::ImmatureSignature => println!("The `nbf` claim is in the future which isn't allowed"),
                ErrorKind::InvalidAlgorithm => {
                    println!(
                        "The JWT provided has a different signing algorithm than the one you \
                              provided"
                    )
                }
                _ => println!("The JWT provided is invalid because {:?}", err),
            }
        }
    }
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
            let token_data = decode_token(&decode_matches);

            print_decoded_token(token_data);
        }
        _ => (),
    }
}
