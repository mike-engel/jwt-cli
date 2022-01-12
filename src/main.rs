use atty::Stream;
use base64::decode as base64_decode;
use chrono::{TimeZone, Utc};
use clap::{AppSettings, ArgEnum, Parser, Subcommand};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct PayloadItem(String, Value);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Payload(BTreeMap<String, Value>);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TokenOutput {
    header: Header,
    payload: Payload,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, ArgEnum)]
#[clap(rename_all = "UPPERCASE")]
enum SupportedAlgorithms {
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
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, ArgEnum)]
enum SupportedTypes {
    JWT,
}

#[derive(Debug, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

impl PayloadItem {
    fn from_string_with_name(val: Option<&String>, name: &str) -> Option<PayloadItem> {
        match val {
            Some(value) => match from_str(&value) {
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
    fn from_timestamp_with_name(val: Option<&String>, name: &str, now: i64) -> Option<PayloadItem> {
        if let Some(timestamp) = val {
            if timestamp.parse::<u64>().is_err() {
                let duration = parse_duration::parse(&timestamp);
                if let Ok(parsed_duration) = duration {
                    let seconds = parsed_duration.as_secs() + now as u64;
                    return PayloadItem::from_string_with_name(Some(&seconds.to_string()), name);
                }
            }
        }

        PayloadItem::from_string_with_name(val, name)
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

    fn convert_timestamps(&mut self) {
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

impl TokenOutput {
    fn new(data: TokenData<Payload>) -> Self {
        TokenOutput {
            header: data.header,
            payload: data.claims,
        }
    }
}

#[derive(Parser, Debug)]
#[clap(name = "jwt")]
#[clap(about, version, author)]
#[clap(global_setting(AppSettings::PropagateVersion))]
#[clap(global_setting(AppSettings::UseLongFormatForHelpSubcommand))]
struct App {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encode new JWTs
    Encode(EncodeArgs),

    /// Decode a JWT
    Decode(DecodeArgs),
}

#[derive(Debug, Clone, Parser)]
struct EncodeArgs {
    /// the algorithm to use for signing the JWT
    #[clap(long = "alg", short = 'A')]
    #[clap(arg_enum)]
    #[clap(default_value = "HS256")]
    algorithm: SupportedAlgorithms,

    /// the kid to place in the header
    #[clap(long = "kid", short = 'k')]
    kid: Option<String>,

    /// the type of token being encoded
    #[clap(name = "type")]
    #[clap(long = "typ", short = 't')]
    #[clap(arg_enum)]
    typ: Option<SupportedTypes>,

    /// the json payload to encode
    #[clap(index = 1)]
    json: Option<String>,

    /// a key=value pair to add to the payload
    #[clap(long = "payload", short = 'P')]
    #[clap(parse(try_from_str = is_payload_item), multiple_occurrences(true))]
    payload: Option<Vec<Option<PayloadItem>>>,

    /// the time the token should expire, in seconds or a systemd.time string
    #[clap(long = "exp", short = 'e')]
    #[clap(parse(try_from_str = is_timestamp_or_duration))]
    #[clap(default_missing_value = "+30m")]
    expires: Option<String>,

    /// the issuer of the token
    #[clap(long = "iss", short = 'i')]
    issuer: Option<String>,

    /// the subject of the token
    #[clap(long = "sub", short = 's')]
    subject: Option<String>,

    /// the audience of the token
    #[clap(long = "aud", short = 'a')]
    audience: Option<String>,

    /// the jwt id of the token
    #[clap(long = "jti")]
    jwt_id: Option<String>,

    /// the time the JWT should become valid, in seconds or a systemd.time string
    #[clap(long = "nbf", short = 'n')]
    #[clap(parse(try_from_str = is_timestamp_or_duration))]
    not_before: Option<String>,

    /// prevent an iat claim from being automatically added
    #[clap(long)]
    no_iat: bool,

    /// the secret to sign the JWT with. Prefix with @ to read from a file or b64: to use base-64 encoded bytes
    #[clap(long, short = 'S')]
    secret: String,
}

#[derive(Debug, Clone, Parser)]
struct DecodeArgs {
    /// the JWT to decode
    #[clap(index = 1)]
    jwt: String,

    /// the algorithm used to sign the JWT
    #[clap(long = "alg", short = 'A')]
    #[clap(arg_enum)]
    #[clap(default_value = "HS256")]
    algorithm: SupportedAlgorithms,

    /// display unix timestamps as ISO 8601 dates
    #[clap(long = "iso8601")]
    iso_dates: bool,

    /// the secret to validate the JWT with. Prefix with @ to read from a file or b64: to use base-64 encoded bytes
    #[clap(long = "secret", short = 'S')]
    #[clap(default_value = "")]
    secret: String,

    /// render the decoded JWT as JSON
    #[clap(long = "json", short = 'j')]
    json: bool,

    /// ignore token expiration date (`exp` claim) during validation
    #[clap(long = "ignore-exp")]
    ignore_exp: bool,
}

fn is_timestamp_or_duration(val: &str) -> Result<String, String> {
    match val.parse::<i64>() {
        Ok(_) => Ok(val.into()),
        Err(_) => match parse_duration::parse(&val) {
            Ok(_) => Ok(val.into()),
            Err(_) => Err(String::from(
                "must be a UNIX timestamp or systemd.time string",
            )),
        },
    }
}

fn is_payload_item(val: &str) -> Result<Option<PayloadItem>, String> {
    let item: Vec<&str> = val.split('=').collect();

    match item.len() {
        2 => Ok(PayloadItem::from_string_with_name(
            Some(&String::from(item[1])),
            item[0].into(),
        )),
        _ => Err(String::from(
            "payloads must have a key and value in the form key=value",
        )),
    }
}

fn warn_unsupported(arguments: &EncodeArgs) {
    match arguments {
        EncodeArgs { typ: Some(_), .. } => {
            println!("Sorry, `typ` isn't supported quite yet!");
        }
        _ => {}
    };
}

fn translate_algorithm(alg: &SupportedAlgorithms) -> Algorithm {
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
    }
}

fn create_header(alg: Algorithm, kid: Option<&String>) -> Header {
    let mut header = Header::new(alg);

    header.kid = kid.map(|k| k.to_owned());

    header
}

fn slurp_file(file_name: &str) -> Vec<u8> {
    fs::read(file_name).unwrap_or_else(|_| panic!("Unable to read file {}", file_name))
}

fn encoding_key_from_secret(alg: &Algorithm, secret_string: &str) -> JWTResult<EncodingKey> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());
                Ok(EncodingKey::from_secret(&secret))
            } else if secret_string.starts_with("b64:") {
                Ok(EncodingKey::from_secret(
                    &base64_decode(&secret_string.chars().skip(4).collect::<String>()).unwrap(),
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
    }
}

fn decoding_key_from_secret(
    alg: &Algorithm,
    secret_string: &str,
) -> JWTResult<DecodingKey<'static>> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                let secret = slurp_file(&secret_string.chars().skip(1).collect::<String>());
                Ok(DecodingKey::from_secret(&secret).into_static())
            } else if secret_string.starts_with("b64:") {
                Ok(DecodingKey::from_secret(
                    &base64_decode(&secret_string.chars().skip(4).collect::<String>()).unwrap(),
                )
                .into_static())
            } else {
                Ok(DecodingKey::from_secret(secret_string.as_bytes()).into_static())
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
    }
}

fn encode_token(arguments: &EncodeArgs) -> JWTResult<String> {
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

    encoding_key_from_secret(&algorithm, &arguments.secret)
        .and_then(|secret| encode(&header, &claims, &secret))
}

fn decode_token(
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

    let secret_validator = Validation {
        leeway: 1000,
        algorithms: vec![algorithm],
        validate_exp: !arguments.ignore_exp,
        ..Default::default()
    };

    let token_data = dangerous_insecure_decode::<Payload>(&jwt).map(|mut token| {
        if arguments.iso_dates {
            token.claims.convert_timestamps();
        }

        token
    });

    (
        match secret {
            Some(secret_key) => decode::<Payload>(&jwt, &secret_key.unwrap(), &secret_validator),
            None => dangerous_insecure_decode::<Payload>(&jwt),
        },
        token_data,
        if arguments.json {
            OutputFormat::Json
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
            bunt::eprintln!("{$red+bold}Something went awry creating the jwt{/$}\n");
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
                bunt::println!("{$red+bold}The JWT provided is invalid{/$}")
            }
            ErrorKind::InvalidSignature => {
                bunt::eprintln!("{$red+bold}The JWT provided has an invalid signature{/$}")
            }
            ErrorKind::InvalidRsaKey => {
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

fn main() {
    let app = App::parse();
    // let matches = config_options().get_matches();

    match &app.command {
        Commands::Encode(arguments) => {
            warn_unsupported(&arguments);

            let token = encode_token(&arguments);

            print_encoded_token(token);
        }
        Commands::Decode(arguments) => {
            let (validated_token, token_data, format) = decode_token(&arguments);

            print_decoded_token(validated_token, token_data, format);
        }
    }
}
