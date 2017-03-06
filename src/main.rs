#[macro_use]
extern crate clap;
extern crate frank_jwt;

use clap::{App, Arg, ArgMatches, SubCommand};
use frank_jwt::{Header, Payload, Algorithm, encode};

#[derive(Debug)]
struct PayloadItem(String, String);

arg_enum!{
    enum SupportedAlgorithms {
        HS256,
        HS384,
        HS512
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
            Some(split_payload(val.unwrap()))
        } else {
            None
        }
    }
}

impl SupportedAlgorithms {
    fn from_string(alg: &str) -> SupportedAlgorithms {
        match alg {
            "HS256" => SupportedAlgorithms::HS256,
            "HS384" => SupportedAlgorithms::HS384,
            "HS512" => SupportedAlgorithms::HS512,
            _ => SupportedAlgorithms::HS256,
        }
    }
}

fn config_options<'a, 'b>() -> App<'a, 'b> {
    App::new("jwt-cli")
        .about("Encode and decode JWTs from the command line")
        .version("0.1.0")
        .author("Mike Engel <mike@mike-engel.com>")
        .subcommand(SubCommand::with_name("generate")
            .about("Encode new JWTs")
            .version("0.1.0")
            .arg(Arg::with_name("algorithm")
                .help("the algorithm to use for signing the JWT")
                .takes_value(true)
                .long("alg")
                .short("A")
                .possible_values(&SupportedAlgorithms::variants())
                .default_value("HS256"))
            .arg(Arg::with_name("kid")
                .help("the kid to place in the header")
                .takes_value(true)
                .long("kid")
                .short("k"))
            .arg(Arg::with_name("type")
                .help("the type of token being generated")
                .takes_value(true)
                .long("typ")
                .short("t")
                .possible_values(&SupportedTypes::variants()))
            .arg(Arg::with_name("payload")
                .help("a key=value pair to add to the payload")
                .multiple(true)
                .takes_value(true)
                .long("payload")
                .short("p")
                .validator(is_payload))
            .arg(Arg::with_name("expires")
                .help("the time the token should expire, in seconds")
                .takes_value(true)
                .long("expires")
                .short("e")
                .validator(is_num))
            .arg(Arg::with_name("issuer")
                .help("the issuer of the token")
                .takes_value(true)
                .long("iss")
                .short("i"))
            .arg(Arg::with_name("subject")
                .help("the subject of the token")
                .takes_value(true)
                .long("sub")
                .short("s"))
            .arg(Arg::with_name("audience")
                .help("the audience of the token")
                .takes_value(true)
                .long("aud")
                .short("a")
                .requires("principal"))
            .arg(Arg::with_name("principal")
                .help("the principal of the token")
                .takes_value(true)
                .long("prn")
                .short("P")
                .requires("audience"))
            .arg(Arg::with_name("not_before")
                .help("the time the JWT should become valid, in seconds")
                .takes_value(true)
                .long("nbf")
                .short("n"))
            .arg(Arg::with_name("secret")
                .help("the secret to sign the JWT with")
                .takes_value(true)
                .long("secret")
                .short("S")
                .required(true)))
}

fn is_num(val: String) -> Result<(), String> {
    let parse_result = i32::from_str_radix(&val, 10);

    match parse_result {
        Ok(_) => Ok(()),
        Err(_) => Err(String::from("expires must be an integer")),
    }
}

fn is_payload(val: String) -> Result<(), String> {
    let split: Vec<&str> = val.split('=').collect();

    if split.len() == 2 {
        Ok(())
    } else {
        Err(String::from("payloads must have a key and value in the form key=value"))
    }
}

fn warn_unsupported(matches: &ArgMatches) {
    if let Some(_) = matches.value_of("kid") {
        println!("Sorry, `kid` isn't supported quite yet!");
    }

    if let Some(_) = matches.value_of("type") {
        println!("Sorry, `typ` isn't supported quite yet!");
    }
}

fn split_payload(p: &str) -> PayloadItem {
    let split: Vec<&str> = p.split('=').collect();

    PayloadItem(split[0].to_string(), split[1].to_string())
}

fn translate_algorithm(alg: SupportedAlgorithms) -> Algorithm {
    match alg {
        SupportedAlgorithms::HS256 => Algorithm::HS256,
        SupportedAlgorithms::HS384 => Algorithm::HS384,
        SupportedAlgorithms::HS512 => Algorithm::HS512,
    }
}

fn create_payload(payloads: Vec<PayloadItem>) -> Payload {
    let mut payload = Payload::new();

    for PayloadItem(k, v) in payloads {
        payload.insert(k, v);
    }

    payload
}

fn main() {
    let matches = config_options().get_matches();

    if let Some(generate_matches) = matches.subcommand_matches("generate") {
        warn_unsupported(&generate_matches);

        let algorithm =
            translate_algorithm(
                SupportedAlgorithms::from_string(
                    generate_matches.value_of("algorithm").unwrap()
                )
            );
        let header = Header::new(algorithm);
        let custom_payloads: Option<Vec<Option<PayloadItem>>> =
            generate_matches.values_of("payload")
                .map(|maybe_payloads| {
                    maybe_payloads.map(|p| PayloadItem::from_string(Some(p)))
                        .collect()
                });
        let expires = PayloadItem::from_string(generate_matches.value_of("expires"));
        let issuer = PayloadItem::from_string(generate_matches.value_of("issuer"));
        let subject = PayloadItem::from_string(generate_matches.value_of("subject"));
        let audience = PayloadItem::from_string(generate_matches.value_of("audience"));
        let principal = PayloadItem::from_string(generate_matches.value_of("principal"));
        let not_before = PayloadItem::from_string(generate_matches.value_of("not_before"));
        let secret = generate_matches.value_of("secret").unwrap().to_string();
        let mut maybe_payloads: Vec<Option<PayloadItem>> = vec![expires, issuer, subject,
                                                                audience, principal, not_before];

        maybe_payloads.append(&mut custom_payloads.unwrap_or(vec![]));

        let payloads =
            maybe_payloads.into_iter().filter(|p| p.is_some()).map(|p| p.unwrap()).collect();
        let payload = create_payload(payloads);
        let token = encode(header, secret.to_string(), payload);

        println!("Here's your token:");
        println!("{}", token);
    }
}
