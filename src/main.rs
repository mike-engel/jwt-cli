use clap::Parser;
use cli_config::{App, Commands, EncodeArgs};
use translators::decode::{decode_token, print_decoded_token};
use translators::encode::{encode_token, print_encoded_token};

pub mod cli_config;
pub mod translators;
pub mod utils;

fn warn_unsupported(arguments: &EncodeArgs) {
    if arguments.typ.is_some() {
        println!("Sorry, `typ` isn't supported quite yet!");
    };
}

fn main() {
    let app = App::parse();
    // let matches = config_options().get_matches();

    match &app.command {
        Commands::Encode(arguments) => {
            warn_unsupported(arguments);

            let token = encode_token(arguments);

            print_encoded_token(token);
        }
        Commands::Decode(arguments) => {
            let (validated_token, token_data, format) = decode_token(arguments);

            print_decoded_token(validated_token, token_data, format);
        }
    }
}
