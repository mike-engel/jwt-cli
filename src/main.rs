use clap::{Command, CommandFactory, Parser};
use clap_complete::{generate, Generator};
use cli_config::{App, Commands, EncodeArgs};
use std::io;
use std::process::exit;
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

fn print_completions<G: Generator>(gen: G, cmd: &mut Command) {
    generate(gen, cmd, cmd.get_name().to_string(), &mut io::stdout());
}

fn main() {
    let app = App::parse();
    // let matches = config_options().get_matches();

    match &app.command {
        Commands::Encode(arguments) => {
            warn_unsupported(arguments);

            let token = encode_token(arguments);
            let output_path = &arguments.output_path;

            exit(match print_encoded_token(token, output_path) {
                Ok(_) => 0,
                _ => 1,
            });
        }
        Commands::Decode(arguments) => {
            let (validated_token, token_data, format) = decode_token(arguments);
            let output_path = &arguments.output_path;

            exit(
                match print_decoded_token(validated_token, token_data, format, output_path) {
                    Ok(_) => 0,
                    _ => 1,
                },
            );
        }
        Commands::Completion(arguments) => {
            let mut cmd = App::command();
            print_completions(arguments.shell, &mut cmd);
        }
    };
}
