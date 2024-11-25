use clap::{CommandFactory, Parser};
use clap_complete::Shell;
use clap_complete::{generate, Generator};
use clap_complete_nushell::Nushell;
use cli_config::{App, Commands, EncodeArgs, ShellCompletion};
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

fn print_completions(shell: &ShellCompletion) {
    fn generate_completions(gen: impl Generator) {
        let mut cmd = App::command();
        let name = cmd.get_name().to_string();

        generate(gen, &mut cmd, name, &mut io::stdout());
    }

    match shell {
        ShellCompletion::Nushell => generate_completions(Nushell),
        ShellCompletion::Bash => generate_completions(Shell::Bash),
        ShellCompletion::Elvish => generate_completions(Shell::Elvish),
        ShellCompletion::Fish => generate_completions(Shell::Fish),
        ShellCompletion::Powershell => generate_completions(Shell::PowerShell),
        ShellCompletion::Zsh => generate_completions(Shell::Zsh),
    }
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
            print_completions(&arguments.shell);
            exit(0)
        }
    };
}
