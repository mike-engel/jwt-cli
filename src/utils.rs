use std::fs;

use bat::PrettyPrinter;

pub fn slurp_file(file_name: &str) -> Vec<u8> {
    fs::read(file_name).unwrap_or_else(|_| panic!("Unable to read file {}", file_name))
}

pub fn parse_duration_string(val: &str) -> Result<i64, String> {
    let mut base_val = val.replace(" ago", "");

    if val.starts_with('-') {
        base_val = base_val.replacen('-', "", 1);
    }

    match parse_duration::parse(&base_val) {
        Ok(parsed_duration) => {
            let is_past = val.starts_with('-') || val.contains("ago");
            let seconds = parsed_duration.as_secs() as i64;

            if is_past {
                Ok(-seconds)
            } else {
                Ok(seconds)
            }
        }
        Err(_) => Err(String::from(
            "must be a UNIX timestamp or systemd.time string",
        )),
    }
}

pub fn print_json_colorful(json: &[u8]) {
    PrettyPrinter::new()
        .input_from_bytes(json)
        .language("json")
        .print()
        .unwrap();
    println!("");
}