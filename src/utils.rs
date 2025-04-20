use std::fmt;
use std::fs;
use std::path::Path;
use std::str::Utf8Error;

use jsonwebtoken::jwk;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Header;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum JWTError {
    Internal(String),
    External(jsonwebtoken::errors::Error),
}

pub type JWTResult<T> = Result<T, JWTError>;

impl From<jsonwebtoken::errors::Error> for JWTError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        JWTError::External(value)
    }
}

impl From<Utf8Error> for JWTError {
    fn from(value: Utf8Error) -> Self {
        JWTError::Internal(value.to_string())
    }
}

impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JWTError::Internal(err) => write!(f, "{err}"),
            JWTError::External(err) => write!(f, "{err}"),
        }
    }
}

pub fn slurp_file(file_name: String) -> Vec<u8> {
    let err_msg = format!("Unable to read file {file_name}");
    fs::read(file_name).unwrap_or_else(|_| panic!("{err_msg}"))
}

pub fn write_file(path: &Path, content: &[u8]) {
    fs::write(path, content).unwrap_or_else(|_| panic!("Unable to write file {}", path.display()))
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

pub enum SecretType {
    Pem,
    Der,
    Jwks,
    B64,
    Plain,
}

pub fn get_secret_from_file_or_input(
    alg: &Algorithm,
    secret_string: &str,
) -> (Vec<u8>, SecretType) {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret_string.starts_with('@') {
                (
                    slurp_file(strip_leading_symbol(secret_string)),
                    if secret_string.ends_with(".json") {
                        SecretType::Jwks
                    } else {
                        SecretType::Plain
                    },
                )
            } else if secret_string.starts_with("b64:") {
                (
                    secret_string
                        .chars()
                        .skip(4)
                        .collect::<String>()
                        .as_bytes()
                        .to_owned(),
                    SecretType::B64,
                )
            } else {
                (secret_string.as_bytes().to_owned(), SecretType::Plain)
            }
        }
        _ => {
            if secret_string.starts_with('@') {
                (
                    slurp_file(strip_leading_symbol(secret_string)),
                    get_secret_file_type(secret_string),
                )
            } else {
                // allows to read JWKS from argument (e.g. output of 'curl https://auth.domain.com/jwks.json')
                (secret_string.as_bytes().to_vec(), SecretType::Jwks)
            }
        }
    }
}

fn strip_leading_symbol(secret_string: &str) -> String {
    secret_string.chars().skip(1).collect::<String>()
}

fn get_secret_file_type(secret_string: &str) -> SecretType {
    if secret_string.ends_with(".pem") {
        SecretType::Pem
    } else if secret_string.ends_with(".json") {
        SecretType::Jwks
    } else {
        SecretType::Der
    }
}

pub fn decoding_key_from_jwks_secret(
    secret: &[u8],
    header: Option<Header>,
) -> JWTResult<DecodingKey> {
    if let Some(h) = header {
        return match parse_jwks(secret) {
            Some(jwks) => decoding_key_from_jwks(jwks, &h),
            None => Err(JWTError::Internal("Invalid jwks format".to_string())),
        };
    }
    Err(JWTError::Internal("Invalid jwt header".to_string()))
}

pub fn decoding_key_from_jwks(jwks: jwk::JwkSet, header: &Header) -> JWTResult<DecodingKey> {
    let kid = match &header.kid {
        Some(k) => k.to_owned(),
        None => {
            return Err(JWTError::Internal(
                "Missing 'kid' from jwt header".to_string(),
            ));
        }
    };

    let jwk = match jwks.find(&kid) {
        Some(j) => j,
        None => {
            return Err(JWTError::Internal(format!(
                "No jwk found for 'kid' {kid:?}",
            )));
        }
    };

    DecodingKey::from_jwk(jwk).map_err(jsonwebtoken::errors::Error::into)
}

fn parse_jwks(secret: &[u8]) -> Option<jwk::JwkSet> {
    serde_json::from_slice(secret).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_time_string() {
        assert_eq!(parse_duration_string("5s").unwrap(), 5);
        assert_eq!(parse_duration_string("2 days").unwrap(), 60 * 60 * 24 * 2);
        assert_eq!(parse_duration_string("-5s").unwrap(), -5);
        assert_eq!(
            parse_duration_string("2 days ago").unwrap(),
            60 * 60 * 24 * -2
        );
    }
}
