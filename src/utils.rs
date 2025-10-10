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
    Nkey,
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
        Algorithm::EdDSA => {
            if secret_string.starts_with('@') {
                let content = slurp_file(strip_leading_symbol(secret_string));
                let content_str = std::str::from_utf8(&content).unwrap_or("");
                let trimmed = content_str.trim();

                // Check if file contains nkey format (starts with S or P for seeds/private keys,
                // or single letter for public keys: A, U, O, N, C, M, V, X)
                if trimmed.starts_with('S')
                    || trimmed.starts_with('P')
                    || (trimmed.len() > 0
                        && trimmed.len() < 100
                        && (trimmed.starts_with('A')
                            || trimmed.starts_with('U')
                            || trimmed.starts_with('O')
                            || trimmed.starts_with('N')
                            || trimmed.starts_with('C')
                            || trimmed.starts_with('M')
                            || trimmed.starts_with('V')
                            || trimmed.starts_with('X')))
                {
                    (content, SecretType::Nkey)
                } else {
                    (content, get_secret_file_type(secret_string))
                }
            } else if secret_string.starts_with('S') || secret_string.starts_with('P') {
                // Direct nkey string (seed or private key)
                (secret_string.as_bytes().to_vec(), SecretType::Nkey)
            } else if secret_string.len() > 0
                && secret_string.len() < 100
                && (secret_string.starts_with('A')
                    || secret_string.starts_with('U')
                    || secret_string.starts_with('O')
                    || secret_string.starts_with('N')
                    || secret_string.starts_with('C')
                    || secret_string.starts_with('M')
                    || secret_string.starts_with('V')
                    || secret_string.starts_with('X'))
            {
                // Public key format (single letter prefix)
                (secret_string.as_bytes().to_vec(), SecretType::Nkey)
            } else if secret_string.starts_with('@') {
                (
                    slurp_file(strip_leading_symbol(secret_string)),
                    get_secret_file_type(secret_string),
                )
            } else {
                // Fall back to JWKS for other formats
                (secret_string.as_bytes().to_vec(), SecretType::Jwks)
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

/// Converts an nkey seed or private key to raw Ed25519 seed bytes (32 bytes)
/// for use with EncodingKey
pub fn nkey_to_ed25519_seed(nkey_str: &str) -> JWTResult<Vec<u8>> {
    let trimmed = nkey_str.trim();
    // Decode the nkey seed
    match nkeys::decode_seed(trimmed) {
        Ok((_prefix, seed_bytes)) => {
            // seed_bytes should be 32 bytes for Ed25519
            if seed_bytes.len() != 32 {
                return Err(JWTError::Internal(format!(
                    "Invalid nkey seed length: expected 32 bytes, got {}",
                    seed_bytes.len()
                )));
            }
            Ok(seed_bytes.to_vec())
        }
        Err(e) => Err(JWTError::Internal(format!(
            "Failed to decode nkey seed: {}",
            e
        ))),
    }
}

/// Converts an nkey public key to raw Ed25519 public key bytes (32 bytes)
/// for use with DecodingKey
pub fn nkey_to_ed25519_public(nkey_str: &str) -> JWTResult<Vec<u8>> {
    let trimmed = nkey_str.trim();
    match nkeys::from_public_key(trimmed) {
        Ok((_prefix, public_bytes)) => {
            if public_bytes.len() != 32 {
                return Err(JWTError::Internal(format!(
                    "Invalid nkey public key length: expected 32 bytes, got {}",
                    public_bytes.len()
                )));
            }
            Ok(public_bytes.to_vec())
        }
        Err(e) => Err(JWTError::Internal(format!(
            "Failed to decode nkey public key: {}",
            e
        ))),
    }
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

    #[test]
    fn converts_nkey_user_seed_to_ed25519() {
        let seed = "SUAJUNSMQK7AHNZ5HRGV5UI2A24O2DDSWVWIOWP6CVBVBW652GDCM54JNY";
        let result = nkey_to_ed25519_seed(seed);

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 32); // Ed25519 seeds are 32 bytes
    }

    #[test]
    fn converts_nkey_public_key_to_ed25519() {
        let public_key = "UBXGBSBR3U4IK6NCKOTND74FYER3BCVCXIB7IYUBDEPYOD6UGRTIBJAV";
        let result = nkey_to_ed25519_public(public_key);

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 32); // Ed25519 public keys are 32 bytes
    }

    #[test]
    fn returns_error_for_invalid_nkey_seed() {
        let invalid = "INVALID_NKEY";
        let result = nkey_to_ed25519_seed(invalid);

        assert!(result.is_err());
    }

    #[test]
    fn returns_error_for_invalid_nkey_public_key() {
        let invalid = "INVALID_NKEY";
        let result = nkey_to_ed25519_public(invalid);

        assert!(result.is_err());
    }

    #[test]
    fn converts_nkey_account_seed_to_ed25519() {
        let seed = "SAAEPHF7MDRHVD2XWAHRRII766ZTLVCSX7CAX4DLXFDMKPJAOGFPYJNVLM";
        let result = nkey_to_ed25519_seed(seed);

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 32);
    }
}
