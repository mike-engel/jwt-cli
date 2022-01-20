include!("../src/main.rs");

#[cfg(test)]
mod tests {
    use super::{
        create_header, decode_token, decoding_key_from_secret, encode_token,
        encoding_key_from_secret, is_payload_item, is_timestamp_or_duration, parse_duration_string,
        App, DecodeArgs, EncodeArgs, OutputFormat, Payload, PayloadItem,
    };
    use base64::decode as base64_decode;
    use chrono::{Duration, TimeZone, Utc};
    use clap::{FromArgMatches, IntoApp};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData};
    use serde_json::{from_value, json};

    #[test]
    fn payload_item_from_string_with_name() {
        let string = String::from("that");
        let result = PayloadItem::from_string_with_name(Some(&string), "this");
        let expected = Some(PayloadItem("this".to_string(), json!("that")));

        assert_eq!(result, expected);
    }

    #[test]
    fn payload_item_from_none_with_name() {
        let result = PayloadItem::from_string_with_name(None, "this");

        assert_eq!(result, None);
    }

    #[test]
    fn payload_from_payload_items() {
        let payload_item_one =
            PayloadItem::from_string_with_name(Some(&String::from("that")), "this").unwrap();
        let payload_item_two =
            PayloadItem::from_string_with_name(Some(&String::from("yolo")), "full").unwrap();
        let payloads = vec![payload_item_one, payload_item_two];
        let result = Payload::from_payloads(payloads);
        let payload = result.0;

        println!("{:?}", payload.keys());
        assert!(payload.contains_key("this"));
        assert!(payload.contains_key("full"));
        assert_eq!(payload["this"], json!("that"));
        assert_eq!(payload["full"], json!("yolo"));
    }

    #[test]
    fn is_valid_payload_item() {
        assert!(is_payload_item("this=that").is_ok());
    }

    #[test]
    fn is_invalid_payload_item() {
        assert!(is_payload_item("this").is_err());
        assert!(is_payload_item("this=that=yolo").is_err());
        assert!(is_payload_item("this-that_yolo").is_err());
    }

    #[test]
    fn is_valid_timestamp_or_duration() {
        assert!(is_timestamp_or_duration("2").is_ok());
        assert!(is_timestamp_or_duration("39874398").is_ok());
        assert!(is_timestamp_or_duration("12h").is_ok());
        assert!(is_timestamp_or_duration("1 day -1 hour").is_ok());
        assert!(is_timestamp_or_duration("+30 min").is_ok());
    }

    #[test]
    fn is_invalid_timestamp_or_duration() {
        assert!(is_timestamp_or_duration("yolo").is_err());
        assert!(is_timestamp_or_duration("2398ybdfiud93").is_err());
        assert!(is_timestamp_or_duration("1 day -1 hourz").is_err());
    }

    #[test]
    fn creates_jwt_header_with_kid() {
        let algorithm = Algorithm::HS256;
        let kid = String::from("yolo");
        let result = create_header(algorithm, Some(&kid));
        let mut expected = Header::new(algorithm);

        expected.kid = Some(kid);

        assert_eq!(result, expected);
    }

    #[test]
    fn creates_jwt_header_without_kid() {
        let algorithm = Algorithm::HS256;
        let kid = None;
        let result = create_header(algorithm, kid);
        let mut expected = Header::new(algorithm);

        expected.kid = kid.map(|k| k.to_string());

        assert_eq!(result, expected);
    }

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
    fn encodes_a_token() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let nbf = Utc::now().timestamp();
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "-A",
                "HS256",
                "-a",
                "yolo",
                "-e",
                &exp.to_string(),
                "-i",
                "yolo-service",
                "-k",
                "1234",
                "-n",
                &nbf.to_string(),
                "--jti",
                "yolo-jti",
                "-P",
                "this=that",
                "-P",
                "number=10",
                "-P",
                "array=[1, 2, 3]",
                "-P",
                "object={\"foo\": \"bar\"}",
                "-s",
                "yolo-subject",
                "{\"test\":\"json value\",\"bool\":true,\"json_number\":1}",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header } = decoded_token.unwrap();

        assert_eq!(header.alg, Algorithm::HS256);
        assert_eq!(header.kid, Some("1234".to_string()));
        assert_eq!(claims.0["aud"], "yolo");
        assert_eq!(claims.0["iss"], "yolo-service");
        assert_eq!(claims.0["sub"], "yolo-subject");
        assert_eq!(claims.0["nbf"], nbf);
        assert_eq!(claims.0["exp"], exp);
        assert_eq!(claims.0["jti"], "yolo-jti");
        assert_eq!(claims.0["this"], "that");
        assert_eq!(claims.0["test"], "json value");
        assert_eq!(claims.0["bool"], true);
        assert_eq!(claims.0["json_number"], 1);
        assert_eq!(claims.0["number"], 10);
        assert_eq!(claims.0["array"].to_string(), "[1,2,3]");
        assert_eq!(claims.0["object"]["foo"], "bar");
    }

    #[test]
    fn adds_iat_automatically() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "encode", "--exp", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();
        let iat = from_value::<i64>(claims.0["iat"].clone());

        assert!(iat.is_ok());
        assert!(iat.unwrap().is_positive());
    }

    #[test]
    fn stops_exp_from_automatically_being_added() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "encode", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, token_data, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_err());

        let TokenData { claims, header: _ } = token_data.unwrap();

        assert!(claims.0.get("exp").is_none());
    }

    #[test]
    fn adds_default_exp_automatically() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "encode", "--exp", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();
        let exp = from_value::<i64>(claims.0["exp"].clone());

        assert!(exp.is_ok());
        assert!(exp.unwrap().is_positive());
    }

    #[test]
    fn stops_iat_from_automatically_being_added() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "--no-iat",
                "--exp",
                "-S",
                "1234567890",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();

        assert!(claims.0.get("iat").is_none());
    }

    #[test]
    fn allows_for_a_custom_exp() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "-e",
                &exp.to_string(),
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();
        let exp_claim = from_value::<i64>(claims.0["exp"].clone());

        assert!(exp_claim.is_ok());
        assert_eq!(exp_claim.unwrap(), exp);
    }

    #[test]
    fn returns_error_when_exp_is_not_set() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "encode", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_err());
    }

    #[test]
    fn returns_no_error_when_ignore_exp_parameter_is_set() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "encode", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "1234567890",
                "--ignore-exp",
                &encoded_token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());
    }

    #[test]
    fn allows_for_a_custom_exp_as_systemd_string() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "-e",
                "+10 min -30 sec",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();
        let exp_claim = from_value::<i64>(claims.0["exp"].clone());
        let iat_claim = from_value::<i64>(claims.0["iat"].clone());

        assert!(iat_claim.is_ok());
        let iat = iat_claim.unwrap();
        assert!(exp_claim.is_ok());
        let exp = exp_claim.unwrap();
        assert!(iat.is_positive());
        assert!(exp.is_positive());
        assert_eq!(exp - iat, (10 * 60 - 30));
    }

    #[test]
    fn allows_for_nbf_as_systemd_string() {
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "--exp",
                "-n",
                "+5 min",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();
        let nbf_claim = from_value::<i64>(claims.0["nbf"].clone());
        let iat_claim = from_value::<i64>(claims.0["iat"].clone());

        assert!(iat_claim.is_ok());
        let iat = iat_claim.unwrap();
        assert!(nbf_claim.is_ok());
        let nbf = nbf_claim.unwrap();
        assert!(iat.is_positive());
        assert!(nbf.is_positive());
        assert_eq!(nbf - iat, (5 * 60));
    }

    #[test]
    fn decodes_a_token() {
        let matches = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE4OTM0NTYwMDAsImlhdCI6MTU0MjQ5MjMxMywidGhpcyI6InRoYXQifQ.YTWit46_AEMMVv0P48NeJJIqXmMHarGjfRxtR7jLlxE",
                "-S",
                "1234567890",
                "-A",
                "HS256",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn decodes_a_token_as_json() {
        let matches = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0aGlzIjoidGhhdCJ9.AdAECLE_4iRa0uomMEdsMV2hDXv1vhLpym567-AzhrM",
                "-j",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, format) = decode_token(&decode_arguments);

        assert!(result.is_ok());
        assert!(format == OutputFormat::Json);
    }

    #[test]
    fn decodes_a_token_with_invalid_secret() {
        let matches = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0aGlzIjoidGhhdCJ9.AdAECLE_4iRa0uomMEdsMV2hDXv1vhLpym567-AzhrM",
                "-S",
                "yolo",
                "-A",
                "HS256",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_err());
    }

    #[test]
    fn decodes_a_token_without_a_secret() {
        let matches = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0aGlzIjoidGhhdCJ9.AdAECLE_4iRa0uomMEdsMV2hDXv1vhLpym567-AzhrM",
                "-A",
                "HS256",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn decodes_a_token_without_an_alg() {
        let matches = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0aGlzIjoidGhhdCJ9.AdAECLE_4iRa0uomMEdsMV2hDXv1vhLpym567-AzhrM",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn decodes_a_token_without_a_typ() {
        let matches = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.SEQijh6tEuOOAAKpHPuKxgFqEvlTNP1jj4FUNoBwXaM",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn decodes_a_token_with_leading_and_trailing_whitespace() {
        let matches = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "    eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.SEQijh6tEuOOAAKpHPuKxgFqEvlTNP1jj4FUNoBwXaM ",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn encodes_and_decodes_an_rsa_ssa_pkcs1_v1_5_token_using_key_from_file() {
        let body: String = "{\"field\":\"value\"}".to_string();
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-A",
                "RS256",
                "--exp",
                "-S",
                "@./tests/private_rsa_key.der",
                &body,
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "@./tests/public_rsa_key.der",
                "-A",
                "RS256",
                &encoded_token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn encoding_key_from_secret_handles_at() {
        let expected = EncodingKey::from_secret(include_bytes!("hmac-key.bin"));
        let key = encoding_key_from_secret(&Algorithm::HS256, "@./tests/hmac-key.bin").unwrap();
        assert_eq!(expected, key);
    }

    #[test]
    fn encoding_key_from_secret_handles_base64() {
        let b64 = "+t0vs/PPB0dvyYKIk1DYvz5WyCUds5DLy07ycOK5oHA=";
        let arg = format!("b64:{}", b64);
        let expected = EncodingKey::from_secret(&base64_decode(b64).unwrap());
        let key = encoding_key_from_secret(&Algorithm::HS256, &arg).unwrap();
        assert_eq!(expected, key);
    }

    #[test]
    fn decoding_key_from_secret_handles_at() {
        let expected = DecodingKey::from_secret(include_bytes!("hmac-key.bin"));
        let key = decoding_key_from_secret(&Algorithm::HS256, "@./tests/hmac-key.bin").unwrap();
        assert_eq!(expected, key);
    }

    #[test]
    fn decoding_key_from_secret_handles_base64() {
        let b64 = "+t0vs/PPB0dvyYKIk1DYvz5WyCUds5DLy07ycOK5oHA=";
        let arg = format!("b64:{}", b64);
        let expected = DecodingKey::from_secret(&base64_decode(b64).unwrap()).into_static();
        let key = decoding_key_from_secret(&Algorithm::HS256, &arg).unwrap();
        assert_eq!(expected, key);
    }

    #[test]
    fn encodes_and_decodes_an_rsa_ssa_pss_token_using_key_from_file() {
        let body: String = "{\"field\":\"value\"}".to_string();
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-A",
                "PS256",
                "--exp",
                "-S",
                "@./tests/private_rsa_key.der",
                &body,
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        println!("enc {}", encoded_token);
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "@./tests/public_rsa_key.der",
                "-A",
                "PS256",
                &encoded_token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn decodes_an_rsa_ssa_pss_token_using_key_from_file() {
        let token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9.eyJmaWVsZCI6InZhbHVlIiwiaWF0IjoxNjI1OTMxNjAwLCJleHAiOjkwMDAwMDAwMDB9.Tt1siDczvVAi89dH8QqTZ_n5Ejz4gAIzVLqucWN5tEqdAVRdWgP8psuRFdC8RKIn1Lp4OsUkAA7NJ79cZt32Eewy84hTYrCgZZ9mcWg5IfXPHcZmTUm6qSyKqANdsnRWThbG3IJSX1D6obI5Y91NhVI5PTRg8sFlDAXaNN9ZVTmAtZXj0b5-MgsjiRqWMW3xi9xQqTxvb5VN37Oot-KDWZXjkO022ixshzFWu8Jt582uMD4qYRp1d0VldgyGO_viDqqk8qTqNA7soUKWyDds0emuecE_bDMeELMfxMR-A1pQeu3FgEhliazIAdXJMNlwRuJG8znLNqCK1nB2Nd8sUQ".to_string();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "@./tests/public_rsa_key.der",
                "-A",
                "PS512",
                &token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn encodes_and_decodes_an_ecdsa_token_using_key_from_file() {
        let body: String = "{\"field\":\"value\"}".to_string();
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-A",
                "ES256",
                "--exp",
                "-S",
                "@./tests/private_ecdsa_key.pk8",
                &body,
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "@./tests/public_ecdsa_key.pk8",
                "-A",
                "ES256",
                &encoded_token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        dbg!(&result);

        assert!(result.is_ok());
    }

    #[test]
    fn shows_timestamps_as_iso_dates() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let nbf = Utc::now().timestamp();
        let encode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "--exp",
                &exp.to_string(),
                "--nbf",
                &nbf.to_string(),
                "-S",
                "1234567890",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::into_app()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "1234567890",
                "--iso8601",
                &encoded_token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, token_data, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = token_data.unwrap();

        assert!(claims.0.get("iat").is_some());
        assert!(claims.0.get("nbf").is_some());
        assert!(claims.0.get("exp").is_some());
        assert_eq!(
            claims.0.get("iat"),
            Some(&Utc.timestamp(nbf, 0).to_rfc3339().into())
        );
        assert_eq!(
            claims.0.get("nbf"),
            Some(&Utc.timestamp(nbf, 0).to_rfc3339().into())
        );
        assert_eq!(
            claims.0.get("exp"),
            Some(&Utc.timestamp(exp, 0).to_rfc3339().into())
        );
    }
}
