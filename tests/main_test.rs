include!("../src/main.rs");

#[cfg(test)]
mod tests {
    use super::cli_config::{App, DecodeArgs, EncodeArgs};
    use super::translators::decode::{
        decode_token, print_decoded_token, OutputFormat, TokenOutput,
    };
    use super::translators::encode::{encode_token, print_encoded_token};
    use super::translators::TimeFormat;
    use super::utils::slurp_file;
    use chrono::{Duration, FixedOffset, Local, TimeZone, Utc};
    use clap::{CommandFactory, FromArgMatches};
    use jsonwebtoken::{Algorithm, TokenData};
    use serde_json::{from_value, Result as JsonResult};
    use tempdir::TempDir;

    const HOUR: i32 = 3600;

    #[test]
    fn encodes_a_token() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let nbf = Utc::now().timestamp();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "-A",
                "HS256",
                "-a",
                "yolo",
                &format!("-e={}", &exp.to_string()),
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
        let decode_matcher = App::command()
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
        let encode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "encode", "--exp", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
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
        let encode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "encode", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
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
        let encode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "encode", "--exp", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
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
        let encode_matcher = App::command()
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
        let decode_matcher = App::command()
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
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                &format!("-e={}", &exp.to_string()),
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
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
    fn allows_for_a_no_typ() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "--no-typ",
                "-S",
                "1234567890",
                &format!("-e={}", &exp.to_string()),
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_ok());

        let TokenData { claims: _, header } = decoded_token.unwrap();

        assert!(header.typ.is_none());
    }

    #[test]
    fn returns_error_when_exp_is_not_set() {
        let encode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "encode", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, _, _) = decode_token(&decode_arguments);

        assert!(decoded_token.is_err());
    }

    #[test]
    fn returns_no_error_when_ignore_exp_parameter_is_set() {
        let encode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "encode", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
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
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "-e=+10 min -30 sec",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
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
        let encode_matcher = App::command()
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
        let decode_matcher = App::command()
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
        let matches = App::command()
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
        let matches = App::command()
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
        let matches = App::command()
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
        let matches = App::command()
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
        let matches = App::command()
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
        let matches = App::command()
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
        let matches = App::command()
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
        let encode_matcher = App::command()
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
        let decode_matcher = App::command()
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

    // EncodingKey doesn't implement `debug` or `eq`, so we can't run these tests for now
    // #[test]
    // fn encoding_key_from_secret_handles_at() {
    //     let expected = EncodingKey::from_secret(include_bytes!("hmac-key.bin"));
    //     let key = encoding_key_from_secret(&Algorithm::HS256, "@./tests/hmac-key.bin").unwrap();
    //     assert_eq!(expected, key);
    // }

    // #[test]
    // fn encoding_key_from_secret_handles_base64() {
    //     let b64 = "+t0vs/PPB0dvyYKIk1DYvz5WyCUds5DLy07ycOK5oHA=";
    //     let arg = format!("b64:{}", b64);
    //     let expected = EncodingKey::from_secret(&base64_engine.decode(b64).unwrap());
    //     let key = encoding_key_from_secret(&Algorithm::HS256, &arg).unwrap();
    //     assert_eq!(expected, key);
    // }

    // #[test]
    // fn decoding_key_from_secret_handles_at() {
    //     let expected = DecodingKey::from_secret(include_bytes!("hmac-key.bin"));
    //     let key = decoding_key_from_secret(&Algorithm::HS256, "@./tests/hmac-key.bin").unwrap();
    //     assert_eq!(expected, key);
    // }

    // #[test]
    // fn decoding_key_from_secret_handles_base64() {
    //     let b64 = "+t0vs/PPB0dvyYKIk1DYvz5WyCUds5DLy07ycOK5oHA=";
    //     let arg = format!("b64:{}", b64);
    //     let expected = DecodingKey::from_secret(&base64_engine.decode(b64).unwrap()).into_static();
    //     let key = decoding_key_from_secret(&Algorithm::HS256, &arg).unwrap();
    //     assert_eq!(expected, key);
    // }

    #[test]
    fn encodes_and_decodes_an_rsa_ssa_pss_token_using_key_from_file() {
        let body: String = "{\"field\":\"value\"}".to_string();
        let encode_matcher = App::command()
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
        println!("enc {encoded_token}");
        let decode_matcher = App::command()
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
        let decode_matcher = App::command()
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
    fn returns_error_when_file_format_is_wrong_during_encode() {
        let body: String = "{\"field\":\"value\"}".to_string();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-A",
                "PS256",
                "--exp",
                "-S",
                "./tests/private_rsa_key.der",
                &body,
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments);

        assert!(encoded_token.is_err());
    }

    #[test]
    fn returns_error_when_file_format_is_wrong_during_decode() {
        let token: String = "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9.eyJmaWVsZCI6InZhbHVlIiwiaWF0IjoxNjI1OTMxNjAwLCJleHAiOjkwMDAwMDAwMDB9.Tt1siDczvVAi89dH8QqTZ_n5Ejz4gAIzVLqucWN5tEqdAVRdWgP8psuRFdC8RKIn1Lp4OsUkAA7NJ79cZt32Eewy84hTYrCgZZ9mcWg5IfXPHcZmTUm6qSyKqANdsnRWThbG3IJSX1D6obI5Y91NhVI5PTRg8sFlDAXaNN9ZVTmAtZXj0b5-MgsjiRqWMW3xi9xQqTxvb5VN37Oot-KDWZXjkO022ixshzFWu8Jt582uMD4qYRp1d0VldgyGO_viDqqk8qTqNA7soUKWyDds0emuecE_bDMeELMfxMR-A1pQeu3FgEhliazIAdXJMNlwRuJG8znLNqCK1nB2Nd8sUQ".to_string();
        let decode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "./tests/public_rsa_key.der",
                "-A",
                "PS512",
                &token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_err());
    }

    #[test]
    fn encodes_and_decodes_an_ecdsa_token_using_key_from_file() {
        let body: String = "{\"field\":\"value\"}".to_string();
        let encode_matcher = App::command()
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
        let decode_matcher = App::command()
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
    fn encodes_and_decodes_an_eddsa_token_using_key_from_file() {
        let body: String = "{\"field\":\"value\"}".to_string();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-A",
                "EDDSA",
                "--exp",
                "-S",
                "@./tests/private_eddsa_key.pem",
                &body,
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "@./tests/public_eddsa_key.pem",
                "-A",
                "EDDSA",
                &encoded_token,
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (result, _, _) = decode_token(&decode_arguments);

        assert!(result.is_ok());
    }

    #[test]
    fn shows_timestamps_as_dates() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let nbf = Utc::now().timestamp();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                &format!("--exp={}", &exp.to_string()),
                "--nbf",
                &nbf.to_string(),
                "-S",
                "1234567890",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "1234567890",
                "--date",
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
            Some(&Utc.timestamp_opt(nbf, 0).unwrap().to_rfc3339().into())
        );
        assert_eq!(
            claims.0.get("nbf"),
            Some(&Utc.timestamp_opt(nbf, 0).unwrap().to_rfc3339().into())
        );
        assert_eq!(
            claims.0.get("exp"),
            Some(&Utc.timestamp_opt(exp, 0).unwrap().to_rfc3339().into())
        );
    }

    #[test]
    fn writes_output_to_file() {
        let tmp_dir_result = TempDir::new("jwtclitest");
        assert!(tmp_dir_result.is_ok());

        let tmp_dir = tmp_dir_result.unwrap();
        let out_path = tmp_dir.path().join("jwt.out");
        println!("jwt output path: {}", out_path.to_str().unwrap());

        let secret = "1234567890";
        let kid = "1234";
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let nbf = Utc::now().timestamp();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                "-S",
                secret,
                "-A",
                "HS256",
                &format!("-e={}", &exp.to_string()),
                "-k",
                kid,
                "-n",
                &nbf.to_string(),
                "-o",
                out_path.to_str().unwrap(),
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();

        let out_path_from_args = &encode_arguments.output_path;
        assert!(out_path_from_args.is_some());
        assert_eq!(out_path, *out_path_from_args.as_ref().unwrap());

        let encoded_token = encode_token(&encode_arguments);
        let print_encoded_result = print_encoded_token(encoded_token, out_path_from_args);
        assert!(print_encoded_result.is_ok());

        let out_content_buf = slurp_file(out_path.to_str().unwrap());
        let out_content_str = std::str::from_utf8(&out_content_buf);
        assert!(out_content_str.is_ok());
        println!("jwt: {}", out_content_str.unwrap());

        let json_path = tmp_dir.path().join("decoded.json");
        println!("decoded json path: {}", json_path.to_str().unwrap());

        let decode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                secret,
                out_content_str.unwrap(),
                "-o",
                json_path.to_str().unwrap(),
            ])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();
        let (decoded_token, decoded_token_data, decoded_output_format) =
            decode_token(&decode_arguments);
        assert!(decoded_token.is_ok());

        let json_path_from_args = &decode_arguments.output_path;
        assert!(json_path_from_args.is_some());
        assert_eq!(json_path, *json_path_from_args.as_ref().unwrap());

        let json_print_result = print_decoded_token(
            decoded_token,
            decoded_token_data,
            decoded_output_format,
            json_path_from_args,
        );
        assert!(json_print_result.is_ok());

        let json_content_buf = slurp_file(json_path.to_str().unwrap());
        let json_content_str = std::str::from_utf8(&json_content_buf);
        assert!(json_content_str.is_ok());

        let json_result: JsonResult<TokenOutput> = serde_json::from_str(json_content_str.unwrap());
        assert!(json_result.is_ok());
        let json = json_result.unwrap();
        println!("json: {json:#?}");

        let TokenOutput { header, payload } = json;
        assert_eq!(header.alg, Algorithm::HS256);
        assert_eq!(header.kid, Some(kid.to_string()));
        assert_eq!(payload.0["nbf"], nbf);
        assert_eq!(payload.0["exp"], exp);
    }

    #[test]
    fn shows_timestamps_as_dates_with_local_offset() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let nbf = Utc::now().timestamp();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                &format!("--exp={}", &exp.to_string()),
                "--nbf",
                &nbf.to_string(),
                "-S",
                "1234567890",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "1234567890",
                "--date=local",
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
            Some(&Local.timestamp_opt(nbf, 0).unwrap().to_rfc3339().into())
        );
        assert_eq!(
            claims.0.get("nbf"),
            Some(&Local.timestamp_opt(nbf, 0).unwrap().to_rfc3339().into())
        );
        assert_eq!(
            claims.0.get("exp"),
            Some(&Local.timestamp_opt(exp, 0).unwrap().to_rfc3339().into())
        );
    }

    #[test]
    fn shows_timestamps_as_dates_with_fixed_offset() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let nbf = Utc::now().timestamp();
        let encode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "encode",
                &format!("--exp={}", &exp.to_string()),
                "--nbf",
                &nbf.to_string(),
                "-S",
                "1234567890",
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encode_arguments = EncodeArgs::from_arg_matches(encode_matches).unwrap();
        let encoded_token = encode_token(&encode_arguments).unwrap();
        let decode_matcher = App::command()
            .try_get_matches_from(vec![
                "jwt",
                "decode",
                "-S",
                "1234567890",
                "--dates=+03:00",
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
            Some(
                &FixedOffset::east_opt(3 * HOUR)
                    .unwrap()
                    .timestamp_opt(nbf, 0)
                    .unwrap()
                    .to_rfc3339()
                    .into()
            )
        );
        assert_eq!(
            claims.0.get("nbf"),
            Some(
                &FixedOffset::east_opt(3 * HOUR)
                    .unwrap()
                    .timestamp_opt(nbf, 0)
                    .unwrap()
                    .to_rfc3339()
                    .into()
            )
        );
        assert_eq!(
            claims.0.get("exp"),
            Some(
                &FixedOffset::east_opt(3 * HOUR)
                    .unwrap()
                    .timestamp_opt(exp, 0)
                    .unwrap()
                    .to_rfc3339()
                    .into()
            )
        );
    }

    #[test]
    fn parses_date_format_with_no_equals() {
        let decode_matcher = App::command()
            .try_get_matches_from(vec!["jwt", "decode", "--date", "some token"])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decode_arguments = DecodeArgs::from_arg_matches(decode_matches).unwrap();

        assert_eq!(decode_arguments.time_format, Some(TimeFormat::UTC));
    }
}
