include!("../src/main.rs");

#[cfg(test)]
mod tests {
    use super::{config_options, create_header, decode_token, encode_token, is_num, is_payload_item, Payload, PayloadItem, SupportedAlgorithms, translate_algorithm};
    use chrono::{Duration, Utc};
    use jwt::{Algorithm, Header, TokenData};
    use serde_json::from_value;

    #[test]
    fn payload_item_from_string() {
        let string = Some("this=that");
        let result = PayloadItem::from_string(string);
        let expected = Some(PayloadItem("this".to_string(), json!("that")));

        assert_eq!(result, expected);
    }

    #[test]
    fn payload_item_from_string_with_name() {
        let string = Some("that");
        let result = PayloadItem::from_string_with_name(string, "this");
        let expected = Some(PayloadItem("this".to_string(), json!("that")));

        assert_eq!(result, expected);
    }

    #[test]
    fn payload_item_from_none() {
        let result = PayloadItem::from_string(None);

        assert_eq!(result, None);
    }

    #[test]
    fn payload_item_from_none_with_name() {
        let result = PayloadItem::from_string_with_name(None, "this");

        assert_eq!(result, None);
    }

    #[test]
    fn split_payload_item() {
        let string = "this=that";
        let result = PayloadItem::split_payload_item(string);
        let expected = PayloadItem("this".to_string(), json!("that"));

        assert_eq!(result, expected);
    }

    #[test]
    fn payload_from_payload_items() {
        let payload_item_one = PayloadItem::from_string(Some("this=that")).unwrap();
        let payload_item_two = PayloadItem::from_string(Some("full=yolo")).unwrap();
        let payloads = vec![payload_item_one, payload_item_two];
        let result = Payload::from_payloads(payloads);
        let payload = result.0;

        assert!(payload.contains_key("this"));
        assert!(payload.contains_key("full"));
        assert_eq!(payload["this"], json!("that"));
        assert_eq!(payload["full"], json!("yolo"));
    }

    #[test]
    fn supported_algorithm_from_string() {
        assert_eq!(
            SupportedAlgorithms::from_string("HS256"),
            SupportedAlgorithms::HS256
        );
        assert_eq!(
            SupportedAlgorithms::from_string("HS384"),
            SupportedAlgorithms::HS384
        );
        assert_eq!(
            SupportedAlgorithms::from_string("HS512"),
            SupportedAlgorithms::HS512
        );
        assert_eq!(
            SupportedAlgorithms::from_string("RS256"),
            SupportedAlgorithms::RS256
        );
        assert_eq!(
            SupportedAlgorithms::from_string("RS384"),
            SupportedAlgorithms::RS384
        );
        assert_eq!(
            SupportedAlgorithms::from_string("RS512"),
            SupportedAlgorithms::RS512
        );
        assert_eq!(
            SupportedAlgorithms::from_string("yolo"),
            SupportedAlgorithms::HS256
        );
    }

    #[test]
    fn is_valid_num() {
        assert!(is_num("2".to_string()).is_ok());
        assert!(is_num("39874398".to_string()).is_ok());
    }

    #[test]
    fn is_invalid_num() {
        assert!(is_num("yolo".to_string()).is_err());
        assert!(is_num("2398ybdfiud93".to_string()).is_err());
    }

    #[test]
    fn is_valid_payload_item() {
        assert!(is_payload_item("this=that".to_string()).is_ok());
    }

    #[test]
    fn is_invalid_payload_item() {
        assert!(is_payload_item("this".to_string()).is_err());
        assert!(is_payload_item("this=that=yolo".to_string()).is_err());
        assert!(is_payload_item("this-that_yolo".to_string()).is_err());
    }

    #[test]
    fn translates_algorithm() {
        assert_eq!(
            translate_algorithm(SupportedAlgorithms::HS256),
            Algorithm::HS256
        );
        assert_eq!(
            translate_algorithm(SupportedAlgorithms::HS384),
            Algorithm::HS384
        );
        assert_eq!(
            translate_algorithm(SupportedAlgorithms::HS512),
            Algorithm::HS512
        );
        assert_eq!(
            translate_algorithm(SupportedAlgorithms::RS256),
            Algorithm::RS256
        );
        assert_eq!(
            translate_algorithm(SupportedAlgorithms::RS384),
            Algorithm::RS384
        );
        assert_eq!(
            translate_algorithm(SupportedAlgorithms::RS512),
            Algorithm::RS512
        );
    }

    #[test]
    fn creates_jwt_header_with_kid() {
        let algorithm = Algorithm::HS256;
        let kid = Some("yolo");
        let result = create_header(&algorithm, kid);
        let mut expected = Header::new(algorithm);

        expected.kid = kid.map(|k| k.to_string());

        assert_eq!(result, expected);
    }

    #[test]
    fn creates_jwt_header_without_kid() {
        let algorithm = Algorithm::HS256;
        let kid = None;
        let result = create_header(&algorithm, kid);
        let mut expected = Header::new(algorithm);

        expected.kid = kid.map(|k| k.to_string());

        assert_eq!(result, expected);
    }

    #[test]
    fn encodes_a_token() {
        let matches = config_options()
            .get_matches_from_safe(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "-A",
                "HS256",
                "-a",
                "yolo",
                "-e",
                "0987654321",
                "-i",
                "yolo-service",
                "-k",
                "1234",
                "-n",
                "001293",
                "-P",
                "this=that",
                "-p",
                "yolo-principal",
                "-s",
                "yolo-subject",
            ])
            .unwrap();
        let encode_matches = matches.subcommand_matches("encode").unwrap();
        let result = encode_token(&encode_matches);

        assert!(result.is_ok());
    }

    #[test]
    fn adds_iat_exp_automatically() {
        let encode_matcher = config_options()
            .get_matches_from_safe(vec!["jwt", "encode", "-S", "1234567890"])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encoded_token = encode_token(&encode_matches).unwrap();
        let decode_matcher = config_options()
            .get_matches_from_safe(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decoded_token = decode_token(&decode_matches);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();
        let iat = from_value::<i64>(claims.0["iat"].clone());
        let exp = from_value::<i64>(claims.0["exp"].clone());

        assert!(iat.is_ok());
        assert!(exp.is_ok());
        assert!(iat.unwrap().is_positive());
        assert!(exp.unwrap().is_positive());
    }

    #[test]
    fn allows_for_a_custom_exp() {
        let exp = (Utc::now() + Duration::minutes(60)).timestamp();
        let encode_matcher = config_options()
            .get_matches_from_safe(vec![
                "jwt",
                "encode",
                "-S",
                "1234567890",
                "-e",
                &exp.to_string(),
            ])
            .unwrap();
        let encode_matches = encode_matcher.subcommand_matches("encode").unwrap();
        let encoded_token = encode_token(&encode_matches).unwrap();
        let decode_matcher = config_options()
            .get_matches_from_safe(vec!["jwt", "decode", "-S", "1234567890", &encoded_token])
            .unwrap();
        let decode_matches = decode_matcher.subcommand_matches("decode").unwrap();
        let decoded_token = decode_token(&decode_matches);

        assert!(decoded_token.is_ok());

        let TokenData { claims, header: _ } = decoded_token.unwrap();
        let exp_claim = from_value::<i64>(claims.0["exp"].clone());

        assert!(exp_claim.is_ok());
        assert_eq!(exp_claim.unwrap(), exp);
    }

    #[test]
    fn decodes_a_token() {
        let matches = config_options()
            .get_matches_from_safe(vec![
                "jwt",
                "decode",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0aGlzIjoidGhhdCJ9.AdAECLE_4iRa0uomMEdsMV2hDXv1vhLpym567-AzhrM",
                "-S",
                "1234567890",
                "-A",
                "HS256",
            ])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let result = decode_token(&decode_matches);

        assert!(result.is_ok());
    }
}
