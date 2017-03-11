include!("../src/main.rs");

#[cfg(test)]
mod tests {
    use super::{config_options, create_header, decode_token, generate_token, is_num,
                is_payload_item, Payload, PayloadItem, SupportedAlgorithms, translate_algorithm};
    use std::collections::BTreeMap;
    use jwt::{Algorithm, Header};

    #[test]
    fn payload_item_from_string() {
        let string = Some("this=that");
        let result = PayloadItem::from_string(string);
        let expected = Some(PayloadItem("this".to_string(), "that".to_string()));

        assert_eq!(result, expected);
    }

    #[test]
    fn payload_item_from_string_with_name() {
        let string = Some("that");
        let result = PayloadItem::from_string_with_name(string, "this");
        let expected = Some(PayloadItem("this".to_string(), "that".to_string()));

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
        let expected = PayloadItem("this".to_string(), "that".to_string());

        assert_eq!(result, expected);
    }

    #[test]
    fn payload_from_payload_items() {
        let payload_item_one = PayloadItem::from_string(Some("this=that")).unwrap();
        let payload_item_two = PayloadItem::from_string(Some("full=yolo")).unwrap();
        let payloads = vec![payload_item_one, payload_item_two];
        let result = Payload::from_payloads(payloads);
        let mut expected_payload = BTreeMap::new();

        expected_payload.insert("this".to_string(), "that".to_string());
        expected_payload.insert("full".to_string(), "yolo".to_string());

        let expected = Payload(expected_payload);

        assert_eq!(result, expected);
    }

    #[test]
    fn supported_algorithm_from_string() {
        assert_eq!(SupportedAlgorithms::from_string("HS256"),
                   SupportedAlgorithms::HS256);
        assert_eq!(SupportedAlgorithms::from_string("HS384"),
                   SupportedAlgorithms::HS384);
        assert_eq!(SupportedAlgorithms::from_string("HS512"),
                   SupportedAlgorithms::HS512);
        assert_eq!(SupportedAlgorithms::from_string("yolo"),
                   SupportedAlgorithms::HS256);
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
        assert_eq!(translate_algorithm(SupportedAlgorithms::HS256),
                   Algorithm::HS256);
        assert_eq!(translate_algorithm(SupportedAlgorithms::HS384),
                   Algorithm::HS384);
        assert_eq!(translate_algorithm(SupportedAlgorithms::HS512),
                   Algorithm::HS512);
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
    fn generates_a_token() {
        let matches = config_options()
            .get_matches_from_safe(vec!["jwt-cli",
                                        "generate",
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
                                        "yolo-subject"])
            .unwrap();
        let generate_matches = matches.subcommand_matches("generate").unwrap();
        let result = generate_token(&generate_matches);

        assert!(result.is_ok());
    }

    #[test]
    fn decodes_a_token() {
        let matches = config_options()
            .get_matches_from_safe(vec!["jwt-cli",
                                        "decode",
                                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                         eyJfZmllbGQwIjp7fX0.\
                                         kz2I79xHbYSrp7-OKISemPzXNiUmN9kOon-8NHrM5u0",
                                        "-S",
                                        "1234567890",
                                        "-A",
                                        "HS256"])
            .unwrap();
        let decode_matches = matches.subcommand_matches("decode").unwrap();
        let result = decode_token::<Payload>(&decode_matches);

        assert!(result.is_ok());
    }
}
