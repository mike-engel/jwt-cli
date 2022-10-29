include!("../../src/translators.rs");

#[cfg(test)]
mod tests {
    use super::*;

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
}
