include!("../../src/cli_config.rs");

#[cfg(test)]
mod tests {
    use super::*;

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
}
