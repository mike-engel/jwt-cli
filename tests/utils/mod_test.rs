include!("../../src/utils.rs");

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
