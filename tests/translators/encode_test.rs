include!("../../src/translators/encode.rs");

#[cfg(test)]
mod tests {
    use super::*;

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
}
