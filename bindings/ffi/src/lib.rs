uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn base64url_encode(data: Vec<u8>) -> String {
    polyjose::util::b64url_encode(&data)
}
