use crate::attribute::Attribute;

pub fn log_attribute(path: &str, attribute: &Attribute) {
    log::info!("{} | {}", path, serde_json::to_string(attribute).unwrap())
}
