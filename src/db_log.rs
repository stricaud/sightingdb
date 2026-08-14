use crate::attribute::AttributeView;

/// Emit one line per write, so the log doubles as a record of what was written.
///
/// Statistics are deliberately excluded by the caller: they grow without bound
/// and would dominate every line.
pub fn log_attribute(path: &str, attribute: &AttributeView) {
    // `log::info!` is a no-op when the level is disabled, but serializing is
    // not, so skip that work when nobody is listening.
    if !log::log_enabled!(log::Level::Info) {
        return;
    }

    match serde_json::to_string(attribute) {
        Ok(json) => log::info!("{path} | {json}"),
        Err(e) => log::warn!("{path} | could not serialize attribute: {e}"),
    }
}
