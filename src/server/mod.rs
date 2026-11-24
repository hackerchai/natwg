//! The long-running server: the tunnel, and the tasks that keep its public
//! mapping alive and published.

pub mod cloudflare;
pub mod keepalive;
pub mod upnp;

/// An error with the errors that caused it, such as the refused connection
/// behind reqwest's "error sending request".
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
