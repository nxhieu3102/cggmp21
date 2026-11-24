/// Error returned by sessions and helper functions
///
/// Messages never contain secret material: deserialization errors of blobs and peer messages
/// are reported without the underlying decoder message (which could quote input bytes).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Session configuration or function argument is invalid
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// Blob could not be decoded as the expected kind
    #[error("invalid {expected} blob")]
    InvalidBlob {
        /// Kind of blob that was expected
        expected: &'static str,
    },
    /// Message received from a peer was rejected; the session is still usable
    #[error("rejected message from party {sender}: {reason}")]
    InvalidMessage {
        /// Sender of the rejected message, as claimed by the envelope
        sender: u16,
        /// Why the message was rejected
        reason: &'static str,
    },
    /// Protocol failed (e.g. a party misbehaved); the session is terminated
    #[error("protocol failed: {0}")]
    Protocol(String),
    /// Session API used out of order
    #[error("session misuse: {0}")]
    Misuse(&'static str),
    /// Internal error (a bug)
    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl Error {
    /// Builds [`Error::Protocol`] from a protocol error and its chain of sources
    pub(crate) fn protocol(err: &(dyn std::error::Error + 'static)) -> Self {
        let mut msg = err.to_string();
        let mut source = err.source();
        while let Some(s) = source {
            msg.push_str(": ");
            msg.push_str(&s.to_string());
            source = s.source();
        }
        Error::Protocol(msg)
    }
}
