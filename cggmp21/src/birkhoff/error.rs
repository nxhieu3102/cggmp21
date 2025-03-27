use thiserror::Error;

/// Error types for the Birkhoff interpolation module.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// Error when the threshold is equal to or larger than the length of Bk parameters
    #[error("threshold equal or larger than the length of Bk parameters")]
    EqualOrLargerThreshold,
    
    /// Error when no valid Bk parameters are found
    #[error("no valid bks")]
    NoValidBks,
    
    /// Error when Bk parameters are invalid (e.g., duplicate parameters)
    #[error("invalid bks")]
    InvalidBks,
    
    /// Error when a requested Bk parameter does not exist
    #[error("no exist bk")]
    NoExistBk,
    
    /// Error when the computed public key is inconsistent with the expected one
    #[error("inconsistent public key")]
    InconsistentPubKey,
    
    /// Error from matrix operations with a descriptive message
    #[error("matrix error: {0}")]
    MatrixError(String),
    
    /// Error from EC point operations with a descriptive message
    #[error("ec point error: {0}")]
    ECPointError(String),
    
    /// Error when the field order is invalid (e.g., too small)
    #[error("invalid field order")]
    InvalidFieldOrder,
} 
