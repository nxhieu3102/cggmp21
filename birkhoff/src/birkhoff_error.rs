use std::fmt;

/// Error types that can occur in the birkhoff crate
#[derive(Debug, PartialEq, Eq)]
pub enum BirkhoffError {
    /// Error when an element is not invertible
    ElementNotInvertible { row: usize, col: usize },

    /// Error when the ranks and xs have different lengths
    MismatchedLengths { ranks_len: usize, xs_len: usize },

    /// Error when a coefficient is 0 in the birkhoff matrix
    ZeroCoefficient,

    /// Error when a row/column index is out of bounds
    IndexOutOfBounds { index: usize, max_index: usize },

    /// Error when the matrix is not square
    NotSquareMatrix { rows: usize, cols: usize },

    /// Error when the matrix is not diagonal
    NotDiagonalMatrix,
    /// Error when the matrix is not invertible
    NotInvertibleMatrix,

    /// Error when the matrix dimensions do not match for multiplication
    MatrixDimensionsMismatch {
        self_rows: usize,
        self_cols: usize,
        other_rows: usize,
        other_cols: usize,
    },

    /// Error when the rows have different lengths
    RowsDifferentLengths { row1_len: usize, row2_len: usize },

    /// Error when the matrix is not invertible during Gauss elimination
    GaussEliminationFailed,

    /// Error when the matrix is not invertible during matrix inversion
    MatrixInversionFailed,

    /// Error when the matrix is not invertible during pseudo-inverse calculation
    PseudoInverseFailed,

    /// Error when the matrix is not invertible during multi-inverse-diagonal calculation
    MultiInverseDiagonalFailed,

    /// Error when the matrix is not invertible during mod-inverse calculation
    ModInverseFailed,

    /// Error when the matrix is not invertible during polynomial interpolation
    PolynomialInterpolationFailed,

    /// Error when the matrix is not invertible during birkhoff coefficient calculation
    BirkhoffCoefficientFailed,
}

impl fmt::Display for BirkhoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BirkhoffError::ElementNotInvertible { row, col } => {
                write!(f, "Element is not invertible: row={}, col={}", row, col)
            }
            BirkhoffError::MismatchedLengths { ranks_len, xs_len } => {
                write!(
                    f,
                    "Ranks and xs have different lengths: ranks_len={}, xs_len={}",
                    ranks_len, xs_len
                )
            }
            BirkhoffError::ZeroCoefficient => {
                write!(f, "Coefficient is 0")
            }
            BirkhoffError::IndexOutOfBounds { index, max_index } => {
                write!(
                    f,
                    "Row/column index out of bounds: index={}, max_index={}",
                    index, max_index
                )
            }
            BirkhoffError::NotSquareMatrix { rows, cols } => {
                write!(f, "Matrix is not square: rows={}, cols={}", rows, cols)
            }
            BirkhoffError::NotDiagonalMatrix => {
                write!(f, "Matrix is not diagonal")
            }
            BirkhoffError::NotInvertibleMatrix => {
                write!(f, "Matrix is not invertible")
            }
            BirkhoffError::MatrixDimensionsMismatch {
                self_rows,
                self_cols,
                other_rows,
                other_cols,
            } => {
                write!(
                    f,
                    "Matrix dimensions do not match for multiplication: self_rows={}, self_cols={}, other_rows={}, other_cols={}",
                    self_rows, self_cols, other_rows, other_cols
                )
            }
            BirkhoffError::RowsDifferentLengths { row1_len, row2_len } => {
                write!(
                    f,
                    "Rows have different lengths: row1_len={}, row2_len={}",
                    row1_len, row2_len
                )
            }
            BirkhoffError::GaussEliminationFailed => {
                write!(f, "Gauss elimination failed")
            }
            BirkhoffError::MatrixInversionFailed => {
                write!(f, "Matrix inversion failed")
            }
            BirkhoffError::PseudoInverseFailed => {
                write!(f, "Pseudo-inverse calculation failed")
            }
            BirkhoffError::MultiInverseDiagonalFailed => {
                write!(f, "Multi-inverse-diagonal calculation failed")
            }
            BirkhoffError::ModInverseFailed => {
                write!(f, "Mod-inverse calculation failed")
            }
            BirkhoffError::PolynomialInterpolationFailed => {
                write!(f, "Polynomial interpolation failed")
            }
            BirkhoffError::BirkhoffCoefficientFailed => {
                write!(f, "Birkhoff coefficient calculation failed")
            }
        }
    }
}

impl std::error::Error for BirkhoffError {}

/// Result type for the birkhoff crate
pub type BirkhoffResult<T> = Result<T, BirkhoffError>;

/// Helper function to convert a string error to a BirkhoffError
pub fn from_str_error(msg: &'static str) -> BirkhoffError {
    match msg {
        "Element is not invertible" => BirkhoffError::ElementNotInvertible { row: 0, col: 0 },
        "Ranks and xs have different lengths" => BirkhoffError::MismatchedLengths {
            ranks_len: 0,
            xs_len: 0,
        },
        "Coefficient is 0" => BirkhoffError::ZeroCoefficient,
        "Row/column index out of bounds" => BirkhoffError::IndexOutOfBounds {
            index: 0,
            max_index: 0,
        },
        "Matrix is not square" => BirkhoffError::NotSquareMatrix { rows: 0, cols: 0 },
        "Matrix is not diagonal" => BirkhoffError::NotDiagonalMatrix,
        "Matrix is not invertible" => BirkhoffError::NotInvertibleMatrix,
        "Matrix dimensions do not match for multiplication" => {
            BirkhoffError::MatrixDimensionsMismatch {
                self_rows: 0,
                self_cols: 0,
                other_rows: 0,
                other_cols: 0,
            }
        }
        "Rows have different lengths" => BirkhoffError::RowsDifferentLengths {
            row1_len: 0,
            row2_len: 0,
        },
        "Gauss elimination failed" => BirkhoffError::GaussEliminationFailed,
        "Matrix inversion failed" => BirkhoffError::MatrixInversionFailed,
        "Pseudo-inverse calculation failed" => BirkhoffError::PseudoInverseFailed,
        "Multi-inverse-diagonal calculation failed" => BirkhoffError::MultiInverseDiagonalFailed,
        "Mod-inverse calculation failed" => BirkhoffError::ModInverseFailed,
        "Polynomial interpolation failed" => BirkhoffError::PolynomialInterpolationFailed,
        "Birkhoff coefficient calculation failed" => BirkhoffError::BirkhoffCoefficientFailed,
        _ => BirkhoffError::BirkhoffCoefficientFailed,
    }
}
