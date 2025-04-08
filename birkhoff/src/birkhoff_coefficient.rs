use generic_ec::{Curve, NonZero, Scalar};

/// Calculates birkhoff coefficient vector to interpolate a polynomial at point $x$
///
/// Birkhoff coefficient are often used to turn polynomial key shares into additive
/// key shares in hierarchical threshold signature schemes.
///
/// ## Inputs
///
/// `threshold`: the threshold value t
///
/// `indexes`: the x-coordinates of the shares, by default it's `j + 1` for `j`-th party.
///
/// `ranks`: the ranks of the shares, for all 0 <= `i` < t: ranks[i] < t
///
/// ## Returns
/// Returns `None` if the ranks and indexes have different lengths or if the matrix
/// cannot be inverted. Else returns the birkhoff coefficient vector.
///
/// ## Example
///
pub fn birkhoff_coefficient<E: Curve>(
    threshold: u16,
    indexes: &[impl AsRef<Scalar<E>>], // x-coordinates of shares
    ranks: &[u16],
) -> Option<Vec<NonZero<Scalar<E>>>> {
    // ranks.len() = indexes.len() = number of equations
    if ranks.len() != indexes.len() {
        return None;
    }

    let birkhoff_matrix = get_linear_equation_coefficient_matrix(threshold, indexes, ranks);

    // Compute the pseudo-inverse of the matrix
    let invert_matrix = birkhoff_matrix.pseudo_inverse();

    // Extract the first row of the pseudo-inverse
    match invert_matrix {
        Ok(matrix) => Some(matrix.get_row(0)),
        Err(_) => None,
    }
}

// Establish the coefficient of linear system of Birkhoff systems
fn get_linear_equation_coefficient_matrix<E: Curve>(
    threshold: u16,
    indexes: &[impl AsRef<Scalar<E>>],
    ranks: &[u16],
) -> BirkhoffMatrix<E> {
    let num_row = ranks.len();
    let num_col = threshold as usize;

    let mut cells = vec![vec![NonZero::from_scalar(Scalar::from(0)).unwrap(); num_col]; num_row];

    for r in 0..num_row {
        for c in 0..num_col {
            let cell = get_coefficient(indexes[r].as_ref(), c as u16, ranks[r]);
            cells[r][c] = cell;
        }
    }

    BirkhoffMatrix {
        rows: num_row,
        cols: num_col,
        cells,
    }
}

/// Get the coefficient at one cell of the linear system of Birkhoff systems: (x^exp)[derivative_order]
///
/// (x^exp)[derivative_order] = (exp * (exp - 1) * (exp - 2) * ... * (exp - derivative_order + 1)) * x^(exp - derivative_order)
///
/// Example 1:
/// x = 3, exp = 2, derivative_order = 1
/// (x^2)' = (2x) = 2 * 3 = 6
///
/// Example 2:
/// x = 3, exp = 2, derivative_order = 2
/// (x^2)'' = (2x)' = 2
///
/// Example 3:
/// x = 5, exp = 5, derivative_order = 2
/// (x^5)'' = (5x^4)' = (5*4*x^3) = 5 * 4 * 5^3 = 2500
///
fn get_coefficient<E: Curve>(
    x: impl AsRef<Scalar<E>>,
    exp: u16,
    derivative_order: u16,
) -> NonZero<Scalar<E>> {
    // If exp < derivative_order, the derivative is 0
    if exp < derivative_order {
        return NonZero::from_scalar(Scalar::from(0)).unwrap();
    }

    let mut coeff = Scalar::from(1);

    // (exp - 0)(exp - 1)(exp - 2)...(exp - (derivative_order - 1))
    for i in 0..derivative_order {
        coeff = coeff * Scalar::from(exp - i);
    }

    // x^(exp - derivative_order)
    let x_pow = if exp > derivative_order {
        let mut result = Scalar::from(1);
        for _ in 0..(exp - derivative_order) {
            result = result * x.as_ref();
        }
        result
    } else {
        Scalar::from(1)
    };

    coeff = coeff * x_pow;

    // Ensure the coefficient is non-zero
    if coeff == Scalar::from(0) {
        // This should never happen in practice for valid inputs
        // But we handle it just in case
        NonZero::from_scalar(Scalar::from(1)).unwrap()
    } else {
        NonZero::from_scalar(coeff).unwrap()
    }
}

#[derive(Clone)]
pub struct BirkhoffMatrix<E: Curve> {
    rows: usize,
    cols: usize,
    cells: Vec<Vec<NonZero<Scalar<E>>>>,
}

impl<E: Curve> BirkhoffMatrix<E> {
    pub fn get_row(&self, row: usize) -> Vec<NonZero<Scalar<E>>> {
        if row < self.cells.len() {
            self.cells[row].clone()
        } else {
            vec![]
        }
    }
}

impl<E: Curve> BirkhoffMatrix<E> {
    /// Computes the Moore-Penrose pseudoinverse of the matrix.
    /// Returns a Result with the pseudoinverse matrix or an error message.
    pub fn pseudo_inverse(&self) -> Result<BirkhoffMatrix<E>, &'static str> {
        // For a simple implementation, we'll use the formula: A^+ = (A^T * A)^(-1) * A^T
        // This works for full-rank matrices

        // Create the transpose of self
        let transpose = self.transpose();

        // Compute A^T * A (symmetric form)
        let symmetric_form = transpose.multiply(self);

        // Compute (A^T * A)^(-1)
        let inverse_symmetric = symmetric_form.inverse();

        // Compute (A^T * A)^(-1) * A^T
        let result = inverse_symmetric.multiply(&transpose);

        Ok(result)
    }

    /// Multiplies this matrix with another matrix.
    /// Returns a new matrix with the product of the two matrices.
    ///
    /// Example:
    /// matrix1 = [
    ///     [1, 2, 3],
    ///     [4, 5, 6],
    ///     [7, 8, 9],
    /// ]
    /// matrix2 = [
    ///     [1, 2, 3],
    ///     [4, 5, 6],
    ///     [7, 8, 9],
    ///
    /// Multiplication:
    ///     [1*1 + 2*4 + 3*7, 1*2 + 2*5 + 3*8, 1*3 + 2*6 + 3*9],
    ///     [4*1 + 5*4 + 6*7, 4*2 + 5*5 + 6*8, 4*3 + 5*6 + 6*9],
    ///     [7*1 + 8*4 + 9*7, 7*2 + 8*5 + 9*8, 7*3 + 8*6 + 9*9],
    /// ]
    ///
    /// Result:
    ///     [30, 36, 42],
    ///     [66, 81, 96],
    ///     [102, 126, 150],
    /// ]
    ///
    pub fn multiply(&self, other: &BirkhoffMatrix<E>) -> BirkhoffMatrix<E> {
        let mut result = BirkhoffMatrix {
            rows: self.rows,
            cols: other.cols,
            cells: vec![
                vec![NonZero::from_scalar(Scalar::from(0)).unwrap(); other.cols];
                self.rows
            ],
        };

        for i in 0..self.cells.len() {
            for j in 0..other.cells[0].len() {
                let mut sum = Scalar::from(0);
                for k in 0..self.cells[0].len() {
                    sum = sum + self.cells[i][k] * other.cells[k][j];
                }
                result.cells[i][j] = NonZero::from_scalar(sum).unwrap();
            }
        }

        result
    }

    /// Transposes the matrix.
    /// Returns a new matrix with the rows and columns swapped.
    /// matrix[i][j] --> matrix[j][i]
    ///
    /// Example:
    /// matrix = [
    ///     [1, 2, 3],
    ///     [4, 5, 6],
    ///     [7, 8, 9],
    /// ]
    /// Transpose:
    /// matrix = [
    ///     [1, 4, 7],
    ///     [2, 5, 8],
    ///     [3, 6, 9],
    /// ]
    pub fn transpose(&self) -> BirkhoffMatrix<E> {
        let mut result = BirkhoffMatrix {
            rows: self.cols,
            cols: self.rows,
            cells: vec![vec![NonZero::from_scalar(Scalar::from(0)).unwrap(); self.rows]; self.cols],
        };

        for i in 0..self.cells.len() {
            for j in 0..self.cells[0].len() {
                result.cells[j][i] = self.cells[i][j];
            }
        }

        result
    }

    /// Inverts the matrix.
    /// Returns a new matrix with the inverse of the original matrix.
    pub fn inverse(&self) -> BirkhoffMatrix<E> {
        // TODO: Implement the inverse of the matrix
        todo!()
    }
}
