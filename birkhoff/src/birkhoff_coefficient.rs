use generic_ec::{Curve, NonZero, Scalar};

/// Calculates birkhoff coefficient vector to interpolate a polynomial
///
/// In Birkhoff interpolation, the coefficient vector is the solution to a system of linear equations.
///
/// Birkhoff coefficient are often used to turn polynomial key shares into additive
/// key shares in hierarchical threshold signature schemes.
///
/// ## Inputs
///
/// `threshold`: the threshold value t
///
/// `xs`: the x-coordinates of the shares, by default it's `j + 1` for `j`-th party.
///
/// `ranks`: the ranks of the shares, for all 0 <= `i` < t: ranks[i] < t
///
/// ## Returns
/// Returns `None` if the ranks and xs have different lengths or if the matrix
/// cannot be inverted. Else returns the birkhoff coefficient vector.
///
/// ## Example
///
pub fn birkhoff_coefficient<E: Curve>(
    threshold: u16,
    xs: &[impl AsRef<Scalar<E>>], // x-coordinates of shares
    ranks: &[u16],
) -> Option<Vec<NonZero<Scalar<E>>>> {
    // ranks.len() = xs.len() = number of equations
    if ranks.len() != xs.len() {
        return None;
    }

    let birkhoff_matrix = get_linear_equation_coefficient_matrix(threshold, xs, ranks);

    if let Some(birkhoff_matrix) = birkhoff_matrix {
        // Compute the pseudo-inverse of the matrix
        let invert_matrix = birkhoff_matrix.pseudo_inverse();

        // Extract the first row of the pseudo-inverse
        match invert_matrix {
            Ok(matrix) => Some(matrix.get_row(0)),
            // None if the matrix cannot be inverted
            Err(_) => None,
        }
    } else {
        // None if exist coefficient is 0 in the birkhoff matrix
        None
    }
}

// Establish the coefficient of linear system of Birkhoff systems
fn get_linear_equation_coefficient_matrix<E: Curve>(
    threshold: u16,
    xs: &[impl AsRef<Scalar<E>>],
    ranks: &[u16],
) -> Option<BirkhoffMatrix<E>> {
    let num_row = ranks.len();
    let num_col = threshold as usize;

    let mut cells = vec![vec![NonZero::from_scalar(Scalar::from(1)).unwrap(); num_col]; num_row];

    for r in 0..num_row {
        for c in 0..num_col {
            let cell = get_coefficient(xs[r].as_ref(), c as u16, ranks[r]);

            match cell {
                Some(cell) => cells[r][c] = cell,
                None => return None,
            }
        }
    }

    Some(BirkhoffMatrix {
        rows: num_row,
        cols: num_col,
        cells,
    })
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
) -> Option<NonZero<Scalar<E>>> {
    // If exp < derivative_order, the derivative is 0
    if exp < derivative_order {
        return Some(NonZero::from_scalar(Scalar::from(0)).unwrap());
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
        None
    } else {
        Some(NonZero::from_scalar(coeff).unwrap())
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
    /// Returns a Result with the pseudoinverse matrix or an error message
    ///
    /// Pseudoinverse is the general inverse of non-square matrix.
    /// This is a special case of Pseudoinverse. In particular,
    /// if the matrix is non-singular and square, then Pseudoinverse is the standard inverse matrix.
    ///
    /// More details can be found in https://en.wikipedia.org/wiki/Moore%E2%80%93Penrose_inverse
    ///
    /// If m^t*m is invertible. In this case, an explicitly formula is : (m^t*m)^(-1)*m^t.
    ///
    /// This function only works under the following conditions:
    /// - the columns of m are linearly independent
    /// - row rank >= column rank.
    pub fn pseudo_inverse(&self) -> Result<BirkhoffMatrix<E>, &'static str> {
        // For a simple implementation, we'll use the formula: A^+ = (A^T * A)^(-1) * A^T
        // This works for full-rank matrices

        // Create the transpose of self
        let transpose = self.transpose();

        // Compute A^T * A (symmetric form)
        let symmetric_form = transpose.multiply(self)?;

        // Compute (A^T * A)^(-1)
        let inverse_symmetric = symmetric_form.inverse()?;

        // Compute (A^T * A)^(-1) * A^T
        let result = inverse_symmetric.multiply(&transpose)?;

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
    pub fn multiply(&self, other: &BirkhoffMatrix<E>) -> Result<BirkhoffMatrix<E>, &'static str> {
        // Check if the number of columns in the first matrix matches the number of rows in the second matrix
        if self.cols != other.rows {
            return Err("Matrix dimensions do not match");
        }

        let mut result = BirkhoffMatrix {
            rows: self.rows,
            cols: other.cols,
            cells: vec![
                vec![NonZero::from_scalar(Scalar::from(1)).unwrap(); other.cols];
                self.rows
            ],
        };

        for i in 0..self.cells.len() {
            for j in 0..other.cells[0].len() {
                let mut sum = Scalar::from(0);
                for k in 0..self.cells[0].len() {
                    sum = sum + self.cells[i][k] * other.cells[k][j];
                }

                match NonZero::from_scalar(sum) {
                    Some(non_zero) => result.cells[i][j] = non_zero,
                    None => return Err("Matrix contains non-zero elements"),
                }
            }
        }

        Ok(result)
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
            cells: vec![vec![NonZero::from_scalar(Scalar::from(1)).unwrap(); self.rows]; self.cols],
        };

        for i in 0..self.cells.len() {
            for j in 0..self.cells[0].len() {
                result.cells[j][i] = self.cells[i][j];
            }
        }

        result
    }

    /// Inverts the matrix A
    /// Returns a new matrix with the inverse of the original matrix.
    pub fn inverse(&self) -> Result<BirkhoffMatrix<E>, &'static str> {
        // Check if the matrix is square
        if !self.is_square() {
            return Err("Matrix is not square");
        }

        // Get U, L^{-1}. Note that A = L*U
        let (upper_matrix, lower_matrix) = self.get_gauss_elimination()?;

        // Make a copy of lower matrix
        let copy_lower_matrix = lower_matrix.clone();

        // K = U^t
        let upper_matrix = upper_matrix.transpose();

        // Get D, L_K^{-1}. Note that K = L_K*D
        let (temp_upper_matrix, temp_lower_matrix) = upper_matrix.get_gauss_elimination()?;

        // Get (D^{-1}L_{K}^{-1})^t = ((L_K*D)^{-1})^t = (K^{-1})^{t}
        let mut temp_result = temp_lower_matrix.multi_inverse_diagonal(&temp_upper_matrix)?;

        // Transpose to get U^{-1}
        temp_result = temp_result.transpose();

        // U^{-1}*L^{-1} = (L*U)^{-1} = A^{-1}
        let result = temp_result.multiply(&copy_lower_matrix)?;

        Ok(result)
    }
}

impl<E: Curve> BirkhoffMatrix<E> {
    fn is_square(&self) -> bool {
        self.cols != self.rows
    }

    /// Only work "matrixA is squared-matrix"
    /// Then the output is U_A and L^{-1} such that L*U_A = A. Here U_A is a upper triangular matrix
    /// with det(U_A) = det(A). (i.e. <A|I> = <U_A|L^{-1}> by Gauss elimination)
    fn get_gauss_elimination(
        &self,
    ) -> Result<(BirkhoffMatrix<E>, BirkhoffMatrix<E>), &'static str> {
        // Check if the matrix is square
        if !self.is_square() {
            return Err("Matrix is not square");
        }

        // Create identity matrix for lower matrix
        let mut lower = Self::create_identity_matrix(self.rows)?;

        // Create a copy of self for upper matrix
        let mut upper = self.clone();

        // Perform Gaussian elimination
        for i in 0..self.rows {
            // Find a non-zero coefficient in the current column
            let change_index = match upper.get_non_zero_coefficient_by_row(i, i) {
                Some(idx) => idx,
                None => return Err("Matrix is not invertible"),
            };

            // If the index is changed, swap rows
            if i != change_index {
                // Swap rows in upper matrix
                upper = upper.swap_rows(i, change_index)?;

                // Swap rows in lower matrix
                lower = lower.swap_rows(i, change_index)?;
            }

            // Get the inverse of the pivot element
            let inverse = upper.mod_inverse(i, i)?;

            // Eliminate elements below the pivot
            for j in (i + 1)..self.rows {
                // Calculate the factor to eliminate the element
                let factor = upper.cells[j][i] * inverse;
                let inverse_diagonal_component = -factor;

                // Get rows for upper matrix
                let row_i = upper.get_row(i);
                let row_j = upper.get_row(j);

                // Multiply row_i by the factor
                let temp_result_a = self.multiply_scalar(&row_i, inverse_diagonal_component)?;

                // Add the multiplied row to row_j
                upper.cells[j] = self.add_rows(&row_j, &temp_result_a)?;

                // Do the same operation for lower matrix
                let row_lower_i = lower.get_row(i);
                let row_lower_j = lower.get_row(j);

                // Multiply row_lower_i by the factor
                let temp_result_identity =
                    self.multiply_scalar(&row_lower_i, inverse_diagonal_component)?;

                // Add the multiplied row to row_lower_j
                lower.cells[j] = self.add_rows(&row_lower_j, &temp_result_identity)?;
            }
        }

        // Apply modulus to both matrices
        upper = upper.modulus();
        lower = lower.modulus();

        Ok((upper, lower))
    }

    /// Creates an identity matrix with the same dimensions as self
    fn create_identity_matrix(rank: usize) -> Result<BirkhoffMatrix<E>, &'static str> {
        let mut cells = vec![vec![NonZero::from_scalar(Scalar::from(1)).unwrap(); rank]; rank];

        // Set diagonal elements to 1, others to 0
        for i in 0..rank {
            for j in 0..rank {
                if i == j {
                    cells[i][j] = NonZero::from_scalar(Scalar::from(1)).unwrap();
                } else {
                    cells[i][j] = NonZero::from_scalar(Scalar::from(0)).unwrap();
                }
            }
        }

        Ok(BirkhoffMatrix {
            rows: rank,
            cols: rank,
            cells,
        })
    }

    /// Finds a non-zero coefficient in the specified row and column
    fn get_non_zero_coefficient_by_row(&self, row: usize, col: usize) -> Option<usize> {
        // Start from the specified column
        for j in col..self.cols {
            if self.cells[row][j] != NonZero::from_scalar(Scalar::from(0)).unwrap() {
                return Some(j);
            }
        }

        // If no non-zero coefficient is found, return None
        None
    }

    /// Swaps two rows in the matrix
    fn swap_rows(&self, row1: usize, row2: usize) -> Result<BirkhoffMatrix<E>, &'static str> {
        if row1 >= self.rows || row2 >= self.rows {
            return Err("Row index out of bounds");
        }

        let mut result = self.clone();

        // Swap the rows
        result.cells.swap(row1, row2);

        Ok(result)
    }

    /// Multiplies a row by a scalar
    fn multiply_scalar(
        &self,
        row: &[NonZero<Scalar<E>>],
        scalar: Scalar<E>,
    ) -> Result<Vec<NonZero<Scalar<E>>>, &'static str> {
        let mut result = Vec::with_capacity(row.len());

        for &element in row {
            result.push(NonZero::from_scalar(element * scalar).unwrap());
        }

        Ok(result)
    }

    /// Adds two rows element by element
    fn add_rows(
        &self,
        row1: &[NonZero<Scalar<E>>],
        row2: &[NonZero<Scalar<E>>],
    ) -> Result<Vec<NonZero<Scalar<E>>>, &'static str> {
        if row1.len() != row2.len() {
            return Err("Rows have different lengths");
        }

        let mut result = Vec::with_capacity(row1.len());

        for i in 0..row1.len() {
            result.push(NonZero::from_scalar(row1[i] + row2[i]).ok_or("Zero element in result")?);
        }

        Ok(result)
    }

    /// Applies modulus to all elements in the matrix
    fn modulus(&self) -> BirkhoffMatrix<E> {
        self.clone() // In this implementation, we don't need to apply modulus
    }

    /// Inverse the diagonal matrix and multiplies it with the current matrix
    /// Only use in computing the inverse of the matrix
    /// compute: A * diag^{-1}
    fn multi_inverse_diagonal(
        &self,
        diagonal: &BirkhoffMatrix<E>,
    ) -> Result<BirkhoffMatrix<E>, &'static str> {
        // Ensure diagonal matrix is square and has the same number of rows as columns in self
        if self.cols != diagonal.rows || !diagonal.is_square() {
            return Err("Matrix dimensions do not match for multiplication");
        }

        // Create the result matrix with the same number of rows as `self` and columns as `diagonal`
        let mut result = BirkhoffMatrix {
            rows: self.rows,
            cols: diagonal.cols,
            cells: vec![
                vec![NonZero::from_scalar(Scalar::from(1)).unwrap(); diagonal.cols];
                self.rows
            ],
        };

        // Iterate over each element and multiply the corresponding element by the inverse of the diagonal element
        for i in 0..self.rows {
            for j in 0..diagonal.cols {
                // Inverse the diagonal element and multiply with the corresponding column in self
                let inverse_diagonal_element = diagonal.mod_inverse(j, j)?; // Reciprocal of the diagonal element
                result.cells[i][j] =
                    NonZero::from_scalar(self.cells[i][j] * inverse_diagonal_element)
                        .ok_or("Zero element in result matrix")?;
            }
        }

        Ok(result)
    }

    // calculate self.cells[row][col]^-1
    fn mod_inverse(&self, row: usize, col: usize) -> Result<Scalar<E>, &'static str> {
        todo!()
    }
}
