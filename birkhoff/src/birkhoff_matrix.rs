use crate::birkhoff_error::{BirkhoffError, BirkhoffResult};
use generic_ec::{Curve, NonZero, Scalar};

#[derive(Clone)]
pub struct BirkhoffMatrix<E: Curve> {
    /// The coefficient can be 0 at some cells
    cells: Vec<Vec<Scalar<E>>>,
}

impl<E: Curve> BirkhoffMatrix<E> {
    pub fn new_with_size(rows: usize, cols: usize, value: Scalar<E>) -> Self {
        Self {
            cells: vec![vec![value; cols]; rows],
        }
    }

    pub fn new(cells: Vec<Vec<Scalar<E>>>) -> Self {
        Self { cells }
    }

    pub fn rows(&self) -> usize {
        self.cells.len()
    }

    pub fn cols(&self) -> usize {
        self.cells[0].len()
    }
}

impl<E: Curve> BirkhoffMatrix<E> {
    pub fn get_row(&self, row: usize) -> BirkhoffResult<Vec<Scalar<E>>> {
        if row >= self.rows() {
            return Err(BirkhoffError::IndexOutOfBounds {
                index: row,
                max_index: self.rows(),
            });
        }

        Ok(self.cells[row].clone())
    }

    pub fn get_row_non_zero(&self, row: usize) -> BirkhoffResult<Vec<NonZero<Scalar<E>>>> {
        let mut result = Vec::with_capacity(self.cols());

        for i in 0..self.cols() {
            let non_zero = NonZero::from_scalar(self.cells[row][i]);

            match non_zero {
                Some(non_zero) => result.push(non_zero),
                None => return Err(BirkhoffError::ZeroCoefficient),
            }
        }

        Ok(result)
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
    pub fn pseudo_inverse(&self) -> BirkhoffResult<BirkhoffMatrix<E>> {
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
}

impl<E: Curve> BirkhoffMatrix<E> {
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
    pub fn multiply(&self, other: &BirkhoffMatrix<E>) -> BirkhoffResult<BirkhoffMatrix<E>> {
        // Check if the number of columns in the first matrix matches the number of rows in the second matrix
        if self.cols() != other.rows() {
            return Err(BirkhoffError::MatrixDimensionsMismatch {
                self_rows: self.rows(),
                self_cols: self.cols(),
                other_rows: other.rows(),
                other_cols: other.cols(),
            });
        }

        let mut result = BirkhoffMatrix::new_with_size(self.rows(), other.cols(), Scalar::zero());

        for i in 0..self.cells.len() {
            for j in 0..other.cells[0].len() {
                let mut sum = Scalar::from(0);
                for k in 0..self.cells[0].len() {
                    sum = sum + self.cells[i][k] * other.cells[k][j];
                }

                result.cells[i][j] = sum;
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
        let mut result = BirkhoffMatrix::new_with_size(self.cols(), self.rows(), Scalar::zero());

        for i in 0..self.cells.len() {
            for j in 0..self.cells[0].len() {
                result.cells[j][i] = self.cells[i][j];
            }
        }

        result
    }

    /// Inverts the matrix A
    /// Returns a new matrix with the inverse of the original matrix.
    pub fn inverse(&self) -> BirkhoffResult<BirkhoffMatrix<E>> {
        // Check if the matrix is square
        if !self.is_square() {
            return Err(BirkhoffError::NotSquareMatrix {
                rows: self.rows(),
                cols: self.cols(),
            });
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
        self.cols() == self.rows()
    }

    /// Only work "matrixA is squared-matrix"
    /// Then the output is U_A and L^{-1} such that L*U_A = A. Here U_A is a upper triangular matrix
    /// with det(U_A) = det(A). (i.e. <A|I> = <U_A|L^{-1}> by Gauss elimination)
    fn get_gauss_elimination(&self) -> BirkhoffResult<(BirkhoffMatrix<E>, BirkhoffMatrix<E>)> {
        // Check if the matrix is square
        if !self.is_square() {
            return Err(BirkhoffError::NotSquareMatrix {
                rows: self.rows(),
                cols: self.cols(),
            });
        }

        // Create identity matrix for lower matrix
        let mut lower = Self::create_identity_matrix(self.rows())?;

        // Create a copy of self for upper matrix
        let mut upper = self.clone();

        // Perform Gaussian elimination
        for i in 0..self.rows() {
            // Find a non-zero coefficient in the current column
            let change_index = match upper.get_non_zero_coefficient_by_row(i, i) {
                Some(idx) => idx,
                None => return Err(BirkhoffError::MatrixInversionFailed),
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
            for j in (i + 1)..self.rows() {
                // Calculate the factor to eliminate the element
                let factor = upper.cells[j][i] * inverse;
                let inverse_diagonal_component = -factor;

                // Get rows for upper matrix
                let row_i = upper.get_row(i)?;
                let row_j = upper.get_row(j)?;

                // Multiply row_i by the factor
                let temp_result_a = self.multiply_scalar(&row_i, inverse_diagonal_component);

                // Add the multiplied row to row_j
                upper.cells[j] = self.add_rows(&row_j, &temp_result_a)?;

                // Do the same operation for lower matrix
                let row_lower_i = lower.get_row(i)?;
                let row_lower_j = lower.get_row(j)?;

                // Multiply row_lower_i by the factor
                let temp_result_identity =
                    self.multiply_scalar(&row_lower_i, inverse_diagonal_component);

                // Add the multiplied row to row_lower_j
                lower.cells[j] = self.add_rows(&row_lower_j, &temp_result_identity)?;
            }
        }

        Ok((upper, lower))
    }

    /// Creates an identity matrix with the same dimensions as self
    fn create_identity_matrix(rank: usize) -> BirkhoffResult<BirkhoffMatrix<E>> {
        let mut cells = vec![vec![Scalar::from(0); rank]; rank];

        // Set diagonal elements to 1, others to 0
        for i in 0..rank {
            cells[i][i] = Scalar::from(1);
        }

        Ok(BirkhoffMatrix::new(cells))
    }

    /// Finds a non-zero coefficient in the specified row
    /// Start from the specified column
    /// Return the index of the non-zero coefficient
    fn get_non_zero_coefficient_by_row(&self, row: usize, col: usize) -> Option<usize> {
        // Start from the specified column
        for j in col..self.cols() {
            if self.cells[row][j] != Scalar::from(0) {
                return Some(j);
            }
        }

        // If no non-zero coefficient is found, return None
        None
    }

    /// Swaps two rows in the matrix
    fn swap_rows(&self, row1: usize, row2: usize) -> BirkhoffResult<BirkhoffMatrix<E>> {
        if row1 >= self.rows() || row2 >= self.rows() {
            return Err(BirkhoffError::IndexOutOfBounds {
                index: row1.max(row2),
                max_index: self.rows(),
            });
        }

        let mut result = self.clone();

        // Swap the rows
        result.cells.swap(row1, row2);

        Ok(result)
    }

    /// Multiplies a row by a scalar
    fn multiply_scalar(&self, row: &[Scalar<E>], scalar: Scalar<E>) -> Vec<Scalar<E>> {
        let mut result = Vec::with_capacity(row.len());

        for &element in row {
            result.push(element * scalar);
        }

        result
    }

    /// Adds two rows element by element
    fn add_rows(&self, row1: &[Scalar<E>], row2: &[Scalar<E>]) -> BirkhoffResult<Vec<Scalar<E>>> {
        if row1.len() != row2.len() {
            return Err(BirkhoffError::RowsDifferentLengths {
                row1_len: row1.len(),
                row2_len: row2.len(),
            });
        }

        let mut result = Vec::with_capacity(row1.len());

        for i in 0..row1.len() {
            result.push(row1[i] + row2[i]);
        }

        Ok(result)
    }

    /// Inverse the diagonal matrix and multiplies it with the current matrix
    /// Only use in computing the inverse of the matrix
    /// compute: A * diag^{-1}
    fn multi_inverse_diagonal(
        &self,
        diagonal: &BirkhoffMatrix<E>,
    ) -> BirkhoffResult<BirkhoffMatrix<E>> {
        // Ensure diagonal matrix is square and has the same number of rows as columns in self
        if self.cols() != diagonal.rows() || !diagonal.is_square() {
            return Err(BirkhoffError::MatrixDimensionsMismatch {
                self_rows: self.rows(),
                self_cols: self.cols(),
                other_rows: diagonal.rows(),
                other_cols: diagonal.cols(),
            });
        }

        // Create the result matrix with the same number of rows as `self` and columns as `diagonal`
        let mut result =
            BirkhoffMatrix::new_with_size(self.rows(), diagonal.cols(), Scalar::zero());

        // Iterate over each element and multiply the corresponding element by the inverse of the diagonal element
        for i in 0..self.rows() {
            for j in 0..diagonal.cols() {
                // Inverse the diagonal element and multiply with the corresponding column in self
                let inverse_diagonal_element = diagonal.mod_inverse(j, j)?; // Reciprocal of the diagonal element
                result.cells[i][j] = self.cells[i][j] * inverse_diagonal_element;
            }
        }

        Ok(result)
    }

    // calculate self.cells[row][col]^-1
    fn mod_inverse(&self, row: usize, col: usize) -> BirkhoffResult<Scalar<E>> {
        if row >= self.rows() || col >= self.cols() {
            return Err(BirkhoffError::IndexOutOfBounds {
                index: row.max(col),
                max_index: self.rows().max(self.cols()),
            });
        }

        let element = self.cells[row][col];

        let inverse = element.invert();

        match inverse {
            Some(inverse) => Ok(inverse),
            None => Err(BirkhoffError::ElementNotInvertible { row: row, col: col }),
        }
    }
}
