use crate::birkhoff_error::{BirkhoffError, BirkhoffResult};
use generic_ec::{Curve, NonZero, Scalar};

#[derive(Clone, Debug, PartialEq, Eq)]
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
                max_index: self.rows() - 1,
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

        // Compute (A^T * A)^(-1) * A^T = A^+
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
                    sum += self.cells[i][k] * other.cells[k][j];
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

        // K = U^t
        let transpose_upper_matrix = upper_matrix.transpose();

        // Get D, L_K^{-1}. Note that K = L_K*D
        let (temp_upper_matrix, temp_lower_matrix) =
            transpose_upper_matrix.get_gauss_elimination()?;

        // Get (D^{-1}L_{K}^{-1})^t = ((L_K*D)^{-1})^t = (K^{-1})^{t}
        // K = U^t, so the result is (U^t)^{-1}^t
        let temp_result = temp_lower_matrix.multi_inverse_diagonal(&temp_upper_matrix)?;

        // Transpose to get U^{-1}
        // Transpose (U^t)^{-1}^t --> (U^t)^{-1}
        // Why (U^t)^{-1} = (U^{-1})
        let transpose_result = temp_result.transpose();

        // U^{-1}*L^{-1} = (L*U)^{-1} = A^{-1}
        let result = transpose_result.multiply(&lower_matrix)?;

        Ok(result)
    }
}

impl<E: Curve> BirkhoffMatrix<E> {
    fn is_square(&self) -> bool {
        self.cols() == self.rows()
    }

    fn is_diagonal(&self) -> bool {
        // check if the matrix is square
        if !self.is_square() {
            return false;
        }

        for i in 0..self.rows() {
            for j in 0..self.cols() {
                if i != j && self.cells[i][j] != Scalar::zero() {
                    return false;
                }
            }
        }

        true
    }

    fn is_identity(&self) -> bool {
        if !self.is_square() {
            return false;
        }

        for i in 0..self.rows() {
            for j in 0..self.cols() {
                if (i != j && self.cells[i][j] != Scalar::zero())
                    || (i == j && self.cells[i][j] != Scalar::one())
                {
                    return false;
                }
            }
        }

        true
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
        let mut lower = Self::create_identity_matrix(self.rows());

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
                upper.cells[j] = Self::add_rows(&row_j, &temp_result_a)?;

                // Do the same operation for lower matrix
                let row_lower_i = lower.get_row(i)?;
                let row_lower_j = lower.get_row(j)?;

                // Multiply row_lower_i by the factor
                let temp_result_identity =
                    self.multiply_scalar(&row_lower_i, inverse_diagonal_component);

                // Add the multiplied row to row_lower_j
                lower.cells[j] = Self::add_rows(&row_lower_j, &temp_result_identity)?;
            }
        }

        Ok((upper, lower))
    }

    /// Creates an identity matrix with the same dimensions as self
    fn create_identity_matrix(rank: usize) -> BirkhoffMatrix<E> {
        let mut cells = vec![vec![Scalar::from(0); rank]; rank];

        // Set diagonal elements to 1, others to 0
        for (i, row_i) in cells.iter_mut().enumerate().take(rank) {
            row_i[i] = Scalar::from(1);
        }

        BirkhoffMatrix::new(cells)
    }

    /// Finds a non-zero coefficient in the specified row
    /// Start from the specified column
    /// Return the index of the non-zero coefficient
    fn get_non_zero_coefficient_by_row(&self, row: usize, col: usize) -> Option<usize> {
        (col..self.cols()).find(|&j| self.cells[row][j] != Scalar::from(0))
    }

    /// Swaps two rows in the matrix
    fn swap_rows(&self, row1: usize, row2: usize) -> BirkhoffResult<BirkhoffMatrix<E>> {
        if row1 >= self.rows() || row2 >= self.rows() {
            return Err(BirkhoffError::IndexOutOfBounds {
                index: row1.max(row2),
                max_index: self.rows() - 1,
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
    fn add_rows(row1: &[Scalar<E>], row2: &[Scalar<E>]) -> BirkhoffResult<Vec<Scalar<E>>> {
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
    /// compute: diag^{-1} * A
    /// result[i] = A[i] * diag^{-1}[i][i]
    fn multi_inverse_diagonal(
        &self,
        diagonal: &BirkhoffMatrix<E>,
    ) -> BirkhoffResult<BirkhoffMatrix<E>> {
        // Ensure diagonal matrix is square and has the same number of rows as columns in self
        if diagonal.cols() != self.rows() {
            return Err(BirkhoffError::MatrixDimensionsMismatch {
                self_rows: diagonal.rows(),
                self_cols: diagonal.cols(),
                other_rows: self.rows(),
                other_cols: self.cols(),
            });
        }

        // check if the diagonal matrix is diagonal
        if !diagonal.is_diagonal() {
            return Err(BirkhoffError::NotDiagonalMatrix);
        }

        // Create the result matrix with the same number of rows as `self` and columns as `diagonal`
        let mut result =
            BirkhoffMatrix::new_with_size(diagonal.rows(), self.cols(), Scalar::zero());

        // Iterate over each element and multiply the corresponding element by the inverse of the diagonal element
        for i in 0..diagonal.rows() {
            for j in 0..self.cols() {
                // Inverse the diagonal element and multiply with the corresponding column in self
                let inverse_diagonal_element = diagonal.mod_inverse(i, i)?; // Reciprocal of the diagonal element
                result.cells[i][j] = self.cells[i][j] * inverse_diagonal_element;
            }
        }

        Ok(result)
    }

    // calculate self.cells[row][col]^-1
    fn mod_inverse(&self, row: usize, col: usize) -> BirkhoffResult<Scalar<E>> {
        if row >= self.rows() {
            return Err(BirkhoffError::IndexOutOfBounds {
                index: row,
                max_index: self.rows() - 1,
            });
        }

        if col >= self.cols() {
            return Err(BirkhoffError::IndexOutOfBounds {
                index: col,
                max_index: self.cols() - 1,
            });
        }

        let element = self.cells[row][col];

        let inverse = element.invert();

        match inverse {
            Some(inverse) => Ok(inverse),
            None => Err(BirkhoffError::ElementNotInvertible { row, col }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::curves;

    type E = curves::Secp256k1;

    #[test]
    fn test_new() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        assert_eq!(matrix.rows(), 2);
        assert_eq!(matrix.cols(), 3);

        assert_eq!(matrix.cells[0][0], Scalar::from(1));
        assert_eq!(matrix.cells[0][1], Scalar::from(2));
        assert_eq!(matrix.cells[0][2], Scalar::from(3));
        assert_eq!(matrix.cells[1][0], Scalar::from(4));
        assert_eq!(matrix.cells[1][1], Scalar::from(5));
        assert_eq!(matrix.cells[1][2], Scalar::from(6));
    }

    #[test]
    fn test_new_with_size() {
        let matrix = BirkhoffMatrix::<E>::new_with_size(2, 3, Scalar::from(10));

        assert_eq!(matrix.rows(), 2);
        assert_eq!(matrix.cols(), 3);

        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                assert_eq!(matrix.cells[i][j], Scalar::from(10));
            }
        }
    }

    #[test]
    fn test_create_identity_matrix() {
        let matrix = BirkhoffMatrix::<E>::create_identity_matrix(3);

        assert_eq!(matrix.rows(), 3);
        assert_eq!(matrix.cols(), 3);
        assert!(matrix.is_identity());
    }

    #[test]
    fn happy_test_get_non_zero_coefficient_by_row() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(0), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(6)],
        ]);

        assert_eq!(matrix.get_non_zero_coefficient_by_row(0, 0), Some(1));
        assert_eq!(matrix.get_non_zero_coefficient_by_row(0, 1), Some(1));
        assert_eq!(matrix.get_non_zero_coefficient_by_row(1, 1), Some(2));
    }

    #[test]
    fn unhappy_test_get_non_zero_coefficient_by_row() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(6)],
        ]);

        assert_eq!(matrix.get_non_zero_coefficient_by_row(0, 0), None);
    }

    #[test]
    fn happy_test_is_identity() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(1), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(1)],
        ]);

        assert!(matrix.is_identity());
    }

    #[test]
    fn unhappy_test_is_identity() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(1), Scalar::from(0)],
        ]);

        assert!(!matrix.is_identity());
    }

    #[test]
    fn happy_test_is_diagonal() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(24325346), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(1)],
        ]);

        assert!(matrix.is_diagonal());
    }

    #[test]
    fn unhappy_test_is_diagonal() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(24325346), Scalar::from(0)],
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(1)],
        ]);

        assert!(!matrix.is_diagonal());
    }

    #[test]
    fn happy_test_is_square() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        assert!(matrix.is_square());
    }

    #[test]
    fn unhappy_test_is_square() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        assert!(!matrix.is_square());
    }

    #[test]
    fn happy_test_mod_inverse_cell() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(0), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                if matrix.cells[i][j] != Scalar::from(0) {
                    let inverse_element = matrix.mod_inverse(i, j).unwrap();
                    assert_eq!(Scalar::from(1), inverse_element * matrix.cells[i][j]);
                }
            }
        }
    }

    #[test]
    fn unhappy_test_mod_inverse_cell() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(0), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(0)],
            vec![Scalar::from(7), Scalar::from(0), Scalar::from(9)],
        ]);

        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                if matrix.cells[i][j] == Scalar::from(0) {
                    let inverse_element = matrix.mod_inverse(i, j);
                    let expected_error =
                        Err(BirkhoffError::ElementNotInvertible { row: i, col: j });
                    assert_eq!(inverse_element, expected_error);
                }
            }
        }
    }

    #[test]
    fn happy_test_get_row_non_zero() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(0)],
        ]);

        let row = matrix.get_row_non_zero(0).unwrap();
        let expected_row = vec![
            NonZero::from_scalar(Scalar::from(1)).unwrap(),
            NonZero::from_scalar(Scalar::from(2)).unwrap(),
            NonZero::from_scalar(Scalar::from(3)).unwrap(),
        ];
        assert_eq!(row, expected_row);

        let row = matrix.get_row_non_zero(1).unwrap();
        let expected_row = vec![
            NonZero::from_scalar(Scalar::from(4)).unwrap(),
            NonZero::from_scalar(Scalar::from(5)).unwrap(),
            NonZero::from_scalar(Scalar::from(6)).unwrap(),
        ];
        assert_eq!(row, expected_row);
    }

    #[test]
    fn unhappy_test_get_row_non_zero() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(0)],
        ]);

        let row = matrix.get_row_non_zero(0);
        let expected_error = Err(BirkhoffError::ZeroCoefficient);
        assert_eq!(row, expected_error);

        let row = matrix.get_row_non_zero(1);
        let expected_error = Err(BirkhoffError::ZeroCoefficient);
        assert_eq!(row, expected_error);
    }

    #[test]
    fn happy_test_get_row() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let row = matrix.get_row(0).unwrap();
        let expected_row = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)];
        assert_eq!(row, expected_row);

        let row = matrix.get_row(1).unwrap();
        let expected_row = vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)];
        assert_eq!(row, expected_row);
    }

    #[test]
    fn unhappy_test_get_row() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let row = matrix.get_row(3);
        let expected_error = Err(BirkhoffError::IndexOutOfBounds {
            index: 3,
            max_index: 1,
        });
        assert_eq!(row, expected_error);
    }

    #[test]
    fn happy_test_add_rows() {
        let row1: Vec<Scalar<E>> = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)];
        let row2: Vec<Scalar<E>> = vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)];
        let result = BirkhoffMatrix::add_rows(&row1, &row2).unwrap();
        let expected_result = vec![Scalar::from(5), Scalar::from(7), Scalar::from(9)];
        assert_eq!(result, expected_result);
    }

    #[test]
    fn unhappy_test_add_rows() {
        let row1: Vec<Scalar<E>> = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)];
        let row2: Vec<Scalar<E>> = vec![Scalar::from(4), Scalar::from(5)];
        let result = BirkhoffMatrix::add_rows(&row1, &row2);
        let expected_error = Err(BirkhoffError::RowsDifferentLengths {
            row1_len: row1.len(),
            row2_len: row2.len(),
        });
        assert_eq!(result, expected_error);
    }

    #[test]
    fn happy_test_swap_rows() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let result = matrix.swap_rows(0, 1).unwrap();

        let expected_result = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
        ]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unhappy_test_swap_rows() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let result = matrix.swap_rows(0, 3);
        let expected_error = Err(BirkhoffError::IndexOutOfBounds {
            index: 3,
            max_index: 1,
        });
        assert_eq!(result, expected_error);
    }

    #[test]
    fn test_multiply_scalar() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let result = matrix.multiply_scalar(&matrix.cells[0], Scalar::from(2));
        let expected_result = vec![Scalar::from(2), Scalar::from(4), Scalar::from(6)];
        assert_eq!(result, expected_result);

        let result = matrix.multiply_scalar(&matrix.cells[1], Scalar::from(2));
        let expected_result = vec![Scalar::from(8), Scalar::from(10), Scalar::from(12)];
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_transpose() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let result = matrix.transpose();
        let expected_result = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(4)],
            vec![Scalar::from(2), Scalar::from(5)],
            vec![Scalar::from(3), Scalar::from(6)],
        ]);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn happy_test_multiply_birkhoff_matrix() {
        let matrix1 = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let matrix2 = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        let expected = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(30), Scalar::from(36), Scalar::from(42)],
            vec![Scalar::from(66), Scalar::from(81), Scalar::from(96)],
        ]);

        let result = matrix1.multiply(&matrix2).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn unhappy_test_multiply_birkhoff_matrix() {
        let matrix1 = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let matrix2 = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
        ]);

        let expected_error = BirkhoffError::MatrixDimensionsMismatch {
            self_rows: matrix1.rows(),
            self_cols: matrix1.cols(),
            other_rows: matrix2.rows(),
            other_cols: matrix2.cols(),
        };

        let result = matrix1.multiply(&matrix2);

        match result {
            Ok(_) => panic!("Expected an error"),
            Err(e) => assert_eq!(e, expected_error),
        }
    }

    #[test]
    fn happy_test_multi_inverse_identity() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        let identity = BirkhoffMatrix::<E>::create_identity_matrix(3);

        let result = matrix.multi_inverse_diagonal(&identity).unwrap();

        // identity matrix^ {-1} * A = A
        assert_eq!(result, matrix);
    }

    #[test]
    fn happy_test_multi_inverse_diagonal() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        let diagonal = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(10), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(100)],
        ]);

        let inverse_diagonal = BirkhoffMatrix::<E>::new(vec![
            vec![
                Scalar::from(1).invert().unwrap(),
                Scalar::from(0),
                Scalar::from(0),
            ],
            vec![
                Scalar::from(0),
                Scalar::from(10).invert().unwrap(),
                Scalar::from(0),
            ],
            vec![
                Scalar::from(0),
                Scalar::from(0),
                Scalar::from(100).invert().unwrap(),
            ],
        ]);

        let identity = BirkhoffMatrix::<E>::create_identity_matrix(3);
        // check for correct inverse, which help us calculate the correct expected value
        assert_eq!(diagonal.multiply(&inverse_diagonal).unwrap(), identity);

        let expected_result = inverse_diagonal.multiply(&matrix).unwrap();
        let result = matrix.multi_inverse_diagonal(&diagonal).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn unhappy_test_multi_inverse_diagonal_1() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(17), Scalar::from(8), Scalar::from(9)],
        ]);

        let diagonal = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(1)],
            vec![Scalar::from(0), Scalar::from(1), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(100)],
        ]);

        let result = matrix.multi_inverse_diagonal(&diagonal);
        let expected_error = Err(BirkhoffError::NotDiagonalMatrix);
        assert_eq!(result, expected_error);
    }

    #[test]
    fn unhappy_test_multi_inverse_diagonal_2() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(17), Scalar::from(8), Scalar::from(9)],
        ]);

        let diagonal = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(0), Scalar::from(100)],
        ]);

        let result = matrix.multi_inverse_diagonal(&diagonal);
        let expected_error = Err(BirkhoffError::ElementNotInvertible { row: 1, col: 1 });
        assert_eq!(result, expected_error);
    }

    #[test]
    fn happy_test_get_gauss_elimination() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(15), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        // Get U_A and L^{-1}
        let (upper, lower_inv) = matrix.get_gauss_elimination().unwrap();

        // Verify U_A is upper triangular
        for i in 0..upper.rows() {
            for j in 0..i {
                assert_eq!(
                    upper.cells[i][j],
                    Scalar::from(0),
                    "U_A is not upper triangular at position ({}, {})",
                    i,
                    j
                );
            }
        }

        // Verify L^{-1} is lower triangular
        for i in 0..lower_inv.rows() {
            for j in (i + 1)..lower_inv.cols() {
                assert_eq!(
                    lower_inv.cells[i][j],
                    Scalar::from(0),
                    "L^{{-1}} is not lower triangular at position ({}, {})",
                    i,
                    j
                );
            }
        }

        // Verify L*U_A = A or L^{-1} * A = U_A
        let reconstructed = lower_inv.multiply(&matrix).unwrap();
        assert_eq!(
            reconstructed, upper,
            "L*U_A does not equal original matrix A"
        );

        // Verify det(U_A) = det(A)
        // Note: This requires implementing determinant calculation
        // For now, we'll skip this check as it requires additional functionality
    }

    #[test]
    fn happy_test_get_gauss_elimination_identity() {
        // Test with identity matrix
        let matrix = BirkhoffMatrix::<E>::create_identity_matrix(3);

        let (upper, lower_inv) = matrix.get_gauss_elimination().unwrap();

        // For identity matrix, U_A should be identity and L^{-1} should be identity
        assert!(upper.is_identity(), "U_A is not identity matrix");
        assert!(lower_inv.is_identity(), "L^{{-1}} is not identity matrix");
    }

    #[test]
    fn unhappy_test_get_gauss_elimination_singular() {
        // Test with a singular matrix (non-invertible)
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(2), Scalar::from(4), Scalar::from(6)],
            vec![Scalar::from(3), Scalar::from(6), Scalar::from(9)],
        ]);

        // This should fail as the matrix is singular
        assert!(matrix.get_gauss_elimination().is_err());
    }

    #[test]
    fn happy_test_inverse_matrix() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(15), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        let inverse = matrix.inverse().unwrap();

        // matrix * inverse = identity
        let check = matrix.multiply(&inverse).unwrap();
        let identity = BirkhoffMatrix::<E>::create_identity_matrix(3);

        assert_eq!(check, identity);
    }

    #[test]
    fn happy_test_inverse_identity() {
        // inverse of identity matrix is itself
        let matrix = BirkhoffMatrix::<E>::create_identity_matrix(3);
        let inverse = matrix.inverse().unwrap();

        assert_eq!(matrix, inverse);
    }

    #[test]
    fn unhappy_test_inverse_matrix() {
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)],
            vec![Scalar::from(4), Scalar::from(5), Scalar::from(6)],
            vec![Scalar::from(7), Scalar::from(8), Scalar::from(9)],
        ]);

        let inverse = matrix.inverse();

        assert!(
            inverse.is_err(),
            "The matrix is not invertible. Expect an error."
        );
    }

    #[test]
    fn happy_test_pseudo_inverse() {
        // the columns of m are linearly independent
        // row rank >= column rank.
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(1), Scalar::from(0)],
            vec![Scalar::from(0), Scalar::from(1)],
            vec![Scalar::from(1), Scalar::from(1)],
        ]);

        let pseudo_inverse = matrix.pseudo_inverse().unwrap();

        let check = matrix.multiply(&pseudo_inverse).unwrap();
        let check = check.multiply(&matrix).unwrap();

        // A * A^+ * A = A (Moore-Penrose condition)
        assert_eq!(check, matrix);
    }

    #[test]
    fn unhappy_test_pseudo_inverse() {
        // the columns of m are not linearly independent
        let matrix = BirkhoffMatrix::<E>::new(vec![
            vec![Scalar::from(10), Scalar::from(5)],
            vec![Scalar::from(8), Scalar::from(4)],
        ]);

        let pseudo_inverse = matrix.pseudo_inverse();

        assert!(pseudo_inverse.is_err());
    }
}
