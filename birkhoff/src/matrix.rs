use super::error::Error;
use num_bigint::BigInt;
use std::fmt;

/// A matrix over a finite field with modular arithmetic operations.
#[derive(Clone)]
pub struct Matrix {
    _field_order: BigInt,
    matrix: Vec<Vec<BigInt>>,
    rows: usize,
    cols: usize,
}

impl Matrix {
    /// Prints the matrix to stdout in a row-by-row format.
    pub fn print_matrix(&self) {
        for i in 0..self.rows {
            for j in 0..self.cols {
                print!("{} ", self.matrix[i][j]);
            }
            println!();
        }
    }

    /// Creates a new matrix with the given field order and data.
    /// Returns an error if the data is empty or has inconsistent row lengths.
    pub fn new(field_order: BigInt, data: Vec<Vec<BigInt>>) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::MatrixError("Empty matrix".to_string()));
        }

        let rows = data.len();
        let cols = data[0].len();

        // Ensure all rows have the same length
        for row in &data {
            if row.len() != cols {
                return Err(Error::MatrixError("Inconsistent row lengths".to_string()));
            }
        }

        Ok(Matrix {
            _field_order: field_order,
            matrix: data,
            rows,
            cols,
        })
    }

    /// Gets the element at the specified row and column, applying field modulus.
    pub fn get(&self, row: u64, col: u64) -> BigInt {
        let value = &self.matrix[row as usize][col as usize];
        // Apply modulus to ensure value is within the field
        let mut result = value.clone() % &self._field_order;
        // Ensure we have a positive representation (consistent with finite field)
        if result < BigInt::from(0) {
            result += &self._field_order;
        }
        result
    }

    /// Returns a copy of the specified row.
    /// Returns an error if the row index is out of bounds.
    pub fn get_row(&self, row: usize) -> Result<Vec<BigInt>, Error> {
        if row >= self.rows {
            return Err(Error::MatrixError("Row index out of bounds".to_string()));
        }

        Ok(self.matrix[row].clone())
    }

    /// Calculates the rank of the matrix over the specified field.
    /// Returns an error if matrix operations fail.
    pub fn get_matrix_rank(&self, _field_order: &BigInt) -> Result<u64, Error> {
        // Create a copy of self for the rank calculation
        let mut upper = self.clone();

        // If we have more rows than columns, use the transpose for the rank calculation
        // This improves the efficiency and logic of the algorithm
        if upper.rows < upper.cols {
            upper = upper.transpose()?;
        }

        let mut rank = 0u64;

        // Process each column
        for i in 0..upper.cols {
            // Find a non-zero element in column i starting from row 'rank'
            let change_index = match upper.get_non_zero_coefficient_by_row(rank as usize, i)? {
                Some(idx) => idx,
                // If the column is all zeros (from row 'rank' downwards), skip this column
                None => continue,
            };

            // If needed, swap rows to get the non-zero element to the diagonal position
            if rank as usize != change_index {
                upper.swap_row(rank as usize, change_index)?;
            }

            // Get the inverse of the diagonal element for elimination
            let inverse = upper.mod_inverse(upper.get_raw(rank as usize, i))?;

            // Get the current pivot row
            let row_i = upper.get_row(rank as usize)?;

            // Eliminate elements below the pivot
            for j in (rank + 1)..upper.rows as u64 {
                // Calculate the coefficient for elimination
                let temp_value = upper.get_raw(j as usize, i) * &inverse;
                let inverse_diagonal_component = BigInt::from(0) - &temp_value;

                // Get the row to be modified
                let row_j = upper.get_row(j as usize)?;

                // Apply elimination: row_j = row_j + inverse_diagonal_component * row_i
                let temp_result_slice = Self::multi_scalar(&row_i, &inverse_diagonal_component);
                upper.matrix[j as usize] = Self::add_slices(&row_j, &temp_result_slice);
            }

            // Apply modulus and increment rank
            upper = upper.modulus();
            rank += 1;
        }

        Ok(rank)
    }

    /// Computes the Moore-Penrose pseudoinverse of the matrix.
    /// Returns an error if matrix operations fail.
    pub fn pseudoinverse(&self) -> Result<Self, Error> {
        // Create a copy of self (original matrix)
        let copy = self.clone();

        // Create the transpose of self
        let transpose = self.transpose()?;

        // Compute m^T * m (symmetric form)
        let symmetric_form = transpose.multiply(&copy)?;

        // Compute (m^T * m)^(-1)
        let inverse_symmetric = symmetric_form.inverse()?;
        // Compute (m^T * m)^(-1) * m^T
        let result = inverse_symmetric.multiply(&transpose)?;

        // Apply modulus to handle finite field arithmetic
        Ok(result.modulus())
    }

    /// Returns a reference to the underlying matrix data.
    pub fn get_matrix(&self) -> &Vec<Vec<BigInt>> {
        &self.matrix
    }

    /// Computes the transpose of the matrix.
    /// Returns an error if matrix operations fail.
    pub fn transpose(&self) -> Result<Self, Error> {
        let mut transpose_matrix = vec![vec![BigInt::from(0); self.rows]; self.cols];

        for (i, row) in transpose_matrix.iter_mut().enumerate().take(self.cols) {
            for (j, val) in row.iter_mut().enumerate().take(self.rows) {
                *val = self.matrix[j][i].clone();
            }
        }

        Matrix::new(self._field_order.clone(), transpose_matrix)
    }

    /// Multiplies this matrix with another matrix.
    /// Returns an error if the matrices have incompatible dimensions.
    pub fn multiply(&self, other: &Self) -> Result<Self, Error> {
        // Check if matrices can be multiplied
        if self.cols != other.rows {
            return Err(Error::MatrixError(
                "Inconsistent dimensions for multiplication".to_string(),
            ));
        }

        let mut result = vec![vec![BigInt::from(0); other.cols]; self.rows];

        for (i, row) in result.iter_mut().enumerate().take(self.rows) {
            for (j, val) in row.iter_mut().enumerate().take(other.cols) {
                for k in 0..self.cols {
                    let temp = self.matrix[i][k].clone() * &other.matrix[k][j];
                    *val += temp;
                }
            }
        }

        Matrix::new(self._field_order.clone(), result)
    }

    /// Computes the inverse of the matrix.
    /// Returns an error if the matrix is not square or not invertible.
    pub fn inverse(&self) -> Result<Self, Error> {
        // Check if matrix is square
        if self.rows != self.cols {
            return Err(Error::MatrixError("Not a square matrix".to_string()));
        }

        // Get U, L^{-1}. Note that A = L*U
        let (upper_matrix, lower_matrix, _) = self.get_gauss_elimination()?;
        println!("upper_matrix: ");
        upper_matrix.print_matrix();
        println!("lower_matrix: ");
        lower_matrix.print_matrix();
        // Copy the lower matrix
        let copy_lower_matrix = lower_matrix.clone();

        // K = U^t
        let transposed_upper = upper_matrix.transpose()?;

        // Get D, L_K^{-1}. Note that K = L_K*D
        let (temp_upper_result, temp_lower_result, _) = transposed_upper.get_gauss_elimination()?;

        // Get tempResult = tempLowerResult * inverse(diagonal of tempUpperResult)
        let temp_result = temp_lower_result.multi_inverse_diagonal(&temp_upper_result)?;

        // Get (D^{-1}L_{K}^{-1})^t = ((L_K*D)^{-1})^t = (K^{-1})^{t}
        // So the transpose of (K^{-1})^{t} is U^{-1}
        let transposed_result = temp_result.transpose()?;

        // U^{-1}*L^{-1} = (L*U)^{-1} = A^{-1}
        let result = transposed_result.multiply(&copy_lower_matrix)?;

        // Apply modulus
        Ok(result.modulus())
    }

    /// Applies field modulus to all matrix elements.
    pub fn modulus(&self) -> Self {
        // Create a new matrix with elements modulo field_order
        let mut result = self.clone();

        for row in result.matrix.iter_mut() {
            for val in row.iter_mut() {
                *val = val.clone() % &self._field_order;

                // Ensure positive modulus
                if *val < BigInt::from(0) {
                    *val += &self._field_order;
                }
            }
        }

        result
    }

    // Helper methods required for matrix inversion

    // Gets Gaussian elimination matrices, returns (upper, lower, permutation_times)
    fn get_gauss_elimination(&self) -> Result<(Self, Self, usize), Error> {
        if self.rows != self.cols {
            return Err(Error::MatrixError("Not a square matrix".to_string()));
        }

        // Create identity matrix for lower
        let mut lower: Matrix = self.identity_matrix()?;

        // Create a copy of self for upper
        let mut upper = self.clone();

        let mut permutation_times = 0;

        for i in 0..self.rows {
            // Find non-zero coefficient
            println!("loop in {} ", i);
            let change_index = match upper.get_non_zero_coefficient_by_row(i, i)? {
                Some(idx) => idx,
                None => return Err(Error::MatrixError("not invertible matrix".to_string())),
            };

            // If the index is changed, swap rows
            if i != change_index {
                permutation_times += 1;
                upper.swap_row(i, change_index)?;
                lower.swap_row(i, change_index)?;
            }

            // Get inverse of diagonal element
            let inverse = self.mod_inverse(upper.get_raw(i, i))?;
            println!("inverse: {}", inverse);
            for j in i + 1..self.rows {
                // Calculate coefficient for elimination
                let temp_value = upper.get_raw(j, i) * &inverse;
                let inverse_diagonal_component = BigInt::from(0) - &temp_value;

                // Make (j, i) element zero at upper matrix
                let row_i = upper.get_row(i)?;
                let row_j = upper.get_row(j)?;
                let temp_result_a_slice = Self::multi_scalar(&row_i, &inverse_diagonal_component);
                upper.matrix[j] = Self::add_slices(&row_j, &temp_result_a_slice);

                // Do same operation on lower matrix
                let row_lower_i = lower.get_row(i)?;
                let row_lower_j = lower.get_row(j)?;
                let temp_result_identity_slice =
                    Self::multi_scalar(&row_lower_i, &inverse_diagonal_component);
                lower.matrix[j] = Self::add_slices(&row_lower_j, &temp_result_identity_slice);
            }

            println!("upper in loop {} ", i);
            upper.print_matrix();
            println!("lower in loop {} ", i);
            lower.print_matrix();
        }

        // Apply modulus to both matrices
        upper = upper.modulus();
        lower = lower.modulus();
        println!("upper in end get_gauss_elimination: ");
        upper.print_matrix();
        println!("lower in end get_gauss_elimination: ");
        lower.print_matrix();
        Ok((upper, lower, permutation_times))
    }

    // Create identity matrix of size n x n
    fn identity_matrix(&self) -> Result<Self, Error> {
        let mut matrix = vec![vec![BigInt::from(0); self.rows]; self.rows];

        for (i, row) in matrix.iter_mut().enumerate() {
            row[i] = BigInt::from(1);
        }

        Matrix::new(self._field_order.clone(), matrix)
    }

    // Find non-zero coefficient by row
    fn get_non_zero_coefficient_by_row(
        &self,
        from_row_index: usize,
        column_idx: usize,
    ) -> Result<Option<usize>, Error> {
        for (i, _) in self.matrix.iter().enumerate().skip(from_row_index) {
            if self.get_raw(i, column_idx) != &BigInt::from(0) {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    // Swap rows in a matrix
    fn swap_row(&mut self, index_row1: usize, index_row2: usize) -> Result<(), Error> {
        if index_row1 >= self.rows || index_row2 >= self.rows {
            return Err(Error::MatrixError("Row index out of range".to_string()));
        }

        // Do nothing if indices are the same
        if index_row1 == index_row2 {
            return Ok(());
        }

        // Swap each pair of elements in the two rows using enumerate
        for (i, _) in (0..self.cols).enumerate() {
            let temp = self.matrix[index_row1][i].clone();
            self.matrix[index_row1][i] = self.matrix[index_row2][i].clone();
            self.matrix[index_row2][i] = temp;
        }

        Ok(())
    }

    // Get raw matrix element without applying modulus
    fn get_raw(&self, row: usize, col: usize) -> &BigInt {
        &self.matrix[row][col]
    }

    // Calculate modular multiplicative inverse
    fn mod_inverse(&self, value: &BigInt) -> Result<BigInt, Error> {
        // Handle negative modulus
        let n = if self._field_order < BigInt::from(0) {
            -self._field_order.clone()
        } else {
            self._field_order.clone()
        };

        // Handle negative input by taking modulo n
        let g = if value < &BigInt::from(0) {
            (value % &n) + &n
        } else {
            value.clone()
        };

        // Calculate GCD and Bézout's identity coefficients
        let (d, x) = self.extended_gcd(&g, &n);

        // Check if numbers are coprime (GCD == 1)
        if d != BigInt::from(1) {
            return Err(Error::MatrixError("Not invertible element".to_string()));
        }

        // Ensure result is in range [0, n)
        let result = if x < BigInt::from(0) { x + n } else { x };

        Ok(result)
    }

    // Helper method to compute extended GCD
    fn extended_gcd(&self, a: &BigInt, b: &BigInt) -> (BigInt, BigInt) {
        let mut old_r = a.clone();
        let mut r = b.clone();
        let mut old_s = BigInt::from(1);
        let mut s = BigInt::from(0);

        while r != BigInt::from(0) {
            let quotient = &old_r / &r;
            let temp_r = r.clone();
            r = old_r - &quotient * &r;
            old_r = temp_r;

            let temp_s = s.clone();
            s = old_s - quotient * &s;
            old_s = temp_s;
        }

        (old_r, old_s)
    }

    // Multiplies a slice by a scalar
    fn multi_scalar(slice: &[BigInt], scalar: &BigInt) -> Vec<BigInt> {
        slice.iter().map(|val| val * scalar).collect()
    }

    // Adds two slices element-wise
    fn add_slices(slice1: &[BigInt], slice2: &[BigInt]) -> Vec<BigInt> {
        slice1
            .iter()
            .zip(slice2.iter())
            .map(|(a, b)| a + b)
            .collect()
    }

    // Multiply inverse diagonal
    fn multi_inverse_diagonal(&self, diagonal: &Self) -> Result<Self, Error> {
        let mut result = self.clone();

        for (i, row) in result.matrix.iter_mut().enumerate() {
            let inverse = self.mod_inverse(diagonal.get_raw(i, i))?;

            for val in row.iter_mut() {
                *val = val.clone() * &inverse;
            }
        }

        Ok(result)
    }
}

impl fmt::Debug for Matrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Matrix {}x{}", self.rows, self.cols)?;
        for row in &self.matrix {
            write!(f, "[")?;
            for (i, val) in row.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", val)?;
            }
            writeln!(f, "]")?;
        }
        Ok(())
    }
}
