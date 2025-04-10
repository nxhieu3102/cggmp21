use generic_ec::{Curve, NonZero, Scalar};

use crate::birkhoff_error::{BirkhoffError, BirkhoffResult};
use crate::birkhoff_matrix::BirkhoffMatrix;

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
/// Returns `Err(BirkhoffError)` if the ranks and xs have different lengths OR if the matrix
/// cannot be inverted OR if the coefficient is 0 in the birkhoff matrix.
/// Else returns the birkhoff coefficient vector.
///
/// ## Example
///
pub fn birkhoff_coefficient<E: Curve>(
    threshold: u16,
    xs: &[NonZero<Scalar<E>>], // x-coordinates of shares
    ranks: &[u16],
) -> BirkhoffResult<Vec<NonZero<Scalar<E>>>> {
    if ranks.len() != xs.len() {
        return Err(BirkhoffError::MismatchedLengths {
            ranks_len: ranks.len(),
            xs_len: xs.len(),
        });
    }

    let birkhoff_matrix = get_linear_equation_coefficient_matrix(threshold, xs, ranks)?;

    let invert_matrix = birkhoff_matrix.pseudo_inverse()?;

    // Get the birkhoff coefficient by extracting the first row of the pseudo-inverse
    invert_matrix.get_row_non_zero(0)
}

// Establish the coefficient of linear system of Birkhoff systems
fn get_linear_equation_coefficient_matrix<E: Curve>(
    threshold: u16,
    xs: &[NonZero<Scalar<E>>],
    ranks: &[u16],
) -> BirkhoffResult<BirkhoffMatrix<E>> {
    let num_row = ranks.len();
    let num_col = threshold as usize;

    let mut cells = vec![vec![Scalar::default(); num_col]; num_row];

    for r in 0..num_row {
        for c in 0..num_col {
            cells[r][c] = get_coefficient(xs[r], c as u16, ranks[r]);
        }
    }

    Ok(BirkhoffMatrix::new(cells))
}

/// Get the coefficient at one cell of the linear system of Birkhoff systems: (x^exp)[derivative_order]
/// The coefficient CAN be 0
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
fn get_coefficient<E: Curve>(x: NonZero<Scalar<E>>, exp: u16, derivative_order: u16) -> Scalar<E> {
    // If exp < derivative_order, the derivative is 0
    if exp < derivative_order {
        return Scalar::from(0);
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

    coeff
}
