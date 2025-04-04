//! Polynomial derivative operations for cryptographic applications
//!
//! This module provides an extension to the `Polynomial` struct from the `generic-ec-zkp` crate,
//! adding functionality to compute nth derivatives of polynomials at specific points.
//! This is particularly useful in Birkhoff interpolation and other cryptographic applications.
//!
//! # Example
//! ```rust
//! use generic_ec::{Point, Scalar, NonZero, curves::Secp256k1};
//! use generic_ec_zkp::polynomial::Polynomial;
//! use rand_core::OsRng;
//!
//! // Create a random polynomial of degree 3
//! let f: Polynomial<NonZero<Scalar<Secp256k1>>> = Polynomial::sample(&mut OsRng, 3);
//! 
//! // Pick a point to evaluate the derivative at
//! let x = Scalar::<Secp256k1>::random(&mut OsRng);
//! 
//! // Compute the first derivative at point x
//! let first_derivative: Scalar<Secp256k1> = f.nth_derivative_at(&x, 1);
//! 
//! // Compute the second derivative at point x
//! let second_derivative: Scalar<Secp256k1> = f.nth_derivative_at(&x, 2);
//! 
//! // For a polynomial of degree 3, the 4th derivative is always zero
//! let fourth_derivative = f.nth_derivative_at(&x, 4);
//! assert_eq!(fourth_derivative, Scalar::<Secp256k1>::zero());
//! ```

use std::ops;
use generic_ec::traits::Zero;
use generic_ec_zkp::polynomial::Polynomial;

/// Evaluates nth derivative of polynomial at given point: $f^{(d)}(\text{point})$
pub trait Derivative<C> {
    /// Evaluates nth derivative of polynomial at given point: $f^{(d)}(\text{point})$
    ///
    /// Polynomial coefficients, point, and output can all be differently typed.
    ///
    /// # Mathematical Explanation
    /// For a polynomial $f(x) = \sum_{i=0}^{n} a_i x^i$, the d-th derivative is:
    /// 
    /// $f^{(d)}(x) = \sum_{i=d}^{n} a_i \cdot \frac{i!}{(i-d)!} \cdot x^{i-d}$
    ///
    /// This method computes this derivative and evaluates it at the specified point.
    ///
    /// # Arguments
    /// * `point` - The point at which to evaluate the derivative
    /// * `d` - The order of the derivative to compute (0 = original function, 1 = first derivative, etc.)
    /// 
    /// # Returns
    /// The value of the d-th derivative evaluated at the given point. Returns zero if d is greater
    /// than or equal to the degree of the polynomial plus one.
    ///
    /// ## Example
    /// ```rust
    /// use generic_ec::{Point, Scalar, NonZero, curves::Secp256k1};
    /// use generic_ec_zkp::polynomial::Polynomial;
    /// # use rand_core::OsRng;
    ///
    /// let f: Polynomial<NonZero<Scalar<Secp256k1>>> = Polynomial::sample(&mut OsRng, 3);
    /// let x = Scalar::random(&mut OsRng);
    /// let d = 2;
    /// let result = f.nth_derivative_at(&x, d);
    /// ```
    fn nth_derivative_at<P, O>(&self, point: &P, d: u64) -> O
    where
        O: Zero,
        for<'a> O: ops::Mul<&'a P, Output = O> + ops::Add<O, Output = O>,
        for<'a> &'a C: ops::Mul<P, Output = O>,
        P: From<u64> + ops::Mul<Output = P>;
}

impl<C> Derivative<C> for Polynomial<C> {
    fn nth_derivative_at<P, O>(&self, point: &P, d: u64) -> O
    where
        O: Zero,
        for<'a> O: ops::Mul<&'a P, Output = O> + ops::Add<O, Output = O>,
        for<'a> &'a C: ops::Mul<P, Output = O>,
        P: From<u64> + ops::Mul<Output = P>,
    {
        if d >= self.coefs().len() as u64 {
            return O::zero();
        }

        // Compute nth derivative coefficients on the fly
        let derived_coefs = self
            .coefs()
            .iter()
            .enumerate()
            .skip(d.try_into().unwrap())
            .map(|(i, coef)| {
                let mut factor = P::from(1); // Convert factor to type P
                let start = (i as i64 - d as i64 + 1) as u64;
                let end = i as u64;
                for j in start..=end {
                    factor = factor * P::from(j); // Convert index to P before multiplication
                }
                coef * factor // Multiply coefficient by factor
            });

        // Evaluate derivative at point
        derived_coefs
            .rev()
            .fold(O::zero(), |acc, coef| acc * point + coef)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::{Point, Scalar, curves};
    
    #[test]
    fn test_polynomial_derivatives() {
        // Setup: Create a polynomial and its corresponding point polynomial
        let coefs = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)];
        let x = Scalar::from(4);
        let f = Polynomial::<Scalar<curves::Secp256k1>>::from_coefs(coefs);
        let F: Polynomial<Point<curves::Secp256k1>> = &f * &Point::generator();
        
        // Test polynomial evaluation
        assert_eq!(
            f.value::<_, Scalar<_>>(&x) * Point::generator(),
            F.value::<_, Point<_>>(&x),
            "Polynomial evaluation at x should be the same for both types"
        );
        
        // Test first derivative
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 1) * Point::generator(),
            F.nth_derivative_at::<_, Point<_>>(&x, 1),
            "First derivative evaluation at x should be the same for both types"
        );
        
        // Test second derivative
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 2) * Point::generator(),
            F.nth_derivative_at::<_, Point<_>>(&x, 2),
            "Second derivative evaluation at x should be the same for both types"
        );
        
        // Test third derivative
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 3) * Point::generator(),
            F.nth_derivative_at::<_, Point<_>>(&x, 3),
            "Third derivative evaluation at x should be the same for both types"
        );
        
        // Test higher derivative (should be zero for degree 2 polynomial)
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 4),
            Scalar::<curves::Secp256k1>::zero(),
            "Fourth derivative of a degree 2 polynomial should be zero"
        );
    }
    
    #[test]
    fn test_linearity_of_derivatives() {
        // For a polynomial f(x) = x^2, f'(x) = 2x, f''(x) = 2, f'''(x) = 0
        let quadratic = vec![
            Scalar::<curves::Secp256k1>::zero(),
            Scalar::<curves::Secp256k1>::zero(),
            Scalar::<curves::Secp256k1>::from(1),
        ];
        let f = Polynomial::<Scalar<curves::Secp256k1>>::from_coefs(quadratic);
        
        let x = Scalar::from(5);
        
        // Check values of derivatives
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 0),
            Scalar::from(25),  // x^2 = 5^2 = 25
            "f(x) = x^2 evaluated at x=5 should be 25"
        );
        
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 1),
            Scalar::from(10),  // f'(x) = 2x at x=5 is 10
            "f'(x) = 2x evaluated at x=5 should be 10"
        );
        
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 2),
            Scalar::from(2),   // f''(x) = 2
            "f''(x) should be constant 2"
        );
        
        assert_eq!(
            f.nth_derivative_at::<_, Scalar<_>>(&x, 3),
            Scalar::<curves::Secp256k1>::zero(),  // f'''(x) = 0
            "f'''(x) should be zero for a quadratic polynomial"
        );
    }
}
