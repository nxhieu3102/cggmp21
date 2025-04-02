use generic_ec::{Point, Scalar, NonZero, curves::Secp256k1};
use generic_ec_zkp::polynomial::Polynomial;
use rand_core::OsRng;

// A helper function to print polynomial coefficients
fn print_polynomial<C: std::fmt::Debug>(name: &str, poly: &Polynomial<C>) {
    println!("{}:", name);
    for (i, coef) in poly.coefs().iter().enumerate() {
        println!("  a_{} = {:?}", i, coef);
    }
    println!();
}

// Helper to compute analytical derivatives of a polynomial
fn compute_derivative_coefficients(poly: &Polynomial<NonZero<Scalar<Secp256k1>>>, d: u64) -> Vec<Scalar<Secp256k1>> {
    let coefficients = poly.coefs();
    let mut derivative_coeffs = Vec::new();
    
    // Skip coefficients that will become zero in d-th derivative
    for i in d as usize..coefficients.len() {
        let mut factor = Scalar::<Secp256k1>::one();
        // Compute i! / (i - d)!
        for j in (i - d as usize + 1)..=i {
            factor = factor * Scalar::from(j as u64);
        }
        derivative_coeffs.push(factor * coefficients[i].as_ref());
    }
    
    derivative_coeffs
}

fn main() {
    // Create a random polynomial of degree 3
    // f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3
    let f: Polynomial<NonZero<Scalar<Secp256k1>>> = Polynomial::sample(&mut OsRng, 3);
    print_polynomial("Original polynomial f(x)", &f);
    
    // Pick a random point to evaluate the derivative at
    let x = Scalar::<Secp256k1>::random(&mut OsRng);
    println!("Evaluation point x = {:?}\n", x);
    
    // Compute first derivative (d=1)
    // f'(x) = a_1 + 2*a_2*x + 3*a_3*x^2
    let d = 1;
    let derivative_1 = f.nth_derivative_at(&x, d);
    println!("First derivative f'({:?}) = {:?}", x, derivative_1);
    
    // Compute the coefficients of the first derivative for verification
    let d1_coeffs = compute_derivative_coefficients(&f, d);
    println!("First derivative coefficients:");
    for (i, coef) in d1_coeffs.iter().enumerate() {
        println!("  b_{} = {:?}", i, coef);
    }
    
    // Manually evaluate the first derivative at x
    let mut manual_result = Scalar::<Secp256k1>::zero();
    for (i, coef) in d1_coeffs.iter().enumerate().rev() {
        manual_result = manual_result * &x + coef;
    }
    println!("Manual evaluation of f'({:?}) = {:?}", x, manual_result);
    println!("Verification: values match = {}\n", derivative_1 == manual_result);
    
    // Compute second derivative (d=2)
    // f''(x) = 2*a_2 + 6*a_3*x
    let d = 2;
    let derivative_2 = f.nth_derivative_at(&x, d);
    println!("Second derivative f''({:?}) = {:?}", x, derivative_2);
    
    // Compute the coefficients of the second derivative for verification
    let d2_coeffs = compute_derivative_coefficients(&f, d);
    println!("Second derivative coefficients:");
    for (i, coef) in d2_coeffs.iter().enumerate() {
        println!("  c_{} = {:?}", i, coef);
    }
    
    // Manually evaluate the second derivative at x
    let mut manual_result = Scalar::<Secp256k1>::zero();
    for (i, coef) in d2_coeffs.iter().enumerate().rev() {
        manual_result = manual_result * &x + coef;
    }
    println!("Manual evaluation of f''({:?}) = {:?}", x, manual_result);
    println!("Verification: values match = {}\n", derivative_2 == manual_result);
    
    // Compute third derivative (d=3)
    // f'''(x) = 6*a_3 (constant)
    let d = 3;
    let derivative_3 = f.nth_derivative_at(&x, d);
    println!("Third derivative f'''({:?}) = {:?}", x, derivative_3);
    
    // Compute the coefficients of the third derivative for verification
    let d3_coeffs = compute_derivative_coefficients(&f, d);
    println!("Third derivative coefficients:");
    for (i, coef) in d3_coeffs.iter().enumerate() {
        println!("  d_{} = {:?}", i, coef);
    }
    println!("Manual evaluation of f'''({:?}) = {:?}", x, d3_coeffs.get(0).unwrap_or(&Scalar::zero()));
    println!("Verification: values match = {}\n", 
             derivative_3 == *d3_coeffs.get(0).unwrap_or(&Scalar::zero()));
    
    // Compute fourth derivative (d=4)
    // f''''(x) = 0 (our polynomial is degree 3, so 4th derivative is zero)
    let d = 4;
    let derivative_4 = f.nth_derivative_at(&x, d);
    println!("Fourth derivative f''''({:?}) = {:?}", x, derivative_4);
    println!("Verification: value is zero = {}", derivative_4 == Scalar::zero());
} 