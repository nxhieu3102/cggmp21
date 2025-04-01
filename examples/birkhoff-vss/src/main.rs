use generic_ec::{Point, Scalar, curves};
use generic_ec_zkp::polynomial::Polynomial;
use rand_dev::DevRng;

fn main() {
    let mut rng = DevRng::new();
    let t = 3;
    let coefs = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)];
    let x = Scalar::from(4);
    let f = Polynomial::<Scalar<curves::Secp256k1>>::from_coefs(coefs);
    let F: Polynomial<Point<_>> = &f * &Point::generator();

    assert_eq!(
        f.value::<_, Scalar<_>>(&x) * Point::generator(),
        F.value::<_, Point<_>>(&x),
        "Polynomial evaluation at x should be the same for both types"
    );

    debug_assert_eq!(
        f.value::<_, Scalar<_>>(&x) * Point::generator(),
        F.value::<_, Point<_>>(&x),
        "Polynomial evaluation at x should be the same for both types"
    );

    debug_assert_eq!(
        f.nth_derivative_at::<_, Scalar<_>>(&x, 1) * Point::generator(),
        F.nth_derivative_at::<_, Point<_>>(&x, 1),
        "Derivative evaluation at x should be the same for both types"
    );

    debug_assert_eq!(
        f.nth_derivative_at::<_, Scalar<_>>(&x, 2) * Point::generator(),
        F.nth_derivative_at::<_, Point<_>>(&x, 2),
        "Derivative evaluation at x should be the same for both types"
    );

    debug_assert_eq!(
        f.nth_derivative_at::<_, Scalar<_>>(&x, 3) * Point::generator(),
        F.nth_derivative_at::<_, Point<_>>(&x, 3),
        "Derivative evaluation at x should be the same for both types"
    );
}
