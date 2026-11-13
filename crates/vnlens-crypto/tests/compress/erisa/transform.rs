#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn float_dct_and_lot_vectors_and_shape_errors() {
    let dct = Dct::new(3).unwrap();
    assert_eq!(dct.inverse(&[2.0, 0.0, 0.0, 0.0]).unwrap(), [2.0; 4]);
    assert_eq!(
        dct.inverse(&[2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
            .unwrap(),
        [2.0; 8]
    );
    assert!(dct.inverse(&[0.0; 5]).is_err());
    assert_eq!(inverse_lot(&[1.0, 2.0], &[3.0, 4.0]).unwrap(), [5.0, -3.0]);
    assert!(inverse_lot(&[], &[1.0]).is_err());
    let params = revolve_parameters(32).unwrap();
    let mut zero = [0.0; 32];
    odd_givens_inverse(&mut zero, &params).unwrap();
    assert_eq!(zero, [0.0; 32]);
    assert!(odd_givens_inverse(&mut zero, &[]).is_err());
}
