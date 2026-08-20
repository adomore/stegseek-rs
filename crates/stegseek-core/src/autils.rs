//! Port of `AUtils.h` — non-standard arithmetic helpers.
//!
//! These are generic over the unsigned integer types used by the original
//! templates (`u16`, `u32`, `u64`, `usize`). Behaviour is bit-for-bit
//! equivalent to the C++ templates for the value ranges steghide uses.

use core::ops::{Add, Div, Sub};

/// `a` divided by `b`, rounded up. Equivalent to the original
/// `div_roundup(a, b) { T c = b--; return (a + b) / c; }` i.e. `(a + b - 1) / b`.
pub fn div_roundup<T>(a: T, b: T) -> T
where
    T: Copy + Add<Output = T> + Sub<Output = T> + Div<Output = T> + From<u8>,
{
    let one = T::from(1u8);
    (a + (b - one)) / b
}

/// Saturating subtraction returning zero on negative difference
/// (`bminus(a, b) = max(a - b, 0)`).
pub fn bminus<T>(a: T, b: T) -> T
where
    T: Copy + PartialOrd + Sub<Output = T> + From<u8>,
{
    if a > b {
        a - b
    } else {
        T::from(0u8)
    }
}

/// Saturating addition capped at `top` (`bplus(a, b, top) = min(a + b, top)`).
pub fn bplus<T>(a: T, b: T, top: T) -> T
where
    T: Copy + PartialOrd + Add<Output = T>,
{
    let s = a + b;
    if s > top {
        top
    } else {
        s
    }
}

/// Number of bits needed to store values from `{0, ..., n-1}`, i.e. the
/// 2-logarithm of `n` rounded up. Matches `AUtils::log2_ceil`.
pub fn log2_ceil<T>(mut n: T) -> T
where
    T: Copy + PartialOrd + Add<Output = T> + Sub<Output = T> + Div<Output = T> + From<u8>,
{
    let one = T::from(1u8);
    let two = T::from(2u8);
    let mut retval = T::from(0u8);
    while n > one {
        n = div_roundup(n, two);
        retval = retval + one;
    }
    retval
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn div_roundup_matches_reference() {
        assert_eq!(div_roundup::<u32>(0, 8), 0);
        assert_eq!(div_roundup::<u32>(1, 8), 1);
        assert_eq!(div_roundup::<u32>(8, 8), 1);
        assert_eq!(div_roundup::<u32>(9, 8), 2);
        assert_eq!(div_roundup::<u64>(24, 7), 4);
    }

    #[test]
    fn bminus_saturates() {
        assert_eq!(bminus::<u32>(5, 3), 2);
        assert_eq!(bminus::<u32>(3, 5), 0);
        assert_eq!(bminus::<u32>(5, 5), 0);
    }

    #[test]
    fn log2_ceil_matches_reference() {
        // bits needed to store {0..n-1}
        assert_eq!(log2_ceil::<u32>(1), 0);
        assert_eq!(log2_ceil::<u32>(2), 1);
        assert_eq!(log2_ceil::<u32>(3), 2);
        assert_eq!(log2_ceil::<u32>(4), 2);
        assert_eq!(log2_ceil::<u32>(5), 3);
        assert_eq!(log2_ceil::<u32>(256), 8);
    }
}
