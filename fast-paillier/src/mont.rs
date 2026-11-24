//! Montgomery modular exponentiation in pure Rust.
//!
//! This module does all modular exponentiation for the crate, on every target including
//! `wasm32-unknown-unknown`. Residues are stored as fixed-length little-endian limb slices.
//! 64-bit targets use `u64` limbs with `u128` products. Other targets use `u32` limbs with `u64`
//! products, because wasm32 has no 64×64→128 multiply.
//!
//! Montgomery multiplication and squaring use finely integrated product scanning. Each column of
//! the product and of the reduction is summed in multi-word accumulators, so the loops carry no
//! limb-to-limb carry chains. Squaring computes each cross product once. On wasm32, building with
//! `-C target-feature=+simd128` switches the column sums to 128-bit SIMD, which roughly halves the
//! exponentiation time.
//!
//! The exponentiation loops do not allocate. Each call allocates its tables and scratch space
//! once, up front.
//!
//! ## Timing
//! The Montgomery multiplication and squaring kernels contain no branches or memory accesses that
//! depend on the operands.
//! * `Montgomery::pow` and `Montgomery::multi_pow` use a fixed window. They read every table
//!   entry on each lookup. The sequence of operations depends only on the bit length of the
//!   exponent(s) and on the size of the modulus. Use them for secret exponents.
//! * `Montgomery::pow_vartime` uses a sliding window. Its timing depends on the exponent but not
//!   on the base. Use it only for public exponents.
//!
//! Converting between `BigUint` and limbs reveals the operands' limb counts, as any `BigUint`
//! arithmetic does. A base with more limbs than the modulus is first reduced with `BigUint`
//! division.

use core::{fmt, mem};

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

#[cfg(target_pointer_width = "64")]
type Word = u64;
#[cfg(not(target_pointer_width = "64"))]
type Word = u32;

/// Upper bound on the limbs held by the [`Montgomery::multi_pow`] tables. The window shrinks to
/// stay under it.
const MAX_TABLE_LIMBS: usize = 1 << 20;

/// Precomputed Montgomery context for an odd modulus m > 1.
///
/// Its `Debug` output shows only the bit length of the modulus, so secret moduli (such as
/// Paillier primes) do not leak into logs.
#[derive(Clone)]
pub struct Montgomery(Context<Word>);

impl Montgomery {
    /// Builds the context. Returns `None` if `m` is even or `m <= 1`.
    pub fn new(m: &BigUint) -> Option<Self> {
        Context::new(m).map(Self)
    }

    /// The modulus `m`
    pub fn modulus(&self) -> &BigUint {
        &self.0.modulus
    }

    /// base^exp mod m. Regular (fixed-window, constant-time table select) — use for SECRET exponents.
    ///
    /// `base` may be `>= m`. The result is always in `[0, m)`, and `exp = 0` gives `1`.
    pub fn pow(&self, base: &BigUint, exp: &BigUint) -> BigUint {
        self.0.pow(base, exp)
    }

    /// base^exp mod m, sliding window, variable time — only for PUBLIC exponents.
    ///
    /// The timing does not depend on `base`, so `base` may be secret. `base` may be `>= m`. The
    /// result is always in `[0, m)`.
    pub fn pow_vartime(&self, base: &BigUint, exp: &BigUint) -> BigUint {
        self.0.pow_vartime(base, exp)
    }

    /// `prod_i bases[i]^exps[i] mod m` (Straus/interleaved). Regular w.r.t. exponents.
    ///
    /// All the exponentiations share one chain of squarings. An empty `pairs` gives `1`.
    pub fn multi_pow(&self, pairs: &[(&BigUint, &BigUint)]) -> BigUint {
        self.0.multi_pow(pairs)
    }
}

impl fmt::Debug for Montgomery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Montgomery")
            .field("modulus_bits", &self.0.modulus.bits())
            .finish_non_exhaustive()
    }
}

/// Convenience: odd m → Montgomery path; even m → num-bigint modpow fallback. Panics never; m == 0 → returns None.
///
/// The odd-modulus path uses the regular [`Montgomery::pow`], so `exp` may be secret. The even
/// fallback is not constant-time. `m == 1` gives `Some(0)`.
pub fn pow_mod(base: &BigUint, exp: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_zero() {
        return None;
    }
    if m.is_one() {
        return Some(BigUint::zero());
    }
    Some(match Montgomery::new(m) {
        Some(ctx) => ctx.pow(base, exp),
        None => base.modpow(exp, m),
    })
}

/// A machine word used as a limb. Products go to the double-width type.
trait Limb:
    Copy
    + Eq
    + fmt::Debug
    + core::ops::BitAnd<Output = Self>
    + core::ops::BitOr<Output = Self>
    + core::ops::Not<Output = Self>
    + core::ops::Shl<u32, Output = Self>
    + core::ops::Shr<u32, Output = Self>
{
    const BITS: u32;
    const ZERO: Self;
    const ONE: Self;

    /// Column accumulator for product scanning
    type Acc: Accumulator<Self>;

    /// `a - b - borrow`, with `borrow` in `{0, 1}`, as `(difference, borrow_out in {0, 1})`
    fn sbb(a: Self, b: Self, borrow: Self) -> (Self, Self);
    fn wrapping_mul(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
    fn to_u64(self) -> u64;
    /// `0` → all zeros, `1` → all ones
    fn mask(bit: u64) -> Self;

    /// Little-endian limbs of `x`, without leading zeros
    fn digits(x: &BigUint) -> Vec<Self>;
    /// Writes the limbs of `x` into `out` and zero-pads it. `x` must fit in `out`.
    fn load(x: &BigUint, out: &mut [Self]);
    fn to_biguint(x: &[Self]) -> BigUint;
}

macro_rules! impl_limb {
    ($w:ident, $d:ident, $acc:ty, $iter_digits:ident, $digits:ident) => {
        impl Limb for $w {
            const BITS: u32 = <$w>::BITS;
            const ZERO: Self = 0;
            const ONE: Self = 1;

            type Acc = $acc;

            #[inline(always)]
            fn sbb(a: Self, b: Self, borrow: Self) -> (Self, Self) {
                let t = (a as $d).wrapping_sub(b as $d).wrapping_sub(borrow as $d);
                (t as $w, ((t >> <$w>::BITS) as $w) & 1)
            }
            #[inline(always)]
            fn wrapping_mul(self, rhs: Self) -> Self {
                <$w>::wrapping_mul(self, rhs)
            }
            #[inline(always)]
            fn wrapping_sub(self, rhs: Self) -> Self {
                <$w>::wrapping_sub(self, rhs)
            }
            #[inline(always)]
            fn to_u64(self) -> u64 {
                self as u64
            }
            #[inline(always)]
            fn mask(bit: u64) -> Self {
                (bit as $w).wrapping_neg()
            }

            fn digits(x: &BigUint) -> Vec<Self> {
                x.$digits()
            }
            fn load(x: &BigUint, out: &mut [Self]) {
                let mut digits = x.$iter_digits();
                for o in out.iter_mut() {
                    *o = digits.next().unwrap_or(0);
                }
                debug_assert!(digits.next().is_none(), "value does not fit");
            }
            fn to_biguint(x: &[Self]) -> BigUint {
                impl_limb!(@to_biguint $w, x)
            }
        }
    };
    (@to_biguint u32, $x:ident) => {
        BigUint::from_slice($x)
    };
    (@to_biguint u64, $x:ident) => {
        BigUint::new($x.iter().flat_map(|&d| [d as u32, (d >> 32) as u32]).collect())
    };
}

impl_limb!(u32, u64, Split32, iter_u32_digits, to_u32_digits);
impl_limb!(u64, u128, Acc128, iter_u64_digits, to_u64_digits);

/// Running sum of a product-scanning column. It holds up to a few thousand double-word
/// products without overflowing.
trait Accumulator<W: Copy>: Copy + Default {
    /// `self += a·b`
    fn mul_add(&mut self, a: W, b: W);
    /// `self += other`
    fn add(&mut self, other: &Self);
    /// `self += 2·other`
    fn add_double(&mut self, other: &Self);
    /// Lowest word
    fn low(&self) -> W;
    /// Returns the lowest word and shifts the rest down by one word
    fn shift(&mut self) -> W;

    /// `self += Σ x[j]·y[j] + Σ u[j]·v[j]` for `j < x.len()`: one column of [`mont_mul`].
    /// Each iteration does two products of each kind on four fresh accumulators. They are
    /// independent of each other and of the previous column.
    #[inline(always)]
    fn add_mul_column(&mut self, x: &[W], y: &[W], u: &[W], v: &[W]) {
        let len = x.len();
        let (y, u, v) = (&y[..len], &u[..len], &v[..len]);
        let [mut s0, mut s1, mut r0, mut r1] = [Self::default(); 4];
        for (((&[x0, x1], &[y0, y1]), &[u0, u1]), &[v0, v1]) in (x.as_chunks().0.iter())
            .zip(y.as_chunks().0)
            .zip(u.as_chunks().0)
            .zip(v.as_chunks().0)
        {
            s0.mul_add(x0, y0);
            s1.mul_add(x1, y1);
            r0.mul_add(u0, v0);
            r1.mul_add(u1, v1);
        }
        if len % 2 == 1 {
            s0.mul_add(x[len - 1], y[len - 1]);
            r0.mul_add(u[len - 1], v[len - 1]);
        }
        s0.add(&s1);
        r0.add(&r1);
        s0.add(&r0);
        self.add(&s0);
    }

    /// `self += 2·Σ x[j]·y[j] + Σ u[j]·v[j]`: one column of [`mont_sqr`]. `x` has
    /// `⌊u.len()/2⌋` or one more elements. Each iteration does one cross product and two `u·v`
    /// products on three fresh accumulators.
    #[inline(always)]
    fn add_sqr_column(&mut self, x: &[W], y: &[W], u: &[W], v: &[W]) {
        let (len, pairs) = (u.len(), u.len() / 2);
        let (y, v) = (&y[..x.len()], &v[..len]);
        let [mut cross, mut r0, mut r1] = [Self::default(); 3];
        for ((&xj, &yj), (&[u0, u1], &[v0, v1])) in
            (x.iter().zip(y)).zip(u.as_chunks().0.iter().zip(v.as_chunks().0))
        {
            cross.mul_add(xj, yj);
            r0.mul_add(u0, v0);
            r1.mul_add(u1, v1);
        }
        if x.len() > pairs {
            cross.mul_add(x[pairs], y[pairs]);
        }
        if len % 2 == 1 {
            r0.mul_add(u[len - 1], v[len - 1]);
        }
        r0.add(&r1);
        r0.add_double(&cross);
        self.add(&r0);
    }
}

/// Column sum `hi·2^128 + lo` for `u64` limbs
#[derive(Clone, Copy, Default)]
struct Acc128 {
    lo: u128,
    hi: u64,
}

impl Accumulator<u64> for Acc128 {
    #[inline(always)]
    fn mul_add(&mut self, a: u64, b: u64) {
        let (s, o) = self.lo.overflowing_add(u128::from(a) * u128::from(b));
        self.lo = s;
        self.hi = self.hi.wrapping_add(u64::from(o));
    }
    #[inline(always)]
    fn add(&mut self, other: &Self) {
        let (s, o) = self.lo.overflowing_add(other.lo);
        self.lo = s;
        self.hi = self.hi.wrapping_add(other.hi).wrapping_add(u64::from(o));
    }
    #[inline(always)]
    fn add_double(&mut self, other: &Self) {
        let (s, o) = self.lo.overflowing_add(other.lo << 1);
        self.lo = s;
        let doubled_hi = (other.hi << 1) | (other.lo >> 127) as u64;
        self.hi = self.hi.wrapping_add(doubled_hi).wrapping_add(u64::from(o));
    }
    #[inline(always)]
    fn low(&self) -> u64 {
        self.lo as u64
    }
    #[inline(always)]
    fn shift(&mut self) -> u64 {
        let low = self.lo as u64;
        self.lo = (self.lo >> 64) | (u128::from(self.hi) << 64);
        self.hi = 0;
        low
    }
}

/// Column sum `S` for `u32` limbs, stored as `lo = S mod 2^64` and `hi` with `S = 2^32·hi + e`
/// for some `0 <= e < 2^64`. Adding a product `p` is `lo += p` (wrapping) and `hi += p >> 32`.
/// That raises `e` by less than 2^32 and needs no carry handling. This suits wasm32, which has
/// 64-bit adds but no carry flag.
#[derive(Clone, Copy, Default)]
struct Split32 {
    lo: u64,
    hi: u64,
}

impl Accumulator<u32> for Split32 {
    #[inline(always)]
    fn mul_add(&mut self, a: u32, b: u32) {
        let p = u64::from(a) * u64::from(b);
        self.lo = self.lo.wrapping_add(p);
        self.hi += p >> 32;
    }
    #[inline(always)]
    fn add(&mut self, other: &Self) {
        self.lo = self.lo.wrapping_add(other.lo);
        self.hi += other.hi;
    }
    #[inline(always)]
    fn add_double(&mut self, other: &Self) {
        self.lo = self.lo.wrapping_add(other.lo << 1);
        self.hi += other.hi << 1;
    }
    #[inline(always)]
    fn low(&self) -> u32 {
        self.lo as u32
    }
    #[inline(always)]
    fn shift(&mut self) -> u32 {
        let low = self.lo as u32;
        let e = self.lo.wrapping_sub(self.hi << 32);
        self.lo = self.hi + (e >> 32);
        self.hi = 0;
        low
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[inline(always)]
    fn add_mul_column(&mut self, x: &[u32], y: &[u32], u: &[u32], v: &[u32]) {
        let len = x.len();
        let mut lanes = simd::Lanes::new();
        lanes.dot(self, x, &y[..len]);
        lanes.dot(self, u, &v[..len]);
        lanes.add_to(self);
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[inline(always)]
    fn add_sqr_column(&mut self, x: &[u32], y: &[u32], u: &[u32], v: &[u32]) {
        let mut cross = Split32::default();
        let mut lanes = simd::Lanes::new();
        lanes.dot(&mut cross, x, &y[..x.len()]);
        lanes.add_to(&mut cross);
        let mut lanes = simd::Lanes::new();
        lanes.dot(self, u, &v[..u.len()]);
        lanes.add_to(self);
        self.add_double(&cross);
    }
}

/// Column sums for [`Split32`] with wasm SIMD. `i64x2.extmul_{low,high}_i32x4_u` does two
/// 32×32-bit products per instruction. Builds with `-C target-feature=+simd128` use this, and it
/// makes modular exponentiation about twice as fast.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod simd {
    use core::arch::wasm32::{
        u64x2_add, u64x2_extmul_high_u32x4, u64x2_extmul_low_u32x4, u64x2_extract_lane, u64x2_shr,
        u64x2_splat, v128, v128_load,
    };

    use super::{Accumulator, Split32};

    /// Two [`Split32`] sums, one per 64-bit lane
    pub(super) struct Lanes {
        lo: v128,
        hi: v128,
    }

    impl Lanes {
        #[inline(always)]
        pub(super) fn new() -> Self {
            Self {
                lo: u64x2_splat(0),
                hi: u64x2_splat(0),
            }
        }

        /// Adds `Σ x[j]·y[j]` (equal lengths). The lanes take four products per step and
        /// `tail` takes the remaining `len % 4`.
        #[inline(always)]
        pub(super) fn dot(&mut self, tail: &mut Split32, x: &[u32], y: &[u32]) {
            let (xc, xr) = x.as_chunks::<4>();
            let (yc, yr) = y.as_chunks::<4>();
            for (a, b) in xc.iter().zip(yc) {
                // SAFETY: `a` and `b` are 16 readable bytes each, and v128_load accepts any
                // alignment
                let (a, b) =
                    unsafe { (v128_load(a.as_ptr().cast()), v128_load(b.as_ptr().cast())) };
                let p0 = u64x2_extmul_low_u32x4(a, b);
                let p1 = u64x2_extmul_high_u32x4(a, b);
                self.lo = u64x2_add(self.lo, u64x2_add(p0, p1));
                self.hi = u64x2_add(self.hi, u64x2_add(u64x2_shr(p0, 32), u64x2_shr(p1, 32)));
            }
            for (&a, &b) in xr.iter().zip(yr) {
                tail.mul_add(a, b);
            }
        }

        /// Adds both lanes to `acc`
        #[inline(always)]
        pub(super) fn add_to(&self, acc: &mut Split32) {
            acc.add(&Split32 {
                lo: u64x2_extract_lane::<0>(self.lo).wrapping_add(u64x2_extract_lane::<1>(self.lo)),
                hi: u64x2_extract_lane::<0>(self.hi) + u64x2_extract_lane::<1>(self.hi),
            });
        }
    }
}

/// Montgomery context over limb type `W`. `R = 2^(W::BITS * n)`, where `n` is the modulus
/// limb count.
#[derive(Clone)]
struct Context<W> {
    modulus: BigUint,
    /// Modulus limbs (`n` of them, top limb non-zero)
    m: Box<[W]>,
    /// `m` with its limbs reversed, so that column sums read both operands forwards
    m_rev: Box<[W]>,
    /// `-m^-1 mod 2^W::BITS`
    n0inv: W,
    /// `R^2 mod m`, limbs reversed (the `b_rev` operand of [`mont_mul`])
    r2_rev: Box<[W]>,
    /// `R mod m`, i.e. 1 in Montgomery form
    one: Box<[W]>,
}

impl<W: Limb> Context<W> {
    fn new(modulus: &BigUint) -> Option<Self> {
        if modulus.is_even() || modulus.is_one() {
            return None;
        }
        let m = W::digits(modulus).into_boxed_slice();
        let n = m.len();
        let r_mod_m = (BigUint::one() << (n as u64 * u64::from(W::BITS))) % modulus;
        let r2_mod_m = (&r_mod_m * &r_mod_m) % modulus;
        let mut one = vec![W::ZERO; n].into_boxed_slice();
        let mut r2_rev = vec![W::ZERO; n].into_boxed_slice();
        W::load(&r_mod_m, &mut one);
        W::load(&r2_mod_m, &mut r2_rev);
        r2_rev.reverse();
        Some(Self {
            modulus: modulus.clone(),
            n0inv: neg_inv(m[0]),
            m_rev: m.iter().rev().copied().collect(),
            m,
            r2_rev,
            one,
        })
    }

    /// Number of limbs in the modulus
    fn n(&self) -> usize {
        self.m.len()
    }

    /// `out = a·b/R mod m`. Needs `a·b < R·m` and scratch `t` of at least `2n` limbs.
    fn mul(&self, out: &mut [W], a: &[W], b: &[W], t: &mut [W]) {
        let n = self.n();
        let (b_rev, q) = t.split_at_mut(n);
        for (r, &x) in b_rev.iter_mut().zip(b[..n].iter().rev()) {
            *r = x;
        }
        mont_mul(out, a, b_rev, &self.m, &self.m_rev, self.n0inv, q);
    }

    /// `out = a²/R mod m`. Needs `a < m` and scratch `t` of at least `2n` limbs.
    fn sqr(&self, out: &mut [W], a: &[W], t: &mut [W]) {
        let n = self.n();
        let (a_rev, q) = t.split_at_mut(n);
        for (r, &x) in a_rev.iter_mut().zip(a[..n].iter().rev()) {
            *r = x;
        }
        mont_sqr(out, a, a_rev, &self.m, &self.m_rev, self.n0inv, q);
    }

    /// `out = x·R mod m`. Needs scratch `t` of at least `2n` limbs.
    fn to_mont(&self, out: &mut [W], x: &BigUint, t: &mut [W]) {
        let n = self.n();
        let (x_limbs, q) = t.split_at_mut(n);
        // x·r2 < R·m holds whenever x < R, so only a base with more limbs than m needs division
        if x.bits() > n as u64 * u64::from(W::BITS) {
            W::load(&(x % &self.modulus), x_limbs);
        } else {
            W::load(x, x_limbs);
        }
        mont_mul(
            out,
            x_limbs,
            &self.r2_rev,
            &self.m,
            &self.m_rev,
            self.n0inv,
            q,
        );
    }

    /// Converts `x` out of Montgomery form. Needs `out` of `n` limbs and scratch `t` of at
    /// least `2n` limbs.
    fn out_of_mont(&self, out: &mut [W], x: &[W], t: &mut [W]) -> BigUint {
        let n = self.n();
        // Multiply by 1, whose reversed limbs are 0, .., 0, 1
        let (one_rev, q) = t.split_at_mut(n);
        one_rev.fill(W::ZERO);
        one_rev[n - 1] = W::ONE;
        mont_mul(out, x, one_rev, &self.m, &self.m_rev, self.n0inv, q);
        W::to_biguint(&out[..n])
    }

    /// Fills `table` (`2^w` entries) with `base^0, .., base^(2^w - 1)` in Montgomery form
    fn fill_powers(&self, table: &mut [W], base: &BigUint, t: &mut [W]) {
        let n = self.n();
        table[..n].copy_from_slice(&self.one);
        self.to_mont(&mut table[n..2 * n], base, t);
        for i in 2..table.len() / n {
            let (done, rest) = table.split_at_mut(i * n);
            let out = &mut rest[..n];
            if i % 2 == 0 {
                self.sqr(out, &done[i / 2 * n..][..n], t);
            } else {
                self.mul(out, &done[(i - 1) * n..], &done[n..2 * n], t);
            }
        }
    }

    fn pow(&self, base: &BigUint, exp: &BigUint) -> BigUint {
        self.multi_pow(&[(base, exp)])
    }

    fn multi_pow(&self, pairs: &[(&BigUint, &BigUint)]) -> BigUint {
        let bits = pairs.iter().map(|(_, e)| e.bits()).max().unwrap_or(0) as usize;
        if bits == 0 {
            return BigUint::one();
        }
        let n = self.n();
        let w = multi_window(bits, n, pairs.len());
        let table_len = n << w;

        let mut buf = vec![W::ZERO; pairs.len() * table_len + 5 * n];
        let (tables, rest) = buf.split_at_mut(pairs.len() * table_len);
        let (mut acc, rest) = rest.split_at_mut(n);
        let (mut tmp, rest) = rest.split_at_mut(n);
        let (sel, t) = rest.split_at_mut(n);

        for ((base, _), table) in pairs.iter().zip(tables.chunks_exact_mut(table_len)) {
            self.fill_powers(table, base, t);
        }
        let exps: Vec<Vec<W>> = pairs.iter().map(|(_, e)| W::digits(e)).collect();
        let mut terms = exps.iter().zip(tables.chunks_exact(table_len));

        // The top window starts the accumulator directly, which saves squaring 1
        let mut pos = (bits - 1) / w * w;
        if let Some((e, table)) = terms.next() {
            ct_select(acc, table, window(e, pos, w));
        }
        for (e, table) in terms {
            ct_select(sel, table, window(e, pos, w));
            self.mul(tmp, acc, sel, t);
            mem::swap(&mut acc, &mut tmp);
        }
        while pos > 0 {
            pos -= w;
            for _ in 0..w {
                self.sqr(tmp, acc, t);
                mem::swap(&mut acc, &mut tmp);
            }
            for (e, table) in exps.iter().zip(tables.chunks_exact(table_len)) {
                ct_select(sel, table, window(e, pos, w));
                self.mul(tmp, acc, sel, t);
                mem::swap(&mut acc, &mut tmp);
            }
        }
        self.out_of_mont(tmp, acc, t)
    }

    fn pow_vartime(&self, base: &BigUint, exp: &BigUint) -> BigUint {
        let bits = exp.bits() as usize;
        if bits == 0 {
            return BigUint::one();
        }
        let n = self.n();
        let w = sliding_window(bits);
        let entries = 1usize << (w - 1);

        let mut buf = vec![W::ZERO; (entries + 4) * n];
        let (table, rest) = buf.split_at_mut(entries * n);
        let (mut acc, rest) = rest.split_at_mut(n);
        let (mut tmp, t) = rest.split_at_mut(n);

        // table[i] = base^(2i + 1); acc temporarily holds base^2
        self.to_mont(&mut table[..n], base, t);
        if entries > 1 {
            self.sqr(acc, &table[..n], t);
            for i in 1..entries {
                let (done, rest) = table.split_at_mut(i * n);
                self.mul(&mut rest[..n], &done[(i - 1) * n..], acc, t);
            }
        }

        let e = W::digits(exp);
        let bit = |i: usize| window(&e, i, 1) == 1;
        // Bits `0..i` are still to be processed. The top bit is set, so the first iteration
        // takes the window branch and initialises `acc`.
        let mut i = bits;
        let mut started = false;
        while i > 0 {
            if !bit(i - 1) {
                self.sqr(tmp, acc, t);
                mem::swap(&mut acc, &mut tmp);
                i -= 1;
                continue;
            }
            // Longest window of at most `w` bits that ends at bit `i - 1` and starts at a set bit
            let mut lo = i.saturating_sub(w);
            while !bit(lo) {
                lo += 1;
            }
            let width = i - lo;
            let entry = &table[(window(&e, lo, width) >> 1) * n..][..n];
            if started {
                for _ in 0..width {
                    self.sqr(tmp, acc, t);
                    mem::swap(&mut acc, &mut tmp);
                }
                self.mul(tmp, acc, entry, t);
                mem::swap(&mut acc, &mut tmp);
            } else {
                acc.copy_from_slice(entry);
                started = true;
            }
            i = lo;
        }
        self.out_of_mont(tmp, acc, t)
    }
}

/// `-m0^-1 mod 2^W::BITS` for odd `m0`, by Newton iteration
fn neg_inv<W: Limb>(m0: W) -> W {
    // m0·m0 ≡ 1 (mod 8). Each step doubles the number of correct low bits: 3 → 6 → … → 96 ≥ 64.
    let two = W::ONE << 1;
    let mut x = m0;
    for _ in 0..5 {
        x = x.wrapping_mul(two.wrapping_sub(m0.wrapping_mul(x)));
    }
    W::ZERO.wrapping_sub(x)
}

/// `out = a·b/R mod m` by Montgomery multiplication with finely integrated product scanning:
/// column by column, the `a·b` and `q·m` products are summed into multi-word accumulators,
/// without carry chains across limbs.
///
/// `b_rev` and `m_rev` hold `b` and `m` with their limbs reversed, so that column sums read every
/// operand forwards. All operands have `n = m.len()` limbs. `q` is scratch of at least `n` limbs.
/// Needs `a·b < R·m`.
fn mont_mul<W: Limb>(
    out: &mut [W],
    a: &[W],
    b_rev: &[W],
    m: &[W],
    m_rev: &[W],
    n0inv: W,
    q: &mut [W],
) {
    let n = m.len();
    let (a, b_rev, m_rev, q) = (&a[..n], &b_rev[..n], &m_rev[..n], &mut q[..n]);
    let mut acc = W::Acc::default();
    // Columns 0..n choose q[i] so that the column's low word becomes zero.
    // b[i - j] = b_rev[n - 1 - i + j].
    for i in 0..n {
        let off = n - 1 - i;
        acc.add_mul_column(&a[..i], &b_rev[off..], &q[..i], &m_rev[off..]);
        acc.mul_add(a[i], b_rev[n - 1]);
        let qi = acc.low().wrapping_mul(n0inv);
        q[i] = qi;
        acc.mul_add(qi, m[0]);
        acc.shift();
    }
    // Columns n..2n-1 give the result words. Column i reads q[i+1-n..], so result word i - n
    // can replace q[i - n].
    for i in n..2 * n - 1 {
        let lo = i + 1 - n;
        acc.add_mul_column(&a[lo..], b_rev, &q[lo..], m_rev);
        q[i - n] = acc.shift();
    }
    // The result is below 2m, so the accumulator's remaining value is 0 or 1
    q[n - 1] = acc.shift();
    reduce_once(out, q, acc.low(), m);
}

/// `out = a²/R mod m`. It works like [`mont_mul`], but sums each column's cross products
/// `a[j]·a[k]` (`j < k`) only once and doubles them.
///
/// `a_rev` and `m_rev` hold `a` and `m` with their limbs reversed. `q` is scratch of at least `n`
/// limbs. Needs `a < m`.
fn mont_sqr<W: Limb>(
    out: &mut [W],
    a: &[W],
    a_rev: &[W],
    m: &[W],
    m_rev: &[W],
    n0inv: W,
    q: &mut [W],
) {
    let n = m.len();
    let (a, a_rev, m_rev, q) = (&a[..n], &a_rev[..n], &m_rev[..n], &mut q[..n]);
    let mut acc = W::Acc::default();
    // Column i sums a[j]·a[i - j] over j < i - j (doubled), a[i/2]² for even i, and the q·m
    // products as in mont_mul. a[i - j] = a_rev[n - 1 - i + j].
    for i in 0..n {
        let off = n - 1 - i;
        if i % 2 == 0 {
            acc.mul_add(a[i / 2], a[i / 2]);
        }
        acc.add_sqr_column(&a[..i.div_ceil(2)], &a_rev[off..], &q[..i], &m_rev[off..]);
        let qi = acc.low().wrapping_mul(n0inv);
        q[i] = qi;
        acc.mul_add(qi, m[0]);
        acc.shift();
    }
    for i in n..2 * n - 1 {
        let lo = i + 1 - n;
        if i % 2 == 0 {
            acc.mul_add(a[i / 2], a[i / 2]);
        }
        acc.add_sqr_column(&a[lo..i.div_ceil(2)], a_rev, &q[lo..], m_rev);
        q[i - n] = acc.shift();
    }
    q[n - 1] = acc.shift();
    reduce_once(out, q, acc.low(), m);
}

/// `out = (hi·R + x) mod m` for `hi·R + x < 2m`, without data-dependent branches
#[inline]
fn reduce_once<W: Limb>(out: &mut [W], x: &[W], hi: W, m: &[W]) {
    let n = m.len();
    let (out, x) = (&mut out[..n], &x[..n]);
    let mut borrow = W::ZERO;
    for ((o, &xi), &mi) in out.iter_mut().zip(x).zip(m) {
        let (d, b) = W::sbb(xi, mi, borrow);
        *o = d;
        borrow = b;
    }
    // The value is below m iff hi == 0 and subtracting m borrowed. Then keep x.
    // black_box stops the compiler from turning the masked select into a branch
    let keep = core::hint::black_box(W::ZERO.wrapping_sub(borrow & !hi));
    for (o, &xi) in out.iter_mut().zip(x) {
        *o = (xi & keep) | (*o & !keep);
    }
}

/// Copies entry `index` of `table` into `out`, reading every entry
fn ct_select<W: Limb>(out: &mut [W], table: &[W], index: usize) {
    out.fill(W::ZERO);
    for (k, entry) in table.chunks_exact(out.len()).enumerate() {
        let diff = (k ^ index) as u64;
        let is_eq = ((diff | diff.wrapping_neg()) >> 63) ^ 1;
        let mask = W::mask(core::hint::black_box(is_eq));
        for (o, &e) in out.iter_mut().zip(entry) {
            *o = *o | (e & mask);
        }
    }
}

/// Bits `pos..pos + width` of the little-endian limbs `e` (zero past the end), `width < 32`.
/// Branches depend only on `pos`, `width` and `e.len()`.
#[inline]
fn window<W: Limb>(e: &[W], pos: usize, width: usize) -> usize {
    let limb_bits = W::BITS as usize;
    let (limb, offset) = (pos / limb_bits, pos % limb_bits);
    let mut v = e.get(limb).map_or(0, |x| x.to_u64() >> offset);
    if offset + width > limb_bits {
        if let Some(x) = e.get(limb + 1) {
            v |= x.to_u64() << (limb_bits - offset);
        }
    }
    (v & ((1 << width) - 1)) as usize
}

/// Fixed-window width for `bits`-bit exponents modulo an `n`-limb modulus. It minimises table
/// setup plus one multiplication per window, counting the constant-time scan of a `2^w`-entry
/// table at about `2^w / 4n` of a multiplication.
fn fixed_window(bits: usize, n: usize) -> usize {
    (1..=6)
        .min_by_key(|&w| {
            let entries = 1usize << w;
            bits.div_ceil(w) * (4 * n + entries) + entries * 4 * n
        })
        .unwrap_or(1)
}

/// [`fixed_window`] for `k` bases, capped so that all tables fit in [`MAX_TABLE_LIMBS`]
fn multi_window(bits: usize, n: usize, k: usize) -> usize {
    let mut w = fixed_window(bits, n);
    while w > 1 && (k * n) << w > MAX_TABLE_LIMBS {
        w -= 1;
    }
    w
}

/// Sliding-window width: about `bits / (w + 1)` multiplications plus `2^(w-1)` odd powers
fn sliding_window(bits: usize) -> usize {
    (1..=7)
        .min_by_key(|&w| bits / (w + 1) + (1 << (w - 1)))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{One, Zero};
    use rand::{Rng, RngCore};
    use rand_dev::DevRng;

    use super::{pow_mod, Context, Limb, Montgomery};

    /// Random number of random bit length `0..=max_bits`
    fn random_upto(rng: &mut DevRng, max_bits: u64) -> BigUint {
        let bits = rng.gen_range(0..=max_bits);
        rng.gen_biguint(bits)
    }

    fn random_odd(rng: &mut DevRng, bits: u64) -> BigUint {
        assert!(bits >= 2);
        let mut m = rng.gen_biguint(bits);
        m.set_bit(bits - 1, true);
        m.set_bit(0, true);
        m
    }

    /// Checks pow, pow_vartime and single-pair multi_pow against num-bigint
    fn check<W: Limb>(ctx: &Context<W>, base: &BigUint, exp: &BigUint) {
        let m = &ctx.modulus;
        let expected = base.modpow(exp, m);
        assert_eq!(
            ctx.pow(base, exp),
            expected,
            "pow m={m:x} base={base:x} exp={exp:x}"
        );
        assert_eq!(
            ctx.pow_vartime(base, exp),
            expected,
            "pow_vartime m={m:x} base={base:x} exp={exp:x}"
        );
        assert_eq!(
            ctx.multi_pow(&[(base, exp)]),
            expected,
            "multi_pow m={m:x} base={base:x} exp={exp:x}"
        );
    }

    /// Moduli of 1..=200 limbs: top limb full, top limb 1, and random top limb. Exponents and
    /// bases have random lengths, and bases may be longer than the modulus.
    fn limb_counts<W: Limb>() {
        let mut rng = DevRng::new();
        let limb_bits = u64::from(W::BITS);
        for limbs in 1..=200u64 {
            let full = limb_bits * limbs;
            for bits in [
                full,
                full - limb_bits + 1,
                full - 1 - rng.gen_range(0..limb_bits - 1),
            ] {
                let m = if bits < 2 {
                    BigUint::from(3u8)
                } else {
                    random_odd(&mut rng, bits)
                };
                let ctx = Context::<W>::new(&m).unwrap();
                assert_eq!(ctx.n() as u64, m.bits().div_ceil(limb_bits));
                let max_exp_bits = if limbs <= 16 { full + 8 } else { 160 };
                for _ in 0..2 {
                    let base = random_upto(&mut rng, bits + 70);
                    let exp = random_upto(&mut rng, max_exp_bits);
                    check(&ctx, &base, &exp);
                }
            }
        }
    }

    #[test]
    fn limb_counts_u32() {
        limb_counts::<u32>()
    }

    #[test]
    fn limb_counts_u64() {
        limb_counts::<u64>()
    }

    fn edge_cases<W: Limb>() {
        let mut rng = DevRng::new();
        let limb_bits = u64::from(W::BITS);
        let mut moduli: Vec<BigUint> = [3u32, 5, 7, 9, 15, 0xffff_ffff]
            .into_iter()
            .map(BigUint::from)
            .collect();
        for k in [2u64, 3, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1024, 3072] {
            moduli.push((BigUint::one() << k) - 1u8);
        }
        for limbs in 1..=4u64 {
            // Top limb is 1, low limb is 1
            moduli.push((BigUint::one() << (limb_bits * limbs)) + 1u8);
            // Top limb is 1, the rest random
            let mut m = rng.gen_biguint(limb_bits * limbs) | BigUint::one();
            m.set_bit(limb_bits * limbs, true);
            moduli.push(m);
        }
        for m in &moduli {
            let ctx = Context::<W>::new(m).unwrap();
            let r = BigUint::one() << (ctx.n() as u64 * limb_bits);
            let bases = [
                BigUint::zero(),
                BigUint::one(),
                BigUint::from(2u8),
                m - 1u8,
                m.clone(),
                m + 1u8,
                m * 2u8,
                m * m + 3u8,
                &r - 1u8,
                r.clone(),
                &r + 1u8,
                &r * &r * 7u8 + m,
                rng.gen_biguint_below(m),
            ];
            let exps = [
                BigUint::zero(),
                BigUint::one(),
                BigUint::from(2u8),
                BigUint::from(3u8),
                m - 1u8,
                m.clone(),
                &r - 1u8,
                r.clone(),
                rng.gen_biguint(m.bits() + 3),
            ];
            for base in &bases {
                for exp in &exps {
                    check(&ctx, base, exp);
                }
            }
        }
    }

    #[test]
    fn edge_cases_u32() {
        edge_cases::<u32>()
    }

    #[test]
    fn edge_cases_u64() {
        edge_cases::<u64>()
    }

    /// Full-size exponents modulo 3072- and 6144-bit moduli (Paillier N and N²), so every
    /// window width is used
    fn full_size<W: Limb>() {
        let mut rng = DevRng::new();
        for (mod_bits, exp_bits) in [(3072, 3072), (3072, 3080), (6144, 3072), (6144, 6144)] {
            let m = random_odd(&mut rng, mod_bits);
            let ctx = Context::<W>::new(&m).unwrap();
            let base = rng.gen_biguint_below(&m);
            let exp = rng.gen_biguint(exp_bits);
            check(&ctx, &base, &exp);
            let base2 = rng.gen_biguint_below(&m);
            let exp2 = rng.gen_biguint(exp_bits / 2);
            assert_eq!(
                ctx.multi_pow(&[(&base, &exp), (&base2, &exp2)]),
                base.modpow(&exp, &m) * base2.modpow(&exp2, &m) % &m
            );
        }
    }

    #[test]
    fn full_size_u32() {
        full_size::<u32>()
    }

    #[test]
    fn full_size_u64() {
        full_size::<u64>()
    }

    fn multi_pow_matches_product<W: Limb>() {
        let mut rng = DevRng::new();
        for mod_bits in [2u64, 33, 64, 65, 200, 1024, 1537] {
            let m = random_odd(&mut rng, mod_bits);
            let ctx = Context::<W>::new(&m).unwrap();
            assert_eq!(ctx.multi_pow(&[]), BigUint::one());
            for k in 1..=5 {
                for _ in 0..4 {
                    let bases: Vec<BigUint> = (0..k)
                        .map(|_| random_upto(&mut rng, mod_bits + 70))
                        .collect();
                    // Different lengths, including zero exponents
                    let exps: Vec<BigUint> = (0..k)
                        .map(|_| random_upto(&mut rng, mod_bits + 10))
                        .collect();
                    let pairs: Vec<(&BigUint, &BigUint)> = bases.iter().zip(&exps).collect();
                    let expected = bases
                        .iter()
                        .zip(&exps)
                        .fold(BigUint::one(), |acc, (b, e)| acc * b.modpow(e, &m) % &m);
                    assert_eq!(ctx.multi_pow(&pairs), expected, "m={m:x} pairs={pairs:x?}");
                }
            }
        }
    }

    #[test]
    fn multi_pow_matches_product_u32() {
        multi_pow_matches_product::<u32>()
    }

    #[test]
    fn multi_pow_matches_product_u64() {
        multi_pow_matches_product::<u64>()
    }

    #[test]
    fn neg_inv() {
        let mut rng = DevRng::new();
        for _ in 0..1000 {
            let m = rng.next_u64() | 1;
            assert_eq!(m.wrapping_mul(super::neg_inv(m)), u64::MAX);
            let m = m as u32 | 1;
            assert_eq!(m.wrapping_mul(super::neg_inv(m)), u32::MAX);
        }
    }

    #[test]
    fn public_api() {
        let mut rng = DevRng::new();
        for m in [0u32, 1, 2, 4, 6, 1 << 20] {
            assert!(Montgomery::new(&BigUint::from(m)).is_none(), "m = {m}");
        }
        assert!(Montgomery::new(&(BigUint::one() << 3072)).is_none());

        let m = random_odd(&mut rng, 2048);
        let ctx = Montgomery::new(&m).unwrap();
        assert_eq!(ctx.modulus(), &m);
        assert!(!format!("{ctx:?}").contains(&format!("{m:x}")));
        let (b1, e1) = (rng.gen_biguint(2100), rng.gen_biguint(2048));
        let (b2, e2) = (rng.gen_biguint_below(&m), rng.gen_biguint(256));
        let expected = b1.modpow(&e1, &m);
        assert_eq!(ctx.pow(&b1, &e1), expected);
        assert_eq!(ctx.pow_vartime(&b1, &e1), expected);
        assert_eq!(
            ctx.multi_pow(&[(&b1, &e1), (&b2, &e2)]),
            expected * b2.modpow(&e2, &m) % &m
        );

        let three = BigUint::from(3u8);
        let ctx = Montgomery::new(&three).unwrap();
        assert_eq!(
            ctx.pow(&BigUint::from(5u8), &BigUint::from(3u8)),
            BigUint::from(2u8)
        );
        assert_eq!(ctx.pow(&BigUint::zero(), &BigUint::zero()), BigUint::one());
    }

    #[test]
    fn pow_mod_dispatch() {
        let mut rng = DevRng::new();
        let (b, e) = (rng.gen_biguint(300), rng.gen_biguint(200));
        assert_eq!(pow_mod(&b, &e, &BigUint::zero()), None);
        assert_eq!(pow_mod(&b, &e, &BigUint::one()), Some(BigUint::zero()));
        assert_eq!(
            pow_mod(&b, &BigUint::zero(), &BigUint::one()),
            Some(BigUint::zero())
        );
        for bits in [2u64, 64, 255, 1024] {
            let odd = random_odd(&mut rng, bits);
            let even = &odd + 1u8;
            assert_eq!(pow_mod(&b, &e, &odd), Some(b.modpow(&e, &odd)));
            assert_eq!(pow_mod(&b, &e, &even), Some(b.modpow(&e, &even)));
            assert_eq!(pow_mod(&b, &BigUint::zero(), &even), Some(BigUint::one()));
        }
        let two = BigUint::from(2u8);
        assert_eq!(pow_mod(&BigUint::from(3u8), &e, &two), Some(BigUint::one()));
    }
}
