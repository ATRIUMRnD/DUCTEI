//! Sampled stand-in for the `kani` crate, so every proof harness also runs
//! under plain `cargo test` (including on Windows, where Kani doesn't run).
//!
//! This is NOT verification. It draws random inputs, biased toward edge
//! values (0, 1, MAX, MAX-1, small lengths, delimiter bytes). Only
//! `cargo kani`, which swaps in the real crate, checks every input within
//! a harness's bounds. Shared by ductei-core and ductei-qallow via #[path].
#![allow(dead_code)]

use std::cell::Cell;

thread_local! {
    static RNG: Cell<u64> = const { Cell::new(0x9E37_79B9_7F4A_7C15) };
}

fn next() -> u64 {
    RNG.with(|r| {
        let mut x = r.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        r.set(x);
        x
    })
}

fn edge(max: u64) -> u64 {
    match next() % 8 {
        0 => 0,
        1 => 1,
        2 => max,
        3 => max - 1,
        4 | 5 => next() % 16,
        _ => next() & max,
    }
}

/// Marker payload for a rejected sample. Raised with `resume_unwind`, which
/// skips the panic hook, so rejected samples print nothing.
pub struct AssumeViolated;

pub fn assume(cond: bool) {
    if !cond {
        std::panic::resume_unwind(Box::new(AssumeViolated));
    }
}

pub trait Arbitrary {
    fn any() -> Self;
}

pub fn any<T: Arbitrary>() -> T {
    T::any()
}

impl Arbitrary for bool {
    fn any() -> Self { next() & 1 == 1 }
}
impl Arbitrary for u8 {
    fn any() -> Self {
        const INTERESTING: &[u8] = b",|a\0\x01\x02\x03\x7f\x80\xff";
        if next() % 4 == 0 {
            INTERESTING[(next() % INTERESTING.len() as u64) as usize]
        } else {
            next() as u8
        }
    }
}
impl Arbitrary for u16 {
    fn any() -> Self { edge(u16::MAX as u64) as u16 }
}
impl Arbitrary for u32 {
    fn any() -> Self { edge(u32::MAX as u64) as u32 }
}
impl Arbitrary for u64 {
    fn any() -> Self { edge(u64::MAX) }
}
impl Arbitrary for usize {
    fn any() -> Self { edge(usize::MAX as u64) as usize }
}
impl<T: Arbitrary> Arbitrary for Option<T> {
    fn any() -> Self { if bool::any() { Some(T::any()) } else { None } }
}
impl<T: Arbitrary, const N: usize> Arbitrary for [T; N] {
    fn any() -> Self { std::array::from_fn(|_| T::any()) }
}

/// Run `harness` on `samples` random draws. Samples rejected by `assume`
/// are skipped; any other panic (a failed assertion) fails the test.
pub fn run(harness: fn(), samples: usize) {
    let mut checked = 0usize;
    for _ in 0..samples {
        match std::panic::catch_unwind(harness) {
            Ok(()) => checked += 1,
            Err(p) if p.is::<AssumeViolated>() => {}
            Err(p) => std::panic::resume_unwind(p),
        }
    }
    assert!(checked > samples / 100, "only {checked}/{samples} samples passed `assume`");
}
