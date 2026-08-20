//! Port of `Selector` (`Selector.cc` / `.h`) — a random permutation of a
//! random combination, driven by the steghide LCG. This determines the order
//! in which samples are visited for embedding/extraction, so it must reproduce
//! the original byte-for-byte.

use crate::rng::{passphrase_seed, PseudoRandomSource};
use std::collections::HashMap;

pub struct Selector {
    x: Vec<u32>,
    y: Vec<u32>,
    xreversed: HashMap<u32, u32>,
    maximum: u32,
    num_in_array: u32,
    prandom: Option<PseudoRandomSource>,
}

impl Selector {
    /// Construct from a passphrase (seed = MD5-fold of the passphrase).
    pub fn from_passphrase(m: u32, passphrase: &[u8]) -> Self {
        Selector::from_seed(m, passphrase_seed(passphrase))
    }

    /// Construct from an explicit 32-bit seed.
    pub fn from_seed(m: u32, seed: u32) -> Self {
        Selector {
            x: Vec::new(),
            y: Vec::new(),
            xreversed: HashMap::new(),
            maximum: m,
            num_in_array: 0,
            prandom: Some(PseudoRandomSource::new(seed)),
        }
    }

    /// Identity permutation with range `m` (`(*this)[i] == i`).
    pub fn identity(m: u32) -> Self {
        Selector {
            x: (0..m).collect(),
            y: Vec::new(),
            xreversed: HashMap::new(),
            maximum: m,
            num_in_array: m,
            prandom: None,
        }
    }

    /// Selector returning predefined values; `maximum` is `retvals.len()`.
    pub fn from_values(retvals: Vec<u32>) -> Self {
        let n = retvals.len() as u32;
        Selector {
            x: retvals,
            y: Vec::new(),
            xreversed: HashMap::new(),
            maximum: n,
            num_in_array: n,
            prandom: None,
        }
    }

    pub fn range(&self) -> u32 {
        self.maximum
    }

    /// Value at position `i` (mirrors `operator[]`).
    pub fn at(&mut self, i: u32) -> u32 {
        assert!(i < self.maximum);
        self.calculate(i + 1);
        self.x[i as usize]
    }

    /// Fill `x`, `y` and `xreversed` up to (but not including) index `m`.
    fn calculate(&mut self, m: u32) {
        let mut j = self.num_in_array;

        if m > self.num_in_array {
            self.num_in_array = m;
            if self.num_in_array as usize > self.x.len() {
                self.x.resize(self.num_in_array as usize, 0);
                self.y.resize(self.num_in_array as usize, 0);
            }
        }

        while j < m {
            // k is a number from {j, ..., Maximum-1}
            let range = self.maximum - j;
            let k = j + self
                .prandom
                .as_mut()
                .expect("Selector without a PRNG cannot calculate new positions")
                .get_value(range);

            let mut i = 0u32;
            if self.idx_x(k, j, &mut i) {
                // there exists i < j with X[i] = k -> use Y[i] instead of k
                let yi = self.y[i as usize];
                self.set_x(j, yi);

                if self.x[j as usize] > j {
                    self.y[j as usize] = j;
                }
                if self.x[i as usize] > j {
                    self.y[i as usize] = j;
                    let mut l = 0u32;
                    let yi_now = self.y[i as usize];
                    if self.idx_x(yi_now, j, &mut l) {
                        self.y[i as usize] = self.y[l as usize];
                    }
                }
            } else {
                self.set_x(j, k);
                self.y[j as usize] = j;
            }

            if self.x[j as usize] > j {
                let mut i2 = 0u32;
                let yj = self.y[j as usize];
                if self.idx_x(yj, j, &mut i2) {
                    self.y[j as usize] = self.y[i2 as usize];
                }
            }

            j += 1;
        }
    }

    /// Find an index `i` with `0 <= i < m` and `X[i] == v`.
    fn idx_x(&self, v: u32, m: u32, p: &mut u32) -> bool {
        if let Some(&idx) = self.xreversed.get(&v) {
            if idx < m {
                *p = idx;
                return true;
            }
        }
        false
    }

    fn set_x(&mut self, i: u32, v: u32) {
        self.x[i as usize] = v;
        self.xreversed.insert(v, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn assert_is_permutation(sel: &mut Selector, m: u32) {
        let mut seen = HashSet::new();
        for i in 0..m {
            let v = sel.at(i);
            assert!(v < m, "value {v} out of range {m}");
            assert!(
                seen.insert(v),
                "value {v} produced twice — not a permutation"
            );
        }
        assert_eq!(seen.len() as u32, m);
    }

    #[test]
    fn seed_selector_is_permutation() {
        for seed in [0u32, 1, 42, 0xDEAD_BEEF, 0xFFFF_FFFF] {
            let mut sel = Selector::from_seed(1000, seed);
            assert_is_permutation(&mut sel, 1000);
        }
    }

    #[test]
    fn passphrase_selector_is_permutation() {
        let mut sel = Selector::from_passphrase(2000, b"hunter2");
        assert_is_permutation(&mut sel, 2000);
    }

    #[test]
    fn identity_selector() {
        let mut sel = Selector::identity(50);
        for i in 0..50 {
            assert_eq!(sel.at(i), i);
        }
    }

    #[test]
    fn deterministic_same_seed() {
        let mut a = Selector::from_seed(500, 12345);
        let mut b = Selector::from_seed(500, 12345);
        for i in 0..500 {
            assert_eq!(a.at(i), b.at(i));
        }
    }

    #[test]
    fn incremental_matches_direct() {
        // Accessing in order must match accessing a fresh selector at each index.
        let mut seq = Selector::from_seed(300, 999);
        let in_order: Vec<u32> = (0..300).map(|i| seq.at(i)).collect();
        for &idx in &[0u32, 7, 42, 100, 299] {
            let mut fresh = Selector::from_seed(300, 999);
            assert_eq!(fresh.at(idx), in_order[idx as usize]);
        }
    }
}
