//! Performance regression guard for the password-crack hot path.
//!
//! steghide / stegseek check the file "magic" for every candidate passphrase
//! using a fixed buffer that the C++ keeps on the stack (`UWORD32 rngBuf[25 *
//! samplesPerVertex]`). An early version of this Rust port heap-allocated that
//! buffer (`vec![0u32; 25 * spv]`) on EVERY call — a malloc/free per passphrase
//! that made the cracker ~1.8x slower than it needed to be (and slower than the
//! C++ original). This test pins the buffer to the stack: a counting global
//! allocator asserts that `verify_magic_seed` performs ZERO heap allocations
//! across 100k calls. If someone reintroduces a per-passphrase allocation, this
//! fails loudly.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct CountingAlloc;
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

use stegseek_core::crack::Cracker;
use stegseek_core::format::read_file;

fn stego(name: &str) -> String {
    format!(
        "{}/../../tests/data/stego/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

#[test]
fn verify_magic_seed_is_allocation_free() {
    // Setup (reading the file + building the Cracker) is allowed to allocate;
    // we only measure the steady-state hot loop afterwards.
    let file = read_file(&stego("none.jpg")).expect("read none.jpg");
    let cracker = Cracker::new(&*file);
    // Warm up once so any one-time lazy initialisation is excluded.
    black_box(cracker.verify_magic_seed(1));

    let before = ALLOCS.load(Ordering::Relaxed);
    let mut hits = 0u64;
    for seed in 0u32..100_000 {
        if black_box(cracker.verify_magic_seed(black_box(seed))) {
            hits += 1;
        }
    }
    black_box(hits);
    let allocs = ALLOCS.load(Ordering::Relaxed) - before;

    assert_eq!(
        allocs, 0,
        "verify_magic_seed heap-allocated {allocs} time(s) over 100k calls \
         (expected 0 — the collision buffer must stay on the stack)"
    );
}
