use std::vec::Vec;

use log::debug;

pub const E: usize = 16;
pub const D: usize = E + 1;
pub const N: usize = 1 << E as usize;
const INDEX_MASK: usize = N - 1;

pub const ABSOLUTE_SPEEDUP_UPPERBOUND: usize = E * (1 << (E - 1)) * E + (N / 2) - 1;
const DESIRED_SPEEDUP_RATIO: usize = 2;
const STEPS_LOWERBOUND: usize = DESIRED_SPEEDUP_RATIO * ABSOLUTE_SPEEDUP_UPPERBOUND;
pub const SIZE: usize = (STEPS_LOWERBOUND + (E - 1)) / E;

pub type Fragment = u64;
pub const BLOCK_BYTE_SIZE: usize = N * 8;

pub const GROUP_SIZE: usize = 4;
pub const GROUP_BYTE_SIZE: usize = BLOCK_BYTE_SIZE * GROUP_SIZE;
pub type FragmentGroup = [Fragment; GROUP_SIZE];

pub type BlockGroup = Vec<FragmentGroup>;

pub const INIT_SIZE_EXP: usize = 2;
pub const INIT_SIZE: usize = 1 << INIT_SIZE_EXP;
pub const INIT_MASK: usize = INIT_SIZE - 1;
pub type InitGroup = [FragmentGroup; INIT_SIZE];

/// Core memory-hard block generation function.
/// Ported as-is from the thesis (with AVX2 SIMD support).
pub fn block_gen(inits: InitGroup) -> BlockGroup {
    if is_x86_feature_detected!("avx2") {
        debug!("AVX2 activated");
        unsafe { block_gen_avx2(inits) }
    } else {
        debug!("AVX2 NOT activated");
        block_gen_inner(inits)
    }
}

#[target_feature(enable = "avx2")]
unsafe fn block_gen_avx2(inits: InitGroup) -> BlockGroup {
    block_gen_inner(inits)
}

#[inline(always)]
fn block_gen_inner(inits: InitGroup) -> BlockGroup {
    let mut block: BlockGroup = vec![[0; GROUP_SIZE]; N as usize];

    let start = N - (SIZE % N);

    let mut from = 0;
    let mut last: FragmentGroup = inits[0];
    for k in 0..D {
        let to = 1 << k;
        for i in from..to {
            let index = (i + start) & INDEX_MASK;
            let init = inits[(i + start) & INIT_MASK];
            let mut next_fragment = last;
            for j in 1..k {
                let jump = 1 << j;
                let target = (index + N - jump) & INDEX_MASK;
                let x = block[target];
                if (j & 1) == 1 {
                    next_fragment = add(next_fragment, x);
                } else {
                    next_fragment = xor(next_fragment, x);
                }
            }
            for j in k..D {
                if (j & 1) == 1 {
                    next_fragment = add(next_fragment, init);
                } else {
                    next_fragment = xor(next_fragment, init);
                }
            }
            last = rot(next_fragment);
            block[index] = last;
        }
        from = to;
    }
    for i in N..SIZE {
        let index = (i + start) % N;
        let mut next_fragment = last;
        for j in 1..D {
            let jump = 1 << j;
            let target = (index + N - jump) & INDEX_MASK;
            let x = block[target];
            if (j & 1) == 1 {
                next_fragment = add(next_fragment, x);
            } else {
                next_fragment = xor(next_fragment, x);
            }
        }
        last = rot(next_fragment);
        block[index] = last;
    }
    block
}

#[inline(always)]
fn add(a: FragmentGroup, b: FragmentGroup) -> FragmentGroup {
    let mut c: FragmentGroup = [0; GROUP_SIZE];
    for i in 0..GROUP_SIZE {
        c[i] = a[i].wrapping_add(b[i]);
    }
    c
}

#[inline(always)]
fn xor(a: FragmentGroup, b: FragmentGroup) -> FragmentGroup {
    let mut c: FragmentGroup = [0; GROUP_SIZE];
    for i in 0..GROUP_SIZE {
        c[i] = a[i] ^ b[i];
    }
    c
}

#[inline(always)]
fn rot(a: FragmentGroup) -> FragmentGroup {
    let mut b: FragmentGroup = [0; GROUP_SIZE];
    for i in 0..GROUP_SIZE {
        b[i] = a[i].rotate_left(19);
    }
    b
}
