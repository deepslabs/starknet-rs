#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

#[cfg(all(not(feature = "std"), any(test, feature = "alloc")))]
extern crate alloc;

#[cfg(all(
    target_arch = "wasm32",
    not(feature = "std"),
    feature = "alloc"
))]
mod wasm_runtime {
    use core::alloc::{GlobalAlloc, Layout};
    use core::arch::wasm32;

    /// Allocator that delegates to the host's Substrate allocator interface.
    struct SubstrateWasmAllocator;

    unsafe impl GlobalAlloc for SubstrateWasmAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // Try the Substrate host allocator (v1), falling back to a static
            // bump area for standalone use.
            let size = layout.size() as u32;
            // Allocate from the heap base region exported to the host.
            // The host provides memory from __heap_base onwards.
            // We use a minimal approach: the wasm executor is expected to
            // provide ext_allocator_malloc/free host functions.
            extern "C" {
                fn ext_allocator_malloc_version_1(size: u32) -> u32;
            }
            ext_allocator_malloc_version_1(size) as *mut u8
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            extern "C" {
                fn ext_allocator_free_version_1(addr: u32);
            }
            ext_allocator_free_version_1(ptr as u32);
        }
    }

    #[global_allocator]
    static ALLOCATOR: SubstrateWasmAllocator = SubstrateWasmAllocator;

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        wasm32::unreachable()
    }
}

mod ecdsa;
mod error;
mod fe_utils;
mod pedersen_hash;
mod pedersen_points;
mod poseidon_hash;
mod rfc6979;

#[cfg(test)]
mod test_utils;

pub use starknet_ff::FieldElement;

pub use pedersen_hash::pedersen_hash;

pub use poseidon_hash::{
    poseidon_hash, poseidon_hash_many, poseidon_hash_single, poseidon_permute_comp, PoseidonHasher,
};

pub use ecdsa::{get_public_key, recover, sign, verify, ExtendedSignature, Signature};

pub use crate::rfc6979::generate_k as rfc6979_generate_k;

pub use error::{RecoverError, SignError, VerifyError};
