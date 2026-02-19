//! FFI to CUDA keyhunt C API. Build with feature "cuda" and link keyhunt_cuda_capi + ecc_cuda.

#![allow(non_camel_case_types)]

use crate::hash160::Hash160;
use crate::results::Hash160SearchResult;
use std::ffi::CStr;

#[repr(C)]
pub struct KeyhuntHash160 {
    pub h: [u32; 5],
}

#[repr(C)]
#[derive(Clone)]
pub struct KeyhuntSearchResult {
    pub cuda_device_id: i32,
    pub thread_id: u32,
    pub block_id: u32,
    pub idx: u32,
    pub compressed: bool,
    pub digest: [u32; 5],
    pub iteration: u32,
    pub private_x_part: u32,
    pub private_y_part: u32,
    pub private_key: [u32; 8],
}

// ecc_cuda линкуется в build.rs с --whole-archive (полный путь к .a), не здесь
#[link(name = "keyhunt_cuda_capi")]
#[link(name = "cudart_static")]
#[link(name = "stdc++")]
extern "C" {
    fn keyhunt_init(device_id: i32) -> *mut std::ffi::c_void;
    fn keyhunt_set_params(
        h: *mut std::ffi::c_void,
        points_per_thread: u32,
        compression_type: u32,
        grid_size: u32,
        block_size: u32,
    ) -> i32;
    fn keyhunt_set_targets(h: *mut std::ffi::c_void, targets: *const KeyhuntHash160, count: usize) -> i32;
    fn keyhunt_prepare(h: *mut std::ffi::c_void) -> i32;
    fn keyhunt_keys_per_iteration(h: *mut std::ffi::c_void) -> u32;
    fn keyhunt_run_iteration(h: *mut std::ffi::c_void, private_x_part: u32, iteration: u32) -> i32;
    fn keyhunt_get_results(
        h: *mut std::ffi::c_void,
        out_results: *mut KeyhuntSearchResult,
        max_count: u32,
        iteration: u32,
        private_x_part: u32,
    ) -> u32;
    fn keyhunt_destroy(h: *mut std::ffi::c_void);
    fn keyhunt_device_count() -> i32;
    fn keyhunt_last_error() -> *const i8;

    // --- Double-buffer pipeline API ---
    fn keyhunt_pregenerate_keys(h: *mut std::ffi::c_void, private_x_part: u32, iteration: u32) -> i32;
    fn keyhunt_launch_kernel(h: *mut std::ffi::c_void) -> i32;
    fn keyhunt_sync_and_get_results(
        h: *mut std::ffi::c_void,
        out_results: *mut KeyhuntSearchResult,
        max_count: u32,
        iteration: u32,
        private_x_part: u32,
    ) -> u32;
}

pub struct KeyhuntHandle {
    ptr: *mut std::ffi::c_void,
    device_id: i32,
}

impl KeyhuntHandle {
    pub fn init(device_id: i32) -> Result<Self, crate::Error> {
        let ptr = unsafe { keyhunt_init(device_id) };
        if ptr.is_null() {
            let msg = unsafe { CStr::from_ptr(keyhunt_last_error()).to_string_lossy().into_owned() };
            return Err(crate::Error::Cuda(msg));
        }
        Ok(KeyhuntHandle { ptr, device_id })
    }

    pub fn set_params(
        &self,
        points_per_thread: u32,
        compression_type: u32,
        grid_size: u32,
        block_size: u32,
    ) -> Result<(), crate::Error> {
        let r = unsafe {
            keyhunt_set_params(self.ptr, points_per_thread, compression_type, grid_size, block_size)
        };
        if r != 0 {
            let msg = unsafe { CStr::from_ptr(keyhunt_last_error()).to_string_lossy().into_owned() };
            return Err(crate::Error::Cuda(msg));
        }
        Ok(())
    }

    pub fn set_targets(&self, targets: &[Hash160]) -> Result<(), crate::Error> {
        let raw: Vec<KeyhuntHash160> = targets.iter().map(|h| KeyhuntHash160 { h: h.to_words() }).collect();
        let r = unsafe { keyhunt_set_targets(self.ptr, raw.as_ptr(), raw.len()) };
        if r != 0 {
            let msg = unsafe { CStr::from_ptr(keyhunt_last_error()).to_string_lossy().into_owned() };
            return Err(crate::Error::Cuda(msg));
        }
        Ok(())
    }

    pub fn prepare(&self) -> Result<(), crate::Error> {
        let r = unsafe { keyhunt_prepare(self.ptr) };
        if r != 0 {
            let msg = unsafe { CStr::from_ptr(keyhunt_last_error()).to_string_lossy().into_owned() };
            return Err(crate::Error::Cuda(msg));
        }
        Ok(())
    }

    pub fn keys_per_iteration(&self) -> u32 {
        unsafe { keyhunt_keys_per_iteration(self.ptr) }
    }

    pub fn run_iteration(&self, private_x_part: u32, iteration: u32) -> Result<(), crate::Error> {
        let r = unsafe { keyhunt_run_iteration(self.ptr, private_x_part, iteration) };
        if r != 0 {
            let msg = unsafe { CStr::from_ptr(keyhunt_last_error()).to_string_lossy().into_owned() };
            return Err(crate::Error::Cuda(msg));
        }
        Ok(())
    }

    pub fn get_results(
        &self,
        out: &mut [KeyhuntSearchResult],
        iteration: u32,
        private_x_part: u32,
    ) -> u32 {
        unsafe { keyhunt_get_results(self.ptr, out.as_mut_ptr(), out.len() as u32, iteration, private_x_part) }
    }

    // --- Double-buffer pipeline API ---

    /// Step 1: start generating private keys for (x, iter) into the staging buffer.
    /// Returns immediately (async GPU op).
    pub fn pregenerate_keys(&self, private_x_part: u32, iteration: u32) -> Result<(), crate::Error> {
        let r = unsafe { keyhunt_pregenerate_keys(self.ptr, private_x_part, iteration) };
        if r != 0 {
            let msg = unsafe { CStr::from_ptr(keyhunt_last_error()).to_string_lossy().into_owned() };
            return Err(crate::Error::Cuda(msg));
        }
        Ok(())
    }

    /// Step 2: sync key-gen, swap buffers, launch hash-check kernel async.
    /// Returns immediately (kernel runs in background).
    pub fn launch_kernel(&self) -> Result<(), crate::Error> {
        let r = unsafe { keyhunt_launch_kernel(self.ptr) };
        if r != 0 {
            let msg = unsafe { CStr::from_ptr(keyhunt_last_error()).to_string_lossy().into_owned() };
            return Err(crate::Error::Cuda(msg));
        }
        Ok(())
    }

    /// Step 3: sync kernel + read results.  Use after launch_kernel.
    pub fn sync_and_get_results(
        &self,
        out: &mut [KeyhuntSearchResult],
        iteration: u32,
        private_x_part: u32,
    ) -> u32 {
        unsafe { keyhunt_sync_and_get_results(self.ptr, out.as_mut_ptr(), out.len() as u32, iteration, private_x_part) }
    }

    pub fn device_id(&self) -> i32 {
        self.device_id
    }
}

impl Drop for KeyhuntHandle {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { keyhunt_destroy(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

pub fn device_count() -> i32 {
    unsafe { keyhunt_device_count() }
}

pub fn keyhunt_search_result_from_c(r: &KeyhuntSearchResult) -> Hash160SearchResult {
    Hash160SearchResult {
        cuda_device_id: r.cuda_device_id,
        private_x_part: r.private_x_part,
        private_y_part: r.private_y_part,
        compressed: r.compressed,
        digest: r.digest,
        private_key: r.private_key,
    }
}
