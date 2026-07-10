//! Real CUDA Driver-API backend via `dlopen` of the driver library
//! (`nvcuda.dll` on Windows, `libcuda.so.1` on Linux). No CUDA toolkit needed —
//! the `cu*` signatures are declared by hand. The same calls were proven on an
//! RTX 3070; this wraps them behind the [`Backend`] trait.
//!
//! Context affinity: the CUDA context becomes current on the thread that calls
//! `cuCtxCreate`. The host runs one [`serve`](super::serve) loop per connection
//! on a single thread, and `ctx_create` is invoked on that thread, so all later
//! calls on the connection see the right current context.

use super::{Backend, CuResult};
use libloading::{Library, Symbol};
use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};

#[cfg(windows)]
const CUDA_LIB: &str = "nvcuda.dll";
#[cfg(target_os = "linux")]
const CUDA_LIB: &str = "libcuda.so.1";
#[cfg(target_os = "macos")]
const CUDA_LIB: &str = "libcuda.dylib"; // not expected to exist; macOS has no CUDA

type CuResultCode = c_int;

/// Hand-declared driver entry points. Stored as `'static` fn pointers; `_lib`
/// keeps the library mapped for as long as the backend lives.
pub struct GpuBackend {
    _lib: Library,
    init: unsafe extern "C" fn(c_uint) -> CuResultCode,
    device_get_count: unsafe extern "C" fn(*mut c_int) -> CuResultCode,
    device_get_name: unsafe extern "C" fn(*mut c_char, c_int, c_int) -> CuResultCode,
    device_total_mem: unsafe extern "C" fn(*mut usize, c_int) -> CuResultCode,
    driver_get_version: unsafe extern "C" fn(*mut c_int) -> CuResultCode,
    device_get_attribute: unsafe extern "C" fn(*mut c_int, c_int, c_int) -> CuResultCode,
    device_get_uuid: unsafe extern "C" fn(*mut u8, c_int) -> CuResultCode,
    ctx_create: unsafe extern "C" fn(*mut *mut c_void, c_uint, c_int) -> CuResultCode,
    ctx_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    ctx_set_current: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    primary_ctx_retain: unsafe extern "C" fn(*mut *mut c_void, c_int) -> CuResultCode,
    primary_ctx_release: unsafe extern "C" fn(c_int) -> CuResultCode,
    module_load_data: unsafe extern "C" fn(*mut *mut c_void, *const c_void) -> CuResultCode,
    module_get_function:
        unsafe extern "C" fn(*mut *mut c_void, *mut c_void, *const c_char) -> CuResultCode,
    module_unload: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    /// `cuFuncGetParamInfo` — CUDA 12.4+. `None` on older drivers, where
    /// [`Backend::func_get_param_info`] reports `CUDA_ERROR_NOT_SUPPORTED`.
    func_get_param_info:
        Option<unsafe extern "C" fn(*mut c_void, usize, *mut usize, *mut usize) -> CuResultCode>,
    mem_alloc: unsafe extern "C" fn(*mut u64, usize) -> CuResultCode,
    mem_free: unsafe extern "C" fn(u64) -> CuResultCode,
    memcpy_htod: unsafe extern "C" fn(u64, *const c_void, usize) -> CuResultCode,
    memcpy_dtoh: unsafe extern "C" fn(*mut c_void, u64, usize) -> CuResultCode,
    memcpy_dtod: unsafe extern "C" fn(u64, u64, usize) -> CuResultCode,
    memset_d8: unsafe extern "C" fn(u64, u8, usize) -> CuResultCode,
    mem_get_info: unsafe extern "C" fn(*mut usize, *mut usize) -> CuResultCode,
    #[allow(clippy::type_complexity)]
    launch_kernel: unsafe extern "C" fn(
        *mut c_void,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> CuResultCode,
    ctx_synchronize: unsafe extern "C" fn() -> CuResultCode,
    stream_create: unsafe extern "C" fn(*mut *mut c_void, c_uint) -> CuResultCode,
    stream_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    stream_synchronize: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    event_create: unsafe extern "C" fn(*mut *mut c_void, c_uint) -> CuResultCode,
    event_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    event_record: unsafe extern "C" fn(*mut c_void, *mut c_void) -> CuResultCode,
    event_synchronize: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    event_elapsed_time: unsafe extern "C" fn(*mut f32, *mut c_void, *mut c_void) -> CuResultCode,
}

unsafe fn sym<T>(lib: &Library, name: &[u8]) -> Result<T, String> {
    let s: Symbol<T> = lib
        .get(name)
        .map_err(|e| format!("symbol {}: {e}", String::from_utf8_lossy(name)))?;
    // Transmute the borrowed Symbol into a bare fn pointer; `_lib` in the
    // struct keeps the library loaded for the pointer's whole lifetime.
    Ok(std::ptr::read(&s as *const Symbol<T> as *const T))
}

/// Resolve `primary`, falling back to `fallback` — for entry points whose
/// canonical name gained a `_v2` suffix in a later CUDA release.
unsafe fn sym2<T>(lib: &Library, primary: &[u8], fallback: &[u8]) -> Result<T, String> {
    sym(lib, primary).or_else(|_| sym(lib, fallback))
}

impl GpuBackend {
    /// Load the driver and resolve every entry point. Returns the library name
    /// + error string on failure so the caller can fall back (e.g. to CPU).
    pub fn load() -> Result<GpuBackend, String> {
        unsafe {
            let lib = Library::new(CUDA_LIB).map_err(|e| format!("load {CUDA_LIB}: {e}"))?;
            let b = GpuBackend {
                init: sym(&lib, b"cuInit\0")?,
                device_get_count: sym(&lib, b"cuDeviceGetCount\0")?,
                device_get_name: sym(&lib, b"cuDeviceGetName\0")?,
                device_total_mem: sym(&lib, b"cuDeviceTotalMem_v2\0")?,
                driver_get_version: sym(&lib, b"cuDriverGetVersion\0")?,
                device_get_attribute: sym(&lib, b"cuDeviceGetAttribute\0")?,
                device_get_uuid: sym2(&lib, b"cuDeviceGetUuid_v2\0", b"cuDeviceGetUuid\0")?,
                ctx_create: sym(&lib, b"cuCtxCreate_v2\0")?,
                ctx_destroy: sym(&lib, b"cuCtxDestroy_v2\0")?,
                ctx_set_current: sym(&lib, b"cuCtxSetCurrent\0")?,
                primary_ctx_retain: sym(&lib, b"cuDevicePrimaryCtxRetain\0")?,
                primary_ctx_release: sym2(
                    &lib,
                    b"cuDevicePrimaryCtxRelease_v2\0",
                    b"cuDevicePrimaryCtxRelease\0",
                )?,
                module_load_data: sym(&lib, b"cuModuleLoadData\0")?,
                module_get_function: sym(&lib, b"cuModuleGetFunction\0")?,
                module_unload: sym(&lib, b"cuModuleUnload\0")?,
                func_get_param_info: sym(&lib, b"cuFuncGetParamInfo\0").ok(),
                mem_alloc: sym(&lib, b"cuMemAlloc_v2\0")?,
                mem_free: sym(&lib, b"cuMemFree_v2\0")?,
                memcpy_htod: sym(&lib, b"cuMemcpyHtoD_v2\0")?,
                memcpy_dtoh: sym(&lib, b"cuMemcpyDtoH_v2\0")?,
                memcpy_dtod: sym(&lib, b"cuMemcpyDtoD_v2\0")?,
                memset_d8: sym(&lib, b"cuMemsetD8_v2\0")?,
                mem_get_info: sym(&lib, b"cuMemGetInfo_v2\0")?,
                launch_kernel: sym(&lib, b"cuLaunchKernel\0")?,
                ctx_synchronize: sym(&lib, b"cuCtxSynchronize\0")?,
                stream_create: sym(&lib, b"cuStreamCreate\0")?,
                stream_destroy: sym2(&lib, b"cuStreamDestroy_v2\0", b"cuStreamDestroy\0")?,
                stream_synchronize: sym(&lib, b"cuStreamSynchronize\0")?,
                event_create: sym(&lib, b"cuEventCreate\0")?,
                event_destroy: sym2(&lib, b"cuEventDestroy_v2\0", b"cuEventDestroy\0")?,
                event_record: sym(&lib, b"cuEventRecord\0")?,
                event_synchronize: sym(&lib, b"cuEventSynchronize\0")?,
                event_elapsed_time: sym(&lib, b"cuEventElapsedTime\0")?,
                _lib: lib,
            };
            Ok(b)
        }
    }
}

/// Map a raw `CUresult`: 0 → `Ok`, else the code as `Err`.
fn chk(code: CuResultCode) -> CuResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(code)
    }
}

impl Backend for GpuBackend {
    fn init(&mut self) -> CuResult<()> {
        unsafe { chk((self.init)(0)) }
    }
    fn device_get_count(&mut self) -> CuResult<i32> {
        let mut n = 0;
        unsafe { chk((self.device_get_count)(&mut n))? };
        Ok(n)
    }
    fn device_get_name(&mut self, device: i32) -> CuResult<String> {
        let mut buf = [0i8; 256];
        unsafe {
            chk((self.device_get_name)(
                buf.as_mut_ptr() as *mut c_char,
                256,
                device,
            ))?
        };
        let name = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned();
        Ok(name)
    }
    fn device_total_mem(&mut self, device: i32) -> CuResult<u64> {
        let mut bytes: usize = 0;
        unsafe { chk((self.device_total_mem)(&mut bytes, device))? };
        Ok(bytes as u64)
    }
    fn driver_get_version(&mut self) -> CuResult<i32> {
        let mut v = 0;
        unsafe { chk((self.driver_get_version)(&mut v))? };
        Ok(v)
    }
    fn device_get_attribute(&mut self, attrib: i32, device: i32) -> CuResult<i32> {
        let mut v = 0;
        unsafe { chk((self.device_get_attribute)(&mut v, attrib, device))? };
        Ok(v)
    }
    fn device_get_uuid(&mut self, device: i32) -> CuResult<[u8; 16]> {
        let mut uuid = [0u8; 16];
        unsafe { chk((self.device_get_uuid)(uuid.as_mut_ptr(), device))? };
        Ok(uuid)
    }
    fn ctx_create(&mut self, device: i32) -> CuResult<u64> {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.ctx_create)(&mut ctx, 0, device))? };
        Ok(ctx as u64)
    }
    fn ctx_destroy(&mut self, ctx: u64) -> CuResult<()> {
        unsafe { chk((self.ctx_destroy)(ctx as *mut c_void)) }
    }
    fn primary_ctx_retain(&mut self, device: i32) -> CuResult<u64> {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.primary_ctx_retain)(&mut ctx, device))? };
        // Unlike cuCtxCreate, retain does not bind the context to the calling
        // thread — bind it here so every later call on this connection's
        // serving thread (module load, alloc, launch) has a current context.
        unsafe { chk((self.ctx_set_current)(ctx))? };
        Ok(ctx as u64)
    }
    fn primary_ctx_release(&mut self, device: i32) -> CuResult<()> {
        unsafe { chk((self.primary_ctx_release)(device)) }
    }
    fn module_load_data(&mut self, image: &[u8]) -> CuResult<u64> {
        // cuModuleLoadData reads a NUL-terminated PTX string or a cubin blob.
        // Ensure a trailing NUL so PTX text is well-formed for the JIT.
        let mut buf = image.to_vec();
        if !buf.ends_with(&[0]) {
            buf.push(0);
        }
        let mut module: *mut c_void = std::ptr::null_mut();
        unsafe {
            chk((self.module_load_data)(
                &mut module,
                buf.as_ptr() as *const c_void,
            ))?
        };
        Ok(module as u64)
    }
    fn module_get_function(&mut self, module: u64, name: &str) -> CuResult<u64> {
        let cname = CString::new(name).map_err(|_| super::CUDA_ERROR_NOT_FOUND)?;
        let mut func: *mut c_void = std::ptr::null_mut();
        unsafe {
            chk((self.module_get_function)(
                &mut func,
                module as *mut c_void,
                cname.as_ptr(),
            ))?
        };
        Ok(func as u64)
    }
    fn module_unload(&mut self, module: u64) -> CuResult<()> {
        unsafe { chk((self.module_unload)(module as *mut c_void)) }
    }
    fn func_get_param_info(&mut self, function: u64) -> CuResult<Vec<u32>> {
        // CUDA 12.4+. Walk parameter indices until INVALID_VALUE marks the end.
        const CUDA_ERROR_INVALID_VALUE: i32 = 1;
        const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;
        let f = self.func_get_param_info.ok_or(CUDA_ERROR_NOT_SUPPORTED)?;
        let mut sizes = Vec::new();
        for i in 0.. {
            let (mut offset, mut size): (usize, usize) = (0, 0);
            let code = unsafe { f(function as *mut c_void, i, &mut offset, &mut size) };
            match code {
                0 => sizes.push(size as u32),
                CUDA_ERROR_INVALID_VALUE => break,
                other => return Err(other),
            }
        }
        Ok(sizes)
    }
    fn mem_alloc(&mut self, bytes: u64) -> CuResult<u64> {
        let mut dptr: u64 = 0;
        unsafe { chk((self.mem_alloc)(&mut dptr, bytes as usize))? };
        Ok(dptr)
    }
    fn mem_free(&mut self, dptr: u64) -> CuResult<()> {
        unsafe { chk((self.mem_free)(dptr)) }
    }
    fn memcpy_htod(&mut self, dptr: u64, data: &[u8]) -> CuResult<()> {
        unsafe {
            chk((self.memcpy_htod)(
                dptr,
                data.as_ptr() as *const c_void,
                data.len(),
            ))
        }
    }
    fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64) -> CuResult<Vec<u8>> {
        let mut out = vec![0u8; bytes as usize];
        unsafe {
            chk((self.memcpy_dtoh)(
                out.as_mut_ptr() as *mut c_void,
                dptr,
                bytes as usize,
            ))?
        };
        Ok(out)
    }
    fn memcpy_dtod(&mut self, dst: u64, src: u64, bytes: u64) -> CuResult<()> {
        unsafe { chk((self.memcpy_dtod)(dst, src, bytes as usize)) }
    }
    fn memset_d8(&mut self, dptr: u64, value: u8, bytes: u64) -> CuResult<()> {
        unsafe { chk((self.memset_d8)(dptr, value, bytes as usize)) }
    }
    fn mem_get_info(&mut self) -> CuResult<(u64, u64)> {
        let (mut free, mut total): (usize, usize) = (0, 0);
        unsafe { chk((self.mem_get_info)(&mut free, &mut total))? };
        Ok((free as u64, total as u64))
    }
    fn launch_kernel(
        &mut self,
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: &[Vec<u8>],
    ) -> CuResult<()> {
        // The Driver API wants `void* kernelParams[]`, each pointing at one
        // argument's value. Point at each param blob in place (CUDA only reads).
        let mut ptrs: Vec<*mut c_void> = params.iter().map(|p| p.as_ptr() as *mut c_void).collect();
        let params_ptr = if ptrs.is_empty() {
            std::ptr::null_mut()
        } else {
            ptrs.as_mut_ptr()
        };
        unsafe {
            chk((self.launch_kernel)(
                function as *mut c_void,
                grid[0],
                grid[1],
                grid[2],
                block[0],
                block[1],
                block[2],
                shared_bytes,
                stream as *mut c_void,
                params_ptr,
                std::ptr::null_mut(),
            ))
        }
    }
    fn ctx_synchronize(&mut self) -> CuResult<()> {
        unsafe { chk((self.ctx_synchronize)()) }
    }
    fn stream_create(&mut self, flags: u32) -> CuResult<u64> {
        let mut s: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.stream_create)(&mut s, flags))? };
        Ok(s as u64)
    }
    fn stream_destroy(&mut self, stream: u64) -> CuResult<()> {
        unsafe { chk((self.stream_destroy)(stream as *mut c_void)) }
    }
    fn stream_synchronize(&mut self, stream: u64) -> CuResult<()> {
        unsafe { chk((self.stream_synchronize)(stream as *mut c_void)) }
    }
    fn event_create(&mut self, flags: u32) -> CuResult<u64> {
        let mut e: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.event_create)(&mut e, flags))? };
        Ok(e as u64)
    }
    fn event_destroy(&mut self, event: u64) -> CuResult<()> {
        unsafe { chk((self.event_destroy)(event as *mut c_void)) }
    }
    fn event_record(&mut self, event: u64, stream: u64) -> CuResult<()> {
        unsafe {
            chk((self.event_record)(
                event as *mut c_void,
                stream as *mut c_void,
            ))
        }
    }
    fn event_synchronize(&mut self, event: u64) -> CuResult<()> {
        unsafe { chk((self.event_synchronize)(event as *mut c_void)) }
    }
    fn event_elapsed_time(&mut self, start: u64, end: u64) -> CuResult<f32> {
        let mut ms: f32 = 0.0;
        unsafe {
            chk((self.event_elapsed_time)(
                &mut ms,
                start as *mut c_void,
                end as *mut c_void,
            ))?
        };
        Ok(ms)
    }
}
