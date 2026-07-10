//! Wire protocol for CUDA Driver-API remoting over a byte stream (vsock).
//!
//! Framing: every message is a `u32` little-endian length followed by the
//! payload. A request payload is a `u8` opcode then its args; a response payload
//! is an `i32` status (`CUresult`, LE) then return data (present only when
//! `status == 0`). The codec is zero-dependency and transport-agnostic: it
//! operates on any [`Read`]/[`Write`], so the host (AF_UNIX) and guest
//! (AF_VSOCK) share one definition.
//!
//! Handle model: modules, functions and contexts are referred to by opaque
//! `u64` ids minted by the host (so the guest can never forge a host pointer).
//! Device pointers (`CUdeviceptr`) are passed by their real value, because a
//! kernel's launch parameters embed the device address by value — that is how
//! the CUDA Driver API itself works.

use std::io::{self, Read, Write};

/// Maximum accepted message payload (256 MiB) — bounds a hostile/length field.
pub const MAX_MSG: usize = 256 * 1024 * 1024;

/// Request opcodes. Stable wire values — append only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    Init = 0x01,
    DeviceGetCount = 0x02,
    DeviceGetName = 0x03,
    DeviceTotalMem = 0x04,
    DriverGetVersion = 0x05,
    DeviceGetAttribute = 0x06,
    DeviceGetUuid = 0x07,
    CtxCreate = 0x10,
    CtxDestroy = 0x11,
    PrimaryCtxRetain = 0x12,
    PrimaryCtxRelease = 0x13,
    ModuleLoadData = 0x20,
    ModuleGetFunction = 0x21,
    ModuleUnload = 0x22,
    FuncGetParamInfo = 0x23,
    MemAlloc = 0x30,
    MemFree = 0x31,
    MemcpyHtoD = 0x32,
    MemcpyDtoH = 0x33,
    MemcpyDtoD = 0x34,
    MemsetD8 = 0x35,
    MemGetInfo = 0x36,
    LaunchKernel = 0x40,
    CtxSynchronize = 0x50,
    StreamCreate = 0x60,
    StreamDestroy = 0x61,
    StreamSynchronize = 0x62,
    EventCreate = 0x70,
    EventDestroy = 0x71,
    EventRecord = 0x72,
    EventSynchronize = 0x73,
    EventElapsedTime = 0x74,
}

impl Op {
    pub fn from_u8(v: u8) -> Option<Op> {
        Some(match v {
            0x01 => Op::Init,
            0x02 => Op::DeviceGetCount,
            0x03 => Op::DeviceGetName,
            0x04 => Op::DeviceTotalMem,
            0x05 => Op::DriverGetVersion,
            0x06 => Op::DeviceGetAttribute,
            0x07 => Op::DeviceGetUuid,
            0x10 => Op::CtxCreate,
            0x11 => Op::CtxDestroy,
            0x12 => Op::PrimaryCtxRetain,
            0x13 => Op::PrimaryCtxRelease,
            0x20 => Op::ModuleLoadData,
            0x21 => Op::ModuleGetFunction,
            0x22 => Op::ModuleUnload,
            0x23 => Op::FuncGetParamInfo,
            0x30 => Op::MemAlloc,
            0x31 => Op::MemFree,
            0x32 => Op::MemcpyHtoD,
            0x33 => Op::MemcpyDtoH,
            0x34 => Op::MemcpyDtoD,
            0x35 => Op::MemsetD8,
            0x36 => Op::MemGetInfo,
            0x40 => Op::LaunchKernel,
            0x50 => Op::CtxSynchronize,
            0x60 => Op::StreamCreate,
            0x61 => Op::StreamDestroy,
            0x62 => Op::StreamSynchronize,
            0x70 => Op::EventCreate,
            0x71 => Op::EventDestroy,
            0x72 => Op::EventRecord,
            0x73 => Op::EventSynchronize,
            0x74 => Op::EventElapsedTime,
            _ => return None,
        })
    }
}

/// A decoded request. Handles are opaque ids; device pointers are real values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Init,
    DeviceGetCount,
    DeviceGetName {
        device: i32,
    },
    DeviceTotalMem {
        device: i32,
    },
    DriverGetVersion,
    DeviceGetAttribute {
        attrib: i32,
        device: i32,
    },
    DeviceGetUuid {
        device: i32,
    },
    CtxCreate {
        device: i32,
    },
    CtxDestroy {
        ctx: u64,
    },
    PrimaryCtxRetain {
        device: i32,
    },
    PrimaryCtxRelease {
        device: i32,
    },
    ModuleLoadData {
        image: Vec<u8>,
    },
    ModuleGetFunction {
        module: u64,
        name: String,
    },
    ModuleUnload {
        module: u64,
    },
    /// Per-parameter byte sizes of `function`'s kernel arguments, in declaration
    /// order — what a generic client needs to serialize `kernelParams` blobs.
    FuncGetParamInfo {
        function: u64,
    },
    MemAlloc {
        bytes: u64,
    },
    MemFree {
        dptr: u64,
    },
    MemcpyHtoD {
        dptr: u64,
        data: Vec<u8>,
    },
    MemcpyDtoH {
        dptr: u64,
        bytes: u64,
    },
    MemcpyDtoD {
        dst: u64,
        src: u64,
        bytes: u64,
    },
    MemsetD8 {
        dptr: u64,
        value: u8,
        bytes: u64,
    },
    MemGetInfo,
    /// Launch `function` with the given geometry. `params` is one byte-blob per
    /// kernel argument, in order — the host rebuilds the `void*[]` the Driver
    /// API expects by pointing at local copies of each blob. `stream` is an
    /// opaque stream id (0 = the default stream).
    LaunchKernel {
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: Vec<Vec<u8>>,
    },
    CtxSynchronize,
    StreamCreate {
        flags: u32,
    },
    StreamDestroy {
        stream: u64,
    },
    StreamSynchronize {
        stream: u64,
    },
    EventCreate {
        flags: u32,
    },
    EventDestroy {
        event: u64,
    },
    /// Record `event` on `stream` (0 = the default stream).
    EventRecord {
        event: u64,
        stream: u64,
    },
    EventSynchronize {
        event: u64,
    },
    EventElapsedTime {
        start: u64,
        end: u64,
    },
}

/// A decoded successful response body (the `status == 0` payload).
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// No return value beyond status (Init, CtxDestroy, MemFree, Memcpy*, Launch, Sync).
    Ok,
    Count(i32),
    Name(String),
    Bytes(u64),
    Handle(u64),
    Dptr(u64),
    Data(Vec<u8>),
    /// Two u64s (MemGetInfo: free, total).
    Pair(u64, u64),
    /// Milliseconds (EventElapsedTime). f32 bits on the wire.
    Millis(f32),
}

// ---- low-level primitives -------------------------------------------------

fn w_u8(b: &mut Vec<u8>, v: u8) {
    b.push(v);
}
fn w_i32(b: &mut Vec<u8>, v: i32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w_bytes(b: &mut Vec<u8>, v: &[u8]) {
    w_u64(b, v.len() as u64);
    b.extend_from_slice(v);
}
fn w_str(b: &mut Vec<u8>, v: &str) {
    w_bytes(b, v.as_bytes());
}

/// Cursor-based reader over an in-memory payload. Every accessor is
/// bounds-checked so a malformed/hostile message yields `InvalidData`, never a
/// panic.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or_else(bad)?;
        if end > self.b.len() {
            return Err(bad());
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn i32(&mut self) -> io::Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u64()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> io::Result<String> {
        let v = self.bytes()?;
        String::from_utf8(v).map_err(|_| bad())
    }
}

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed cuda-rpc message")
}

// ---- framing --------------------------------------------------------------

/// Write a length-prefixed payload.
pub fn write_msg<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large",
        ));
    }
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Read a length-prefixed payload. Returns `None` on a clean EOF at a frame
/// boundary (peer closed), `Err` on a truncated/oversized frame.
pub fn read_msg<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

// ---- request encode/decode ------------------------------------------------

pub fn encode_request(req: &Request) -> Vec<u8> {
    let mut b = Vec::new();
    match req {
        Request::Init => w_u8(&mut b, Op::Init as u8),
        Request::DeviceGetCount => w_u8(&mut b, Op::DeviceGetCount as u8),
        Request::DeviceGetName { device } => {
            w_u8(&mut b, Op::DeviceGetName as u8);
            w_i32(&mut b, *device);
        }
        Request::DeviceTotalMem { device } => {
            w_u8(&mut b, Op::DeviceTotalMem as u8);
            w_i32(&mut b, *device);
        }
        Request::DriverGetVersion => w_u8(&mut b, Op::DriverGetVersion as u8),
        Request::DeviceGetAttribute { attrib, device } => {
            w_u8(&mut b, Op::DeviceGetAttribute as u8);
            w_i32(&mut b, *attrib);
            w_i32(&mut b, *device);
        }
        Request::DeviceGetUuid { device } => {
            w_u8(&mut b, Op::DeviceGetUuid as u8);
            w_i32(&mut b, *device);
        }
        Request::CtxCreate { device } => {
            w_u8(&mut b, Op::CtxCreate as u8);
            w_i32(&mut b, *device);
        }
        Request::CtxDestroy { ctx } => {
            w_u8(&mut b, Op::CtxDestroy as u8);
            w_u64(&mut b, *ctx);
        }
        Request::PrimaryCtxRetain { device } => {
            w_u8(&mut b, Op::PrimaryCtxRetain as u8);
            w_i32(&mut b, *device);
        }
        Request::PrimaryCtxRelease { device } => {
            w_u8(&mut b, Op::PrimaryCtxRelease as u8);
            w_i32(&mut b, *device);
        }
        Request::ModuleLoadData { image } => {
            w_u8(&mut b, Op::ModuleLoadData as u8);
            w_bytes(&mut b, image);
        }
        Request::ModuleGetFunction { module, name } => {
            w_u8(&mut b, Op::ModuleGetFunction as u8);
            w_u64(&mut b, *module);
            w_str(&mut b, name);
        }
        Request::ModuleUnload { module } => {
            w_u8(&mut b, Op::ModuleUnload as u8);
            w_u64(&mut b, *module);
        }
        Request::FuncGetParamInfo { function } => {
            w_u8(&mut b, Op::FuncGetParamInfo as u8);
            w_u64(&mut b, *function);
        }
        Request::MemAlloc { bytes } => {
            w_u8(&mut b, Op::MemAlloc as u8);
            w_u64(&mut b, *bytes);
        }
        Request::MemFree { dptr } => {
            w_u8(&mut b, Op::MemFree as u8);
            w_u64(&mut b, *dptr);
        }
        Request::MemcpyHtoD { dptr, data } => {
            w_u8(&mut b, Op::MemcpyHtoD as u8);
            w_u64(&mut b, *dptr);
            w_bytes(&mut b, data);
        }
        Request::MemcpyDtoH { dptr, bytes } => {
            w_u8(&mut b, Op::MemcpyDtoH as u8);
            w_u64(&mut b, *dptr);
            w_u64(&mut b, *bytes);
        }
        Request::MemcpyDtoD { dst, src, bytes } => {
            w_u8(&mut b, Op::MemcpyDtoD as u8);
            w_u64(&mut b, *dst);
            w_u64(&mut b, *src);
            w_u64(&mut b, *bytes);
        }
        Request::MemsetD8 { dptr, value, bytes } => {
            w_u8(&mut b, Op::MemsetD8 as u8);
            w_u64(&mut b, *dptr);
            w_u8(&mut b, *value);
            w_u64(&mut b, *bytes);
        }
        Request::MemGetInfo => w_u8(&mut b, Op::MemGetInfo as u8),
        Request::LaunchKernel {
            function,
            grid,
            block,
            shared_bytes,
            stream,
            params,
        } => {
            w_u8(&mut b, Op::LaunchKernel as u8);
            w_u64(&mut b, *function);
            for v in grid {
                w_u32(&mut b, *v);
            }
            for v in block {
                w_u32(&mut b, *v);
            }
            w_u32(&mut b, *shared_bytes);
            w_u64(&mut b, *stream);
            w_u32(&mut b, params.len() as u32);
            for p in params {
                w_bytes(&mut b, p);
            }
        }
        Request::CtxSynchronize => w_u8(&mut b, Op::CtxSynchronize as u8),
        Request::StreamCreate { flags } => {
            w_u8(&mut b, Op::StreamCreate as u8);
            w_u32(&mut b, *flags);
        }
        Request::StreamDestroy { stream } => {
            w_u8(&mut b, Op::StreamDestroy as u8);
            w_u64(&mut b, *stream);
        }
        Request::StreamSynchronize { stream } => {
            w_u8(&mut b, Op::StreamSynchronize as u8);
            w_u64(&mut b, *stream);
        }
        Request::EventCreate { flags } => {
            w_u8(&mut b, Op::EventCreate as u8);
            w_u32(&mut b, *flags);
        }
        Request::EventDestroy { event } => {
            w_u8(&mut b, Op::EventDestroy as u8);
            w_u64(&mut b, *event);
        }
        Request::EventRecord { event, stream } => {
            w_u8(&mut b, Op::EventRecord as u8);
            w_u64(&mut b, *event);
            w_u64(&mut b, *stream);
        }
        Request::EventSynchronize { event } => {
            w_u8(&mut b, Op::EventSynchronize as u8);
            w_u64(&mut b, *event);
        }
        Request::EventElapsedTime { start, end } => {
            w_u8(&mut b, Op::EventElapsedTime as u8);
            w_u64(&mut b, *start);
            w_u64(&mut b, *end);
        }
    }
    b
}

pub fn decode_request(payload: &[u8]) -> io::Result<Request> {
    let mut c = Cur::new(payload);
    let op = Op::from_u8(c.u8()?).ok_or_else(bad)?;
    Ok(match op {
        Op::Init => Request::Init,
        Op::DeviceGetCount => Request::DeviceGetCount,
        Op::DeviceGetName => Request::DeviceGetName { device: c.i32()? },
        Op::DeviceTotalMem => Request::DeviceTotalMem { device: c.i32()? },
        Op::DriverGetVersion => Request::DriverGetVersion,
        Op::DeviceGetAttribute => Request::DeviceGetAttribute {
            attrib: c.i32()?,
            device: c.i32()?,
        },
        Op::DeviceGetUuid => Request::DeviceGetUuid { device: c.i32()? },
        Op::CtxCreate => Request::CtxCreate { device: c.i32()? },
        Op::CtxDestroy => Request::CtxDestroy { ctx: c.u64()? },
        Op::PrimaryCtxRetain => Request::PrimaryCtxRetain { device: c.i32()? },
        Op::PrimaryCtxRelease => Request::PrimaryCtxRelease { device: c.i32()? },
        Op::ModuleLoadData => Request::ModuleLoadData { image: c.bytes()? },
        Op::ModuleGetFunction => Request::ModuleGetFunction {
            module: c.u64()?,
            name: c.string()?,
        },
        Op::ModuleUnload => Request::ModuleUnload { module: c.u64()? },
        Op::FuncGetParamInfo => Request::FuncGetParamInfo { function: c.u64()? },
        Op::MemAlloc => Request::MemAlloc { bytes: c.u64()? },
        Op::MemFree => Request::MemFree { dptr: c.u64()? },
        Op::MemcpyHtoD => Request::MemcpyHtoD {
            dptr: c.u64()?,
            data: c.bytes()?,
        },
        Op::MemcpyDtoH => Request::MemcpyDtoH {
            dptr: c.u64()?,
            bytes: c.u64()?,
        },
        Op::MemcpyDtoD => Request::MemcpyDtoD {
            dst: c.u64()?,
            src: c.u64()?,
            bytes: c.u64()?,
        },
        Op::MemsetD8 => Request::MemsetD8 {
            dptr: c.u64()?,
            value: c.u8()?,
            bytes: c.u64()?,
        },
        Op::MemGetInfo => Request::MemGetInfo,
        Op::LaunchKernel => {
            let function = c.u64()?;
            let grid = [c.u32()?, c.u32()?, c.u32()?];
            let block = [c.u32()?, c.u32()?, c.u32()?];
            let shared_bytes = c.u32()?;
            let stream = c.u64()?;
            let n = c.u32()? as usize;
            let mut params = Vec::with_capacity(n);
            for _ in 0..n {
                params.push(c.bytes()?);
            }
            Request::LaunchKernel {
                function,
                grid,
                block,
                shared_bytes,
                stream,
                params,
            }
        }
        Op::CtxSynchronize => Request::CtxSynchronize,
        Op::StreamCreate => Request::StreamCreate { flags: c.u32()? },
        Op::StreamDestroy => Request::StreamDestroy { stream: c.u64()? },
        Op::StreamSynchronize => Request::StreamSynchronize { stream: c.u64()? },
        Op::EventCreate => Request::EventCreate { flags: c.u32()? },
        Op::EventDestroy => Request::EventDestroy { event: c.u64()? },
        Op::EventRecord => Request::EventRecord {
            event: c.u64()?,
            stream: c.u64()?,
        },
        Op::EventSynchronize => Request::EventSynchronize { event: c.u64()? },
        Op::EventElapsedTime => Request::EventElapsedTime {
            start: c.u64()?,
            end: c.u64()?,
        },
    })
}

// ---- response encode/decode -----------------------------------------------

/// Encode a response: `i32 status` then, only when `status == 0`, the body.
pub fn encode_response(status: i32, resp: &Response) -> Vec<u8> {
    let mut b = Vec::new();
    w_i32(&mut b, status);
    if status == 0 {
        match resp {
            Response::Ok => {}
            Response::Count(v) => w_i32(&mut b, *v),
            Response::Name(s) => w_str(&mut b, s),
            Response::Bytes(v) | Response::Handle(v) | Response::Dptr(v) => w_u64(&mut b, *v),
            Response::Data(d) => w_bytes(&mut b, d),
            Response::Pair(a, z) => {
                w_u64(&mut b, *a);
                w_u64(&mut b, *z);
            }
            Response::Millis(ms) => w_u32(&mut b, ms.to_bits()),
        }
    }
    b
}

/// Decode a response for `op`. Returns `(status, body)`; `body` is `Response::Ok`
/// when status != 0 (error — no body on the wire).
pub fn decode_response(op: Op, payload: &[u8]) -> io::Result<(i32, Response)> {
    let mut c = Cur::new(payload);
    let status = c.i32()?;
    if status != 0 {
        return Ok((status, Response::Ok));
    }
    let body = match op {
        Op::DeviceGetCount | Op::DriverGetVersion | Op::DeviceGetAttribute => {
            Response::Count(c.i32()?)
        }
        Op::DeviceGetName => Response::Name(c.string()?),
        Op::DeviceTotalMem => Response::Bytes(c.u64()?),
        Op::CtxCreate | Op::PrimaryCtxRetain => Response::Handle(c.u64()?),
        Op::ModuleLoadData | Op::ModuleGetFunction => Response::Handle(c.u64()?),
        Op::StreamCreate | Op::EventCreate => Response::Handle(c.u64()?),
        Op::MemAlloc => Response::Dptr(c.u64()?),
        Op::MemcpyDtoH | Op::DeviceGetUuid | Op::FuncGetParamInfo => Response::Data(c.bytes()?),
        Op::MemGetInfo => Response::Pair(c.u64()?, c.u64()?),
        Op::EventElapsedTime => Response::Millis(f32::from_bits(c.u32()?)),
        Op::Init
        | Op::CtxDestroy
        | Op::PrimaryCtxRelease
        | Op::ModuleUnload
        | Op::MemFree
        | Op::MemcpyHtoD
        | Op::MemcpyDtoD
        | Op::MemsetD8
        | Op::LaunchKernel
        | Op::CtxSynchronize
        | Op::StreamDestroy
        | Op::StreamSynchronize
        | Op::EventDestroy
        | Op::EventRecord
        | Op::EventSynchronize => Response::Ok,
    };
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(req: Request) {
        let enc = encode_request(&req);
        let dec = decode_request(&enc).expect("decode");
        assert_eq!(req, dec);
    }

    #[test]
    fn request_roundtrips() {
        roundtrip(Request::Init);
        roundtrip(Request::DeviceGetCount);
        roundtrip(Request::DeviceGetName { device: 3 });
        roundtrip(Request::DeviceTotalMem { device: 0 });
        roundtrip(Request::CtxCreate { device: 1 });
        roundtrip(Request::CtxDestroy { ctx: 0xdead_beef });
        roundtrip(Request::ModuleLoadData {
            image: b".version 7.0\n".to_vec(),
        });
        roundtrip(Request::ModuleGetFunction {
            module: 42,
            name: "vecadd".into(),
        });
        roundtrip(Request::MemAlloc { bytes: 4096 });
        roundtrip(Request::MemFree { dptr: 0x7f00_0000 });
        roundtrip(Request::MemcpyHtoD {
            dptr: 0x7f00_0000,
            data: vec![1, 2, 3, 4],
        });
        roundtrip(Request::MemcpyDtoH {
            dptr: 0x7f00_0000,
            bytes: 16,
        });
        roundtrip(Request::LaunchKernel {
            function: 7,
            grid: [4, 1, 1],
            block: [256, 1, 1],
            shared_bytes: 0,
            stream: 0,
            params: vec![
                0x1000u64.to_le_bytes().to_vec(),
                0x2000u64.to_le_bytes().to_vec(),
                1024u32.to_le_bytes().to_vec(),
            ],
        });
        roundtrip(Request::CtxSynchronize);
    }

    #[test]
    fn extended_request_roundtrips() {
        roundtrip(Request::DriverGetVersion);
        roundtrip(Request::DeviceGetAttribute {
            attrib: 75,
            device: 0,
        });
        roundtrip(Request::DeviceGetUuid { device: 0 });
        roundtrip(Request::PrimaryCtxRetain { device: 0 });
        roundtrip(Request::PrimaryCtxRelease { device: 0 });
        roundtrip(Request::ModuleUnload { module: 7 });
        roundtrip(Request::FuncGetParamInfo { function: 9 });
        roundtrip(Request::MemcpyDtoD {
            dst: 0x2000,
            src: 0x1000,
            bytes: 64,
        });
        roundtrip(Request::MemsetD8 {
            dptr: 0x1000,
            value: 0xAB,
            bytes: 128,
        });
        roundtrip(Request::MemGetInfo);
        roundtrip(Request::StreamCreate { flags: 1 });
        roundtrip(Request::StreamDestroy { stream: 3 });
        roundtrip(Request::StreamSynchronize { stream: 3 });
        roundtrip(Request::EventCreate { flags: 0 });
        roundtrip(Request::EventDestroy { event: 4 });
        roundtrip(Request::EventRecord {
            event: 4,
            stream: 0,
        });
        roundtrip(Request::EventSynchronize { event: 4 });
        roundtrip(Request::EventElapsedTime { start: 4, end: 5 });
    }

    #[test]
    fn extended_response_roundtrips() {
        for (op, resp) in [
            (Op::DriverGetVersion, Response::Count(13000)),
            (Op::DeviceGetAttribute, Response::Count(1024)),
            (Op::DeviceGetUuid, Response::Data(vec![0u8; 16])),
            (Op::PrimaryCtxRetain, Response::Handle(11)),
            (
                Op::FuncGetParamInfo,
                Response::Data(vec![8, 0, 0, 0, 4, 0, 0, 0]),
            ),
            (Op::MemGetInfo, Response::Pair(6 << 30, 8 << 30)),
            (Op::StreamCreate, Response::Handle(21)),
            (Op::EventCreate, Response::Handle(22)),
            (Op::EventElapsedTime, Response::Millis(1.25)),
            (Op::ModuleUnload, Response::Ok),
            (Op::MemsetD8, Response::Ok),
        ] {
            let enc = encode_response(0, &resp);
            let (status, dec) = decode_response(op, &enc).expect("decode");
            assert_eq!(status, 0);
            assert_eq!(dec, resp);
        }
    }

    #[test]
    fn response_roundtrips() {
        for (op, resp) in [
            (Op::DeviceGetCount, Response::Count(2)),
            (
                Op::DeviceGetName,
                Response::Name("NVIDIA GeForce RTX 3070".into()),
            ),
            (Op::DeviceTotalMem, Response::Bytes(8 << 30)),
            (Op::CtxCreate, Response::Handle(99)),
            (Op::ModuleLoadData, Response::Handle(1)),
            (Op::MemAlloc, Response::Dptr(0x7f00_0000)),
            (Op::MemcpyDtoH, Response::Data(vec![9, 8, 7])),
            (Op::CtxSynchronize, Response::Ok),
        ] {
            let enc = encode_response(0, &resp);
            let (status, dec) = decode_response(op, &enc).expect("decode");
            assert_eq!(status, 0);
            assert_eq!(dec, resp);
        }
    }

    #[test]
    fn error_response_has_no_body() {
        let enc = encode_response(700, &Response::Handle(123)); // CUDA_ERROR_*
        let (status, body) = decode_response(Op::ModuleLoadData, &enc).unwrap();
        assert_eq!(status, 700);
        assert_eq!(body, Response::Ok); // body omitted on error
        assert_eq!(enc.len(), 4); // status only
    }

    #[test]
    fn framing_roundtrip_and_eof() {
        let mut buf = Vec::new();
        let payload = encode_request(&Request::DeviceGetCount);
        write_msg(&mut buf, &payload).unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let got = read_msg(&mut cur).unwrap().expect("frame");
        assert_eq!(got, payload);
        // clean EOF at boundary
        assert!(read_msg(&mut cur).unwrap().is_none());
    }

    #[test]
    fn truncated_message_is_error_not_panic() {
        // opcode says ModuleGetFunction but payload is truncated mid-string
        let mut b = vec![Op::ModuleGetFunction as u8];
        b.extend_from_slice(&7u64.to_le_bytes()); // module
        b.extend_from_slice(&100u64.to_le_bytes()); // claims 100-byte name…
        b.extend_from_slice(b"short"); // …but only 5 bytes follow
        assert!(decode_request(&b).is_err());
    }
}
