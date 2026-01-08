#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::LruHashMap,
    programs::TracePointContext,
    helpers::{bpf_get_current_comm, bpf_ktime_get_ns, bpf_get_current_pid_tgid},
};
use spica_common::ProcessInfo;

#[allow(non_upper_case_globals)]
#[unsafe(export_name = "license")]
pub static _license: [u8; 4] = *b"GPL\0";

#[map]
static mut KERNEL_ORBIT: LruHashMap<u32, ProcessInfo> = LruHashMap::<u32, ProcessInfo>::with_max_entries(4096, 0);

#[tracepoint]
pub fn spica_monitor(ctx: TracePointContext) -> u32 {
    match try_spica_monitor(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_spica_monitor(_ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    if pid == 0 {
        return Ok(0);
    }

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };

    let time = unsafe { bpf_ktime_get_ns() };

    let info = ProcessInfo {
        pid,
        tgid,
        comm,
        last_seen: time,
    };

    unsafe {
        KERNEL_ORBIT.insert(&pid, &info, 0)?;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
