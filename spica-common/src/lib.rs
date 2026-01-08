#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub last_seen: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessInfo {}
