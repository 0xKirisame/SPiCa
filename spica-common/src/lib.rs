#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub last_seen: u64,
    pub start_time_ns: u64,
    pub cpu: u32,
    // 0 = normal scheduling event
    // 1 = integrity failure (NMI detected sc_canary mismatch with .bss INTEGRITY_TOKEN)
    pub event_type: u32,
}

/// Emitted by the BPF LSM hook on every READING_MODULE attempt.
/// Not obfuscated — the hook runs before any BASE_KEY context is meaningful.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LkmEvent {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub ktime_ns: u64,
    /// 0 = blocked (gate locked), 1 = allowed (boot window)
    pub allowed: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessInfo {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LkmEvent {}
