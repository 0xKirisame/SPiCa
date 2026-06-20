#![no_std]

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

/// XOR-fold the 64-bit `key` across all `ProcessInfo` fields.
///
/// Symmetric: calling twice with the same key is the identity. Used by the
/// eBPF side to obfuscate before ring-buffer submit and by the userspace
/// side to deobfuscate after ring-buffer read.
///
/// `event_type` is intentionally NOT touched — userspace reads it as a sentinel
/// before calling this function (it distinguishes normal events from the NMI
/// integrity-failure sentinel).
///
/// Threat-model note: this is **obfuscation against read-leakage, not
/// encryption against a capable adversary**. See README "Key Management &
/// Obfuscation" for the honest framing.
#[inline]
pub fn xor_fields(info: &mut ProcessInfo, key: u64) {
    info.pid ^= key as u32;
    info.tgid ^= (key >> 32) as u32;
    info.last_seen ^= key;
    info.start_time_ns ^= key;
    info.cpu ^= key as u32;
    let kb = key.to_ne_bytes();
    info.comm[0..8].iter_mut().zip(kb.iter()).for_each(|(b, k)| *b ^= k);
    info.comm[8..16].iter_mut().zip(kb.iter()).for_each(|(b, k)| *b ^= k);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn sample_info() -> ProcessInfo {
        ProcessInfo {
            pid: 0x1234_5678,
            tgid: 0x9abc_def0,
            comm: *b"spica_test_pad!!",
            last_seen: 0xfeed_face_0011_2233,
            start_time_ns: 0xdead_beef_cafe_babe,
            cpu: 0x4242_4242,
            event_type: 0,
        }
    }

    #[test]
    fn xor_fields_is_identity_when_applied_twice() {
        let key = 0xa5a5_a5a5_a5a5_a5a5;
        let original = sample_info();
        let mut info = original;
        xor_fields(&mut info, key);
        assert_ne!(info, original, "first xor should change the data");
        xor_fields(&mut info, key);
        assert_eq!(info, original, "second xor should restore the original");
    }

    #[test]
    fn xor_fields_preserves_event_type() {
        let key = 0xdead_beef_cafe_babe;
        let original = ProcessInfo { event_type: 0x7, ..sample_info() };
        let mut info = original;
        xor_fields(&mut info, key);
        assert_eq!(info.event_type, original.event_type, "event_type must not be touched");
    }

    #[test]
    fn xor_fields_with_zero_key_is_noop() {
        let original = sample_info();
        let mut info = original;
        xor_fields(&mut info, 0);
        assert_eq!(info, original, "XOR with zero key must be identity");
    }

    #[test]
    fn xor_fields_touches_every_non_event_type_field() {
        let key = 0xffff_ffff_ffff_ffff;
        let original = sample_info();
        let mut info = original;
        xor_fields(&mut info, key);
        assert_ne!(info.pid, original.pid, "pid must be XOR'd");
        assert_ne!(info.tgid, original.tgid, "tgid must be XOR'd");
        assert_ne!(info.last_seen, original.last_seen, "last_seen must be XOR'd");
        assert_ne!(info.start_time_ns, original.start_time_ns, "start_time_ns must be XOR'd");
        assert_ne!(info.cpu, original.cpu, "cpu must be XOR'd");
        assert_ne!(info.comm, original.comm, "comm must be XOR'd");
    }

    #[test]
    fn xor_fields_different_keys_produce_different_output() {
        let original = sample_info();
        let mut a = original;
        let mut b = original;
        xor_fields(&mut a, 0x1111_1111_1111_1111);
        xor_fields(&mut b, 0x2222_2222_2222_2222);
        assert_ne!(a, b, "different keys must produce different output");
    }

    #[test]
    fn xor_fields_handles_all_zero_comm() {
        let key = 0xabcd_ef01_2345_6789;
        let original = ProcessInfo { comm: [0u8; 16], ..sample_info() };
        let mut info = original;
        xor_fields(&mut info, key);
        // comm bytes become the key bytes (XOR with 0)
        let kb = key.to_ne_bytes();
        let expected_comm: [u8; 16] = {
            let mut c = [0u8; 16];
            c[0..8].copy_from_slice(&kb);
            c[8..16].copy_from_slice(&kb);
            c
        };
        assert_eq!(info.comm, expected_comm);
    }

    #[test]
    fn xor_fields_round_trip_with_realistic_comm_values() {
        // Known-plaintext resistance smoke test: same plaintext comm with
        // different keys produces different ciphertext (sanity check on the
        // XOR-fold; we know XOR is structurally weak to known-plaintext but
        // the property should still hold that varying key varies output).
        let known_comm = *b"bash\0\0\0\0\0\0\0\0\0\0\0\0";
        let key1 = 0x0123_4567_89ab_cdef;
        let key2 = 0xfedc_ba98_7654_3210;

        let mut a = ProcessInfo { comm: known_comm, ..sample_info() };
        let mut b = ProcessInfo { comm: known_comm, ..sample_info() };
        xor_fields(&mut a, key1);
        xor_fields(&mut b, key2);
        assert_ne!(a.comm, b.comm);
        assert_ne!(a.comm, known_comm);
        assert_ne!(b.comm, known_comm);
    }
}

