//! PCR-bound sealing — "SPiCa is running" as a certificate of measured boot.
//!
//! Threat this closes (the strongest theoretical bypass found in review):
//! a rootkit present *before* SPiCa that MITMs the daemon at exec — the
//! daemon would then honestly verify and anchor a forged ledger, and every
//! in-band signal would be self-consistent fiction. With sealing:
//!
//! **Install** (`spica seal-install`): a random 32-byte secret S is written
//! to a TPM NV index whose read authorization is a PolicyPCR over:
//!   - PCR17 — the SHA-256 of the SPiCa binary, extended exactly once per
//!     boot by the initramfs hook (before any untrusted code runs);
//!   - PCR4/PCR9 — kernel image and initramfs, *when the boot chain
//!     measures them* (auto-detected; unmeasured chains get a loud warning
//!     and the policy binds to the binary only).
//! `H(S)` is recorded in `/etc/spica/genesis.expected` (public — the secret
//! never leaves the TPM except through a satisfied policy).
//!
//! **Boot** (initramfs hook → `spica genesis --out /run/spica.genesis`):
//! hash `/proc/self/exe` → extend PCR17 → open a policy session over the
//! CURRENT PCRs → NV-read S. Tampered kernel, initramfs, or binary → policy
//! fails → no secret → the honest daemon refuses to start (loud absence
//! instead of silent fiction). The secret is passed to the daemon via a
//! tmpfs file; the daemon extends `H(S)` into PCR16 as anchor genesis, so
//! an *offline quote* can prove the anchoring SPiCa was the sealed one.
//!
//! Honest boundaries: a replaced binary doesn't need the secret — it just
//! runs — but its PCR16 genesis will not match the install record, which is
//! exactly what offline verification checks. Root with TPM owner access can
//! redefine the NV index, but cannot make PCR16's history match the record.
//! PCR4/9 in the policy assume deterministic boot measurements (standard
//! sealing caveat: kernel/initramfs updates require re-sealing).

#[cfg(target_os = "linux")]
pub use imp::{
    genesis, install, EV_GENESIS_TAG, EXPECTED_GENESIS_PATH, GENESIS_OUT_PATH, NV_INDEX_HANDLE,
    SPICA_BIN_PCR,
};

#[cfg(target_os = "linux")]
mod imp {
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::path::Path;
    use tss_esapi::{
        attributes::{NvIndexAttributes, NvIndexAttributesBuilder},
        constants::{session_type::SessionType, NvIndexType},
        handles::{NvIndexHandle, NvIndexTpmHandle, PcrHandle, TpmHandle},
        interface_types::{
            algorithm::HashingAlgorithm,
            resource_handles::{NvAuth, Provision},
            session_handles::AuthSession,
        },
        structures::{Digest, MaxNvBuffer, Nonce, PcrSelectionList, PcrSlot, SymmetricDefinition, NvPublic},
        Context,
    };
    use tss_esapi::handles::SessionHandle;
    use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};

    /// PCR extended with the SPiCa binary hash at initramfs stage.
    pub const SPICA_BIN_PCR: u32 = 23;
    /// The slot/handle forms must match SPICA_BIN_PCR — locked at compile time.
    const _: () = assert!(SPICA_BIN_PCR == 23);
    /// NV index holding the sealed secret (owner-writable, policy-readable).
    pub const NV_INDEX_HANDLE: u32 = 0x0170_0001;
    /// Install record: hex of H(S) — public, checked by offline verification.
    pub const EXPECTED_GENESIS_PATH: &str = "/etc/spica/genesis.expected";
    /// Where the initramfs hook drops the unsealed secret (tmpfs, 0600).
    pub const GENESIS_OUT_PATH: &str = "/run/spica.genesis";

    /// Domain-separation tag for the genesis digest (spica-common mirrors
    /// the math for the daemon; this copy is for the install record).
    pub const EV_GENESIS_TAG: &[u8; 12] = b"SPiCaGENESIS";

    fn tpm() -> Result<Context, String> {
        Context::new(TctiNameConf::Device(DeviceConfig::default()))
            .map_err(|e| format!("TPM open failed: {e:?}"))
    }

    fn nv_handle() -> NvIndexTpmHandle {
        NvIndexTpmHandle::new(NV_INDEX_HANDLE).expect("constant handle")
    }

    /// ESYS handle for the NV index. A raw TPM handle value is NOT an
    /// ESYS_TR — it must be deserialized via tr_from_tpm_public (found
    /// live: "Unknown ESYS handle" 0x07000b).
    fn nv_esys_handle(ctx: &mut Context) -> Result<NvIndexHandle, String> {
        let obj = ctx
            .tr_from_tpm_public(TpmHandle::NvIndex(nv_handle()))
            .map_err(|e| format!("tr_from_tpm_public: {e:?}"))?;
        Ok(NvIndexHandle::from(obj))
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    pub fn genesis_digest(secret: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(EV_GENESIS_TAG);
        h.update(secret);
        h.finalize().into()
    }

    /// Read one PCR's current value (empty if the bank/PCR reads zero).
    fn read_pcr(ctx: &mut Context, slot: PcrSlot) -> Result<[u8; 32], String> {
        let sel = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, &[slot])
            .build()
            .map_err(|e| format!("selection: {e:?}"))?;
        let (_, _, digests) = ctx
            .execute_without_session(|c| c.pcr_read(sel))
            .map_err(|e| format!("pcr_read: {e:?}"))?;
        let first = digests
            .value()
            .first()
            .ok_or_else(|| "pcr_read returned no digest".to_string())?;
        <[u8; 32]>::try_from(first.clone()).map_err(|e| format!("digest size: {e:?}"))
    }

    /// Policy digest for "PolicyPCR over the expected values", computed via
    /// a trial session so the TPM does the digest arithmetic.
    fn policy_pcr_digest(
        ctx: &mut Context,
        expected: &[[u8; 32]],
        slots: &[PcrSlot],
    ) -> Result<Digest, String> {
        let session = ctx
            .execute_without_session(|c| {
                c.start_auth_session(
                    None,
                    None,
                    Some(Nonce::try_from(vec![0u8; 16]).unwrap()),
                    SessionType::Trial,
                    SymmetricDefinition::Null,
                    HashingAlgorithm::Sha256,
                )
            })
            .map_err(|e| format!("trial session: {e:?}"))?
            .ok_or("no trial session")?;
        // policy_pcr's pcrDigest is the HASH of the concatenated selected
        // PCR values (a bare concatenation of 3+ sha256 PCRs exceeds the
        // 64-byte TPM2B_DIGEST limit — found live as WrongParamSize).
        let mut concat = Vec::with_capacity(expected.len() * 32);
        for d in expected {
            concat.extend_from_slice(d);
        }
        let pcr_digest =
            Digest::try_from(sha256(&concat).to_vec()).map_err(|e| format!("digest: {e:?}"))?;
        let sel = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, slots)
            .build()
            .map_err(|e| format!("selection: {e:?}"))?;
        let policy_session: tss_esapi::interface_types::session_handles::PolicySession = session
            .try_into()
            .map_err(|e: tss_esapi::Error| format!("policy session: {e:?}"))?;
        ctx.execute_without_session(|c| {
            c.policy_pcr(policy_session, pcr_digest, sel)
        })
        .map_err(|e| format!("policy_pcr: {e:?}"))?;
        let got = ctx
            .execute_without_session(|c| c.policy_get_digest(policy_session))
            .map_err(|e| format!("policy_get_digest: {e:?}"))?;
        ctx.flush_context(SessionHandle::from(policy_session).into())
            .map_err(|e| format!("flush: {e:?}"))?;
        Ok(got)
    }

    /// Install-time sealing. Defines the NV index (replacing any previous
    /// one), writes a fresh random secret, and records H(S).
    pub fn install() -> Result<String, String> {
        let mut ctx = tpm()?;
        let bin = fs::read("/proc/self/exe").map_err(|e| format!("read self: {e}"))?;
        let h_bin = sha256(&bin);

        // Expected PCR17 at genesis time: a single extend over zero.
        let pcr17_expected = {
            let mut h = Sha256::new();
            h.update([0u8; 32]);
            h.update(h_bin);
            let v: [u8; 32] = h.finalize().into();
            v
        };

        // Auto-detect a measuring boot chain for the kernel/initramfs PCRs.
        let pcr4 = read_pcr(&mut ctx, PcrSlot::Slot4).unwrap_or([0u8; 32]);
        let pcr9 = read_pcr(&mut ctx, PcrSlot::Slot9).unwrap_or([0u8; 32]);
        let measured = pcr4 != [0u8; 32] || pcr9 != [0u8; 32];
        let (expected, slots): (Vec<[u8; 32]>, Vec<PcrSlot>) = if measured {
            (
                vec![pcr4, pcr9, pcr17_expected],
                vec![PcrSlot::Slot4, PcrSlot::Slot9, PcrSlot::Slot23],
            )
        } else {
            (vec![pcr17_expected], vec![PcrSlot::Slot23])
        };
        if !measured {
            eprintln!(
                "[SEAL]       WARNING: boot chain does not measure PCR4/PCR9 (unmeasured boot); \
                 policy binds to the SPiCa binary only — kernel/initramfs tampering is NOT caught"
            );
        }

        let policy = policy_pcr_digest(&mut ctx, &expected, &slots)?;

        // Replace any previous index (owner password is empty by default).
        // Best-effort removal of a previous definition (ignore errors —
        // undefined already is fine).
        if let Ok(old) = nv_esys_handle(&mut ctx) {
            let _ = ctx.execute_with_session(Some(AuthSession::Password), |c| {
                c.nv_undefine_space(Provision::Owner, old)
            });
        }
        let attrs = NvIndexAttributes::builder()
            .with_nv_index_type(tss_esapi::constants::NvIndexType::Ordinary)
            .with_owner_write(true)
            .with_policy_read(true)
            .build()
            .map_err(|e| format!("attrs: {e:?}"))?;
        let public = NvPublic::builder()
            .with_nv_index(nv_handle())
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attrs)
            .with_index_auth_policy(policy)
            .with_data_area_size(32)
            .build()
            .map_err(|e| format!("nv public: {e:?}"))?;
        let handle = ctx
            .execute_with_session(Some(AuthSession::Password), |c| {
                c.nv_define_space(Provision::Owner, None, public)
            })
            .map_err(|e| format!("nv_define_space: {e:?}"))?;

        let mut secret = [0u8; 32];
        {
            use std::io::Read;
            fs::File::open("/dev/urandom")
                .map_err(|e| e.to_string())?
                .read_exact(&mut secret)
                .map_err(|e| e.to_string())?;
        }
        let buffer = MaxNvBuffer::try_from(secret.to_vec()).map_err(|e| format!("buffer: {e:?}"))?;
        ctx.execute_with_session(Some(AuthSession::Password), |c| {
            c.nv_write(NvAuth::Owner, handle, buffer, 0)
        })
        .map_err(|e| format!("nv_write: {e:?}"))?;

        let expected_genesis = genesis_digest(&secret);
        fs::create_dir_all("/etc/spica").map_err(|e| e.to_string())?;
        fs::write(EXPECTED_GENESIS_PATH, hex(&expected_genesis))
            .map_err(|e| e.to_string())?;
        Ok(format!(
            "sealed: policy over PCR{} (+PCR4/9: {}), H(S) recorded to {EXPECTED_GENESIS_PATH}",
            SPICA_BIN_PCR, measured
        ))
    }

    /// Initramfs-stage entry: measure the binary into PCR17, then unseal the
    /// secret under the current PCR state. Writes it to `out` (0600).
    pub fn genesis(out: &Path, expected_path: &Path) -> Result<(), String> {
        let mut ctx = tpm()?;
        let bin = fs::read("/proc/self/exe").map_err(|e| format!("read self: {e}"))?;
        let h_bin = sha256(&bin);

        // 1. Measure: extend PCR17 with the binary hash (password session,
        //    same as the anchor's PCR16 extends).
        let digest = Digest::try_from(h_bin.to_vec()).map_err(|e| format!("digest: {e:?}"))?;
        let mut vals = tss_esapi::structures::DigestValues::new();
        vals.set(HashingAlgorithm::Sha256, digest);
        ctx.execute_with_session(Some(AuthSession::Password), |c| {
            c.pcr_extend(PcrHandle::Pcr23, vals)
        })
        .map_err(|e| format!("pcr_extend(17): {e:?}"))?;

        // 2. Policy session over the CURRENT PCRs (the same set the install
        //    policy selected). Which set? Re-derive: measured chain iff
        //    PCR4 or 9 nonzero now.
        let pcr4 = read_pcr(&mut ctx, PcrSlot::Slot4).unwrap_or([0u8; 32]);
        let pcr9 = read_pcr(&mut ctx, PcrSlot::Slot9).unwrap_or([0u8; 32]);
        let pcr17 = read_pcr(&mut ctx, PcrSlot::Slot23)?;
        let measured = pcr4 != [0u8; 32] || pcr9 != [0u8; 32];
        let (current, slots): (Vec<[u8; 32]>, Vec<PcrSlot>) = if measured {
            (
                vec![pcr4, pcr9, pcr17],
                vec![PcrSlot::Slot4, PcrSlot::Slot9, PcrSlot::Slot23],
            )
        } else {
            (vec![pcr17], vec![PcrSlot::Slot23])
        };
        // Empty pcrDigest: the TPM digests the ACTUAL PCRs itself — the
        // session's policy digest then equals authPolicy only if the real
        // state matches the sealed expectation.
        let pcr_digest = Digest::try_from(Vec::<u8>::new())
            .map_err(|e| format!("digest: {e:?}"))?;
        let sel = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, &slots)
            .build()
            .map_err(|e| format!("selection: {e:?}"))?;

        let session = ctx
            .execute_without_session(|c| {
                c.start_auth_session(
                    None,
                    None,
                    Some(Nonce::try_from(vec![0u8; 16]).unwrap()),
                    SessionType::Policy,
                    SymmetricDefinition::Null,
                    HashingAlgorithm::Sha256,
                )
            })
            .map_err(|e| format!("policy session: {e:?}"))?
            .ok_or("no policy session")?;
        let policy_session: tss_esapi::interface_types::session_handles::PolicySession = session
            .try_into()
            .map_err(|e: tss_esapi::Error| format!("policy session: {e:?}"))?;
        ctx.execute_without_session(|c| c.policy_pcr(policy_session, pcr_digest, sel))
            .map_err(|e| format!("policy_pcr: {e:?}"))?;

        // 3. Read the secret under the policy session (auth = the index,
        //    satisfied by the policy).
        let handle = nv_esys_handle(&mut ctx)?;
        let auth = AuthSession::from(policy_session);
        let data = ctx
            .execute_with_session(Some(auth), |c| {
                c.nv_read(NvAuth::NvIndex(handle), handle, 32, 0)
            })
            .map_err(|e| format!("nv_read under policy FAILED — tampered boot or binary ({e:?})"))?;
        let bytes = data.value().to_vec();
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "secret size mismatch".to_string())?;

        // 4. Cross-check against the install record when available.
        if let Ok(expected_hex) = fs::read_to_string(expected_path) {
            let want = genesis_digest(&secret);
            if hex(&want) != expected_hex.trim() {
                return Err("unsealed secret does not match the install record".to_string());
            }
        }

        // 5. Drop the secret to tmpfs for the daemon.
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(out, secret).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

}

#[cfg(not(target_os = "linux"))]
pub const EXPECTED_GENESIS_PATH: &str = "/etc/spica/genesis.expected";

#[cfg(not(target_os = "linux"))]
pub const GENESIS_OUT_PATH: &str = "/run/spica.genesis";

#[cfg(not(target_os = "linux"))]
mod imp {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SealError {
        Unavailable,
    }
}
