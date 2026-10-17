//! TPM PCR chain-head anchoring — the out-of-band finality layer (stage 3).
//!
//! Every epoch the daemon extends PCR16 with a SHA-256 commitment to its
//! *verified* ledger view (`spica_common::anchor_digest`). PCR extend is
//! one-way in silicon: a rootkit can extend garbage (detected below) but can
//! never rewrite what was extended. This is the only record on the box that
//! survives a full userspace MITM of the daemon.
//!
//! In-band liveness check: because `TPM2_PCR_Extend(sha256)` is defined as
//! `new = SHA256(old ‖ value)`, the daemon mirrors the PCR locally and
//! compares against a live PCR read each epoch. Any divergence — an attacker
//! extending garbage, a second extender, TPM confusion — is reported as
//! `diverged = true` and alerted by the caller as `[PCR-DIVERGE]`.
//!
//! Restart semantics: PCR16 resets to zero on reboot, so each boot's anchor
//! history starts fresh (genesis = first extend of the run). If the daemon
//! restarts *within* a boot, the PCR retains the previous run's extends; the
//! mirror is then seeded from the live PCR value and only future epochs are
//! verified in-band (prior history remains verifiable by an offline quote).
//! A non-zero PCR16 at a fresh boot start is logged loudly: it means either
//! a previous SPiCa run in this boot, or tampering — the offline quote
//! distinguishes them.

#[cfg(target_os = "linux")]
pub use imp::{PcrAnchor, TickOutcome};

#[cfg(target_os = "linux")]
mod imp {
    use spica_common::{ChainSnapshot, PCR_INDEX, anchor_digest, pcr_step};
    use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
    use tss_esapi::{
        Context,
        handles::PcrHandle,
        interface_types::algorithm::HashingAlgorithm,
        interface_types::session_handles::AuthSession,
        structures::{Digest, DigestValues, PcrSelectionList, PcrSlot},
    };

    /// Result of one anchor epoch.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TickOutcome {
        /// Anchor extended and the TPM's PCR matches the local mirror.
        Extended { epoch: u64, mirror: [u8; 32] },
        /// The TPM's PCR diverged from the mirror: someone else extended the
        /// PCR (garbage-extension DoS, second extender, or TPM confusion).
        Diverged {
            epoch: u64,
            mirror: [u8; 32],
            tpm: [u8; 32],
        },
        /// TPM command failed (transient or device gone). The mirror still
        /// advances so the in-band check resumes when the TPM returns; the
        /// caller may alert on repeated failures.
        Failed { epoch: u64 },
    }

    pub struct PcrAnchor {
        ctx: Context,
        epoch: u64,
        mirror: [u8; 32],
        genesis_done: bool,
    }

    impl PcrAnchor {
        /// Open the TPM (kernel resource manager, `/dev/tpmrm0`) and seed the
        /// mirror from the live PCR value. Returns Err with a human-readable
        /// reason if no TPM is present (callers run in degraded mode).
        pub fn open() -> Result<Self, String> {
            let mut ctx = Context::new(TctiNameConf::Device(DeviceConfig::default()))
                .map_err(|e| format!("TPM open failed: {e:?}"))?;
            let tpm = read_pcr(&mut ctx)?;
            if tpm != [0u8; 32] {
                // Prior extends present in this boot: previous SPiCa run or
                // tampering. Seed from the live value; only future epochs are
                // verified in-band — the offline quote covers full history.
                eprintln!(
                    "[PCR]        NOTE: PCR{PCR_INDEX} is non-zero at start — resuming anchor \
                     on existing value (previous run this boot, or tampering; offline quote \
                     distinguishes)"
                );
            }
            Ok(Self {
                ctx,
                epoch: 0,
                mirror: tpm,
                genesis_done: false,
            })
        }

        /// Genesis: the first anchor of a boot, binding the chain to a
        /// measured start. Called once after `open` when sealing is
        /// installed; extends PCR16 with `genesis_digest(secret)` (the
        /// secret obtainable only through the satisfied PCR policy) and
        /// advances the mirror. Epoch counter stays at 0 — epochs number
        /// the *heartbeat* anchors that follow.
        pub fn genesis(&mut self, secret: &[u8; 32]) -> Result<[u8; 32], String> {
            let value = spica_common::genesis_digest(secret);
            self.mirror = pcr_step(self.mirror, value);
            extend_pcr(&mut self.ctx, value).map_err(|e| format!("genesis extend: {e:?}"))?;
            self.genesis_done = true;
            match read_pcr(&mut self.ctx) {
                Ok(tpm) if tpm == self.mirror => Ok(self.mirror),
                Ok(tpm) => Err(format!(
                    "genesis read-back diverged: mirror {} != tpm {}",
                    self.mirror.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    tpm.iter().map(|b| format!("{b:02x}")).collect::<String>()
                )),
                Err(e) => Err(format!("genesis read-back failed: {e}")),
            }
        }

        /// One epoch: extend the PCR with the anchor digest of `snapshot`,
        /// then read the PCR back and compare against the local mirror.
        pub fn tick(&mut self, snapshot: &ChainSnapshot) -> TickOutcome {
            self.epoch += 1;
            let anchor = anchor_digest(self.epoch, snapshot);
            self.mirror = pcr_step(self.mirror, anchor);

            if let Err(e) = extend_pcr(&mut self.ctx, anchor) {
                eprintln!("[PCR]        extend failed at epoch {}: {e:?}", self.epoch);
                return TickOutcome::Failed { epoch: self.epoch };
            }
            match read_pcr(&mut self.ctx) {
                Ok(tpm) if tpm == self.mirror => TickOutcome::Extended {
                    epoch: self.epoch,
                    mirror: self.mirror,
                },
                Ok(tpm) => TickOutcome::Diverged {
                    epoch: self.epoch,
                    mirror: self.mirror,
                    tpm,
                },
                Err(e) => {
                    eprintln!(
                        "[PCR]        read-back failed at epoch {}: {e:?}",
                        self.epoch
                    );
                    TickOutcome::Failed { epoch: self.epoch }
                }
            }
        }

        pub fn epoch(&self) -> u64 {
            self.epoch
        }

        /// True when no genesis has been extended in this PcrAnchor's
        /// lifetime. Daemon restarts within a boot reopen the anchor on a
        /// PCR16 that already carries this boot's genesis (and epochs) — the
        /// secret is not re-extended; the mirror simply resumes from the
        /// live value.
        pub fn genesis_pending(&self) -> bool {
            self.epoch == 0 && !self.genesis_done
        }
    }

    fn extend_pcr(ctx: &mut Context, value: [u8; 32]) -> Result<(), tss_esapi::Error> {
        let digest = Digest::try_from(value.to_vec())?;
        let mut vals = DigestValues::new();
        vals.set(HashingAlgorithm::Sha256, digest);
        // PCR_Extend authorizes the PCR handle: an empty-password session is
        // required. execute_without_session sends ESYS_TR_NONE (no auth at
        // all) and the TPM rejects the command; AuthSession::Password sends
        // ESYS_TR_PASSWORD with the (empty) auth value.
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.pcr_extend(PcrHandle::Pcr16, vals)
        })
    }

    fn read_pcr(ctx: &mut Context) -> Result<[u8; 32], String> {
        let selection = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
            .build()
            .map_err(|e| format!("selection: {e:?}"))?;
        let (_, _, digests) = ctx
            .execute_without_session(|ctx| ctx.pcr_read(selection))
            .map_err(|e| format!("pcr_read: {e:?}"))?;
        let first = digests
            .value()
            .first()
            .ok_or_else(|| "pcr_read returned no digest".to_string())?;
        <[u8; 32]>::try_from(first.clone()).map_err(|e| format!("digest size: {e:?}"))
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    //! Non-Linux hosts (macOS dev machines): no TPM. The runtime runs in
    //! degraded mode with a loud one-time banner; the anchor digest math is
    //! exercised by the spica-common unit tests instead.

    pub struct PcrAnchor;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TickOutcome {
        Unavailable,
    }

    impl PcrAnchor {
        pub fn open() -> Result<Self, String> {
            Err("TPM unavailable: non-Linux host (PCR anchoring disabled)".to_string())
        }

        pub fn tick(&mut self, _snapshot: &[(u32, u64, u64)]) -> TickOutcome {
            TickOutcome::Unavailable
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use imp::{PcrAnchor, TickOutcome};
