//! The length-framed key codec plus the three node keys and their fail-closed decoders (carved out of `lib.rs`).

use crate::*;
use razel_core::{Error, Key, KindId};
use razel_ids::ConfigId;
use std::collections::BTreeMap;

// ──────────────── the hand-rolled length-framed codec plumbing (fail-closed, u64 BE framing) ────────────────

pub(crate) fn enc_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u64).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
}

/// A byte cursor for fail-closed key decoding (a malformed key is a typed error, never a silent default).
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
    what: &'static str,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8], what: &'static str) -> Self {
        Self { b, i: 0, what }
    }
    fn err(&self, detail: &str) -> Error {
        Error::Invalid { what: self.what.into(), detail: detail.into() }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.i.checked_add(n).filter(|&e| e <= self.b.len()).ok_or_else(|| self.err("truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        let raw = self.take(8)?;
        let arr: [u8; 8] = raw.try_into().map_err(|_| self.err("bad length prefix"))?;
        Ok(u64::from_be_bytes(arr))
    }
    fn str(&mut self) -> Result<String, Error> {
        let n = self.u64()? as usize;
        let s = self.take(n)?;
        String::from_utf8(s.to_vec()).map_err(|_| self.err("non-utf8"))
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(self.err(&format!("bad bool tag {t}"))),
        }
    }
    fn done(&self) -> Result<(), Error> {
        if self.i != self.b.len() {
            return Err(self.err("trailing bytes"));
        }
        Ok(())
    }
}

// ──────────────── TOOLCHAIN_CONTEXT key: the frozen ~6-dim surface (lockdown §2) ────────────────

/// The toolchain-context key (mirror Bazel `ToolchainContextKey.java:53-61`). The ONE keyed configuration
/// dimension is `configuration` — the target platform is DERIVED from it (decision C), never a peer field.
/// Construct via [`ToolchainContextKey::new`], which canonicalizes (type set sorted + strictest-deduped;
/// exec constraints sorted + deduped) so equal requests are byte-identical keys (Eq iff byte-identical).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ToolchainContextKey {
    /// The one keyed config dim; the target platform is derived from it (decision C).
    pub configuration: ConfigId,
    /// The requested SET (sorted by type id, strictest-deduped) (decision D).
    pub toolchain_types: Vec<ToolchainTypeReq>,
    /// Extra exec filters (sorted, deduped). Empty in v1 (sentinel: length 0).
    pub exec_constraint_labels: Vec<Constraint>,
    /// `None` in v1 (sentinel: tag 0).
    pub force_exec_platform: Option<String>,
    /// `false` in v1.
    pub debug_target: bool,
}
impl ToolchainContextKey {
    /// The canonicalizing constructor: sorts the type set by type id with STRICTEST dedup (a duplicated
    /// type keeps `mandatory = true` if ANY duplicate was mandatory — Bazel `ToolchainTypeRequirement
    /// .strictest`), and sorts + dedups the exec-constraint labels. Two logically-equal requests therefore
    /// encode byte-identically (the canonical-encoding law, REQ-CORE-014).
    pub fn new(
        configuration: ConfigId,
        toolchain_types: Vec<ToolchainTypeReq>,
        exec_constraint_labels: Vec<Constraint>,
        force_exec_platform: Option<String>,
        debug_target: bool,
    ) -> Self {
        let mut by_type: BTreeMap<ToolchainType, bool> = BTreeMap::new();
        for req in toolchain_types {
            let mandatory = by_type.entry(req.toolchain_type).or_insert(false);
            *mandatory = *mandatory || req.mandatory; // strictest wins
        }
        let toolchain_types = by_type
            .into_iter()
            .map(|(toolchain_type, mandatory)| ToolchainTypeReq { toolchain_type, mandatory })
            .collect();
        let mut exec = exec_constraint_labels;
        exec.sort();
        exec.dedup();
        Self { configuration, toolchain_types, exec_constraint_labels: exec, force_exec_platform, debug_target }
    }
}
impl Key for ToolchainContextKey {
    fn kind(&self) -> KindId {
        TOOLCHAIN_CONTEXT
    }
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        self.configuration.encode_into(&mut b);
        b.extend_from_slice(&(self.toolchain_types.len() as u64).to_be_bytes());
        for req in &self.toolchain_types {
            enc_str(&mut b, &req.toolchain_type.0);
            b.push(req.mandatory as u8);
        }
        if cfg!(feature = "mutant_toolchain_key_drops_reserved_dims") {
            // MUTANT: the reserved dims vanish from the identity → keys differing only in an exec
            // constraint / forced platform / debug bit COLLIDE (the under-keying trap).
            return b;
        }
        b.extend_from_slice(&(self.exec_constraint_labels.len() as u64).to_be_bytes());
        for c in &self.exec_constraint_labels {
            enc_str(&mut b, &c.0);
        }
        match &self.force_exec_platform {
            None => b.push(0), // the fixed v1 sentinel: a future non-null value is a DIFFERENT key
            Some(p) => {
                b.push(1);
                enc_str(&mut b, p);
            }
        }
        b.push(self.debug_target as u8);
        b
    }
}
pub(crate) fn decode_ctx_key(bytes: &[u8]) -> Result<ToolchainContextKey, Error> {
    let mut c = Cur::new(bytes, "TOOLCHAIN_CONTEXT key");
    let configuration = ConfigId(c.str()?);
    let n = c.u64()? as usize;
    let mut toolchain_types = Vec::with_capacity(n);
    for _ in 0..n {
        let toolchain_type = ToolchainType(c.str()?);
        let mandatory = c.bool()?;
        toolchain_types.push(ToolchainTypeReq { toolchain_type, mandatory });
    }
    let n = c.u64()? as usize;
    let mut exec_constraint_labels = Vec::with_capacity(n);
    for _ in 0..n {
        exec_constraint_labels.push(Constraint(c.str()?));
    }
    let force_exec_platform = match c.byte()? {
        0 => None,
        1 => Some(c.str()?),
        t => return Err(Error::Invalid { what: "TOOLCHAIN_CONTEXT key".into(), detail: format!("bad option tag {t}") }),
    };
    let debug_target = c.bool()?;
    c.done()?;
    Ok(ToolchainContextKey { configuration, toolchain_types, exec_constraint_labels, force_exec_platform, debug_target })
}

// ──────────────── REGISTERED_TOOLCHAINS / REGISTERED_EXECUTION_PLATFORMS: the dependency nodes ────────────────

/// Key of the registered-toolchain set node — keyed by CONFIGURATION only (decision A; mirrors Bazel
/// `RegisteredToolchainsValue` keyed on `(BuildConfigurationKey, debug)`; a debug bit can join later).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RegisteredToolchainsKey {
    pub configuration: ConfigId,
}
impl Key for RegisteredToolchainsKey {
    fn kind(&self) -> KindId {
        REGISTERED_TOOLCHAINS
    }
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        self.configuration.encode_into(&mut b);
        b
    }
}
pub(crate) fn decode_registered_toolchains_key(bytes: &[u8]) -> Result<RegisteredToolchainsKey, Error> {
    let mut c = Cur::new(bytes, "REGISTERED_TOOLCHAINS key");
    let configuration = ConfigId(c.str()?);
    c.done()?;
    Ok(RegisteredToolchainsKey { configuration })
}

/// Key of the registered execution-platform set node — same shape (Bazel-faithful:
/// `RegisteredExecutionPlatformsValue` is its own SkyValue, keyed by configuration).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RegisteredExecutionPlatformsKey {
    pub configuration: ConfigId,
}
impl Key for RegisteredExecutionPlatformsKey {
    fn kind(&self) -> KindId {
        REGISTERED_EXECUTION_PLATFORMS
    }
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        self.configuration.encode_into(&mut b);
        b
    }
}
pub(crate) fn decode_registered_exec_platforms_key(bytes: &[u8]) -> Result<RegisteredExecutionPlatformsKey, Error> {
    let mut c = Cur::new(bytes, "REGISTERED_EXECUTION_PLATFORMS key");
    let configuration = ConfigId(c.str()?);
    c.done()?;
    Ok(RegisteredExecutionPlatformsKey { configuration })
}

