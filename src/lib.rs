//! `razel-toolchain` — toolchain resolution (phase #4, the G4 exam), reworked to the RATIFIED ADR-0010 key
//! lockdown (`dev-docs/RazelV4ToolchainKeyLockdown.md` §2). The heart is still `resolve`: a pure,
//! constraint-matching selection over registered toolchains — **data-driven, never a host fixture**; fail
//! closed (a typed error) if none matches — never a default. Around it, the frozen surface:
//!
//! * `ToolchainContextKey` — keyed on `configuration` (`ConfigId`; the **target platform is DERIVED from
//!   it**, decision C — see [`derive_target_platform`]), the requested toolchain-type **SET** with mandatory
//!   flags (sorted by type id, strictest-deduped — decision D), exec-constraint labels (sorted, deduped),
//!   `force_exec_platform` + `debug_target` (reserved dims with fixed v1 sentinels: `None` = tag 0, empty
//!   `Vec` = length 0 — a future non-null value is a *different* key, mirroring the CT-key discipline).
//! * `ResolvedToolchainContextValue` — ONE resolved context for the whole set (decision B): the selected
//!   exec platform (decision F), the derived target platform, and `type_to_resolved` (a missing OPTIONAL
//!   type is simply absent; a missing MANDATORY type fails closed NAMING the type — decision E).
//! * `REGISTERED_TOOLCHAINS` / `REGISTERED_EXECUTION_PLATFORMS` — the registered sets as config-keyed
//!   **dependency nodes** (decision A: invalidation flows through the engine edge + value-equality
//!   early-cutoff; **nothing about the registered set enters any key**). v1 bodies are host-injected,
//!   served from a shared mutable [`ToolchainRegistry`] (the `MutFs` pattern) so a registration change can
//!   be applied + dirtied against a RUNNING engine; `.bzl` `register_toolchains()`/`platform()` later fill
//!   the same nodes behind the same edge — additive, no key change, no rip-out.
//!
//! SPIKE remnants (deliberate, additive): constraints are opaque label strings; platform DEFINITIONS
//! (name → constraints) are injected at the composition root (a real platform node is deferred).

use razel_bzl_api::{encode_provider_instance, ProviderInstance};
use razel_core::{Digest, Error, Key, KindId, NodeKey, Value, ValuePolicy};
use razel_engine_api::{ComputeResult, Demand, DemandContext, DemandEngine, NodeFunction};
use razel_ids::ConfigId;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// Node-kind id for the resolved toolchain CONTEXT (the analysis phase requests ONE per required type-set).
pub const TOOLCHAIN_CONTEXT: KindId = KindId(50);
/// Node-kind id for the config-keyed registered-toolchain set (decision A — a dependency node, never a key).
pub const REGISTERED_TOOLCHAINS: KindId = KindId(51);
/// Node-kind id for the config-keyed registered execution-platform set (Bazel-faithful: its own SkyValue).
pub const REGISTERED_EXECUTION_PLATFORMS: KindId = KindId(52);

/// An opaque constraint label (e.g. `"@platforms//os:linux"`). SPIKE: a string; the setting/value structure is
/// deferred (a platform either carries a constraint label or it doesn't — that's all matching needs here).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Constraint(pub String);

/// A platform DEFINITION: the set of constraints it satisfies (e.g. `[os:linux, cpu:x86_64]`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Platform {
    pub constraints: Vec<Constraint>,
}

/// A toolchain TYPE id (e.g. `"//tools/cpp:toolchain_type"`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ToolchainType(pub String);

/// One requested toolchain type + its mandatory flag — the key's set element (decision D; mirrors Bazel
/// `ToolchainTypeRequirement`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ToolchainTypeReq {
    pub toolchain_type: ToolchainType,
    pub mandatory: bool,
}

/// A registered toolchain: which TYPE it implements, the target constraints it requires, the exec-platform
/// constraints it requires (`exec_compatible_with` — checked against the candidate exec platform), and the
/// `toolchain_info` provider it carries (returned to the rule as `ctx.toolchains[type]`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegisteredToolchain {
    pub toolchain_type: ToolchainType,
    pub target_compatible_with: Vec<Constraint>,
    pub exec_compatible_with: Vec<Constraint>,
    pub info: ProviderInstance,
}

/// A registered EXECUTION platform: its identity (name) + the constraints it provides. The candidate list
/// for exec-platform selection (decision F) is the registered set + the host platform appended last.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegisteredExecPlatform {
    pub name: String,
    pub constraints: Vec<Constraint>,
}

/// Resolve the toolchain of `required` type for a target `platform`, over the `registered` set. Data-driven:
/// the first registered toolchain of that type whose `target_compatible_with` ⊆ `platform.constraints` wins.
/// Fail-closed: if none matches, a typed `NotFound` — NEVER a default/fixture (the anti-#4 guarantee).
/// (The internal per-type pass of the context node; exec-compatibility is the CALLER's pre-filter.)
pub fn resolve(
    platform: &Platform,
    required: &ToolchainType,
    registered: &[RegisteredToolchain],
) -> Result<ProviderInstance, Error> {
    for t in registered {
        if &t.toolchain_type != required {
            continue;
        }
        let compatible = if cfg!(feature = "mutant_toolchain_ignores_constraints") {
            // MUTANT: ignore the constraints → first toolchain of the type wins regardless of the platform.
            // That is exactly the v3 fixture-ish failure (selection not data-driven).
            true
        } else {
            t.target_compatible_with.iter().all(|c| platform.constraints.contains(c))
        };
        if compatible {
            return Ok(t.info.clone());
        }
    }
    Err(Error::NotFound {
        what: "toolchain".into(),
        detail: format!("no registered toolchain of type '{}' is compatible with the target platform", required.0),
    })
}

// ──────────────── the hand-rolled length-framed codec plumbing (fail-closed, u64 BE framing) ────────────────

fn enc_str(b: &mut Vec<u8>, s: &str) {
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
fn decode_ctx_key(bytes: &[u8]) -> Result<ToolchainContextKey, Error> {
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
fn decode_registered_toolchains_key(bytes: &[u8]) -> Result<RegisteredToolchainsKey, Error> {
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
fn decode_registered_exec_platforms_key(bytes: &[u8]) -> Result<RegisteredExecutionPlatformsKey, Error> {
    let mut c = Cur::new(bytes, "REGISTERED_EXECUTION_PLATFORMS key");
    let configuration = ConfigId(c.str()?);
    c.done()?;
    Ok(RegisteredExecutionPlatformsKey { configuration })
}

/// Canonical encoding of one registered toolchain (all runs length-framed; the info via the ONE
/// razel-bzl-api provider codec) — the digest unit for `RegisteredToolchainsValue`.
fn encode_registered_toolchain(t: &RegisteredToolchain, b: &mut Vec<u8>) {
    enc_str(b, &t.toolchain_type.0);
    b.extend_from_slice(&(t.target_compatible_with.len() as u64).to_be_bytes());
    for c in &t.target_compatible_with {
        enc_str(b, &c.0);
    }
    b.extend_from_slice(&(t.exec_compatible_with.len() as u64).to_be_bytes());
    for c in &t.exec_compatible_with {
        enc_str(b, &c.0);
    }
    encode_provider_instance(&t.info, b);
}

/// The registered-toolchain set for one configuration. `comparable` — an EQUAL set early-cuts the context
/// (the decision-A invalidation story: the edge dirties, value-equality prunes).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegisteredToolchainsValue {
    pub toolchains: Vec<RegisteredToolchain>,
}
impl Value for RegisteredToolchainsValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<RegisteredToolchainsValue>().is_some_and(|o| o == self)
    }
    fn content_digest(&self) -> Digest {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.toolchains.len() as u64).to_be_bytes());
        for t in &self.toolchains {
            encode_registered_toolchain(t, &mut b);
        }
        Digest::of(&b)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The registered execution-platform set for one configuration. Same comparable/early-cutoff story.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegisteredExecutionPlatformsValue {
    pub platforms: Vec<RegisteredExecPlatform>,
}
impl Value for RegisteredExecutionPlatformsValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<RegisteredExecutionPlatformsValue>().is_some_and(|o| o == self)
    }
    fn content_digest(&self) -> Digest {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.platforms.len() as u64).to_be_bytes());
        for p in &self.platforms {
            enc_str(&mut b, &p.name);
            b.extend_from_slice(&(p.constraints.len() as u64).to_be_bytes());
            for c in &p.constraints {
                enc_str(&mut b, &c.0);
            }
        }
        Digest::of(&b)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The shared mutable registration store (the `MutFs` pattern): the v1 HOST-INJECTED bodies of the two
/// REGISTERED_* nodes, keyed by configuration. The composition root creates one, hands it to
/// [`register_toolchain_kinds`], and returns the handle to the caller — so a test (and later a real
/// registration producer) can MUTATE the set under a RUNNING engine and dirty the node via
/// `evaluate(.., Diff{changed: [RegisteredToolchainsKey(config)]})`. An unregistered configuration has an
/// EMPTY registered set (a real state — `register_toolchains()` was never called — not an absorb).
#[derive(Default)]
pub struct ToolchainRegistry {
    inner: Mutex<RegistryState>,
}
#[derive(Default)]
struct RegistryState {
    toolchains: HashMap<String, Vec<RegisteredToolchain>>,
    exec_platforms: HashMap<String, Vec<RegisteredExecPlatform>>,
}
impl ToolchainRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_toolchains(&self, configuration: &ConfigId, toolchains: Vec<RegisteredToolchain>) {
        self.inner.lock().unwrap().toolchains.insert(configuration.0.clone(), toolchains);
    }
    pub fn set_exec_platforms(&self, configuration: &ConfigId, platforms: Vec<RegisteredExecPlatform>) {
        self.inner.lock().unwrap().exec_platforms.insert(configuration.0.clone(), platforms);
    }
    pub fn toolchains_for(&self, configuration: &ConfigId) -> Vec<RegisteredToolchain> {
        self.inner.lock().unwrap().toolchains.get(&configuration.0).cloned().unwrap_or_default()
    }
    pub fn exec_platforms_for(&self, configuration: &ConfigId) -> Vec<RegisteredExecPlatform> {
        self.inner.lock().unwrap().exec_platforms.get(&configuration.0).cloned().unwrap_or_default()
    }
}

/// `REGISTERED_TOOLCHAINS`: serve the host-injected registered set for the keyed configuration (a leaf in
/// v1; the `.bzl` `register_toolchains()` producer later computes it from the module graph BEHIND this same
/// node — additive, the edge above never changes).
pub struct RegisteredToolchainsFn {
    store: Arc<ToolchainRegistry>,
}
impl NodeFunction for RegisteredToolchainsFn {
    fn compute(&self, key: &NodeKey, _ctx: &mut dyn DemandContext) -> ComputeResult {
        let k = match decode_registered_toolchains_key(key.canonical()) {
            Ok(k) => k,
            Err(e) => return ComputeResult::Error(e),
        };
        ComputeResult::Ready(Arc::new(RegisteredToolchainsValue { toolchains: self.store.toolchains_for(&k.configuration) }))
    }
}

/// `REGISTERED_EXECUTION_PLATFORMS`: same pattern for the exec-platform candidate list (decision F rides
/// this node's value, + the host platform appended by the context node).
pub struct RegisteredExecutionPlatformsFn {
    store: Arc<ToolchainRegistry>,
}
impl NodeFunction for RegisteredExecutionPlatformsFn {
    fn compute(&self, key: &NodeKey, _ctx: &mut dyn DemandContext) -> ComputeResult {
        let k = match decode_registered_exec_platforms_key(key.canonical()) {
            Ok(k) => k,
            Err(e) => return ComputeResult::Error(e),
        };
        ComputeResult::Ready(Arc::new(RegisteredExecutionPlatformsValue {
            platforms: self.store.exec_platforms_for(&k.configuration),
        }))
    }
}

// ──────────────── the resolved context value (lockdown §2, decision B) ────────────────

/// The full resolved toolchain context — ONE value for the whole requested set (mirror Bazel
/// `UnloadedToolchainContext`). A missing OPTIONAL type is absent from `type_to_resolved` (decision E).
/// Comparable: an equal re-resolved context early-cuts dependents (the decision-A pruning).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedToolchainContextValue {
    /// The ONE chosen exec platform (decision F).
    pub selected_exec_platform: String,
    /// Derived from the configuration (decision C) — recorded, not keyed.
    pub target_platform: String,
    /// type → resolved `toolchain_info` (optional-missing absent).
    pub type_to_resolved: BTreeMap<ToolchainType, ProviderInstance>,
}
impl Value for ResolvedToolchainContextValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<ResolvedToolchainContextValue>().is_some_and(|o| o == self)
    }
    fn content_digest(&self) -> Digest {
        // Deterministic frame: the two platform strings (length-framed — they ARE part of the value's
        // identity), then count + length-framed type ids + each info via the ONE canonical razel-bzl-api
        // provider codec (the single source of truth, so this can't drift from the analysis digests).
        let mut b = Vec::new();
        enc_str(&mut b, &self.selected_exec_platform);
        enc_str(&mut b, &self.target_platform);
        b.extend_from_slice(&(self.type_to_resolved.len() as u64).to_be_bytes());
        for (ty, info) in &self.type_to_resolved {
            enc_str(&mut b, &ty.0);
            encode_provider_instance(info, &mut b);
        }
        Digest::of(&b)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ──────────────── TOOLCHAIN_CONTEXT node: resolve the full type set for one configuration ────────────────

/// THE one isolated target-platform derivation seam (decision C): the target platform is DERIVED from the
/// configuration, never a peer key dimension. v1 minimal cut: the configuration string IS the target
/// platform name (identity). A real platform/config-fragment node slots in HERE — one call site — without
/// touching the key.
fn derive_target_platform(configuration: &ConfigId) -> String {
    configuration.0.clone()
}

/// Is this requested type mandatory for fail-closed purposes (decision E)?
fn req_is_mandatory(req: &ToolchainTypeReq) -> bool {
    // MUTANT: treat every requested type as mandatory — a missing OPTIONAL then errors (decision E regresses).
    req.mandatory || cfg!(feature = "mutant_toolchain_optional_treated_mandatory")
}

/// One exec-platform candidate's resolution attempt: what it resolved, per requested type.
struct CandidateResolution {
    name: String,
    resolved: BTreeMap<ToolchainType, ProviderInstance>,
    supplies_all_mandatory: bool,
}

/// `TOOLCHAIN_CONTEXT`: resolve the requested toolchain-type SET for the keyed configuration into ONE
/// context. A REAL dependency node: it `ctx.request`s the two config-keyed REGISTERED_* nodes
/// (restart-style) — the decision-A invalidation edges — then derives the target platform from the
/// configuration, selects one exec platform (decision F: candidates = registered + host appended, filtered
/// by the key's exec constraints, first-in-registration-order supplying ALL mandatory types with an
/// optional-count tiebreak), and runs the per-type `resolve` pass per (type × candidate).
pub struct ToolchainContextFn {
    /// The shared registration store — read ONLY under the headline mutant (the leaf shape); the real path
    /// reads through the engine edges.
    store: Arc<ToolchainRegistry>,
    /// Platform DEFINITIONS (name → constraints) — injected config-data in v1 (a platform node later).
    platforms: HashMap<String, Platform>,
    /// The host platform — ALWAYS appended as the final exec-platform candidate (decision F; Bazel
    /// `PlatformKeys.java:147-152`).
    host_platform: RegisteredExecPlatform,
}
impl ToolchainContextFn {
    pub fn new(
        store: Arc<ToolchainRegistry>,
        platforms: HashMap<String, Platform>,
        host_platform: RegisteredExecPlatform,
    ) -> Self {
        Self { store, platforms, host_platform }
    }
}
impl NodeFunction for ToolchainContextFn {
    fn compute(&self, key: &NodeKey, ctx: &mut dyn DemandContext) -> ComputeResult {
        let ctk = match decode_ctx_key(key.canonical()) {
            Ok(k) => k,
            Err(e) => return ComputeResult::Error(e),
        };

        // (1) the two registry deps — REAL engine edges (decision A: a registration change flows through
        // them; an equal set / equal resolved context early-cuts).
        let registered: Vec<RegisteredToolchain>;
        let exec_platforms: Vec<RegisteredExecPlatform>;
        if cfg!(feature = "mutant_toolchain_registered_set_not_a_dep") {
            // MUTANT (the headline): bake the registered sets in as a LEAF again — the spike shape. No
            // dependency edge is recorded, so a `register_toolchains()` change invalidates NOTHING and the
            // warm engine serves a stale resolved context.
            registered = self.store.toolchains_for(&ctk.configuration);
            exec_platforms = self.store.exec_platforms_for(&ctk.configuration);
        } else {
            let reg_tc_key = NodeKey::from_key(&RegisteredToolchainsKey { configuration: ctk.configuration.clone() });
            let reg_ep_key =
                NodeKey::from_key(&RegisteredExecutionPlatformsKey { configuration: ctk.configuration.clone() });
            let keys = [reg_tc_key, reg_ep_key];
            let demands = ctx.request_group(&keys);
            let mut missing: Vec<NodeKey> = Vec::new();
            let mut ready: Vec<Option<razel_core::NodeValue>> = Vec::new();
            for (i, d) in demands.into_iter().enumerate() {
                match d {
                    Demand::Ready(v) => ready.push(Some(v)),
                    Demand::Missing => {
                        ready.push(None);
                        missing.push(keys[i].clone());
                    }
                }
            }
            if !missing.is_empty() {
                return ComputeResult::Missing { recorded_dep_keys: missing };
            }
            registered = match ready[0].as_ref().unwrap().as_any().downcast_ref::<RegisteredToolchainsValue>() {
                Some(v) => v.toolchains.clone(),
                None => {
                    return ComputeResult::Error(Error::Invalid {
                        what: "REGISTERED_TOOLCHAINS value".into(),
                        detail: "not a RegisteredToolchainsValue".into(),
                    })
                }
            };
            exec_platforms = match ready[1].as_ref().unwrap().as_any().downcast_ref::<RegisteredExecutionPlatformsValue>() {
                Some(v) => v.platforms.clone(),
                None => {
                    return ComputeResult::Error(Error::Invalid {
                        what: "REGISTERED_EXECUTION_PLATFORMS value".into(),
                        detail: "not a RegisteredExecutionPlatformsValue".into(),
                    })
                }
            };
        }

        // (2) the target platform — DERIVED from the configuration (decision C), then resolved to its
        // constraint set via the injected platform definitions (fail-closed on an unknown platform).
        let target_platform_name = derive_target_platform(&ctk.configuration);
        let target_platform = match self.platforms.get(&target_platform_name) {
            Some(p) => p.clone(),
            None => return ComputeResult::Error(Error::NotFound { what: "platform".into(), detail: target_platform_name }),
        };

        // (3) exec-platform candidates (decision F): registered exec platforms + the host appended LAST
        // (Bazel PlatformKeys.java:147-152); a forced platform restricts the list (fail-closed if unknown);
        // then the key's exec-constraint labels filter.
        let mut candidates: Vec<RegisteredExecPlatform> = exec_platforms;
        candidates.push(self.host_platform.clone());
        if let Some(forced) = &ctk.force_exec_platform {
            candidates.retain(|c| &c.name == forced);
            if candidates.is_empty() {
                return ComputeResult::Error(Error::NotFound {
                    what: "forced exec platform".into(),
                    detail: format!("'{forced}' is not a registered execution platform (nor the host)"),
                });
            }
        }
        candidates.retain(|c| ctk.exec_constraint_labels.iter().all(|l| c.constraints.contains(l)));

        // (4) per (candidate × type): the existing per-type `resolve` pass (target constraints), over the
        // subset of registered toolchains whose `exec_compatible_with` the candidate satisfies.
        let attempts: Vec<CandidateResolution> = candidates
            .iter()
            .map(|cand| {
                let eligible: Vec<RegisteredToolchain> = registered
                    .iter()
                    .filter(|t| t.exec_compatible_with.iter().all(|c| cand.constraints.contains(c)))
                    .cloned()
                    .collect();
                let mut resolved: BTreeMap<ToolchainType, ProviderInstance> = BTreeMap::new();
                for req in &ctk.toolchain_types {
                    if let Ok(info) = resolve(&target_platform, &req.toolchain_type, &eligible) {
                        resolved.insert(req.toolchain_type.clone(), info);
                    }
                }
                let supplies_all_mandatory = ctk
                    .toolchain_types
                    .iter()
                    .filter(|r| req_is_mandatory(r))
                    .all(|r| resolved.contains_key(&r.toolchain_type));
                CandidateResolution { name: cand.name.clone(), resolved, supplies_all_mandatory }
            })
            .collect();

        // (5) selection (decision F, Bazel ToolchainResolutionFunction.java:324-358): among candidates
        // supplying ALL mandatory types, pick the one resolving the MOST requested types (every viable
        // candidate supplies all mandatory, so the surplus is the optional count); a tie keeps the
        // EARLIEST candidate (registration order first; host last) — a stable max.
        let selected: Option<CandidateResolution> = if cfg!(feature = "mutant_toolchain_exec_selection_first_candidate") {
            // MUTANT: the first candidate wins regardless of whether it supplies the mandatory types.
            attempts.into_iter().next()
        } else {
            attempts.into_iter().filter(|c| c.supplies_all_mandatory).fold(None, |best, c| match best {
                None => Some(c),
                Some(b) if c.resolved.len() > b.resolved.len() => Some(c),
                Some(b) => Some(b),
            })
        };
        let selected = match selected {
            Some(s) => s,
            None => {
                // Fail-closed (decision E): NAME the mandatory type(s) that could not be supplied.
                let mandatory: Vec<String> = ctk
                    .toolchain_types
                    .iter()
                    .filter(|r| req_is_mandatory(r))
                    .map(|r| r.toolchain_type.0.clone())
                    .collect();
                return ComputeResult::Error(Error::NotFound {
                    what: "toolchain".into(),
                    detail: format!(
                        "no execution platform supplies all mandatory toolchain type(s) [{}] for target platform '{}'",
                        mandatory.join(", "),
                        target_platform_name
                    ),
                });
            }
        };
        // Belt (decision E, fail-closed even if selection were wrong): every mandatory type MUST be present.
        for req in &ctk.toolchain_types {
            if req_is_mandatory(req) && !selected.resolved.contains_key(&req.toolchain_type) {
                return ComputeResult::Error(Error::NotFound {
                    what: "toolchain".into(),
                    detail: format!(
                        "mandatory toolchain type '{}' is not supplied by the selected execution platform '{}'",
                        req.toolchain_type.0, selected.name
                    ),
                });
            }
        }

        ComputeResult::Ready(Arc::new(ResolvedToolchainContextValue {
            selected_exec_platform: selected.name,
            target_platform: target_platform_name,
            type_to_resolved: selected.resolved,
        }))
    }
}

/// Register the three toolchain node-kinds. The composition root supplies the shared registration store
/// (the handle it keeps so registrations can be seeded/mutated against the RUNNING engine), the platform
/// definitions, and the host platform (always the final exec candidate).
pub fn register_toolchain_kinds(
    engine: &mut dyn DemandEngine,
    store: Arc<ToolchainRegistry>,
    platforms: HashMap<String, Platform>,
    host_platform: RegisteredExecPlatform,
) {
    engine.register(TOOLCHAIN_CONTEXT, Box::new(ToolchainContextFn::new(store.clone(), platforms, host_platform)));
    engine.register(REGISTERED_TOOLCHAINS, Box::new(RegisteredToolchainsFn { store: store.clone() }));
    engine.register(REGISTERED_EXECUTION_PLATFORMS, Box::new(RegisteredExecutionPlatformsFn { store }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use razel_bzl_api::{BzlValue, ProviderId};
    use razel_core::NodeValue;

    fn cc(tag: &str, os: &str) -> RegisteredToolchain {
        RegisteredToolchain {
            toolchain_type: ToolchainType("//cc:toolchain_type".into()),
            target_compatible_with: vec![Constraint(format!("os:{os}"))],
            exec_compatible_with: vec![],
            info: ProviderInstance {
                provider: ProviderId::from_name("CcToolchainInfo"),
                fields: vec![("id".to_string(), BzlValue::Str(tag.into()))],
            },
        }
    }
    fn platform(os: &str) -> Platform {
        Platform { constraints: vec![Constraint(format!("os:{os}"))] }
    }
    fn ty() -> ToolchainType {
        ToolchainType("//cc:toolchain_type".into())
    }
    fn req(t: &str, mandatory: bool) -> ToolchainTypeReq {
        ToolchainTypeReq { toolchain_type: ToolchainType(t.into()), mandatory }
    }
    fn host() -> RegisteredExecPlatform {
        RegisteredExecPlatform { name: "host".into(), constraints: vec![] }
    }

    // ──────────────── resolve(): the per-type pass (unchanged discipline) ────────────────

    #[test]
    fn resolves_by_constraint_no_fixture() {
        // THE G4 property (unit level): two toolchains of one type; the platform picks the matching one, and
        // flipping the platform flips the selection — selection is DATA-DRIVEN, not a host fixture.
        let registered = vec![cc("linux-cc", "linux"), cc("macos-cc", "macos")];
        let pick = |os| resolve(&platform(os), &ty(), &registered).unwrap().get("id").cloned();
        assert_eq!(pick("linux"), Some(BzlValue::Str("linux-cc".into())));
        assert_eq!(
            pick("macos"),
            Some(BzlValue::Str("macos-cc".into())),
            "flipping the target platform flips the resolved toolchain (data-driven, no fixture)"
        );
    }

    #[test]
    fn no_matching_toolchain_is_fail_closed() {
        // No toolchain compatible with the platform → a typed error, NEVER a default/fixture.
        let registered = vec![cc("linux-cc", "linux")];
        assert!(
            matches!(resolve(&platform("windows"), &ty(), &registered), Err(Error::NotFound { .. })),
            "an unsatisfiable platform must fail closed (no compatible toolchain), never resolve to a default"
        );
    }

    #[test]
    fn wrong_type_is_fail_closed() {
        let registered = vec![cc("linux-cc", "linux")];
        assert!(
            resolve(&platform("linux"), &ToolchainType("//rust:toolchain_type".into()), &registered).is_err(),
            "a required type with no registered toolchain must fail closed"
        );
    }

    // ──────────────── the frozen key: canonical codec + distinct-key-per-dimension ────────────────

    fn base_key() -> ToolchainContextKey {
        ToolchainContextKey::new(
            ConfigId("cfg-a".into()),
            vec![req("//cc:toolchain_type", true), req("//rust:toolchain_type", false)],
            vec![Constraint("exec:gpu".into())],
            None,
            false,
        )
    }

    #[test]
    fn ctx_key_round_trips() {
        let k = base_key();
        assert_eq!(decode_ctx_key(&k.encode()).unwrap(), k, "the key must survive encode → decode");
        // and with the reserved dims populated (a future non-sentinel key round-trips too).
        let k2 = ToolchainContextKey::new(
            ConfigId("cfg-b".into()),
            vec![req("//cc:toolchain_type", true)],
            vec![],
            Some("ep1".into()),
            true,
        );
        assert_eq!(decode_ctx_key(&k2.encode()).unwrap(), k2);
    }

    #[test]
    fn ctx_key_distinct_per_dimension() {
        // EVERY dimension is in the identity: flipping any single one is a DIFFERENT key (the ADR-0010
        // `toolchain_context_key_*` gates; goes RED under `mutant_toolchain_key_drops_reserved_dims`).
        let base = base_key().encode();
        let mut k = base_key();
        k.configuration = ConfigId("cfg-b".into());
        assert_ne!(k.encode(), base, "configuration is keyed");
        let mut k = base_key();
        k.toolchain_types = vec![req("//cc:toolchain_type", true)];
        assert_ne!(k.encode(), base, "the requested type SET is keyed");
        let mut k = base_key();
        k.toolchain_types = vec![req("//cc:toolchain_type", true), req("//rust:toolchain_type", true)];
        assert_ne!(k.encode(), base, "a type's MANDATORY flag is keyed (optional vs mandatory sets differ)");
        let mut k = base_key();
        k.exec_constraint_labels = vec![];
        assert_ne!(k.encode(), base, "the exec-constraint labels are keyed (empty vs non-empty differ)");
        let mut k = base_key();
        k.force_exec_platform = Some("ep1".into());
        assert_ne!(k.encode(), base, "force_exec_platform is keyed (None sentinel vs Some differ)");
        let mut k = base_key();
        k.debug_target = true;
        assert_ne!(k.encode(), base, "debug_target is keyed");
    }

    #[test]
    fn ctx_key_canonicalizes_set_and_constraints() {
        // Order-insensitive + strictest-deduped: two spellings of the same request are ONE key.
        let a = ToolchainContextKey::new(
            ConfigId("c".into()),
            vec![req("//b:t", false), req("//a:t", true), req("//b:t", true)],
            vec![Constraint("x".into()), Constraint("x".into()), Constraint("a".into())],
            None,
            false,
        );
        let b = ToolchainContextKey::new(
            ConfigId("c".into()),
            vec![req("//b:t", true), req("//a:t", true)],
            vec![Constraint("a".into()), Constraint("x".into())],
            None,
            false,
        );
        assert_eq!(a.encode(), b.encode(), "sorted + strictest-deduped: dup type ⇒ mandatory wins");
        assert_eq!(a.toolchain_types, vec![req("//a:t", true), req("//b:t", true)]);
        assert_eq!(a.exec_constraint_labels, vec![Constraint("a".into()), Constraint("x".into())]);
    }

    #[test]
    fn ctx_key_decode_is_fail_closed() {
        let k = base_key().encode();
        assert!(matches!(decode_ctx_key(&k[..k.len() - 1]), Err(Error::Invalid { .. })), "truncated → typed error");
        let mut trailing = k.clone();
        trailing.push(0);
        assert!(matches!(decode_ctx_key(&trailing), Err(Error::Invalid { .. })), "trailing bytes → typed error");
        let mut bad_tag = k;
        let last = bad_tag.len() - 1;
        bad_tag[last] = 7; // debug_target byte must be 0|1
        assert!(matches!(decode_ctx_key(&bad_tag), Err(Error::Invalid { .. })), "bad bool tag → typed error");
    }

    // ──────────────── the context node over a stub DemandContext serving the registry values ────────────────

    use razel_engine_api::Demand;
    /// A stub context that SERVES the two registry values (the unit-level stand-in for the engine edge).
    struct ServeMap(HashMap<NodeKey, NodeValue>);
    impl DemandContext for ServeMap {
        fn request(&mut self, k: &NodeKey) -> Demand {
            match self.0.get(k) {
                Some(v) => Demand::Ready(v.clone()),
                None => Demand::Missing,
            }
        }
        fn request_group(&mut self, ks: &[NodeKey]) -> Vec<Demand> {
            ks.iter().map(|k| self.request(k)).collect()
        }
        fn register_dep(&mut self, _k: &NodeKey) {}
    }
    fn serve(cfg: &str, toolchains: Vec<RegisteredToolchain>, eps: Vec<RegisteredExecPlatform>) -> ServeMap {
        let mut m: HashMap<NodeKey, NodeValue> = HashMap::new();
        m.insert(
            NodeKey::from_key(&RegisteredToolchainsKey { configuration: ConfigId(cfg.into()) }),
            Arc::new(RegisteredToolchainsValue { toolchains }),
        );
        m.insert(
            NodeKey::from_key(&RegisteredExecutionPlatformsKey { configuration: ConfigId(cfg.into()) }),
            Arc::new(RegisteredExecutionPlatformsValue { platforms: eps }),
        );
        ServeMap(m)
    }
    fn ctx_fn(platforms: &[(&str, &str)]) -> ToolchainContextFn {
        let mut m = HashMap::new();
        for (name, os) in platforms {
            m.insert(name.to_string(), platform(os));
        }
        ToolchainContextFn::new(Arc::new(ToolchainRegistry::new()), m, host())
    }
    fn ctx_key(cfg: &str, types: Vec<ToolchainTypeReq>) -> NodeKey {
        NodeKey::from_key(&ToolchainContextKey::new(ConfigId(cfg.into()), types, vec![], None, false))
    }
    fn resolved(r: ComputeResult) -> ResolvedToolchainContextValue {
        match r {
            ComputeResult::Ready(v) => v.as_any().downcast_ref::<ResolvedToolchainContextValue>().unwrap().clone(),
            ComputeResult::Error(e) => panic!("expected Ready, got Error({e:?})"),
            _ => panic!("expected Ready"),
        }
    }

    #[test]
    fn context_requests_registries_restart_style() {
        // With neither registry value available, compute must record BOTH dep keys and return Missing —
        // never publish, never default (REQ-ENGINE-001/002).
        let f = ctx_fn(&[("p_linux", "linux")]);
        let r = f.compute(&ctx_key("p_linux", vec![req("//cc:toolchain_type", true)]), &mut ServeMap(HashMap::new()));
        match r {
            ComputeResult::Missing { recorded_dep_keys } => {
                assert_eq!(
                    recorded_dep_keys,
                    vec![
                        NodeKey::from_key(&RegisteredToolchainsKey { configuration: ConfigId("p_linux".into()) }),
                        NodeKey::from_key(&RegisteredExecutionPlatformsKey { configuration: ConfigId("p_linux".into()) }),
                    ],
                    "both config-keyed registry deps are recorded before restart"
                );
            }
            _ => panic!("expected Missing with the two registry dep keys"),
        }
    }

    #[test]
    fn context_reads_registered_set_through_the_dep_edge() {
        // The decision-A property at unit level: the context resolves against the value SERVED THROUGH the
        // dependency edge, not a baked-in store snapshot. The store is EMPTY here; only the stub-served
        // registry has the toolchain. RED under `mutant_toolchain_registered_set_not_a_dep` (the leaf shape
        // reads the empty store and fails).
        let f = ctx_fn(&[("p_linux", "linux")]);
        let mut ctx = serve("p_linux", vec![cc("linux-cc", "linux")], vec![]);
        let v = resolved(f.compute(&ctx_key("p_linux", vec![req("//cc:toolchain_type", true)]), &mut ctx));
        assert_eq!(v.type_to_resolved.get(&ty()).and_then(|i| i.get("id").cloned()), Some(BzlValue::Str("linux-cc".into())));
        assert_eq!(v.target_platform, "p_linux", "the target platform is DERIVED from the configuration");
        assert_eq!(v.selected_exec_platform, "host", "no registered exec platform → the appended host is selected");
    }

    #[test]
    fn context_resolves_by_derived_platform() {
        // The G4 property at node level: flipping the CONFIGURATION (the key dim) flips the derived target
        // platform and hence the resolved toolchain — data-driven, no fixture.
        let f = ctx_fn(&[("p_linux", "linux"), ("p_macos", "macos")]);
        let registered = vec![cc("linux-cc", "linux"), cc("macos-cc", "macos")];
        let pick = |cfg: &str| {
            let mut ctx = serve(cfg, registered.clone(), vec![]);
            resolved(f.compute(&ctx_key(cfg, vec![req("//cc:toolchain_type", true)]), &mut ctx))
                .type_to_resolved
                .get(&ty())
                .and_then(|i| i.get("id").cloned())
        };
        assert_eq!(pick("p_linux"), Some(BzlValue::Str("linux-cc".into())));
        assert_eq!(pick("p_macos"), Some(BzlValue::Str("macos-cc".into())), "config flip ⇒ resolution flip");
    }

    #[test]
    fn missing_mandatory_type_fails_closed_naming_it() {
        // Decision E: a mandatory type with no compatible toolchain is a typed NotFound NAMING the type.
        let f = ctx_fn(&[("p_linux", "linux")]);
        let mut ctx = serve("p_linux", vec![cc("linux-cc", "linux")], vec![]);
        let r = f.compute(
            &ctx_key("p_linux", vec![req("//cc:toolchain_type", true), req("//rust:toolchain_type", true)]),
            &mut ctx,
        );
        match r {
            ComputeResult::Error(Error::NotFound { detail, .. }) => {
                assert!(detail.contains("//rust:toolchain_type"), "the error must NAME the missing mandatory type: {detail}");
            }
            _ => panic!("a missing mandatory type must be a typed NotFound"),
        }
    }

    #[test]
    fn missing_optional_type_is_absent_not_an_error() {
        // Decision E: a missing OPTIONAL type resolves the context fine — it is simply absent from the map.
        // RED under `mutant_toolchain_optional_treated_mandatory`.
        let f = ctx_fn(&[("p_linux", "linux")]);
        let mut ctx = serve("p_linux", vec![cc("linux-cc", "linux")], vec![]);
        let v = resolved(f.compute(
            &ctx_key("p_linux", vec![req("//cc:toolchain_type", true), req("//rust:toolchain_type", false)]),
            &mut ctx,
        ));
        assert!(v.type_to_resolved.contains_key(&ty()), "the mandatory type resolved");
        assert!(
            !v.type_to_resolved.contains_key(&ToolchainType("//rust:toolchain_type".into())),
            "the missing OPTIONAL type is absent from the map — not an error, not a default"
        );
    }

    #[test]
    fn exec_selection_requires_all_mandatory_types() {
        // Decision F (containsAll): the first registered exec platform cannot supply the mandatory type
        // (the toolchain is exec-compatible only with the second) → the SECOND is selected. RED under
        // `mutant_toolchain_exec_selection_first_candidate` (first-candidate-wins → fail-closed error).
        let f = ctx_fn(&[("p_linux", "linux")]);
        let mut tc = cc("linux-cc", "linux");
        tc.exec_compatible_with = vec![Constraint("exec:cap".into())];
        let eps = vec![
            RegisteredExecPlatform { name: "ep_plain".into(), constraints: vec![] },
            RegisteredExecPlatform { name: "ep_cap".into(), constraints: vec![Constraint("exec:cap".into())] },
        ];
        let mut ctx = serve("p_linux", vec![tc], eps);
        let v = resolved(f.compute(&ctx_key("p_linux", vec![req("//cc:toolchain_type", true)]), &mut ctx));
        assert_eq!(
            v.selected_exec_platform, "ep_cap",
            "selection must pick the platform supplying ALL mandatory types, not the first candidate"
        );
    }

    #[test]
    fn exec_selection_is_registration_order_first() {
        // Both registered platforms supply the mandatory type equally → the EARLIEST registered wins
        // (and the host, appended last, is not preferred).
        let f = ctx_fn(&[("p_linux", "linux")]);
        let eps = vec![
            RegisteredExecPlatform { name: "ep_first".into(), constraints: vec![] },
            RegisteredExecPlatform { name: "ep_second".into(), constraints: vec![] },
        ];
        let mut ctx = serve("p_linux", vec![cc("linux-cc", "linux")], eps);
        let v = resolved(f.compute(&ctx_key("p_linux", vec![req("//cc:toolchain_type", true)]), &mut ctx));
        assert_eq!(v.selected_exec_platform, "ep_first", "registration order breaks the tie");
    }

    #[test]
    fn exec_selection_tiebreaks_by_optional_count() {
        // Both platforms supply the mandatory type; only the SECOND also supplies the optional one → the
        // second wins (most resolved types), registration order only breaks true ties (Bazel stable max).
        let f = ctx_fn(&[("p_linux", "linux")]);
        let rust = RegisteredToolchain {
            toolchain_type: ToolchainType("//rust:toolchain_type".into()),
            target_compatible_with: vec![Constraint("os:linux".into())],
            exec_compatible_with: vec![Constraint("exec:cap".into())],
            info: ProviderInstance { provider: ProviderId::from_name("RustInfo"), fields: vec![] },
        };
        let eps = vec![
            RegisteredExecPlatform { name: "ep_plain".into(), constraints: vec![] },
            RegisteredExecPlatform { name: "ep_cap".into(), constraints: vec![Constraint("exec:cap".into())] },
        ];
        let mut ctx = serve("p_linux", vec![cc("linux-cc", "linux"), rust], eps);
        let v = resolved(f.compute(
            &ctx_key("p_linux", vec![req("//cc:toolchain_type", true), req("//rust:toolchain_type", false)]),
            &mut ctx,
        ));
        assert_eq!(v.selected_exec_platform, "ep_cap", "the platform resolving MORE optional types wins");
        assert!(v.type_to_resolved.contains_key(&ToolchainType("//rust:toolchain_type".into())));
    }

    #[test]
    fn exec_constraint_labels_filter_candidates() {
        // The key's exec_constraint_labels filter the candidate list (decision F / PlatformKeys filter).
        let f = ctx_fn(&[("p_linux", "linux")]);
        let eps = vec![
            RegisteredExecPlatform { name: "ep_plain".into(), constraints: vec![] },
            RegisteredExecPlatform { name: "ep_gpu".into(), constraints: vec![Constraint("exec:gpu".into())] },
        ];
        let mut ctx = serve("p_linux", vec![cc("linux-cc", "linux")], eps);
        let key = NodeKey::from_key(&ToolchainContextKey::new(
            ConfigId("p_linux".into()),
            vec![req("//cc:toolchain_type", true)],
            vec![Constraint("exec:gpu".into())],
            None,
            false,
        ));
        let v = resolved(f.compute(&key, &mut ctx));
        assert_eq!(v.selected_exec_platform, "ep_gpu", "candidates lacking the keyed exec constraint are filtered");
    }

    #[test]
    fn unknown_derived_platform_fails_closed() {
        let f = ctx_fn(&[("p_linux", "linux")]);
        let mut ctx = serve("p_unknown", vec![cc("linux-cc", "linux")], vec![]);
        assert!(
            matches!(
                f.compute(&ctx_key("p_unknown", vec![req("//cc:toolchain_type", true)]), &mut ctx),
                ComputeResult::Error(Error::NotFound { .. })
            ),
            "an unknown derived target platform → fail closed"
        );
    }

    // ──────────────── value digests (the canonical-codec discipline) ────────────────

    #[test]
    fn content_digest_distinguishes_non_string_fields() {
        // Regression heritage: the digest delegates to the ONE razel-bzl-api provider codec, so an
        // Int-only field difference must change it, and name/value framing cannot alias.
        let mk = |n: i64| ResolvedToolchainContextValue {
            selected_exec_platform: "host".into(),
            target_platform: "p".into(),
            type_to_resolved: BTreeMap::from([(
                ty(),
                ProviderInstance { provider: ProviderId::from_name("CcInfo"), fields: vec![("v".to_string(), BzlValue::Int(n))] },
            )]),
        };
        assert_ne!(mk(1).content_digest(), mk(2).content_digest(), "Int-only difference must change the digest");
        assert_eq!(mk(7).content_digest(), mk(7).content_digest(), "equal values → equal digest (determinism)");
        let base = mk(1);
        let mut other_platform = base.clone();
        other_platform.selected_exec_platform = "ep1".into();
        assert_ne!(base.content_digest(), other_platform.content_digest(), "the selected exec platform is in the digest");
    }

    #[test]
    fn registered_set_digest_covers_every_field() {
        let base = RegisteredToolchainsValue { toolchains: vec![cc("linux-cc", "linux")] };
        let mut diff_exec = base.clone();
        diff_exec.toolchains[0].exec_compatible_with = vec![Constraint("exec:cap".into())];
        assert_ne!(base.content_digest(), diff_exec.content_digest(), "exec_compatible_with is digested");
        let mut diff_target = base.clone();
        diff_target.toolchains[0].target_compatible_with = vec![Constraint("os:macos".into())];
        assert_ne!(base.content_digest(), diff_target.content_digest(), "target_compatible_with is digested");
        let eps = RegisteredExecutionPlatformsValue {
            platforms: vec![RegisteredExecPlatform { name: "ab".into(), constraints: vec![Constraint("c".into())] }],
        };
        let eps2 = RegisteredExecutionPlatformsValue {
            platforms: vec![RegisteredExecPlatform { name: "a".into(), constraints: vec![Constraint("bc".into())] }],
        };
        assert_ne!(eps.content_digest(), eps2.content_digest(), "name/constraint boundary is framed, not concatenated");
    }
}
