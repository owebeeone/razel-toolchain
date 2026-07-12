//! The REGISTERED_* dependency nodes: their values, the shared registry store, the two node
//! functions, and the resolved toolchain-context value (carved out of `lib.rs`).

use crate::*;
use razel_bzl_api::{encode_provider_instance, ProviderInstance};
use razel_core::{Digest, NodeKey, Value, ValuePolicy};
use razel_engine_api::{ComputeResult, DemandContext, NodeFunction};
use razel_ids::ConfigId;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

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
    pub(crate) store: Arc<ToolchainRegistry>,
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
    pub(crate) store: Arc<ToolchainRegistry>,
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

