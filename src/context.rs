//! The TOOLCHAIN_CONTEXT node: target-platform derivation, exec-platform selection, per-type
//! resolution, and the node-kind registration entry point (carved out of `lib.rs`).

use crate::*;
use razel_bzl_api::ProviderInstance;
use razel_core::{Error, NodeKey};
use razel_engine_api::{ComputeResult, Demand, DemandContext, DemandEngine, NodeFunction};
use razel_ids::ConfigId;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

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

