//! `razel-toolchain` — toolchain resolution (phase #4, the G4 exam). The heart is `resolve`: a pure,
//! constraint-matching selection over registered toolchains — **data-driven, never a host fixture** (the v3 sin
//! was `resolve_toolchain("cc") => macos_fixture`). Given a target platform's constraints + a required toolchain
//! type, pick the registered toolchain whose `target_compatible_with` is satisfied by the platform; fail closed
//! (a typed error) if none matches — never a default.
//!
//! SPIKE scope (minimal cut): constraints are opaque label strings (the `constraint_setting`/`constraint_value`
//! distinction + `exec_compatible_with`/exec-platform + `config_setting` are deferred — additive). First-match
//! wins (Bazel registration order). The `TOOLCHAIN_CONTEXT` node-kind (KindId 50) + the `platform()`/`toolchain()`
//! builtins that produce this data from `.bzl` + the `ctx.toolchains` wiring are the integration steps (B2/B3);
//! this module is the resolver core, provable in isolation (the unit G4 below).

use razel_bzl_api::{encode_provider_instance, ProviderInstance};
use razel_core::{Digest, Error, Key, KindId, NodeKey, Value, ValuePolicy};
use razel_engine_api::{ComputeResult, DemandContext, DemandEngine, NodeFunction};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Node-kind id for a resolved toolchain (the analysis phase requests one per required type).
pub const TOOLCHAIN_CONTEXT: KindId = KindId(50);

/// An opaque constraint label (e.g. `"@platforms//os:linux"`). SPIKE: a string; the setting/value structure is
/// deferred (a platform either carries a constraint label or it doesn't — that's all matching needs here).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Constraint(pub String);

/// A platform: the set of constraints it satisfies (e.g. `[os:linux, cpu:x86_64]`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Platform {
    pub constraints: Vec<Constraint>,
}

/// A toolchain TYPE id (e.g. `"//tools/cpp:toolchain_type"`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ToolchainType(pub String);

/// A registered toolchain: which TYPE it implements, the target constraints it requires, and the
/// `toolchain_info` provider it carries (returned to the rule as `ctx.toolchains[type]`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegisteredToolchain {
    pub toolchain_type: ToolchainType,
    pub target_compatible_with: Vec<Constraint>,
    pub info: ProviderInstance,
}

/// Resolve the toolchain of `required` type for a target `platform`, over the `registered` set. Data-driven:
/// the first registered toolchain of that type whose `target_compatible_with` ⊆ `platform.constraints` wins.
/// Fail-closed: if none matches, a typed `NotFound` — NEVER a default/fixture (the anti-#4 guarantee).
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

// ──────────────── TOOLCHAIN_CONTEXT node: resolve one (target platform, type) → toolchain_info ────────────────

/// Key: the target platform (the analysis CONFIGURATION dimension — anti-corner I) + the required toolchain
/// type. Flipping the platform is a distinct key → a distinct resolution (the G4 property over the engine).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ToolchainContextKey {
    pub target_platform: String,
    pub toolchain_type: String,
}
impl Key for ToolchainContextKey {
    fn kind(&self) -> KindId {
        TOOLCHAIN_CONTEXT
    }
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for s in [self.target_platform.as_str(), self.toolchain_type.as_str()] {
            b.extend_from_slice(&(s.len() as u64).to_be_bytes());
            b.extend_from_slice(s.as_bytes());
        }
        b
    }
}
fn decode_ctx_key(bytes: &[u8]) -> Result<ToolchainContextKey, Error> {
    let err = || Error::Invalid { what: "TOOLCHAIN_CONTEXT key".into(), detail: "malformed".into() };
    let take = |b: &[u8], i: &mut usize| -> Result<String, Error> {
        let end = i.checked_add(8).filter(|&e| e <= b.len()).ok_or_else(err)?;
        let n = u64::from_be_bytes(b[*i..end].try_into().unwrap()) as usize;
        let s_end = end.checked_add(n).filter(|&e| e <= b.len()).ok_or_else(err)?;
        let s = String::from_utf8(b[end..s_end].to_vec()).map_err(|_| err())?;
        *i = s_end;
        Ok(s)
    };
    let mut i = 0;
    let target_platform = take(bytes, &mut i)?;
    let toolchain_type = take(bytes, &mut i)?;
    if i != bytes.len() {
        return Err(err());
    }
    Ok(ToolchainContextKey { target_platform, toolchain_type })
}

/// Value: the resolved `toolchain_info` provider for this (platform, type). Comparable for early cutoff.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedToolchainValue {
    pub info: ProviderInstance,
}
impl Value for ResolvedToolchainValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<ResolvedToolchainValue>().is_some_and(|o| o == self)
    }
    fn content_digest(&self) -> Digest {
        // Delegate to the canonical razel-bzl-api provider codec (lossless + injective + length-framed) — the one
        // source of truth, so this can't drift from the loading/analysis digests. (A former local Str-only scheme
        // digested two toolchains differing only in an Int field identically; value_eq is the live cutoff today,
        // this stays correct for the eventual cross-process / action-cache key.)
        let mut b = Vec::new();
        encode_provider_instance(&self.info, &mut b);
        Digest::of(&b)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `TOOLCHAIN_CONTEXT`: resolve a (target platform, required type) to its `toolchain_info`, over the registered
/// toolchains + platforms supplied at the composition root. A LEAF (no node deps): pure data-driven selection.
/// SPIKE: the registered set + platforms are injected here (config-data); `.bzl` `toolchain()`/`platform()`
/// declarations that produce this data are a deferred fidelity refinement (additive). The SELECTION is already
/// data-driven + by-constraint + fail-closed — the anti-#4 property holds regardless of the data's source.
pub struct ToolchainContextFn {
    registered: Vec<RegisteredToolchain>,
    platforms: HashMap<String, Platform>,
}
impl ToolchainContextFn {
    pub fn new(registered: Vec<RegisteredToolchain>, platforms: HashMap<String, Platform>) -> Self {
        Self { registered, platforms }
    }
}
impl NodeFunction for ToolchainContextFn {
    fn compute(&self, key: &NodeKey, _ctx: &mut dyn DemandContext) -> ComputeResult {
        let ctk = match decode_ctx_key(key.canonical()) {
            Ok(k) => k,
            Err(e) => return ComputeResult::Error(e),
        };
        let platform = match self.platforms.get(&ctk.target_platform) {
            Some(p) => p,
            None => return ComputeResult::Error(Error::NotFound { what: "platform".into(), detail: ctk.target_platform }),
        };
        match resolve(platform, &ToolchainType(ctk.toolchain_type), &self.registered) {
            Ok(info) => ComputeResult::Ready(Arc::new(ResolvedToolchainValue { info })),
            Err(e) => ComputeResult::Error(e),
        }
    }
}

/// Register `TOOLCHAIN_CONTEXT` with the registered toolchains + platforms (the composition root supplies them).
pub fn register_toolchain_kinds(
    engine: &mut dyn DemandEngine,
    registered: Vec<RegisteredToolchain>,
    platforms: HashMap<String, Platform>,
) {
    engine.register(TOOLCHAIN_CONTEXT, Box::new(ToolchainContextFn::new(registered, platforms)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use razel_bzl_api::{BzlValue, ProviderId};

    fn cc(tag: &str, os: &str) -> RegisteredToolchain {
        RegisteredToolchain {
            toolchain_type: ToolchainType("//cc:toolchain_type".into()),
            target_compatible_with: vec![Constraint(format!("os:{os}"))],
            info: ProviderInstance {
                provider: ProviderId("CcToolchainInfo".into()),
                fields: vec![("id".to_string(), BzlValue::Str(tag.into()))],
            },
        }
    }
    fn platform(os: &str) -> Platform {
        Platform { constraints: vec![Constraint(format!("os:{os}"))] }
    }

    #[test]
    fn content_digest_distinguishes_non_string_fields() {
        // Regression: the digest was Str-only, so two toolchain infos differing only in an Int field collided.
        let mk = |n: i64| ResolvedToolchainValue {
            info: ProviderInstance { provider: ProviderId("CcInfo".into()), fields: vec![("v".to_string(), BzlValue::Int(n))] },
        };
        assert_ne!(mk(1).content_digest(), mk(2).content_digest(), "Int-only difference must change the digest");
        assert_eq!(mk(7).content_digest(), mk(7).content_digest(), "equal values → equal digest (determinism)");
        // and a field-name vs value framing cannot alias (length-framing).
        let a = ResolvedToolchainValue {
            info: ProviderInstance { provider: ProviderId("P".into()), fields: vec![("ab".to_string(), BzlValue::Str("c".into()))] },
        };
        let b = ResolvedToolchainValue {
            info: ProviderInstance { provider: ProviderId("P".into()), fields: vec![("a".to_string(), BzlValue::Str("bc".into()))] },
        };
        assert_ne!(a.content_digest(), b.content_digest(), "name/value boundary must be framed, not concatenated");
    }
    fn ty() -> ToolchainType {
        ToolchainType("//cc:toolchain_type".into())
    }

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

    use razel_engine_api::Demand;
    struct NoDeps;
    impl DemandContext for NoDeps {
        fn request(&mut self, _k: &NodeKey) -> Demand {
            Demand::Missing
        }
        fn request_group(&mut self, ks: &[NodeKey]) -> Vec<Demand> {
            ks.iter().map(|_| Demand::Missing).collect()
        }
        fn register_dep(&mut self, _k: &NodeKey) {}
    }
    fn node_resolve(f: &ToolchainContextFn, plat: &str) -> ComputeResult {
        let k = NodeKey::from_key(&ToolchainContextKey {
            target_platform: plat.into(),
            toolchain_type: "//cc:toolchain_type".into(),
        });
        f.compute(&k, &mut NoDeps)
    }

    #[test]
    fn toolchain_context_node_resolves_by_platform() {
        // The G4 property OVER THE ENGINE (node level): the target platform is a KEY dimension; flipping it
        // flips the resolved toolchain — data-driven, no fixture.
        let mut platforms = HashMap::new();
        platforms.insert("p_linux".to_string(), platform("linux"));
        platforms.insert("p_macos".to_string(), platform("macos"));
        let f = ToolchainContextFn::new(vec![cc("linux-cc", "linux"), cc("macos-cc", "macos")], platforms);
        let id = |r: ComputeResult| match r {
            ComputeResult::Ready(v) => v.as_any().downcast_ref::<ResolvedToolchainValue>().unwrap().info.get("id").cloned(),
            _ => None,
        };
        assert_eq!(id(node_resolve(&f, "p_linux")), Some(BzlValue::Str("linux-cc".into())));
        assert_eq!(
            id(node_resolve(&f, "p_macos")),
            Some(BzlValue::Str("macos-cc".into())),
            "flipping the target platform (the key) flips the resolved toolchain — no fixture"
        );
    }

    #[test]
    fn toolchain_context_node_fail_closed() {
        let mut platforms = HashMap::new();
        platforms.insert("p_win".to_string(), platform("windows"));
        let f = ToolchainContextFn::new(vec![cc("linux-cc", "linux")], platforms);
        assert!(
            matches!(node_resolve(&f, "p_win"), ComputeResult::Error(Error::NotFound { .. })),
            "no compatible toolchain for the platform → fail closed"
        );
        assert!(
            matches!(node_resolve(&f, "unknown"), ComputeResult::Error(Error::NotFound { .. })),
            "an unknown target platform → fail closed"
        );
    }
}
