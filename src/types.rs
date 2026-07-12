//! Toolchain domain vocabulary + the pure constraint-matching `resolve` (carved out of `lib.rs`).

use razel_bzl_api::ProviderInstance;
use razel_core::{Error, KindId};

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

