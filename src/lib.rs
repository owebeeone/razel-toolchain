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

use razel_bzl_api::ProviderInstance;
use razel_core::{Error, KindId};

/// Reserved node-kind id for the configured-target's resolved toolchains (wired in B2/B3).
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
}
