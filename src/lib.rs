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
//!
//! The surface is carved across cohesion modules ([`types`], [`keys`], [`nodes`], [`context`]); this root
//! re-exports the whole public API so `razel_toolchain::X` paths resolve unchanged.

mod context;
mod keys;
mod nodes;
mod types;

pub use context::*;
pub use keys::*;
pub use nodes::*;
pub use types::*;

#[cfg(test)]
mod tests;
