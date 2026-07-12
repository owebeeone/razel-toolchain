    use super::*;
    use razel_bzl_api::{BzlValue, ProviderId, ProviderInstance};
    use razel_core::{Error, Key, NodeKey, NodeValue, Value};
    use razel_engine_api::{ComputeResult, DemandContext, NodeFunction};
    use razel_ids::ConfigId;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

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
