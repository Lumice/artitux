//! Per-title reference data for Reflex protocol behavior. Live CPUID and
//! registration probes drive Artitux's protocol logic in `cpuid.rs` and
//! `reflex/state.rs`.
//!
//! CPU identity, KUSER recipe, registration scope, and dispatch arrangement
//! vary independently.

/// The CPU identity family presented to a title's Reflex client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuIdentityFamily {
    /// The default CPU presentation.
    Default,
    /// Legacy-CPU brand strings (i9-10900K / Ryzen 9 5900X).
    Modern,
}

/// The [`crate::kuser::Recipe`] family a title's Reflex client expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KuserRecipeFamily {
    Resume,
    Dispatch,
}

/// How a title's Reflex client proves it is running in the registered
/// target process — see `protocol::reflex::IdentityScope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflexIdentityScope {
    Cr3,
    DebugRegister,
}

/// Whether a title's Reflex client registers one resume-target handler, or
/// the explicit dual-dispatch form — see `protocol::reflex::Routing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchArrangement {
    SingleResumeTarget,
    DualDispatch,
}

/// The Reflex protocol behavior observed for one title.
#[derive(Debug, Clone, Copy)]
pub struct Title {
    pub name: &'static str,
    pub cpu_identity: CpuIdentityFamily,
    pub kuser_recipe: KuserRecipeFamily,
    pub identity_scope: ReflexIdentityScope,
    pub dispatch: DispatchArrangement,
}

pub const TITLES: &[Title] = &[
    Title {
        name: "ACBFR",
        cpu_identity: CpuIdentityFamily::Default,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::DebugRegister,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "BGE",
        cpu_identity: CpuIdentityFamily::Default,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "FC6",
        cpu_identity: CpuIdentityFamily::Default,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "NFSPB",
        cpu_identity: CpuIdentityFamily::Default,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::DebugRegister,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "TopSpin",
        cpu_identity: CpuIdentityFamily::Default,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "SMT5V",
        // SMT5V pairs the dispatch recipe with a single resume target.
        cpu_identity: CpuIdentityFamily::Modern,
        kuser_recipe: KuserRecipeFamily::Dispatch,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "Hatsune Miku",
        cpu_identity: CpuIdentityFamily::Modern,
        kuser_recipe: KuserRecipeFamily::Dispatch,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::DualDispatch,
    },
    Title {
        name: "LADPYIH",
        cpu_identity: CpuIdentityFamily::Modern,
        kuser_recipe: KuserRecipeFamily::Dispatch,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::DualDispatch,
    },
];

#[cfg(test)]
mod tests {
    use super::TITLES;

    #[test]
    fn every_supported_title_is_present_once() {
        let expected = [
            "ACBFR",
            "BGE",
            "FC6",
            "NFSPB",
            "TopSpin",
            "SMT5V",
            "Hatsune Miku",
            "LADPYIH",
        ];
        assert_eq!(TITLES.len(), expected.len());
        for name in expected {
            assert_eq!(
                TITLES.iter().filter(|title| title.name == name).count(),
                1,
                "{name} should appear exactly once"
            );
        }
    }
}
