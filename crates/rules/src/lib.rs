pub mod classify;
pub mod inventory;
pub mod manager;
pub mod model;
pub mod sources;

pub use classify::{
    classify_yara_match, classify_yara_rule, signature_category_for, SIGNATURE_CATEGORIES,
    YARA_CATEGORIES,
};
pub use inventory::{build_inventory, collect_yara_roots, YaraRoot};
pub use manager::{now_utc, ManagerError, RuleManager};
pub use model::*;
pub use sources::{default_profiles, default_sources};

pub fn category_label_for_signature(id: &str) -> String {
    classify::signature_category_label(id).to_string()
}

pub fn category_label_for_yara(id: &str) -> String {
    classify::yara_category_label(id).to_string()
}

pub fn has_yara_roots(roots: &[YaraRoot]) -> bool {
    !roots.is_empty()
}
