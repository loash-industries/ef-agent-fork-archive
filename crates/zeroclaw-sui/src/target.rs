//! Fully-qualified Move call targets, compared structurally rather than as text.
//!
//! Sui prints the same package many ways: `0x2`, `0x02`, and the full 32-byte
//! form all name the framework. A transaction decoded from BCS always carries
//! the padded 32-byte form, so an allowlist written the short way would never
//! match and would fail *open* if comparison were done on strings and a
//! mismatch were treated as "not a call we recognize". Parsing both sides into
//! [`Address`] removes the question.

use std::fmt;
use std::str::FromStr;

use sui_sdk_types::Address;

/// A `package::module::function` triple with the package in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MoveTarget {
    pub package: Address,
    pub module: String,
    pub function: String,
}

/// Why a target string could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetParseError {
    #[error("move target must be `package::module::function`, got `{0}`")]
    Shape(String),
    #[error("move target `{target}` has an unparseable package address: {reason}")]
    Package { target: String, reason: String },
    #[error("move target `{0}` has an empty module or function name")]
    EmptyName(String),
}

impl MoveTarget {
    /// Render in canonical form: full 32-byte package address, `::`-separated.
    pub fn canonical(&self) -> String {
        format!("{}::{}::{}", self.package, self.module, self.function)
    }
}

impl fmt::Display for MoveTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.package, self.module, self.function)
    }
}

impl FromStr for MoveTarget {
    type Err = TargetParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = raw.split("::").collect();
        let [package, module, function] = parts.as_slice() else {
            return Err(TargetParseError::Shape(raw.to_string()));
        };
        if module.is_empty() || function.is_empty() {
            return Err(TargetParseError::EmptyName(raw.to_string()));
        }
        Ok(Self {
            package: parse_package(package).map_err(|reason| TargetParseError::Package {
                target: raw.to_string(),
                reason,
            })?,
            module: (*module).to_string(),
            function: (*function).to_string(),
        })
    }
}

/// Parse a package address, accepting the abbreviated forms Sui tooling prints.
///
/// `Address` parsing is strict about width, so left-pad to 32 bytes first. That
/// makes `0x2`, `0x02`, and the fully padded form all resolve to one value.
fn parse_package(raw: &str) -> Result<Address, String> {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.is_empty() {
        return Err("address is empty".to_string());
    }
    if hex.len() > 64 {
        return Err(format!("address is {} hex digits, max 64", hex.len()));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("address contains a non-hex digit".to_string());
    }
    let padded = format!("0x{:0>64}", hex);
    Address::from_str(&padded).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_package_forms_are_the_same_target() {
        // The trap this module exists to close: an allowlist written `0x2::`
        // must match a transaction that decodes to the padded form.
        let short: MoveTarget = "0x2::coin::zero".parse().expect("short form parses");
        let long: MoveTarget =
            "0x0000000000000000000000000000000000000000000000000000000000000002::coin::zero"
                .parse()
                .expect("long form parses");
        assert_eq!(short, long);
        assert_eq!(short.canonical(), long.canonical());
    }

    #[test]
    fn leading_zero_variants_normalize() {
        let a: MoveTarget = "0x02::m::f".parse().expect("parses");
        let b: MoveTarget = "0x2::m::f".parse().expect("parses");
        let c: MoveTarget = "2::m::f".parse().expect("bare hex parses");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn distinct_packages_stay_distinct() {
        let a: MoveTarget = "0x2::m::f".parse().expect("parses");
        let b: MoveTarget = "0x3::m::f".parse().expect("parses");
        assert_ne!(a, b);
    }

    #[test]
    fn module_and_function_are_case_sensitive_and_exact() {
        let a: MoveTarget = "0x2::m::f".parse().expect("parses");
        let b: MoveTarget = "0x2::M::f".parse().expect("parses");
        let c: MoveTarget = "0x2::m::F".parse().expect("parses");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn malformed_targets_are_rejected() {
        for bad in [
            "0x2::coin",
            "0x2::coin::zero::extra",
            "coin::zero",
            "",
            "0x2::::zero",
            "0x2::coin::",
            "0xZZ::coin::zero",
        ] {
            assert!(
                bad.parse::<MoveTarget>().is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn oversized_package_is_rejected() {
        let too_long = format!("0x{}::m::f", "a".repeat(65));
        assert!(too_long.parse::<MoveTarget>().is_err());
    }
}
