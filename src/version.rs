//! Tag / version parsing and update severity classification.

use regex::Regex;
use serde::Serialize;
use std::cmp::Ordering;
use std::sync::LazyLock;

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(v?)(\d+(?:\.\d+){0,3})((?:-[A-Za-z0-9._-]+)?)$").unwrap()
});
static LOOSE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?").unwrap());

/// A tag shaped like a version: `v1.2.3-alpine`, `18-alpine`, `8.34`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagVersion {
    pub prefix: String,
    pub nums: Vec<u64>,
    pub suffix: String,
}

impl TagVersion {
    pub fn parse(tag: &str) -> Option<Self> {
        let c = TAG_RE.captures(tag)?;
        let nums = c[2]
            .split('.')
            .map(|n| n.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            prefix: c[1].to_string(),
            nums,
            suffix: c[3].to_string(),
        })
    }

    /// Same "shape": prefix, suffix and precision (`18-alpine` vs `19-alpine`, not `18.1-alpine`).
    pub fn same_shape(&self, other: &Self) -> bool {
        self.prefix == other.prefix
            && self.suffix == other.suffix
            && self.nums.len() == other.nums.len()
    }

    /// Single big number (`20240101`, `1700`): probably a date or build number, not semver.
    pub fn looks_like_build_number(&self) -> bool {
        self.nums.len() == 1 && self.nums[0] >= 1000
    }

    pub fn cmp_nums(&self, other: &Self) -> Ordering {
        self.nums.cmp(&other.nums)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Patch,
    Minor,
    Major,
    Unknown,
}

impl Severity {
    /// Breaking = major bump (or minor bump on 0.x, per semver).
    pub fn between(cur: &[u64], new: &[u64]) -> Severity {
        let g = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
        if g(new, 0) != g(cur, 0) {
            Severity::Major
        } else if g(new, 1) != g(cur, 1) {
            if g(cur, 0) == 0 {
                Severity::Major
            } else {
                Severity::Minor
            }
        } else {
            Severity::Patch
        }
    }

    pub fn is_breaking(self) -> bool {
        self == Severity::Major
    }
}

/// Loose numeric parse of a version label (`v2.11.3`, `1.32.0-alpine`, `3.4`).
pub fn loose_version(s: &str) -> Option<Vec<u64>> {
    let c = LOOSE_RE.captures(s.trim())?;
    let mut v = vec![c[1].parse().ok()?];
    for i in 2..=3 {
        if let Some(m) = c.get(i) {
            v.push(m.as_str().parse().ok()?);
        }
    }
    Some(v)
}

/// Compare the version labels of the running and remote images.
pub fn classify_labels(cur: Option<&str>, new: Option<&str>) -> Severity {
    match (cur.and_then(loose_version), new.and_then(loose_version)) {
        // A lone big number is a date/build id, not a semver major.
        (Some(c), Some(_)) if c.len() == 1 && c[0] >= 1000 => Severity::Unknown,
        (Some(c), Some(n)) => Severity::between(&c, &n),
        _ => Severity::Unknown,
    }
}

/// Highest newer tag in the same major as `current` (same prefix, suffix and
/// precision), like diun: other majors are never proposed, so `18-alpine`
/// never leads to `19-alpine`.
pub fn same_major_candidate(current: &str, tags: &[String]) -> Option<(String, Severity)> {
    let cur = TagVersion::parse(current)?;
    if cur.looks_like_build_number() {
        return None;
    }
    let mut newer: Vec<(TagVersion, &String)> = tags
        .iter()
        .filter_map(|t| TagVersion::parse(t).map(|v| (v, t)))
        .filter(|(v, _)| v.same_shape(&cur) && v.cmp_nums(&cur) == Ordering::Greater)
        .collect();
    newer.sort_by(|a, b| a.0.cmp_nums(&b.0));

    newer
        .iter()
        .rev()
        .find(|(v, _)| !Severity::between(&cur.nums, &v.nums).is_breaking())
        .map(|(v, t)| ((*t).clone(), Severity::between(&cur.nums, &v.nums)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_shapes() {
        let t = TagVersion::parse("18-alpine").unwrap();
        assert_eq!(t.nums, vec![18]);
        assert_eq!(t.suffix, "-alpine");
        assert!(TagVersion::parse("latest").is_none());
        assert!(TagVersion::parse("ee-latest").is_none());
        assert_eq!(TagVersion::parse("v1.2.3").unwrap().prefix, "v");
    }

    #[test]
    fn same_major_only() {
        let t = tags(&["8.33", "8.35", "8.36", "9.0", "9", "8.36-rc1"]);
        assert_eq!(same_major_candidate("8.34", &t), Some(("8.36".into(), Severity::Minor)));
        // Already the latest of its major: nothing, even though 9.0 exists.
        assert_eq!(same_major_candidate("8.36", &t), None);
    }

    #[test]
    fn major_tags_are_never_proposed() {
        // postgres:18-alpine must not lead to postgres:19-alpine.
        let t = tags(&["18", "19-alpine", "20-alpine", "18.1-alpine", "17-alpine"]);
        assert_eq!(same_major_candidate("18-alpine", &t), None);
        // 0.x: a minor bump is breaking, so it is not proposed either.
        assert_eq!(same_major_candidate("0.4.1", &tags(&["0.4.2", "0.5.0"])), Some(("0.4.2".into(), Severity::Patch)));
    }

    #[test]
    fn zero_major_minor_is_breaking() {
        assert_eq!(Severity::between(&[0, 4, 1], &[0, 5, 0]), Severity::Major);
        assert_eq!(Severity::between(&[1, 4, 1], &[1, 5, 0]), Severity::Minor);
        assert_eq!(Severity::between(&[1, 4, 1], &[1, 4, 2]), Severity::Patch);
    }

    #[test]
    fn label_classification() {
        assert_eq!(classify_labels(Some("v3.1.2"), Some("v3.2.0")), Severity::Minor);
        assert_eq!(classify_labels(Some("2.11"), Some("3.0")), Severity::Major);
        assert_eq!(classify_labels(Some("latest"), Some("3.0")), Severity::Unknown);
        assert_eq!(classify_labels(None, Some("3.0")), Severity::Unknown);
    }
}
