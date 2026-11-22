use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    exact: BTreeMap<String, Vec<String>>,
    wildcards: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern<'a> {
    Exact(&'a str),
    Wildcard(&'a str),
}

pub fn parse_pattern(p: &str) -> Pattern<'_> {
    match p.strip_prefix("*.") {
        Some(rest) => Pattern::Wildcard(rest),
        None => Pattern::Exact(p),
    }
}

impl Access {
    pub fn new(rules: BTreeMap<String, Vec<String>>) -> Self {
        let mut exact = BTreeMap::new();
        let mut wildcards = Vec::new();
        for (pattern, groups) in rules {
            match parse_pattern(&pattern) {
                Pattern::Exact(h) => {
                    exact.insert(h.to_owned(), groups);
                }
                Pattern::Wildcard(base) => wildcards.push((format!(".{base}"), groups)),
            }
        }
        wildcards.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        Self { exact, wildcards }
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty()
    }

    pub fn groups_for(&self, host: &str) -> Option<&[String]> {
        let host = host.strip_suffix('.').unwrap_or(host);
        if let Some(g) = self.exact.get(host) {
            return Some(g);
        }
        self.wildcards
            .iter()
            .find(|(suffix, _)| host.len() > suffix.len() && host.ends_with(suffix.as_str()))
            .map(|(_, g)| g.as_slice())
    }
}

pub fn allows(rule: &[String], user_groups: &[String]) -> bool {
    user_groups.iter().any(|g| rule.contains(g))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(rules: &[(&str, &[&str])]) -> Access {
        Access::new(
            rules
                .iter()
                .map(|(h, g)| ((*h).to_owned(), g.iter().map(|s| (*s).to_owned()).collect()))
                .collect(),
        )
    }

    #[test]
    fn exact_beats_wildcards_and_longest_wildcard_wins() {
        let a = access(&[
            ("*.example.com", &["users"]),
            ("*.lab.example.com", &["admins"]),
            ("open.lab.example.com", &["family"]),
        ]);
        assert_eq!(
            a.groups_for("open.lab.example.com"),
            Some(&["family".to_owned()][..])
        );
        assert_eq!(
            a.groups_for("x.lab.example.com"),
            Some(&["admins".to_owned()][..])
        );
        assert_eq!(
            a.groups_for("a.b.lab.example.com"),
            Some(&["admins".to_owned()][..])
        );
        assert_eq!(
            a.groups_for("lab.example.com"),
            Some(&["users".to_owned()][..])
        );
        assert_eq!(
            a.groups_for("grafana.example.com"),
            Some(&["users".to_owned()][..])
        );
        assert_eq!(a.groups_for("example.com"), None);
        assert_eq!(a.groups_for("evilexample.com"), None);
        assert_eq!(a.groups_for("example.com.evil.net"), None);
        assert_eq!(a.groups_for(".example.com"), None);
        assert!(!a.is_empty());
        assert_eq!(a.len(), 3);
        assert!(Access::default().is_empty());
    }

    #[test]
    fn a_trailing_dot_is_the_same_host() {
        let a = access(&[("grafana.example.com", &["admins"])]);
        assert!(a.groups_for("grafana.example.com.").is_some());
        assert!(a.groups_for("grafana.example.com..").is_none());
    }

    #[test]
    fn a_user_needs_one_listed_group() {
        let rule = ["admins".to_owned(), "ops".to_owned()];
        assert!(allows(&rule, &["family".to_owned(), "ops".to_owned()]));
        assert!(!allows(&rule, &["family".to_owned()]));
        assert!(!allows(&rule, &[]));
        assert!(!allows(&[], &["admins".to_owned()]));
    }
}
