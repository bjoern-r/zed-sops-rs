//! Minimal `.sops.yaml` support: find the config that applies to a file and
//! check whether one of its `creation_rules` (with an explicit `path_regex`)
//! claims the file. Used to warn about plaintext files that are supposed to
//! be encrypted.

use regex::Regex;
use std::path::{Path, PathBuf};
use yaml_rust2::{Yaml, YamlLoader};

const CONFIG_NAMES: &[&str] = &[".sops.yaml", ".sops.yml"];

/// Walk upwards from the file's directory, like sops does from its cwd.
pub fn find_config(file: &Path) -> Option<PathBuf> {
    let mut dir = file.parent();
    while let Some(d) = dir {
        for name in CONFIG_NAMES {
            let candidate = d.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        dir = d.parent();
    }
    None
}

/// Returns the `path_regex` of the first creation rule that matches `file`,
/// if that rule has an explicit `path_regex` (catch-all rules are ignored to
/// avoid flagging every YAML file in a repository).
pub fn matching_rule(config: &Path, file: &Path) -> Option<String> {
    let text = std::fs::read_to_string(config).ok()?;
    let docs = YamlLoader::load_from_str(&text).ok()?;
    let rules = docs.first()?["creation_rules"].as_vec()?;

    let abs = file.to_string_lossy().replace('\\', "/");
    let rel = config
        .parent()
        .and_then(|base| file.strip_prefix(base).ok())
        .map(|p| p.to_string_lossy().replace('\\', "/"));

    for rule in rules {
        match &rule["path_regex"] {
            Yaml::String(pattern) => {
                let Ok(re) = Regex::new(pattern) else { continue };
                if re.is_match(&abs) || rel.as_deref().is_some_and(|r| re.is_match(r)) {
                    return Some(pattern.clone());
                }
            }
            // sops takes the first matching rule; a catch-all rule ends the search.
            Yaml::BadValue | Yaml::Null => return None,
            _ => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_relative_and_absolute() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        std::fs::write(
            dir.path().join(".sops.yaml"),
            "creation_rules:\n  - path_regex: ^secrets/.*\\.yaml$\n    age: age1x\n",
        )
        .unwrap();
        let f = dir.path().join("secrets/app.yaml");
        let cfg = find_config(&f).unwrap();
        assert!(matching_rule(&cfg, &f).is_some());
        assert!(matching_rule(&cfg, &dir.path().join("other.yaml")).is_none());
    }
}
