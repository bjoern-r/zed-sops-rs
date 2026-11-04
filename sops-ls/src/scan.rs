//! Static analysis of a document: which format it is, where the `ENC[...]`
//! tokens are, which key path every scalar value lives at, and what the
//! SOPS metadata block says. Nothing in here ever decrypts anything.

use regex::Regex;
use std::{fmt, path::Path, sync::LazyLock};
use yaml_rust2::{
    parser::{Event, MarkedEventReceiver, Parser},
    scanner::{Marker, TScalarStyle},
};

// ---------------------------------------------------------------- format

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    Yaml,
    Json,
    Dotenv,
    Ini,
}

impl Format {
    /// Detect the format from the LSP language id, falling back to the file name.
    pub fn detect(language_id: &str, path: Option<&Path>) -> Option<Format> {
        let by_lang = match language_id.to_ascii_lowercase().as_str() {
            "yaml" => Some(Format::Yaml),
            "json" | "jsonc" => Some(Format::Json),
            "dotenv" | "env" => Some(Format::Dotenv),
            "ini" | "properties" => Some(Format::Ini),
            _ => None,
        };
        by_lang.or_else(|| {
            let name = path?.file_name()?.to_str()?.to_ascii_lowercase();
            if name.ends_with(".yaml") || name.ends_with(".yml") {
                Some(Format::Yaml)
            } else if name.ends_with(".json") {
                Some(Format::Json)
            } else if name.ends_with(".ini") {
                Some(Format::Ini)
            } else if name.ends_with(".env") || name.starts_with(".env") {
                Some(Format::Dotenv)
            } else {
                None
            }
        })
    }

    /// Value for sops' `--input-type` / `--output-type`.
    pub fn sops_type(self) -> &'static str {
        match self {
            Format::Yaml => "yaml",
            Format::Json => "json",
            Format::Dotenv => "dotenv",
            Format::Ini => "ini",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Yaml => "yaml",
            Format::Json => "json",
            Format::Dotenv => "env",
            Format::Ini => "ini",
        }
    }

    /// Cheap syntax check used before handing plaintext to sops (an invalid
    /// document would otherwise make `sops edit` try to re-open an editor).
    pub fn validate(self, text: &str) -> Result<(), String> {
        match self {
            Format::Yaml => yaml_rust2::YamlLoader::load_from_str(text)
                .map(|_| ())
                .map_err(|e| format!("invalid YAML: {e}")),
            Format::Json => serde_json::from_str::<serde_json::Value>(text)
                .map(|_| ())
                .map_err(|e| format!("invalid JSON: {e}")),
            Format::Dotenv | Format::Ini => Ok(()),
        }
    }
}

// ---------------------------------------------------------------- ENC tokens

static ENC_STRICT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^ENC\[AES256_GCM,data:[A-Za-z0-9+/]*={0,2},iv:[A-Za-z0-9+/]{43}=,tag:[A-Za-z0-9+/]{22}==,type:(str|int|float|bool|bytes|comment)\]$",
    )
    .unwrap()
});
static ENC_LOOSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"ENC\[[^\]\r\n]*(\]|$)").unwrap());

#[derive(Clone, Debug)]
pub struct EncToken {
    pub start: usize,
    pub end: usize,
    /// `Some(type)` for a well-formed token, `None` for a malformed one.
    pub value_type: Option<String>,
}

impl EncToken {
    pub fn is_comment(&self) -> bool {
        self.value_type.as_deref() == Some("comment")
    }
}

pub fn enc_tokens(text: &str) -> Vec<EncToken> {
    let mut out = Vec::new();
    for line_start in line_starts(text) {
        let line_end = text[line_start..].find('\n').map_or(text.len(), |i| line_start + i);
        let line = &text[line_start..line_end];
        for m in ENC_LOOSE.find_iter(line) {
            let s = m.as_str().trim_end_matches('\r');
            let value_type = ENC_STRICT.captures(s).map(|c| c[1].to_string());
            out.push(EncToken {
                start: line_start + m.start(),
                end: line_start + m.start() + s.len(),
                value_type,
            });
        }
    }
    out
}

fn line_starts(text: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(text.match_indices('\n').map(|(i, _)| i + 1).filter(move |&i| i < text.len()))
}

// ---------------------------------------------------------------- key paths

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Seg {
    Key(String),
    Index(usize),
}

pub struct PathDisplay<'a>(pub &'a [Seg]);

impl fmt::Display for PathDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, seg) in self.0.iter().enumerate() {
            match seg {
                Seg::Key(k) if i == 0 => write!(f, "{k}")?,
                Seg::Key(k) => write!(f, ".{k}")?,
                Seg::Index(n) => write!(f, "[{n}]")?,
            }
        }
        Ok(())
    }
}

/// A scalar value in the document together with its key path and byte span.
#[derive(Clone, Debug)]
pub struct Leaf {
    pub path: Vec<Seg>,
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub is_null: bool,
}

impl Leaf {
    pub fn is_metadata(&self, fmt: Format) -> bool {
        match (fmt, self.path.first()) {
            (Format::Dotenv, Some(Seg::Key(k))) => k.starts_with("sops_"),
            (_, Some(Seg::Key(k))) => k == "sops",
            _ => false,
        }
    }
    pub fn is_encrypted(&self) -> bool {
        ENC_STRICT.is_match(self.value.trim())
    }
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.path.iter().filter_map(|s| match s {
            Seg::Key(k) => Some(k.as_str()),
            Seg::Index(_) => None,
        })
    }
}

pub fn leaves(text: &str, fmt: Format) -> Vec<Leaf> {
    match fmt {
        Format::Yaml => yaml_leaves(text),
        Format::Json => json_leaves(text),
        Format::Dotenv => dotenv_leaves(text),
        Format::Ini => ini_leaves(text),
    }
}

/// The leaf whose value span contains `offset`.
pub fn leaf_at(leaves: &[Leaf], offset: usize) -> Option<&Leaf> {
    leaves.iter().find(|l| l.start <= offset && offset <= l.end)
}

// --- YAML (event parser with position markers)

enum Frame {
    Map { key: Option<String>, expect_key: bool },
    Seq { idx: usize },
}

struct YamlCollector<'a> {
    text: &'a str,
    char_to_byte: Option<Vec<usize>>,
    stack: Vec<Frame>,
    out: Vec<Leaf>,
}

impl YamlCollector<'_> {
    fn byte(&self, m: &Marker) -> usize {
        match &self.char_to_byte {
            Some(map) => map.get(m.index()).copied().unwrap_or(self.text.len()),
            None => m.index().min(self.text.len()),
        }
    }
    fn path(&self) -> Vec<Seg> {
        self.stack
            .iter()
            .filter_map(|f| match f {
                Frame::Map { key: Some(k), .. } => Some(Seg::Key(k.clone())),
                Frame::Map { key: None, .. } => None,
                Frame::Seq { idx } => Some(Seg::Index(*idx)),
            })
            .collect()
    }
    /// A value (scalar, alias or finished collection) was consumed.
    fn advance(&mut self) {
        match self.stack.last_mut() {
            Some(Frame::Map { key, expect_key }) => {
                *key = None;
                *expect_key = true;
            }
            Some(Frame::Seq { idx }) => *idx += 1,
            None => {}
        }
    }
    fn is_key_position(&self) -> bool {
        matches!(self.stack.last(), Some(Frame::Map { expect_key: true, .. }))
    }
}

impl MarkedEventReceiver for YamlCollector<'_> {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::Scalar(value, style, _, _) => {
                if self.is_key_position() {
                    if let Some(Frame::Map { key, expect_key }) = self.stack.last_mut() {
                        *key = Some(value);
                        *expect_key = false;
                    }
                    return;
                }
                let start = self.byte(&mark);
                let end = yaml_scalar_end(self.text, start, style);
                let is_null = style == TScalarStyle::Plain
                    && matches!(value.as_str(), "" | "~" | "null" | "Null" | "NULL");
                self.out.push(Leaf { path: self.path(), start, end, value, is_null });
                self.advance();
            }
            Event::Alias(_) => {
                if self.is_key_position() {
                    if let Some(Frame::Map { key, expect_key }) = self.stack.last_mut() {
                        *key = Some("*alias".into());
                        *expect_key = false;
                    }
                } else {
                    self.advance();
                }
            }
            Event::MappingStart(..) => {
                if self.is_key_position() {
                    // Complex keys are not something sops produces; treat as opaque.
                    if let Some(Frame::Map { key, expect_key }) = self.stack.last_mut() {
                        *key = Some("?complex".into());
                        *expect_key = false;
                    }
                }
                self.stack.push(Frame::Map { key: None, expect_key: true });
            }
            Event::SequenceStart(..) => self.stack.push(Frame::Seq { idx: 0 }),
            Event::MappingEnd | Event::SequenceEnd => {
                self.stack.pop();
                self.advance();
            }
            _ => {}
        }
    }
}

fn yaml_scalar_end(text: &str, start: usize, style: TScalarStyle) -> usize {
    let bytes = text.as_bytes();
    let line_end = text[start..].find('\n').map_or(text.len(), |i| start + i);
    match style {
        TScalarStyle::DoubleQuoted => {
            let mut i = start + 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'"' => return i + 1,
                    _ => i += 1,
                }
            }
            line_end
        }
        TScalarStyle::SingleQuoted => {
            let mut i = start + 1;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        i += 2;
                        continue;
                    }
                    return i + 1;
                }
                i += 1;
            }
            line_end
        }
        TScalarStyle::Plain => {
            let line = &text[start..line_end];
            let cut = line.find(" #").unwrap_or(line.len());
            start + line[..cut].trim_end().len()
        }
        _ => start + text[start..line_end].trim_end().len(),
    }
}

fn yaml_leaves(text: &str) -> Vec<Leaf> {
    let char_to_byte = if text.is_ascii() {
        None
    } else {
        let mut v: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
        v.push(text.len());
        Some(v)
    };
    let mut c = YamlCollector { text, char_to_byte, stack: Vec::new(), out: Vec::new() };
    let mut parser = Parser::new_from_str(text);
    // On a syntax error we keep whatever was collected up to that point.
    let _ = parser.load(&mut c, false);
    c.out
}

// --- JSON (small hand-written tokenizer; sops emits tab-indented JSON)

fn json_leaves(text: &str) -> Vec<Leaf> {
    enum JFrame {
        Obj { key: Option<String>, expect_key: bool },
        Arr { idx: usize },
    }
    let bytes = text.as_bytes();
    let mut stack: Vec<JFrame> = Vec::new();
    let mut out = Vec::new();
    let mut i = 0;

    fn path(stack: &[JFrame]) -> Vec<Seg> {
        stack
            .iter()
            .filter_map(|f| match f {
                JFrame::Obj { key: Some(k), .. } => Some(Seg::Key(k.clone())),
                JFrame::Obj { key: None, .. } => None,
                JFrame::Arr { idx } => Some(Seg::Index(*idx)),
            })
            .collect()
    }

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'{' => {
                stack.push(JFrame::Obj { key: None, expect_key: true });
                i += 1;
            }
            b'[' => {
                stack.push(JFrame::Arr { idx: 0 });
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                i += 1;
            }
            b',' => {
                match stack.last_mut() {
                    Some(JFrame::Obj { key, expect_key }) => {
                        *key = None;
                        *expect_key = true;
                    }
                    Some(JFrame::Arr { idx }) => *idx += 1,
                    None => {}
                }
                i += 1;
            }
            b':' => i += 1,
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                // JSONC line comment
                i = text[i..].find('\n').map_or(bytes.len(), |n| i + n);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = text[i + 2..].find("*/").map_or(bytes.len(), |n| i + 2 + n + 2);
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                let end = i.min(bytes.len());
                let s: String = serde_json::from_str(&text[start..end])
                    .unwrap_or_else(|_| text[start + 1..end.saturating_sub(1)].to_string());
                if let Some(JFrame::Obj { key, expect_key }) = stack.last_mut() {
                    if *expect_key {
                        *key = Some(s);
                        *expect_key = false;
                        continue;
                    }
                }
                out.push(Leaf { path: path(&stack), start, end, value: s, is_null: false });
            }
            c if c.is_ascii_whitespace() => i += 1,
            _ => {
                // number / true / false / null
                let start = i;
                while i < bytes.len() && !b",}]: \t\r\n".contains(&bytes[i]) {
                    i += 1;
                }
                let value = text[start..i].to_string();
                let is_null = value == "null";
                out.push(Leaf { path: path(&stack), start, end: i, value, is_null });
            }
        }
    }
    out
}

// --- dotenv / INI (line based)

fn dotenv_leaves(text: &str) -> Vec<Leaf> {
    let mut out = Vec::new();
    for ls in line_starts(text) {
        let le = text[ls..].find('\n').map_or(text.len(), |i| ls + i);
        let line = text[ls..le].trim_end_matches('\r');
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let start = ls + eq + 1;
            out.push(Leaf {
                path: vec![Seg::Key(key)],
                start,
                end: ls + line.len(),
                value: line[eq + 1..].to_string(),
                is_null: false,
            });
        }
    }
    out
}

fn ini_leaves(text: &str) -> Vec<Leaf> {
    let mut out = Vec::new();
    let mut section = "DEFAULT".to_string();
    for ls in line_starts(text) {
        let le = text[ls..].find('\n').map_or(text.len(), |i| ls + i);
        let line = text[ls..le].trim_end_matches('\r');
        let t = line.trim();
        if t.is_empty() || t.starts_with(';') || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') && t.ends_with(']') {
            section = t[1..t.len() - 1].trim().to_string();
            continue;
        }
        if let Some(sep) = line.find(['=', ':']) {
            let key = line[..sep].trim().to_string();
            let raw = &line[sep + 1..];
            let lead = raw.len() - raw.trim_start().len();
            let start = ls + sep + 1 + lead;
            out.push(Leaf {
                path: vec![Seg::Key(section.clone()), Seg::Key(key)],
                start,
                end: ls + line.trim_end().len(),
                value: raw.trim().to_string(),
                is_null: false,
            });
        }
    }
    out
}

// ---------------------------------------------------------------- metadata

/// Flattened SOPS metadata, with paths normalised across formats, e.g.
/// `["age", "0", "recipient"]` for YAML/JSON as well as dotenv's
/// `sops_age__list_0__map_recipient`.
#[derive(Debug, Default)]
pub struct Metadata {
    pub entries: Vec<(Vec<String>, String)>,
    /// Byte offset to anchor metadata-level diagnostics on.
    pub anchor: Option<(usize, usize)>,
}

impl Metadata {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(p, _)| p.len() == 1 && p[0] == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_sops(&self) -> bool {
        self.get("mac").is_some() && (self.get("version").is_some() || self.get("lastmodified").is_some())
    }

    /// Key-type → identifying strings (recipients, fingerprints, ARNs, ...).
    pub fn recipients(&self) -> Vec<(&'static str, Vec<String>)> {
        const KINDS: &[(&str, &str)] = &[
            ("age", "recipient"),
            ("pgp", "fp"),
            ("kms", "arn"),
            ("gcp_kms", "resource_id"),
            ("azure_kv", "vault_url"),
            ("hc_vault", "vault_address"),
        ];
        let mut out = Vec::new();
        for (kind, field) in KINDS {
            let vals: Vec<String> = self
                .entries
                .iter()
                .filter(|(p, _)| p.iter().any(|s| s == kind) && p.last().map(String::as_str) == Some(*field))
                .map(|(_, v)| v.clone())
                .collect();
            if !vals.is_empty() {
                out.push((*kind, vals));
            }
        }
        out
    }

    pub fn rules(&self) -> EncryptionRules {
        let re = |k| self.get(k).and_then(|s| Regex::new(s).ok());
        if let Some(s) = self.get("unencrypted_suffix") {
            EncryptionRules::UnencryptedSuffix(s.to_string())
        } else if let Some(s) = self.get("encrypted_suffix") {
            EncryptionRules::EncryptedSuffix(s.to_string())
        } else if let Some(r) = re("unencrypted_regex") {
            EncryptionRules::UnencryptedRegex(r)
        } else if let Some(r) = re("encrypted_regex") {
            EncryptionRules::EncryptedRegex(r)
        } else {
            EncryptionRules::UnencryptedSuffix("_unencrypted".into())
        }
    }
}

pub fn metadata(leaves: &[Leaf], fmt: Format) -> Metadata {
    let mut md = Metadata::default();
    for leaf in leaves.iter().filter(|l| l.is_metadata(fmt)) {
        let path: Vec<String> = match fmt {
            Format::Dotenv => match &leaf.path[0] {
                Seg::Key(k) => split_flat(&k["sops_".len()..]),
                _ => continue,
            },
            Format::Ini => match leaf.path.get(1) {
                Some(Seg::Key(k)) => split_flat(k),
                _ => continue,
            },
            _ => leaf.path[1..]
                .iter()
                .map(|s| match s {
                    Seg::Key(k) => k.clone(),
                    Seg::Index(i) => i.to_string(),
                })
                .collect(),
        };
        if path.len() == 1 && path[0] == "mac" {
            md.anchor = Some((leaf.start, leaf.end));
        }
        let value = match fmt {
            Format::Dotenv | Format::Ini => leaf.value.replace("\\n", "\n"),
            _ => leaf.value.clone(),
        };
        md.entries.push((path, value));
    }
    md
}

fn split_flat(k: &str) -> Vec<String> {
    k.split("__")
        .map(|s| s.strip_prefix("list_").or_else(|| s.strip_prefix("map_")).unwrap_or(s).to_string())
        .collect()
}

pub enum EncryptionRules {
    UnencryptedSuffix(String),
    EncryptedSuffix(String),
    UnencryptedRegex(Regex),
    EncryptedRegex(Regex),
}

impl EncryptionRules {
    /// Whether sops would encrypt a value at a path with these keys.
    pub fn should_encrypt<'a>(&self, mut keys: impl Iterator<Item = &'a str>) -> bool {
        match self {
            Self::UnencryptedSuffix(s) => !keys.any(|k| k.ends_with(s.as_str())),
            Self::EncryptedSuffix(s) => keys.any(|k| k.ends_with(s.as_str())),
            Self::UnencryptedRegex(r) => !keys.any(|k| r.is_match(k)),
            Self::EncryptedRegex(r) => keys.any(|k| r.is_match(k)),
        }
    }
}

/// Look up a key path inside the decrypted JSON tree.
pub fn lookup<'v>(root: &'v serde_json::Value, path: &[Seg]) -> Option<&'v serde_json::Value> {
    path.iter().try_fold(root, |v, seg| match seg {
        Seg::Key(k) => v.get(k),
        Seg::Index(i) => v.get(i),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = "# c\ndb:\n    user: ENC[AES256_GCM,data:k9lh85E=,iv:xdNWNEHgJuMaoMu/uqEz5d4CrenoH1oZsQy3m+AiixI=,tag:9DHhFkaXw4PKxL+WlxXOjA==,type:str]\n    näme: \"x y\" # comment\nlist:\n    - a\n    - b: 1\nempty:\nsops:\n    mac: ENC[AES256_GCM,data:Gj,iv:fy0efxXttZ9ykKA2VQkGtQre/niHdhSbZucaI6g5BHY=,tag:eFiLQtAYNxs99cVsyuZ4ig==,type:str]\n    version: 3.13.3\n    age:\n        - recipient: age1abc\n";

    #[test]
    fn yaml_paths_and_spans() {
        let ls = leaves(YAML, Format::Yaml);
        let find = |p: &str| ls.iter().find(|l| PathDisplay(&l.path).to_string() == p).unwrap();
        let user = find("db.user");
        assert!(YAML[user.start..user.end].starts_with("ENC[") && YAML[user.start..user.end].ends_with(']'));
        assert!(user.is_encrypted());
        let name = find("db.näme");
        assert_eq!(&YAML[name.start..name.end], "\"x y\"");
        assert_eq!(find("list[0]").value, "a");
        assert_eq!(find("list[1].b").value, "1");
        assert!(find("empty").is_null);
        let md = metadata(&ls, Format::Yaml);
        assert!(md.is_sops());
        assert_eq!(md.recipients(), vec![("age", vec!["age1abc".to_string()])]);
    }

    #[test]
    fn json_paths() {
        let t = "{\n\t\"a\": {\"b\": \"x\", \"n\": 3},\n\t\"arr\": [1, \"two\", null]\n}";
        let ls = leaves(t, Format::Json);
        let p: Vec<String> = ls.iter().map(|l| PathDisplay(&l.path).to_string()).collect();
        assert_eq!(p, ["a.b", "a.n", "arr[0]", "arr[1]", "arr[2]"]);
        assert_eq!(&t[ls[0].start..ls[0].end], "\"x\"");
        assert!(ls[4].is_null);
    }

    #[test]
    fn dotenv_and_ini_metadata() {
        let env = "A=1\nsops_age__list_0__map_recipient=age1x\nsops_mac=ENC[x]\nsops_version=3.9.0\n";
        let md = metadata(&leaves(env, Format::Dotenv), Format::Dotenv);
        assert!(md.is_sops());
        assert_eq!(md.recipients()[0].1, vec!["age1x"]);
        let ini = "[db]\nuser = x\n\n[sops]\nage__list_0__map_recipient = age1y\nmac = ENC[x]\nversion = 3\n";
        let ls = leaves(ini, Format::Ini);
        assert_eq!(PathDisplay(&ls[0].path).to_string(), "db.user");
        assert_eq!(metadata(&ls, Format::Ini).recipients()[0].1, vec!["age1y"]);
    }

    #[test]
    fn rules() {
        let r = EncryptionRules::UnencryptedSuffix("_unencrypted".into());
        assert!(r.should_encrypt(["db", "password"].into_iter()));
        assert!(!r.should_encrypt(["cfg_unencrypted", "x"].into_iter()));
        let r = EncryptionRules::EncryptedRegex(Regex::new("^(data|stringData)$").unwrap());
        assert!(r.should_encrypt(["data", "x"].into_iter()));
        assert!(!r.should_encrypt(["metadata", "name"].into_iter()));
    }

    #[test]
    fn malformed_tokens() {
        let t = "a: ENC[AES256_GCM,data:abc,iv:short,tag:x,type:str]\nb: ENC[AES256_GCM,data:k9lh85E=,iv:xdNWNEHgJuMaoMu/uqEz5d4CrenoH1oZsQy3m+AiixI=,tag:9DHhFkaXw4PKxL+WlxXOjA==,type:str]\n";
        let toks = enc_tokens(t);
        assert_eq!(toks.len(), 2);
        assert!(toks[0].value_type.is_none());
        assert_eq!(toks[1].value_type.as_deref(), Some("str"));
    }
}
