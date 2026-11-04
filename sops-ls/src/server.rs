use crate::{
    rules,
    scan::{self, EncToken, Format, Leaf, Metadata, PathDisplay},
    sops::Sops,
    text::{Encoding, LineIndex},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower_lsp_server::{
    jsonrpc::{Error as RpcError, Result},
    ls_types::*,
    Client, LanguageServer,
};

pub const CMD_DECRYPT: &str = "sops.decrypt";
pub const CMD_ENCRYPT: &str = "sops.encrypt";
pub const CMD_DISCARD: &str = "sops.discard";
pub const CMD_TOGGLE_HINTS: &str = "sops.toggleInlayHints";
pub const CMD_UPDATE_KEYS: &str = "sops.updateKeys";
pub const CMD_ROTATE: &str = "sops.rotate";

const KIND_DECRYPT: &str = "source.sops.decrypt";
const KIND_ENCRYPT: &str = "source.sops.encrypt";
const KIND_MAINTENANCE: &str = "source.sops.maintenance";

// ---------------------------------------------------------------- settings

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// Path to the sops binary.
    pub sops_path: String,
    /// Show decrypted values when hovering an `ENC[...]` value.
    pub hover_decrypt: bool,
    /// Show decrypted values as inlay hints (off by default: shoulder surfing).
    pub inlay_hints: bool,
    /// Re-encrypt a decrypted buffer automatically when it is saved.
    pub encrypt_on_save: bool,
    /// Run `sops decrypt` on open/save to surface MAC mismatches & key problems.
    pub verify_on_open: bool,
    /// Timeout for any sops invocation.
    pub timeout_secs: u64,
    /// Extra environment for sops, e.g. `SOPS_AGE_KEY_FILE`.
    pub env: HashMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            sops_path: "sops".into(),
            hover_decrypt: true,
            inlay_hints: false,
            encrypt_on_save: true,
            verify_on_open: true,
            timeout_secs: 30,
            env: HashMap::new(),
        }
    }
}

impl Settings {
    fn from_value(v: &Value) -> Option<Self> {
        let v = v.get("sops").filter(|s| s.is_object()).unwrap_or(v);
        if !v.is_object() {
            return None;
        }
        serde_json::from_value(v.clone()).ok()
    }

    fn sops(&self) -> Sops {
        Sops {
            binary: self.sops_path.clone(),
            env: self.env.clone(),
            timeout: Duration::from_secs(self.timeout_secs.max(1)),
        }
    }
}

// ---------------------------------------------------------------- state

struct Doc {
    text: String,
    fmt: Option<Format>,
    path: Option<PathBuf>,
}

#[derive(Default)]
struct State {
    docs: HashMap<Uri, Doc>,
    settings: Settings,
    encoding: Option<Encoding>,
    /// Last ciphertext seen per document. A document whose current text is
    /// *not* encrypted but which has an entry here is a "decrypted session".
    ciphertexts: HashMap<Uri, String>,
    /// Decryption results keyed by content hash.
    decrypted: HashMap<Uri, (u64, std::result::Result<Value, String>)>,
    inlay_override: Option<bool>,
}

/// Everything derivable from a document's text without decrypting it.
struct Analysis {
    fmt: Format,
    tokens: Vec<EncToken>,
    leaves: Vec<Leaf>,
    meta: Metadata,
    encrypted: bool,
}

impl Analysis {
    fn new(text: &str, fmt: Format) -> Self {
        let tokens = scan::enc_tokens(text);
        let leaves = scan::leaves(text, fmt);
        let meta = scan::metadata(&leaves, fmt);
        let encrypted = meta.is_sops();
        Self { fmt, tokens, leaves, meta, encrypted }
    }
}

#[derive(Clone)]
struct Snapshot {
    text: String,
    fmt: Format,
    path: Option<PathBuf>,
    hash: u64,
    session: bool,
    settings: Settings,
    encoding: Encoding,
}

fn hash_text(t: &str) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

pub struct Backend {
    client: Client,
    state: Arc<Mutex<State>>,
    /// Serialises sops invocations so users get at most one PIN prompt at a time.
    sops_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            state: Arc::new(Mutex::new(State::default())),
            sops_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn snapshot(&self, uri: &Uri) -> Option<Snapshot> {
        let st = self.state.lock().unwrap();
        let doc = st.docs.get(uri)?;
        let fmt = doc.fmt?;
        let encrypted = Analysis::new(&doc.text, fmt).encrypted;
        Some(Snapshot {
            text: doc.text.clone(),
            fmt,
            path: doc.path.clone(),
            hash: hash_text(&doc.text),
            session: !encrypted && st.ciphertexts.contains_key(uri),
            settings: st.settings.clone(),
            encoding: st.encoding.unwrap_or(Encoding::Utf16),
        })
    }

    fn update_doc(&self, uri: Uri, text: String, language_id: Option<String>) {
        let mut st = self.state.lock().unwrap();
        let path = uri.to_file_path().map(|p| p.into_owned());
        let fmt = match (language_id, st.docs.get(&uri)) {
            (Some(lang), _) => Format::detect(&lang, path.as_deref()),
            (None, Some(doc)) => doc.fmt,
            (None, None) => Format::detect("", path.as_deref()),
        };
        if let Some(f) = fmt {
            if Analysis::new(&text, f).encrypted {
                st.ciphertexts.insert(uri.clone(), text.clone());
            }
        }
        st.docs.insert(uri, Doc { text, fmt, path });
    }

    // ------------------------------------------------------------ decryption

    async fn decrypted_tree(&self, uri: &Uri) -> Option<std::result::Result<Value, String>> {
        let snap = self.snapshot(uri)?;
        let cached = |st: &State| {
            st.decrypted
                .get(uri)
                .filter(|(h, _)| *h == snap.hash)
                .map(|(_, r)| r.clone())
        };
        if let Some(r) = cached(&self.state.lock().unwrap()) {
            return Some(r);
        }
        let _guard = self.sops_lock.lock().await;
        if let Some(r) = cached(&self.state.lock().unwrap()) {
            return Some(r);
        }
        let cwd = snap.path.as_deref().and_then(Path::parent);
        let result = snap.settings.sops().decrypt_json(&snap.text, snap.fmt, cwd).await;
        self.state
            .lock()
            .unwrap()
            .decrypted
            .insert(uri.clone(), (snap.hash, result.clone()));
        Some(result)
    }

    async fn encrypt_text(&self, uri: &Uri, plaintext: &str) -> std::result::Result<String, String> {
        let snap = self.snapshot(uri).ok_or("document is not open or has an unsupported format")?;
        snap.fmt.validate(plaintext)?;
        let previous = self.state.lock().unwrap().ciphertexts.get(uri).cloned();
        let sops = snap.settings.sops();
        let _guard = self.sops_lock.lock().await;
        match previous {
            Some(prev) => sops.reencrypt(&prev, plaintext, snap.fmt).await,
            None => {
                let path = snap.path.as_deref().ok_or("cannot encrypt an unsaved buffer: no file path")?;
                let config = rules::find_config(path);
                sops.encrypt_new(plaintext, snap.fmt, path, config.as_deref()).await
            }
        }
    }

    // ------------------------------------------------------------ diagnostics

    async fn publish(&self, uri: &Uri) {
        let Some(snap) = self.snapshot(uri) else {
            self.client.publish_diagnostics(uri.clone(), vec![], None).await;
            return;
        };
        let decrypt_err = {
            let st = self.state.lock().unwrap();
            st.decrypted
                .get(uri)
                .filter(|(h, _)| *h == snap.hash)
                .and_then(|(_, r)| r.as_ref().err().cloned())
        };
        let diags = compute_diagnostics(&snap, decrypt_err.as_deref());
        self.client.publish_diagnostics(uri.clone(), diags, None).await;
    }

    /// Verify the file decrypts (MAC, key access), then republish diagnostics.
    async fn verify(&self, uri: &Uri) {
        let Some(snap) = self.snapshot(uri) else { return };
        if snap.settings.verify_on_open && Analysis::new(&snap.text, snap.fmt).encrypted {
            self.decrypted_tree(uri).await;
        }
        self.publish(uri).await;
    }

    async fn replace_buffer(&self, uri: &Uri, new_text: String, label: &str) -> std::result::Result<(), String> {
        let Some(snap) = self.snapshot(uri) else { return Err("document not open".into()) };
        let idx = LineIndex::new(&snap.text, snap.encoding);
        let edit = WorkspaceEdit {
            changes: Some(HashMap::from([(uri.clone(), vec![TextEdit::new(idx.full_range(), new_text)])])),
            ..Default::default()
        };
        match self.client.apply_edit(edit).await {
            Ok(r) if r.applied => Ok(()),
            Ok(r) => Err(format!("{label}: editor rejected the edit {}", r.failure_reason.unwrap_or_default())),
            Err(e) => Err(format!("{label}: {e}")),
        }
    }

    async fn error(&self, msg: impl std::fmt::Display) {
        self.client.show_message(MessageType::ERROR, format!("SOPS: {msg}")).await;
    }

    // ------------------------------------------------------------ commands

    async fn run_command(&self, command: &str, uri: &Uri) -> std::result::Result<(), String> {
        let snap = self.snapshot(uri).ok_or("document not open or unsupported format")?;
        match command {
            CMD_DECRYPT => {
                let cwd = snap.path.as_deref().and_then(Path::parent);
                let plain = {
                    let _g = self.sops_lock.lock().await;
                    snap.settings.sops().decrypt_native(&snap.text, snap.fmt, cwd).await?
                };
                self.state.lock().unwrap().ciphertexts.insert(uri.clone(), snap.text.clone());
                self.replace_buffer(uri, plain, "decrypt").await
            }
            CMD_ENCRYPT => {
                let cipher = self.encrypt_text(uri, &snap.text).await?;
                self.replace_buffer(uri, cipher, "encrypt").await
            }
            CMD_DISCARD => {
                let cipher = self
                    .state
                    .lock()
                    .unwrap()
                    .ciphertexts
                    .get(uri)
                    .cloned()
                    .ok_or("no previous ciphertext known for this file")?;
                self.replace_buffer(uri, cipher, "discard").await
            }
            CMD_TOGGLE_HINTS => {
                {
                    let mut st = self.state.lock().unwrap();
                    let cur = st.inlay_override.unwrap_or(st.settings.inlay_hints);
                    st.inlay_override = Some(!cur);
                }
                let _ = self.client.inlay_hint_refresh().await;
                Ok(())
            }
            CMD_UPDATE_KEYS | CMD_ROTATE => {
                let path = snap.path.as_deref().ok_or("buffer has no file on disk")?;
                let on_disk = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                if on_disk != snap.text {
                    return Err("save the file first; this command operates on the file on disk".into());
                }
                let config = rules::find_config(path);
                let args: &[&str] = if command == CMD_ROTATE { &["rotate", "-i"] } else { &["updatekeys", "-y"] };
                let _g = self.sops_lock.lock().await;
                let out = snap.settings.sops().in_place(args, path, config.as_deref()).await?;
                let msg = if out.is_empty() { "done".to_string() } else { out };
                self.client
                    .show_message(MessageType::INFO, format!("SOPS {}: {msg}", args[0]))
                    .await;
                Ok(())
            }
            other => Err(format!("unknown command {other}")),
        }
    }
}

// ---------------------------------------------------------------- pure helpers

fn compute_diagnostics(snap: &Snapshot, decrypt_err: Option<&str>) -> Vec<Diagnostic> {
    let a = Analysis::new(&snap.text, snap.fmt);
    let idx = LineIndex::new(&snap.text, snap.encoding);
    let mut out = Vec::new();
    let diag = |range, severity, code: &str, message: String| Diagnostic {
        range,
        severity: Some(severity),
        code: Some(NumberOrString::String(code.into())),
        source: Some("sops".into()),
        message,
        ..Default::default()
    };
    let first_line = idx.range(0, idx.line_end(0));

    if a.encrypted || !a.tokens.is_empty() {
        for t in a.tokens.iter().filter(|t| t.value_type.is_none()) {
            out.push(diag(
                idx.range(t.start, t.end),
                DiagnosticSeverity::ERROR,
                "malformed-ciphertext",
                "Malformed SOPS ciphertext; sops will not be able to decrypt this value.".into(),
            ));
        }
    }

    if a.encrypted {
        let rules = a.meta.rules();
        for leaf in a.leaves.iter().filter(|l| !l.is_metadata(a.fmt) && !l.is_null && !l.is_encrypted()) {
            if rules.should_encrypt(leaf.keys()) {
                out.push(diag(
                    idx.range(leaf.start, leaf.end),
                    DiagnosticSeverity::WARNING,
                    "plaintext-value",
                    format!(
                        "`{}` is stored in plaintext, but sops expects it to be encrypted; `sops decrypt` will fail. Use \"SOPS: Decrypt for editing\" to add secrets.",
                        PathDisplay(&leaf.path)
                    ),
                ));
            }
        }
        if let Some(err) = decrypt_err {
            let range = a.meta.anchor.map_or(first_line, |(s, e)| idx.range(s, e));
            out.push(diag(range, DiagnosticSeverity::ERROR, "decrypt-failed", format!("sops cannot decrypt this file:\n{err}")));
        }
    } else if snap.session {
        let (sev, msg) = if snap.settings.encrypt_on_save {
            (DiagnosticSeverity::WARNING, "This buffer contains DECRYPTED secrets. It will be re-encrypted when you save.")
        } else {
            (DiagnosticSeverity::ERROR, "This buffer contains DECRYPTED secrets. Run \"SOPS: Re-encrypt\" before saving.")
        };
        out.push(diag(first_line, sev, "decrypted-buffer", msg.into()));
    } else if let Some(path) = &snap.path {
        if let Some(cfg) = rules::find_config(path) {
            if let Some(re) = rules::matching_rule(&cfg, path) {
                out.push(diag(
                    first_line,
                    DiagnosticSeverity::WARNING,
                    "should-be-encrypted",
                    format!("This file matches the creation rule `{re}` in {} but is not encrypted.", cfg.display()),
                ));
            }
        }
    }
    out
}

fn display_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn fenced(s: &str) -> String {
    let fence = if s.contains("```") { "~~~~" } else { "```" };
    format!("{fence}text\n{s}\n{fence}")
}

fn metadata_markdown(a: &Analysis) -> String {
    let m = &a.meta;
    let mut s = format!("**SOPS-encrypted file** (sops {})\n\n", m.get("version").unwrap_or("?"));
    if let Some(lm) = m.get("lastmodified") {
        s += &format!("- Last modified: {lm}\n");
    }
    let recips = m.recipients();
    if recips.is_empty() {
        s += "- Recipients: none found\n";
    }
    for (kind, vals) in recips {
        s += &format!("- {kind}: {}\n", vals.iter().map(|v| format!("`{v}`")).collect::<Vec<_>>().join(", "));
    }
    for key in ["unencrypted_suffix", "encrypted_suffix", "unencrypted_regex", "encrypted_regex", "mac_only_encrypted"] {
        if let Some(v) = m.get(key) {
            s += &format!("- {key}: `{v}`\n");
        }
    }
    let enc = a.leaves.iter().filter(|l| !l.is_metadata(a.fmt) && l.is_encrypted()).count();
    let plain = a.leaves.iter().filter(|l| !l.is_metadata(a.fmt) && !l.is_encrypted()).count();
    s += &format!("- Values: {enc} encrypted, {plain} plaintext\n");
    s
}

fn on_metadata_header(text: &str, idx: &LineIndex, offset: usize, fmt: Format) -> bool {
    let line = idx.line_of(offset);
    let start = idx.offset(Position::new(line as u32, 0));
    let l = text[start..idx.line_end(line)].trim();
    match fmt {
        Format::Yaml => l == "sops:",
        Format::Json => l.starts_with("\"sops\""),
        Format::Ini => l == "[sops]",
        Format::Dotenv => false,
    }
}

fn truncate(s: &str, max: usize) -> String {
    let one_line = s.replace('\n', "⏎");
    if one_line.chars().count() <= max {
        one_line
    } else {
        format!("{}…", one_line.chars().take(max).collect::<String>())
    }
}

fn command(title: &str, cmd: &str, uri: &Uri) -> Command {
    Command::new(title.into(), cmd.into(), Some(vec![json!(uri.as_str())]))
}

fn action(title: &str, kind: &'static str, cmd: &str, uri: &Uri) -> CodeActionOrCommand {
    CodeActionOrCommand::CodeAction(CodeAction {
        title: title.into(),
        kind: Some(CodeActionKind::from(kind)),
        command: Some(command(title, cmd, uri)),
        ..Default::default()
    })
}

// ---------------------------------------------------------------- LSP

impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        let utf8 = params
            .capabilities
            .general
            .as_ref()
            .and_then(|g| g.position_encodings.as_ref())
            .is_some_and(|encs| encs.contains(&PositionEncodingKind::UTF8));
        {
            let mut st = self.state.lock().unwrap();
            st.encoding = Some(if utf8 { Encoding::Utf8 } else { Encoding::Utf16 });
            if let Some(s) = params.initialization_options.as_ref().and_then(Settings::from_value) {
                st.settings = s;
            }
        }
        Ok(InitializeResult {
            server_info: Some(ServerInfo { name: "sops-ls".into(), version: Some(env!("CARGO_PKG_VERSION").into()) }),
            capabilities: ServerCapabilities {
                position_encoding: Some(if utf8 { PositionEncodingKind::UTF8 } else { PositionEncodingKind::UTF16 }),
                text_document_sync: Some(TextDocumentSyncCapability::Options(TextDocumentSyncOptions {
                    open_close: Some(true),
                    change: Some(TextDocumentSyncKind::FULL),
                    will_save: None,
                    will_save_wait_until: Some(true),
                    save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions { include_text: Some(true) })),
                })),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                inlay_hint_provider: Some(OneOf::Left(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                    code_action_kinds: Some(vec![KIND_DECRYPT.into(), KIND_ENCRYPT.into(), KIND_MAINTENANCE.into(), CodeActionKind::QUICKFIX]),
                    ..Default::default()
                })),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: [CMD_DECRYPT, CMD_ENCRYPT, CMD_DISCARD, CMD_TOGGLE_HINTS, CMD_UPDATE_KEYS, CMD_ROTATE]
                        .map(String::from)
                        .to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            offset_encoding: None,
        })
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        if let Some(s) = Settings::from_value(&params.settings) {
            let uris: Vec<Uri> = {
                let mut st = self.state.lock().unwrap();
                st.settings = s;
                st.docs.keys().cloned().collect()
            };
            for uri in uris {
                self.publish(&uri).await;
            }
            let _ = self.client.inlay_hint_refresh().await;
        }
    }

    async fn did_open(&self, p: DidOpenTextDocumentParams) {
        let uri = p.text_document.uri;
        self.update_doc(uri.clone(), p.text_document.text, Some(p.text_document.language_id));
        self.publish(&uri).await;
        self.verify(&uri).await;
    }

    async fn did_change(&self, p: DidChangeTextDocumentParams) {
        let uri = p.text_document.uri;
        if let Some(change) = p.content_changes.into_iter().last() {
            self.update_doc(uri.clone(), change.text, None);
        }
        self.publish(&uri).await;
    }

    async fn did_close(&self, p: DidCloseTextDocumentParams) {
        let uri = p.text_document.uri;
        {
            let mut st = self.state.lock().unwrap();
            st.docs.remove(&uri);
            st.decrypted.remove(&uri);
            // `ciphertexts` is kept on purpose: if the file is re-opened in
            // plaintext later, we can still protect it.
        }
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn will_save_wait_until(&self, p: WillSaveTextDocumentParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = p.text_document.uri;
        match self.snapshot(&uri) {
            Some(s) if s.session && s.settings.encrypt_on_save => self.formatting_edit(&uri, &s).await,
            _ => Ok(None),
        }
    }

    async fn did_save(&self, p: DidSaveTextDocumentParams) {
        let uri = p.text_document.uri;
        if let Some(text) = p.text {
            self.update_doc(uri.clone(), text, None);
        }
        let Some(snap) = self.snapshot(&uri) else { return };
        if snap.session && snap.settings.encrypt_on_save {
            // Plaintext just hit the disk (the client did not run our
            // formatter / willSaveWaitUntil). Re-encrypt the file in place;
            // the editor reloads the now-encrypted file from disk.
            let Some(path) = snap.path.clone() else { return };
            match self.encrypt_text(&uri, &snap.text).await {
                Ok(cipher) => match atomic_write(&path, &cipher) {
                    Ok(()) => {
                        self.client
                            .log_message(MessageType::INFO, format!("sops-ls: re-encrypted {} on save", path.display()))
                            .await;
                    }
                    Err(e) => self.error(format!("could not write encrypted file, PLAINTEXT IS ON DISK: {e}")).await,
                },
                Err(e) => self.error(format!("re-encryption failed, PLAINTEXT IS ON DISK: {e}")).await,
            }
            return;
        }
        self.verify(&uri).await;
    }

    async fn formatting(&self, p: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = p.text_document.uri;
        match self.snapshot(&uri) {
            Some(s) if s.session => self.formatting_edit(&uri, &s).await,
            _ => Ok(None),
        }
    }

    async fn hover(&self, p: HoverParams) -> Result<Option<Hover>> {
        let uri = p.text_document_position_params.text_document.uri;
        let Some(snap) = self.snapshot(&uri) else { return Ok(None) };
        let a = Analysis::new(&snap.text, snap.fmt);
        if !a.encrypted {
            return Ok(None);
        }
        let idx = LineIndex::new(&snap.text, snap.encoding);
        let offset = idx.offset(p.text_document_position_params.position);

        let md = if let Some(tok) = a.tokens.iter().find(|t| t.start <= offset && offset <= t.end) {
            let range = Some(idx.range(tok.start, tok.end));
            let leaf = scan::leaf_at(&a.leaves, tok.start);
            let body = match (&tok.value_type, leaf) {
                (None, _) => "**SOPS** · malformed ciphertext".to_string(),
                (Some(_), _) if tok.is_comment() => {
                    "**SOPS** · encrypted comment\n\nUse *SOPS: Decrypt for editing* to view comments.".into()
                }
                (Some(_), Some(leaf)) if leaf.is_metadata(a.fmt) => metadata_markdown(&a),
                (Some(ty), leaf) => {
                    let path = leaf.map(|l| PathDisplay(&l.path).to_string()).unwrap_or_else(|| "?".into());
                    let header = format!("**SOPS** · `{path}` · `{ty}`");
                    if !snap.settings.hover_decrypt {
                        format!("{header}\n\n_Hover decryption is disabled (`hoverDecrypt`)._")
                    } else {
                        match (self.decrypted_tree(&uri).await, leaf) {
                            (Some(Ok(tree)), Some(leaf)) => match scan::lookup(&tree, &leaf.path) {
                                Some(v) => format!("{header}\n\n{}", fenced(&display_value(v))),
                                None => format!("{header}\n\n_Value not found in decrypted output._"),
                            },
                            (Some(Err(e)), _) => format!("{header}\n\n**Decryption failed**\n\n{}", fenced(&e)),
                            _ => header,
                        }
                    }
                }
            };
            return Ok(Some(Hover { contents: HoverContents::Markup(MarkupContent { kind: MarkupKind::Markdown, value: body }), range }));
        } else if scan::leaf_at(&a.leaves, offset).is_some_and(|l| l.is_metadata(a.fmt))
            || on_metadata_header(&snap.text, &idx, offset, a.fmt)
        {
            metadata_markdown(&a)
        } else {
            return Ok(None);
        };
        Ok(Some(Hover { contents: HoverContents::Markup(MarkupContent { kind: MarkupKind::Markdown, value: md }), range: None }))
    }

    async fn inlay_hint(&self, p: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        let uri = p.text_document.uri;
        let Some(snap) = self.snapshot(&uri) else { return Ok(None) };
        let enabled = self.state.lock().unwrap().inlay_override.unwrap_or(snap.settings.inlay_hints);
        let a = Analysis::new(&snap.text, snap.fmt);
        if !enabled || !a.encrypted {
            return Ok(None);
        }
        let Some(Ok(tree)) = self.decrypted_tree(&uri).await else { return Ok(None) };
        let idx = LineIndex::new(&snap.text, snap.encoding);
        let (lo, hi) = (idx.offset(p.range.start), idx.offset(p.range.end));
        let hints = a
            .tokens
            .iter()
            .filter(|t| t.value_type.is_some() && !t.is_comment() && t.end >= lo && t.start <= hi)
            .filter_map(|t| {
                let leaf = scan::leaf_at(&a.leaves, t.start).filter(|l| !l.is_metadata(a.fmt))?;
                let v = scan::lookup(&tree, &leaf.path)?;
                // In JSON the token sits inside quotes: put the hint after the closing quote.
                let at = if snap.text[t.end..].starts_with('"') { t.end + 1 } else { t.end };
                Some(InlayHint {
                    position: idx.position(at),
                    label: InlayHintLabel::String(format!("🔓 {}", truncate(&display_value(v), 60))),
                    kind: None,
                    text_edits: None,
                    tooltip: Some(InlayHintTooltip::String(PathDisplay(&leaf.path).to_string())),
                    padding_left: Some(true),
                    padding_right: None,
                    data: None,
                })
            })
            .collect();
        Ok(Some(hints))
    }

    async fn code_action(&self, p: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = p.text_document.uri;
        let Some(snap) = self.snapshot(&uri) else { return Ok(None) };
        let a = Analysis::new(&snap.text, snap.fmt);
        let only = p.context.only.unwrap_or_default();
        let wants = |kind: &str| only.is_empty() || only.iter().any(|k| kind.starts_with(k.as_str()));
        let mut out: Vec<CodeActionOrCommand> = Vec::new();

        // When the editor asks *specifically* for the encrypt kind (e.g. Zed's
        // `code_actions_on_format`), compute the edit eagerly so it can be
        // applied without a round-trip through workspace/executeCommand.
        let eager = !only.is_empty() && only.iter().any(|k| k.as_str() == KIND_ENCRYPT);

        if a.encrypted {
            if wants(KIND_DECRYPT) {
                out.push(action("SOPS: Decrypt for editing", KIND_DECRYPT, CMD_DECRYPT, &uri));
            }
            if wants(KIND_MAINTENANCE) {
                let on = self.state.lock().unwrap().inlay_override.unwrap_or(snap.settings.inlay_hints);
                let title = if on { "SOPS: Hide decrypted values" } else { "SOPS: Show decrypted values inline" };
                out.push(action(title, KIND_MAINTENANCE, CMD_TOGGLE_HINTS, &uri));
                if snap.path.as_deref().and_then(rules::find_config).is_some() {
                    out.push(action("SOPS: Update keys from .sops.yaml", KIND_MAINTENANCE, CMD_UPDATE_KEYS, &uri));
                }
                out.push(action("SOPS: Rotate data key", KIND_MAINTENANCE, CMD_ROTATE, &uri));
            }
        } else if snap.session {
            if eager {
                match self.encrypt_text(&uri, &snap.text).await {
                    Ok(cipher) => {
                        let idx = LineIndex::new(&snap.text, snap.encoding);
                        out.push(CodeActionOrCommand::CodeAction(CodeAction {
                            title: "SOPS: Re-encrypt".into(),
                            kind: Some(KIND_ENCRYPT.into()),
                            edit: Some(WorkspaceEdit {
                                changes: Some(HashMap::from([(uri.clone(), vec![TextEdit::new(idx.full_range(), cipher)])])),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }));
                    }
                    Err(e) => self.error(format!("re-encryption failed: {e}")).await,
                }
            } else if wants(KIND_ENCRYPT) {
                out.push(action("SOPS: Re-encrypt", KIND_ENCRYPT, CMD_ENCRYPT, &uri));
                out.push(action("SOPS: Discard changes (restore ciphertext)", KIND_ENCRYPT, CMD_DISCARD, &uri));
            }
        } else if !eager && wants(KIND_ENCRYPT) {
            if let Some(path) = &snap.path {
                if rules::find_config(path).is_some() {
                    let related: Vec<Diagnostic> = p
                        .context
                        .diagnostics
                        .iter()
                        .filter(|d| d.code == Some(NumberOrString::String("should-be-encrypted".into())))
                        .cloned()
                        .collect();
                    out.push(CodeActionOrCommand::CodeAction(CodeAction {
                        title: "SOPS: Encrypt file using .sops.yaml".into(),
                        kind: Some(if related.is_empty() { KIND_ENCRYPT.into() } else { CodeActionKind::QUICKFIX }),
                        is_preferred: Some(!related.is_empty()),
                        diagnostics: (!related.is_empty()).then_some(related),
                        command: Some(command("SOPS: Encrypt file using .sops.yaml", CMD_ENCRYPT, &uri)),
                        ..Default::default()
                    }));
                }
            }
        }
        Ok(Some(out))
    }

    async fn execute_command(&self, p: ExecuteCommandParams) -> Result<Option<LSPAny>> {
        let uri = p
            .arguments
            .first()
            .and_then(Value::as_str)
            .and_then(|s| Uri::from_str(s).ok())
            .ok_or_else(|| RpcError::invalid_params("expected the document URI as first argument"))?;
        if let Err(e) = self.run_command(&p.command, &uri).await {
            self.error(&e).await;
            return Err(RpcError { code: tower_lsp_server::jsonrpc::ErrorCode::InternalError, message: e.into(), data: None });
        }
        Ok(None)
    }
}

impl Backend {
    async fn formatting_edit(&self, uri: &Uri, snap: &Snapshot) -> Result<Option<Vec<TextEdit>>> {
        match self.encrypt_text(uri, &snap.text).await {
            Ok(cipher) => {
                let idx = LineIndex::new(&snap.text, snap.encoding);
                Ok(Some(vec![TextEdit::new(idx.full_range(), cipher)]))
            }
            Err(e) => {
                self.error(format!("re-encryption failed: {e}")).await;
                Err(RpcError { code: tower_lsp_server::jsonrpc::ErrorCode::InternalError, message: e.into(), data: None })
            }
        }
    }
}

/// Replace a file atomically, keeping its permissions.
fn atomic_write(path: &Path, content: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.sops-ls~"));
    std::fs::write(&tmp, content)?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path)
}
