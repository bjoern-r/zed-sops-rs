//! Thin async wrapper around the `sops` binary. The server never implements
//! any cryptography itself; all key handling (age, PGP, KMS, Vault, ...) is
//! delegated to sops and the user's existing configuration.
//!
//! Plaintext is only ever passed through pipes, never written to temp files.

use crate::scan::Format;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command};

/// Exit code sops uses for "File has not changed, exiting." in `sops edit`.
const SOPS_EXIT_UNCHANGED: i32 = 200;

/// Hidden subcommand of this binary that sops calls as its "editor".
pub const EDITOR_SUBCOMMAND: &str = "__sops-editor";

#[derive(Clone, Debug)]
pub struct Sops {
    pub binary: String,
    pub env: HashMap<String, String>,
    pub timeout: Duration,
}

struct Output {
    stdout: Vec<u8>,
    stderr: String,
    code: Option<i32>,
}

impl Sops {
    async fn run(&self, mut cmd: Command, stdin: Option<&[u8]>) -> Result<Output, String> {
        cmd.envs(&self.env)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to start `{}`: {e}. Is sops installed and on PATH (or `sopsPath` set)?", self.binary))?;
        if let Some(data) = stdin {
            let mut pipe = child.stdin.take().expect("piped stdin");
            let data = data.to_vec();
            tokio::spawn(async move {
                let _ = pipe.write_all(&data).await;
                // dropping `pipe` closes stdin
            });
        }
        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| format!("sops timed out after {}s (waiting for a PIN/passphrase or KMS?)", self.timeout.as_secs()))?
            .map_err(|e| format!("sops failed: {e}"))?;
        Ok(Output {
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            code: out.status.code(),
        })
    }

    fn command(&self, cwd: Option<&Path>) -> Command {
        let mut cmd = Command::new(&self.binary);
        if let Some(dir) = cwd.filter(|d| d.is_dir()) {
            cmd.current_dir(dir);
        }
        cmd
    }

    /// Decrypt an encrypted document (passed via stdin) into a JSON tree.
    pub async fn decrypt_json(&self, ciphertext: &str, fmt: Format, cwd: Option<&Path>) -> Result<serde_json::Value, String> {
        let text = self.decrypt(ciphertext, fmt, "json", cwd).await?;
        serde_json::from_str(&text).map_err(|e| format!("could not parse sops output: {e}"))
    }

    /// Decrypt an encrypted document into its own format.
    pub async fn decrypt_native(&self, ciphertext: &str, fmt: Format, cwd: Option<&Path>) -> Result<String, String> {
        self.decrypt(ciphertext, fmt, fmt.sops_type(), cwd).await
    }

    async fn decrypt(&self, ciphertext: &str, fmt: Format, out_type: &str, cwd: Option<&Path>) -> Result<String, String> {
        let mut cmd = self.command(cwd);
        cmd.args(["decrypt", "--input-type", fmt.sops_type(), "--output-type", out_type]);
        let out = self.run(cmd, Some(ciphertext.as_bytes())).await?;
        if out.code != Some(0) {
            return Err(clean_error(&out.stderr));
        }
        String::from_utf8(out.stdout).map_err(|e| e.to_string())
    }

    /// Re-encrypt `plaintext` re-using the data key, recipients and settings
    /// of `previous_ciphertext`. This drives `sops edit` non-interactively by
    /// pointing `SOPS_EDITOR` at this very binary, which copies the plaintext
    /// from stdin into sops' temp file. Recipients don't need to be resolvable
    /// via `.sops.yaml`, and only a decryption key is required.
    pub async fn reencrypt(&self, previous_ciphertext: &str, plaintext: &str, fmt: Format) -> Result<String, String> {
        let dir = tempfile::Builder::new()
            .prefix("sops-ls-")
            .tempdir()
            .map_err(|e| format!("cannot create temp dir: {e}"))?;
        // Only ciphertext touches the disk here; sops itself places the
        // decrypted temp file in its own private temp dir as usual.
        let file = dir.path().join(format!("doc.{}", fmt.extension()));
        std::fs::write(&file, previous_ciphertext).map_err(|e| e.to_string())?;
        let sentinel = dir.path().join("editor-ran");

        let exe = std::env::current_exe().map_err(|e| format!("cannot locate sops-ls binary: {e}"))?;
        let editor = format!(
            "{} {} {}",
            shell_quote(&exe.to_string_lossy()),
            EDITOR_SUBCOMMAND,
            shell_quote(&sentinel.to_string_lossy())
        );

        let mut cmd = self.command(None);
        cmd.args(["edit", "--input-type", fmt.sops_type(), "--output-type", fmt.sops_type()])
            .arg(&file)
            .env("SOPS_EDITOR", &editor)
            .env("EDITOR", &editor);
        let out = self.run(cmd, Some(plaintext.as_bytes())).await?;
        match out.code {
            Some(0) | Some(SOPS_EXIT_UNCHANGED) => {
                std::fs::read_to_string(&file).map_err(|e| format!("cannot read re-encrypted file: {e}"))
            }
            _ => Err(clean_error(&out.stderr)),
        }
    }

    /// Encrypt a plaintext document for the first time, using the creation
    /// rules of the nearest `.sops.yaml` for `real_path`.
    pub async fn encrypt_new(&self, plaintext: &str, fmt: Format, real_path: &Path, config: Option<&Path>) -> Result<String, String> {
        let mut cmd = self.command(real_path.parent());
        if let Some(cfg) = config {
            cmd.arg("--config").arg(cfg);
        }
        cmd.args(["encrypt", "--input-type", fmt.sops_type(), "--output-type", fmt.sops_type(), "--filename-override"])
            .arg(real_path);
        let out = self.run(cmd, Some(plaintext.as_bytes())).await?;
        if out.code != Some(0) {
            return Err(clean_error(&out.stderr));
        }
        String::from_utf8(out.stdout).map_err(|e| e.to_string())
    }

    /// Run an in-place maintenance command on a file on disk
    /// (`updatekeys -y`, `rotate -i`).
    pub async fn in_place(&self, args: &[&str], path: &Path, config: Option<&Path>) -> Result<String, String> {
        let mut cmd = self.command(path.parent());
        if let Some(cfg) = config {
            cmd.arg("--config").arg(cfg);
        }
        cmd.args(args).arg(path);
        let out = self.run(cmd, None).await?;
        if out.code != Some(0) {
            return Err(clean_error(&out.stderr));
        }
        Ok(out.stderr)
    }
}

/// The hidden `__sops-editor <sentinel> <file>` entry point. Copies stdin
/// into `file`. If sops invokes the editor a second time (it does that when
/// the content fails to parse), the sentinel makes us fail instead of looping.
pub fn editor_main(args: &[String]) -> i32 {
    use std::io::Read;
    let (Some(sentinel), Some(file)) = (args.first(), args.last()) else {
        eprintln!("usage: sops-ls {EDITOR_SUBCOMMAND} <sentinel> <file>");
        return 2;
    };
    if std::fs::OpenOptions::new().write(true).create_new(true).open(sentinel).is_err() {
        eprintln!("sops-ls: refusing to run the editor twice (plaintext was rejected by sops)");
        return 1;
    }
    let mut buf = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
        eprintln!("sops-ls: reading stdin: {e}");
        return 1;
    }
    match std::fs::write(PathBuf::from(file), buf) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sops-ls: writing {file}: {e}");
            1
        }
    }
}

/// Quote for the shlex-style splitting sops applies to `SOPS_EDITOR`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// sops prefixes errors with log decoration and sometimes appends a usage
/// hint; keep the human-relevant part.
fn clean_error(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(|l| l.trim_start_matches("[CMD]").trim())
        .filter(|l| !l.is_empty() && !l.starts_with("[info]") && !l.contains("is available, you can update"))
        .collect();
    if lines.is_empty() {
        "sops failed without an error message".into()
    } else {
        lines.join("\n")
    }
}
