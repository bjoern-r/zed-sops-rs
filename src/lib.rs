//! Zed extension that launches `sops-ls`, the SOPS language server.
//!
//! Binary resolution order:
//!   1. `lsp.sops-ls.binary.path` in Zed settings
//!   2. `sops-ls` on the worktree's $PATH
//!   3. the latest GitHub release of `GITHUB_REPO` (downloaded once, cached)

use std::fs;
use zed_extension_api::{self as zed, serde_json::json, settings::LspSettings, LanguageServerId, Result};

const SERVER_NAME: &str = "sops-ls";
/// Repository whose releases carry prebuilt `sops-ls` binaries.
const GITHUB_REPO: &str = "OWNER/zed-sops";

struct SopsExtension {
    cached_binary_path: Option<String>,
}

impl SopsExtension {
    fn download_server(&mut self, id: &LanguageServerId) -> Result<String> {
        if let Some(path) = &self.cached_binary_path {
            if fs::metadata(path).is_ok_and(|m| m.is_file()) {
                return Ok(path.clone());
            }
        }

        zed::set_language_server_installation_status(id, &zed::LanguageServerInstallationStatus::CheckingForUpdate);
        let release = zed::latest_github_release(
            GITHUB_REPO,
            zed::GithubReleaseOptions { require_assets: true, pre_release: false },
        )?;

        let (os, arch) = zed::current_platform();
        let target = format!(
            "{}-{}",
            match arch {
                zed::Architecture::Aarch64 => "aarch64",
                zed::Architecture::X8664 => "x86_64",
                zed::Architecture::X86 => return Err("32-bit x86 is not supported".into()),
            },
            match os {
                zed::Os::Mac => "apple-darwin",
                zed::Os::Linux => "unknown-linux-gnu",
                zed::Os::Windows => "pc-windows-msvc",
            }
        );
        let (ext, file_type) = match os {
            zed::Os::Windows => ("zip", zed::DownloadedFileType::Zip),
            _ => ("tar.gz", zed::DownloadedFileType::GzipTar),
        };
        let asset_name = format!("{SERVER_NAME}-{target}.{ext}");
        let asset = release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| format!("no release asset named {asset_name} in {GITHUB_REPO} {}", release.version))?;

        let version_dir = format!("{SERVER_NAME}-{}", release.version);
        let binary_path = format!(
            "{version_dir}/{SERVER_NAME}{}",
            if matches!(os, zed::Os::Windows) { ".exe" } else { "" }
        );

        if !fs::metadata(&binary_path).is_ok_and(|m| m.is_file()) {
            zed::set_language_server_installation_status(id, &zed::LanguageServerInstallationStatus::Downloading);
            zed::download_file(&asset.download_url, &version_dir, file_type)
                .map_err(|e| format!("failed to download {asset_name}: {e}"))?;
            zed::make_file_executable(&binary_path)?;

            // Remove older versions.
            for entry in fs::read_dir(".").map_err(|e| e.to_string())?.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(&format!("{SERVER_NAME}-")) && name != version_dir {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
        zed::set_language_server_installation_status(id, &zed::LanguageServerInstallationStatus::None);
        self.cached_binary_path = Some(binary_path.clone());
        Ok(binary_path)
    }

    /// User settings from `lsp.sops-ls.settings`, with `sopsPath` filled in
    /// from the worktree's PATH if the user did not set it.
    fn server_settings(worktree: &zed::Worktree) -> zed::serde_json::Value {
        let mut settings = LspSettings::for_worktree(SERVER_NAME, worktree)
            .ok()
            .and_then(|s| s.settings)
            .unwrap_or_else(|| json!({}));
        if let Some(obj) = settings.as_object_mut() {
            if !obj.contains_key("sopsPath") {
                if let Some(sops) = worktree.which("sops") {
                    obj.insert("sopsPath".into(), json!(sops));
                }
            }
        }
        settings
    }
}

impl zed::Extension for SopsExtension {
    fn new() -> Self {
        Self { cached_binary_path: None }
    }

    fn language_server_command(&mut self, id: &LanguageServerId, worktree: &zed::Worktree) -> Result<zed::Command> {
        let binary = LspSettings::for_worktree(SERVER_NAME, worktree).ok().and_then(|s| s.binary);
        let args = binary.as_ref().and_then(|b| b.arguments.clone()).unwrap_or_default();

        // sops needs the user's shell environment (SOPS_AGE_KEY_FILE,
        // GNUPGHOME, AWS_PROFILE, VAULT_ADDR, ...).
        let mut env = worktree.shell_env();
        if let Some(extra) = binary.as_ref().and_then(|b| b.env.clone()) {
            env.extend(extra);
        }

        let command = match binary.and_then(|b| b.path) {
            Some(path) => path,
            None => match worktree.which(SERVER_NAME) {
                Some(path) => path,
                None => self.download_server(id)?,
            },
        };
        Ok(zed::Command { command, args, env })
    }

    fn language_server_initialization_options(
        &mut self,
        _id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(Some(json!({ "sops": Self::server_settings(worktree) })))
    }

    fn language_server_workspace_configuration(
        &mut self,
        _id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(Some(json!({ "sops": Self::server_settings(worktree) })))
    }
}

zed::register_extension!(SopsExtension);
