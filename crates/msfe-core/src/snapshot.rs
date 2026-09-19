//! Configuration snapshots: the MailScanner etc tree and MSFE-NG's own
//! `/etc/msfe-ng` in one `tar.gz` with a manifest, for backup, restore and
//! moving a setup to another server.
//!
//! An archive holds `manifest.json`, `mailscanner/<rel>` for every catalog
//! file except the generated phishing lists (megabytes, regenerated nightly)
//! and `msfe/<rel>` for the whole MSFE-NG config dir. `inspect` lists the
//! archive and refuses anything outside those two prefixes, any `..`, any
//! absolute path and any link *before* extracting; it then compares every
//! file with the live tree. `import` writes the selected files through the
//! save pipeline as one set — one lint, one restart — and regenerates the
//! rulesets when policy files changed. A tarball without a manifest whose
//! entries start with `msfe-ng/` is the legacy `msfe-ng backup` format.

use crate::confcatalog::{self, Entry, Kind, Root};
use crate::confsave::{self, LintMode, ReloadMode, SaveReport, SaveRequest};
use crate::json::Json;
use crate::{dbtools, layout, service, sync, Config};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const FORMAT: u32 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct ManifestFile {
    pub id: String,
    pub size: u64,
    pub mode: u32,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub format: u32,
    pub created: u64,
    pub host: String,
    pub msfe_ng: String,
    pub mailscanner_version: Option<String>,
    pub ms_etc: String,
    pub msfe_dir: String,
    pub files: Vec<ManifestFile>,
    /// True for a legacy `msfe-ng backup` tarball (no manifest inside).
    pub legacy: bool,
}

impl Manifest {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("format".into(), Json::Int(self.format as i64)),
            ("created".into(), Json::Int(self.created as i64)),
            ("host".into(), Json::str(&self.host)),
            ("msfe_ng".into(), Json::str(&self.msfe_ng)),
            (
                "mailscanner_version".into(),
                self.mailscanner_version
                    .clone()
                    .map(Json::Str)
                    .unwrap_or(Json::Null),
            ),
            ("ms_etc".into(), Json::str(&self.ms_etc)),
            ("msfe_dir".into(), Json::str(&self.msfe_dir)),
            (
                "files".into(),
                Json::Array(
                    self.files
                        .iter()
                        .map(|f| {
                            Json::Object(vec![
                                ("id".into(), Json::str(&f.id)),
                                ("size".into(), Json::Int(f.size as i64)),
                                ("mode".into(), Json::Int(f.mode as i64)),
                                (
                                    "sha256".into(),
                                    f.sha256.clone().map(Json::Str).unwrap_or(Json::Null),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("legacy".into(), Json::Bool(self.legacy)),
        ])
    }
    pub fn from_json(v: &Json) -> Manifest {
        Manifest {
            format: v.get("format").and_then(Json::as_i64).unwrap_or(0) as u32,
            created: v.get("created").and_then(Json::as_i64).unwrap_or(0) as u64,
            host: v.str_field("host"),
            msfe_ng: v.str_field("msfe_ng"),
            mailscanner_version: v
                .get("mailscanner_version")
                .and_then(Json::as_str)
                .map(str::to_string),
            ms_etc: v.str_field("ms_etc"),
            msfe_dir: v.str_field("msfe_dir"),
            files: v
                .get("files")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(|f| ManifestFile {
                    id: f.str_field("id"),
                    size: f.get("size").and_then(Json::as_i64).unwrap_or(0) as u64,
                    mode: f.get("mode").and_then(Json::as_i64).unwrap_or(0o644) as u32,
                    sha256: f.get("sha256").and_then(Json::as_str).map(str::to_string),
                })
                .collect(),
            legacy: matches!(v.get("legacy"), Some(Json::Bool(true))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Only {
    All,
    Mailscanner,
    Msfe,
}

impl Only {
    pub fn parse(s: &str) -> Option<Only> {
        match s {
            "all" | "" => Some(Only::All),
            "mailscanner" | "ms" => Some(Only::Mailscanner),
            "msfe" | "msfe-ng" => Some(Only::Msfe),
            _ => None,
        }
    }
    fn takes(&self, root: Root) -> bool {
        match self {
            Only::All => true,
            Only::Mailscanner => root == Root::Ms,
            Only::Msfe => root == Root::Msfe,
        }
    }
}

pub fn snapshots_dir(cfg: &Config) -> PathBuf {
    Path::new(&cfg.backup_dir).join("snapshots")
}

fn mkdir_private(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// `ms:rules/x` → `mailscanner/rules/x`, `msfe:config.toml` → `msfe/config.toml`.
fn archive_path(id: &str) -> Option<String> {
    id.strip_prefix("ms:")
        .map(|r| format!("mailscanner/{r}"))
        .or_else(|| id.strip_prefix("msfe:").map(|r| format!("msfe/{r}")))
}

/// The reverse, accepting the legacy `msfe-ng/` prefix.
fn id_of_archive_path(p: &str) -> Option<String> {
    let p = p.strip_prefix("./").unwrap_or(p);
    p.strip_prefix("mailscanner/")
        .map(|r| format!("ms:{r}"))
        .or_else(|| p.strip_prefix("msfe/").map(|r| format!("msfe:{r}")))
        .or_else(|| p.strip_prefix("msfe-ng/").map(|r| format!("msfe:{r}")))
}

/// Every file under the MSFE-NG config dir, relative, files only.
fn msfe_files(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.')
                || name.ends_with(".msfe-ng.bak")
                || name.ends_with(".tmp.msfe-ng")
            {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.is_dir() {
                walk(base, &p, out);
            } else if meta.is_file() {
                if let Ok(rel) = p.strip_prefix(base) {
                    out.push(rel.display().to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out
}

/// The files a snapshot of this host carries, as `(id, live path)`.
fn exportable(
    cfg: &Config,
    config_file: &Path,
    only: Only,
) -> (confcatalog::Catalog, Vec<(String, PathBuf)>) {
    let cat = confcatalog::scan(cfg, config_file);
    let mut out = Vec::new();
    if only.takes(Root::Ms) {
        for e in &cat.entries {
            if e.root != Root::Ms {
                continue;
            }
            if matches!(
                e.kind,
                Kind::ReadOnly(confcatalog::ReadOnlyReason::GeneratedByPhishingUpdater)
                    | Kind::ReadOnly(confcatalog::ReadOnlyReason::Vendor)
            ) {
                continue;
            }
            out.push((e.id.clone(), e.path.clone()));
        }
    }
    if only.takes(Root::Msfe) {
        let backups = Path::new(&cfg.backup_dir);
        for rel in msfe_files(&cat.msfe_dir) {
            let live = cat.msfe_dir.join(&rel);
            if live.starts_with(backups) {
                continue; // snapshots and history are never part of a snapshot
            }
            out.push((format!("msfe:{rel}"), live));
        }
    }
    (cat, out)
}

fn sha256_of(paths: &[PathBuf]) -> Vec<Option<String>> {
    if paths.is_empty() {
        return Vec::new();
    }
    let out = Command::new("sha256sum").args(paths).output();
    let text = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return vec![None; paths.len()],
    };
    paths
        .iter()
        .map(|p| {
            let disp = p.display().to_string();
            text.lines()
                .find(|l| l.ends_with(&disp))
                .and_then(|l| l.split_whitespace().next())
                .map(str::to_string)
        })
        .collect()
}

/// Write a snapshot; `out` defaults to `backup_dir/snapshots/msfe-ng-snapshot-<host>-<stamp>.tar.gz`.
pub fn export(
    cfg: &Config,
    config_file: &Path,
    only: Only,
    out: Option<&Path>,
) -> io::Result<(PathBuf, Manifest)> {
    let (cat, files) = exportable(cfg, config_file, only);
    let sdir = snapshots_dir(cfg);
    mkdir_private(&sdir)?;
    let stamp = dbtools::stamp(dbtools::now_secs());
    let host = hostname();
    let out = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| sdir.join(format!("msfe-ng-snapshot-{host}-{stamp}.tar.gz")));
    let stage = sdir.join(format!(".stage-{}-{stamp}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    mkdir_private(&stage)?;
    let result = (|| -> io::Result<Manifest> {
        let mut manifest = Manifest {
            format: FORMAT,
            created: dbtools::now_secs(),
            host: host.clone(),
            msfe_ng: msfe_api::VERSION.to_string(),
            mailscanner_version: {
                let lay = layout::resolve(cfg);
                lay.version.map(|_| lay.version_string())
            },
            ms_etc: cat.ms_etc.display().to_string(),
            msfe_dir: cat.msfe_dir.display().to_string(),
            files: Vec::new(),
            legacy: false,
        };
        let mut staged: Vec<PathBuf> = Vec::new();
        for (id, live) in &files {
            let Some(ap) = archive_path(id) else {
                continue;
            };
            let dst = stage.join(&ap);
            if let Some(d) = dst.parent() {
                std::fs::create_dir_all(d)?;
            }
            let bytes = match std::fs::read(live) {
                Ok(b) => b,
                Err(_) => continue, // vanished or unreadable: not part of the snapshot
            };
            std::fs::write(&dst, &bytes)?;
            let mode = {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(live)
                    .map(|m| m.mode() & 0o7777)
                    .unwrap_or(0o644)
            };
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(mode));
            }
            manifest.files.push(ManifestFile {
                id: id.clone(),
                size: bytes.len() as u64,
                mode,
                sha256: None,
            });
            staged.push(dst);
        }
        for (f, h) in manifest.files.iter_mut().zip(sha256_of(&staged)) {
            f.sha256 = h;
        }
        std::fs::write(stage.join("manifest.json"), manifest.to_json().to_string())?;
        let st = Command::new("tar")
            .arg("czf")
            .arg(&out)
            .arg("-C")
            .arg(&stage)
            .arg(".")
            .status()?;
        if !st.success() {
            return Err(io::Error::other("tar failed"));
        }
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
        }
        Ok(manifest)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    result.map(|m| (out, m))
}

/// Snapshots on this host, newest first: `(path, size, mtime)`.
pub fn list(cfg: &Config) -> Vec<(PathBuf, u64, u64)> {
    let mut out: Vec<(PathBuf, u64, u64)> = std::fs::read_dir(snapshots_dir(cfg))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.gz"))
                .filter_map(|e| {
                    use std::os::unix::fs::MetadataExt;
                    let m = e.metadata().ok()?;
                    Some((e.path(), m.len(), m.mtime().max(0) as u64))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.2.cmp(&a.2).then(b.0.cmp(&a.0)));
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Same,
    Changed,
    New,
    /// The live file exists but is not editable (generated, shipped).
    ReadOnlyLive,
    /// Not a file the catalog would list (an unknown path).
    NotInCatalog,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Same => "same",
            Status::Changed => "changed",
            Status::New => "new",
            Status::ReadOnlyLive => "readonly",
            Status::NotInCatalog => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileDiff {
    pub id: String,
    pub status: Status,
    pub live_size: Option<u64>,
    pub snap_size: u64,
    /// Whether `import` would write it.
    pub importable: bool,
}

#[derive(Debug, Clone)]
pub struct Inspection {
    pub token: String,
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub files: Vec<FileDiff>,
}

fn incoming_dir(cfg: &Config) -> PathBuf {
    snapshots_dir(cfg).join(".incoming")
}

/// `tar tvzf` lines → checked archive paths. Refuses links, `..`, absolute
/// paths and anything outside the known prefixes.
fn checked_entries(listing: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for line in listing.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let kind = line.chars().next().unwrap_or('?');
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return Err(format!("unreadable archive listing: {line}"));
        }
        let path = fields[5..].join(" ");
        let path = path.strip_prefix("./").unwrap_or(&path).to_string();
        if kind == 'l' || kind == 'h' || path.contains(" -> ") {
            return Err(format!("archive contains a link: {path}"));
        }
        if path.is_empty() || path == "." {
            continue;
        }
        if path.starts_with('/') || path.split('/').any(|c| c == "..") {
            return Err(format!("archive contains an unsafe path: {path}"));
        }
        if kind == 'd' {
            continue;
        }
        if path != "manifest.json"
            && !path.starts_with("mailscanner/")
            && !path.starts_with("msfe/")
            && !path.starts_with("msfe-ng/")
        {
            return Err(format!(
                "archive contains a file outside the snapshot layout: {path}"
            ));
        }
        out.push(path);
    }
    Ok(out)
}

fn diff_against_live(
    cfg: &Config,
    config_file: &Path,
    dir: &Path,
    manifest: &Manifest,
) -> Vec<FileDiff> {
    let cat = confcatalog::scan(cfg, config_file);
    manifest
        .files
        .iter()
        .filter_map(|mf| {
            let ap = archive_path(&mf.id)?;
            let snap = dir.join(ap);
            let snap_bytes = std::fs::read(&snap).ok()?;
            let (status, live_size, importable) = if let Some(rel) = mf.id.strip_prefix("msfe:") {
                let live = cat.msfe_dir.join(rel);
                match std::fs::read(&live) {
                    Ok(b) if b == snap_bytes => (Status::Same, Some(b.len() as u64), true),
                    Ok(b) => (Status::Changed, Some(b.len() as u64), true),
                    Err(_) => (Status::New, None, true),
                }
            } else if let Some(rel) = mf.id.strip_prefix("ms:") {
                match cat.entries.iter().find(|e| e.id == mf.id) {
                    Some(e) if !e.kind.editable() => (Status::ReadOnlyLive, Some(e.size), false),
                    Some(e) => match std::fs::read(&e.path) {
                        Ok(b) if b == snap_bytes => (Status::Same, Some(e.size), true),
                        Ok(_) => (Status::Changed, Some(e.size), true),
                        Err(_) => (Status::Changed, None, true),
                    },
                    None => {
                        let (kind, _, _) = confcatalog::classify(Root::Ms, rel);
                        if kind.editable() {
                            (Status::New, None, true)
                        } else {
                            (Status::NotInCatalog, None, false)
                        }
                    }
                }
            } else {
                (Status::NotInCatalog, None, false)
            };
            Some(FileDiff {
                id: mf.id.clone(),
                status,
                live_size,
                snap_size: snap_bytes.len() as u64,
                importable,
            })
        })
        .collect()
}

fn read_manifest(dir: &Path, entries: &[String]) -> io::Result<Manifest> {
    match std::fs::read_to_string(dir.join("manifest.json")) {
        Ok(t) => {
            let v = Json::parse(&t).map_err(|e| io::Error::other(format!("bad manifest: {e}")))?;
            let m = Manifest::from_json(&v);
            if m.format > FORMAT {
                return Err(io::Error::other(format!(
                    "snapshot format {} is newer than this MSFE-NG understands ({FORMAT})",
                    m.format
                )));
            }
            Ok(m)
        }
        Err(_) => {
            // legacy `msfe-ng backup`: msfe-ng/<rel> entries, no manifest
            let files: Vec<ManifestFile> = entries
                .iter()
                .filter_map(|p| {
                    let id = id_of_archive_path(p)?;
                    let size = std::fs::metadata(dir.join(p)).map(|m| m.len()).unwrap_or(0);
                    Some(ManifestFile {
                        id,
                        size,
                        mode: 0o644,
                        sha256: None,
                    })
                })
                .collect();
            if files.is_empty() {
                return Err(io::Error::other(
                    "not a snapshot: no manifest and no known files",
                ));
            }
            Ok(Manifest {
                format: 0,
                created: 0,
                host: String::new(),
                msfe_ng: String::new(),
                mailscanner_version: None,
                ms_etc: String::new(),
                msfe_dir: String::new(),
                files,
                legacy: true,
            })
        }
    }
}

/// List, check and unpack `tarball` into a private incoming dir, then
/// compare every file with the live tree.
pub fn inspect(cfg: &Config, config_file: &Path, tarball: &Path) -> io::Result<Inspection> {
    let out = Command::new("tar").arg("tvzf").arg(tarball).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "not a tar.gz archive: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let entries =
        checked_entries(&String::from_utf8_lossy(&out.stdout)).map_err(io::Error::other)?;
    let token = format!(
        "{}-{}",
        dbtools::stamp(dbtools::now_secs()),
        std::process::id()
    );
    let dir = incoming_dir(cfg).join(&token);
    let _ = std::fs::remove_dir_all(&dir);
    mkdir_private(&incoming_dir(cfg))?;
    mkdir_private(&dir)?;
    let st = Command::new("tar")
        .arg("xzf")
        .arg(tarball)
        .arg("-C")
        .arg(&dir)
        .arg("--no-same-owner")
        .status()?;
    if !st.success() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(io::Error::other("cannot unpack the archive"));
    }
    // the legacy layout lives under msfe-ng/: move it where ids expect it
    if dir.join("msfe-ng").is_dir() && !dir.join("msfe").exists() {
        std::fs::rename(dir.join("msfe-ng"), dir.join("msfe"))?;
    }
    let manifest = match read_manifest(&dir, &entries) {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    let files = diff_against_live(cfg, config_file, &dir, &manifest);
    Ok(Inspection {
        token,
        dir,
        manifest,
        files,
    })
}

/// An inspection unpacked earlier in this daemon's life, by its token.
pub fn reopen(cfg: &Config, config_file: &Path, token: &str) -> io::Result<Inspection> {
    if !service::safe_name(token) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad token"));
    }
    let dir = incoming_dir(cfg).join(token);
    if !dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no such inspection (upload the snapshot again)",
        ));
    }
    let entries: Vec<String> = msfe_files(&dir);
    let manifest = read_manifest(&dir, &entries)?;
    let files = diff_against_live(cfg, config_file, &dir, &manifest);
    Ok(Inspection {
        token: token.to_string(),
        dir,
        manifest,
        files,
    })
}

pub fn discard(insp: &Inspection) {
    let _ = std::fs::remove_dir_all(&insp.dir);
}

/// Remove every unpacked inspection (daemon start: import sessions do not
/// outlive it).
pub fn sweep(cfg: &Config) {
    let _ = std::fs::remove_dir_all(incoming_dir(cfg));
    if let Ok(rd) = std::fs::read_dir(snapshots_dir(cfg)) {
        for e in rd.filter_map(Result::ok) {
            if e.file_name().to_string_lossy().starts_with(".stage-") {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

/// The snapshot's text of `id`.
pub fn snapshot_content(insp: &Inspection, id: &str) -> io::Result<String> {
    let ap =
        archive_path(id).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad id"))?;
    if !insp.files.iter().any(|f| f.id == id) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "not in the snapshot",
        ));
    }
    std::fs::read(insp.dir.join(ap)).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// The entry a snapshot file maps to on this host: the live catalog entry,
/// or one synthesized for a file that does not exist yet.
fn target_entry(cat: &confcatalog::Catalog, id: &str) -> Option<Entry> {
    if let Some(e) = cat.entries.iter().find(|e| e.id == id) {
        return Some(e.clone());
    }
    if let Some(rel) = id.strip_prefix("ms:") {
        let (kind, reload, validator) = confcatalog::classify(Root::Ms, rel);
        return kind.editable().then(|| Entry {
            id: id.to_string(),
            root: Root::Ms,
            rel: rel.to_string(),
            path: cat.ms_etc.join(rel),
            kind,
            reload,
            validator,
            size: 0,
            mtime: 0,
            symlink_target: None,
        });
    }
    let rel = id.strip_prefix("msfe:")?;
    if rel.contains("..") || rel.starts_with('/') {
        return None;
    }
    let (kind, reload, validator) = confcatalog::classify(Root::Msfe, rel);
    Some(Entry {
        id: id.to_string(),
        root: Root::Msfe,
        rel: rel.to_string(),
        path: cat.msfe_dir.join(rel),
        kind,
        reload,
        validator,
        size: 0,
        mtime: 0,
        symlink_target: None,
    })
}

/// Give a file the snapshot's mode and, on a tree owned by a non-root user
/// (ConfigServer layouts), that owner.
fn adopt_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
    if let Some(dir) = path.parent() {
        if let Ok(m) = std::fs::metadata(dir) {
            if m.uid() != 0 {
                let _ = std::os::unix::fs::chown(path, Some(m.uid()), Some(m.gid()));
            }
        }
    }
}

/// Import the selected ids as one change set. Files that are not in the
/// selection, not importable, or identical are skipped.
pub fn import(
    cfg: &Config,
    config_file: &Path,
    insp: &Inspection,
    select: &[String],
    lint: LintMode,
) -> io::Result<Vec<(String, SaveReport)>> {
    import_with(
        cfg,
        config_file,
        insp,
        select,
        lint,
        &layout::resolve(cfg).bin,
    )
}

pub fn import_with(
    cfg: &Config,
    config_file: &Path,
    insp: &Inspection,
    select: &[String],
    lint: LintMode,
    bin: &Path,
) -> io::Result<Vec<(String, SaveReport)>> {
    let cat = confcatalog::scan(cfg, config_file);
    let mut entries: Vec<(Entry, String, bool, u32)> = Vec::new(); // (entry, text, was_new, mode)
    for f in &insp.files {
        if !select.contains(&f.id) || !f.importable || f.status == Status::Same {
            continue;
        }
        let Some(e) = target_entry(&cat, &f.id) else {
            continue;
        };
        let text = snapshot_content(insp, &f.id)?;
        let mode = insp
            .manifest
            .files
            .iter()
            .find(|m| m.id == f.id)
            .map(|m| m.mode)
            .unwrap_or(0o644);
        entries.push((e, text, f.status == Status::New, mode));
    }
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let reqs: Vec<SaveRequest> = entries
        .iter()
        .map(|(e, text, _, _)| SaveRequest {
            entry: e,
            new_text: text.clone(),
            lint,
            reload: ReloadMode::Auto,
            reason: "import",
            expect_mtime: None,
        })
        .collect();
    let reports = confsave::save_many_with(cfg, reqs, bin)?;
    let mut policy_changed = false;
    for ((e, _, was_new, mode), r) in entries.iter().zip(&reports) {
        if r.changed && *was_new {
            adopt_mode(&e.path, *mode);
        }
        if r.changed && e.root == Root::Msfe && e.rel != "config.toml" {
            policy_changed = true;
        }
    }
    let mut out: Vec<(String, SaveReport)> = entries
        .iter()
        .zip(reports)
        .map(|((e, _, _, _), r)| (e.id.clone(), r))
        .collect();
    if policy_changed {
        // the rulesets are generated from the policy: regenerate and reload
        let note = match sync::run(cfg, config_file, None) {
            Ok(rep) => {
                let reloaded = rep.changed > 0 && sync::reload_mailscanner();
                format!(
                    "policy imported: {} ruleset(s) regenerated, {} changed{}",
                    rep.files,
                    rep.changed,
                    if reloaded {
                        ", MailScanner reloaded"
                    } else {
                        ""
                    }
                )
            }
            Err(e) => format!("policy imported but sync failed: {e} — run: msfe-ng sync"),
        };
        for (_, r) in out.iter_mut() {
            if r.changed {
                r.reloaded.transcript.push(note.clone());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> (PathBuf, Config, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("msfe-snapshot-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("etc/MailScanner");
        std::fs::create_dir_all(etc.join("rules")).unwrap();
        std::fs::create_dir_all(etc.join("conf.d")).unwrap();
        std::fs::write(
            etc.join("MailScanner.conf"),
            format!("%etc-dir% = {}\nMax Children = 5\n", etc.display()),
        )
        .unwrap();
        std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default no\n").unwrap();
        std::fs::write(etc.join("phishing.bad.sites.custom"), "bad.example\n").unwrap();
        std::fs::write(etc.join("phishing.bad.sites.conf"), "generated\n").unwrap();
        std::fs::write(etc.join("spamassassin.conf"), "score X 1\n").unwrap();
        let msfe = base.join("etc/msfe-ng");
        std::fs::create_dir_all(msfe.join("policy/domains")).unwrap();
        let conf = msfe.join("config.toml");
        std::fs::write(&conf, "panel = \"x\"\n").unwrap();
        std::fs::write(msfe.join("policy/msconfig.txt"), "highscore=10\n").unwrap();
        std::fs::write(msfe.join("policy/domains/a.example"), "spam=yes\n").unwrap();
        let bin = base.join("fake");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nc=\"${{2:-{live}}}\"\necho \"Reading configuration file $c\"\nd=$(dirname \"$c\")\nif grep -rq BREAKME \"$d\"; then echo \"Cannot open ruleset file BREAKME\"; exit 1; fi\necho ok\n",
                live = etc.join("MailScanner.conf").display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = Config {
            mailscanner_conf: etc.join("MailScanner.conf").display().to_string(),
            mailscanner_rules_dir: etc.join("rules").display().to_string(),
            backup_dir: base.join("backups").display().to_string(),
            ..Config::default()
        };
        (base, cfg, conf, bin)
    }

    #[test]
    fn export_list_inspect_import_round_trip() {
        let (base, cfg, conf, bin) = fixture("rt");
        let etc = base.join("etc/MailScanner");
        let (path, m) = export(&cfg, &conf, Only::All, None).unwrap();
        assert!(path.starts_with(base.join("backups/snapshots")));
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("msfe-ng-snapshot-"));
        let ids: Vec<&str> = m.files.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"ms:MailScanner.conf"));
        assert!(ids.contains(&"ms:rules/bounce.rules"));
        assert!(ids.contains(&"ms:phishing.bad.sites.custom"));
        assert!(
            !ids.contains(&"ms:phishing.bad.sites.conf"),
            "generated lists stay out"
        );
        assert!(ids.contains(&"msfe:config.toml"));
        assert!(ids.contains(&"msfe:policy/domains/a.example"));
        assert_eq!(m.format, FORMAT);
        assert!(
            m.files
                .iter()
                .all(|f| f.sha256.as_ref().is_some_and(|h| h.len() == 64)),
            "sha256sum present here"
        );
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        }
        let l = list(&cfg);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].0, path);
        assert!(
            !base.join("backups/snapshots").read_dir().unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".stage"))
        );

        // everything identical
        let insp = inspect(&cfg, &conf, &path).unwrap();
        assert!(
            insp.files.iter().all(|f| f.status == Status::Same),
            "{:?}",
            insp.files
        );
        assert_eq!(insp.manifest.host, m.host);
        // change live, add a live file, delete one → statuses
        std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default yes\n").unwrap();
        std::fs::remove_file(etc.join("phishing.bad.sites.custom")).unwrap();
        let insp = inspect(&cfg, &conf, &path).unwrap();
        let st = |id: &str| insp.files.iter().find(|f| f.id == id).unwrap().status;
        assert_eq!(st("ms:rules/bounce.rules"), Status::Changed);
        assert_eq!(st("ms:phishing.bad.sites.custom"), Status::New);
        assert_eq!(st("ms:MailScanner.conf"), Status::Same);
        assert_eq!(
            snapshot_content(&insp, "ms:rules/bounce.rules").unwrap(),
            "FromOrTo: default no\n"
        );
        assert!(snapshot_content(&insp, "ms:../x").is_err());
        let re = reopen(&cfg, &conf, &insp.token).unwrap();
        assert_eq!(re.files.len(), insp.files.len());
        assert!(reopen(&cfg, &conf, "../etc").is_err());

        // import the two, config.toml untouched
        let done = import_with(
            &cfg,
            &conf,
            &insp,
            &[
                "ms:rules/bounce.rules".into(),
                "ms:phishing.bad.sites.custom".into(),
                "ms:MailScanner.conf".into(),
            ],
            LintMode::Auto,
            &bin,
        )
        .unwrap();
        assert_eq!(done.len(), 2, "{done:?}");
        assert!(done.iter().all(|(_, r)| r.changed && r.error.is_none()));
        assert_eq!(
            std::fs::read_to_string(etc.join("rules/bounce.rules")).unwrap(),
            "FromOrTo: default no\n"
        );
        assert_eq!(
            std::fs::read_to_string(etc.join("phishing.bad.sites.custom")).unwrap(),
            "bad.example\n"
        );
        assert_eq!(
            confsave::history(
                &cfg,
                &confcatalog::resolve(&cfg, &conf, "ms:rules/bounce.rules").unwrap()
            )[0]
            .reason,
            "import"
        );
        discard(&insp);
        assert!(!insp.dir.exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_snapshot_that_fails_lint_imports_nothing() {
        let (base, cfg, conf, bin) = fixture("badlint");
        let etc = base.join("etc/MailScanner");
        let (path, _) = export(&cfg, &conf, Only::Mailscanner, None).unwrap();
        std::fs::write(
            etc.join("rules/bounce.rules"),
            "FromOrTo: default BREAKME\n",
        )
        .unwrap();
        // live now says BREAKME; the snapshot has "no" → importing the snapshot is fine
        let insp = inspect(&cfg, &conf, &path).unwrap();
        assert!(insp.files.iter().all(|f| f.id.starts_with("ms:")));
        let ok = import_with(
            &cfg,
            &conf,
            &insp,
            &["ms:rules/bounce.rules".into()],
            LintMode::Auto,
            &bin,
        )
        .unwrap();
        assert!(ok[0].1.changed);
        // the other way round: a snapshot carrying BREAKME is refused as a set
        std::fs::write(
            etc.join("rules/bounce.rules"),
            "FromOrTo: default BREAKME\n",
        )
        .unwrap();
        let (bad, _) = export(
            &cfg,
            &conf,
            Only::Mailscanner,
            Some(&base.join("bad.tar.gz")),
        )
        .unwrap();
        std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default no\n").unwrap();
        std::fs::write(etc.join("phishing.bad.sites.custom"), "other.example\n").unwrap();
        let insp = inspect(&cfg, &conf, &bad).unwrap();
        let r = import_with(
            &cfg,
            &conf,
            &insp,
            &[
                "ms:rules/bounce.rules".into(),
                "ms:phishing.bad.sites.custom".into(),
            ],
            LintMode::Auto,
            &bin,
        )
        .unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|(_, x)| !x.changed && x.error.is_some()));
        assert_eq!(
            std::fs::read_to_string(etc.join("rules/bounce.rules")).unwrap(),
            "FromOrTo: default no\n"
        );
        assert_eq!(
            std::fs::read_to_string(etc.join("phishing.bad.sites.custom")).unwrap(),
            "other.example\n"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn unsafe_archives_are_refused_before_unpacking() {
        let (base, cfg, conf, _) = fixture("unsafe");
        let src = base.join("src");
        std::fs::create_dir_all(src.join("mailscanner")).unwrap();
        std::fs::write(src.join("mailscanner/x.conf"), "x").unwrap();
        // ../ path
        let evil = base.join("evil.tar.gz");
        let st = Command::new("tar")
            .args(["czf"])
            .arg(&evil)
            .args(["-C"])
            .arg(&src)
            .args([
                "--transform",
                "s,^mailscanner/x.conf,../evil.conf,",
                "mailscanner/x.conf",
            ])
            .status()
            .unwrap();
        assert!(st.success());
        let e = inspect(&cfg, &conf, &evil).unwrap_err().to_string();
        assert!(e.contains("unsafe path") || e.contains("outside"), "{e}");
        // a symlink
        std::os::unix::fs::symlink("/etc/passwd", src.join("mailscanner/link")).unwrap();
        let linky = base.join("link.tar.gz");
        Command::new("tar")
            .arg("czf")
            .arg(&linky)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .status()
            .unwrap();
        let e = inspect(&cfg, &conf, &linky).unwrap_err().to_string();
        assert!(e.contains("link"), "{e}");
        // a file outside the layout
        std::fs::remove_file(src.join("mailscanner/link")).unwrap();
        std::fs::write(src.join("stray"), "x").unwrap();
        let stray = base.join("stray.tar.gz");
        Command::new("tar")
            .arg("czf")
            .arg(&stray)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .status()
            .unwrap();
        let e = inspect(&cfg, &conf, &stray).unwrap_err().to_string();
        assert!(e.contains("outside the snapshot layout"), "{e}");
        assert!(
            inspect(&cfg, &conf, &base.join("etc/MailScanner/MailScanner.conf")).is_err(),
            "not an archive"
        );
        assert!(
            !base.join("backups/snapshots/.incoming").exists()
                || std::fs::read_dir(base.join("backups/snapshots/.incoming"))
                    .unwrap()
                    .count()
                    == 0
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn legacy_backup_tarballs_still_restore() {
        let (base, cfg, conf, bin) = fixture("legacy");
        // what `msfe-ng backup` used to write: tar czf file -C /etc msfe-ng
        let legacy = base.join("legacy.tar.gz");
        std::fs::write(
            base.join("etc/msfe-ng/policy/msconfig.txt"),
            "highscore=12\n",
        )
        .unwrap();
        Command::new("tar")
            .arg("czf")
            .arg(&legacy)
            .arg("-C")
            .arg(base.join("etc"))
            .arg("msfe-ng")
            .status()
            .unwrap();
        std::fs::write(
            base.join("etc/msfe-ng/policy/msconfig.txt"),
            "highscore=10\n",
        )
        .unwrap();
        let insp = inspect(&cfg, &conf, &legacy).unwrap();
        assert!(insp.manifest.legacy);
        let st = |id: &str| insp.files.iter().find(|f| f.id == id).map(|f| f.status);
        assert_eq!(st("msfe:policy/msconfig.txt"), Some(Status::Changed));
        assert_eq!(st("msfe:config.toml"), Some(Status::Same));
        let r = import_with(
            &cfg,
            &conf,
            &insp,
            &["msfe:policy/msconfig.txt".into()],
            LintMode::Skip,
            &bin,
        )
        .unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].1.changed, "{r:?}");
        assert_eq!(
            std::fs::read_to_string(base.join("etc/msfe-ng/policy/msconfig.txt")).unwrap(),
            "highscore=12\n"
        );
        assert!(r[0]
            .1
            .reloaded
            .transcript
            .iter()
            .any(|t| t.contains("policy imported")));
        let _ = std::fs::remove_dir_all(&base);
    }
}
