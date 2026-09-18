//! Day index over a log file and its rotated siblings.
//!
//! Logs are append-only and time-ordered, so the byte offset where each day
//! starts is found by binary search over the file (a few dozen seeks per day)
//! instead of a scan. That gives the Logs tab its calendar of available days
//! and lets a day-restricted search read only that day's byte range. Rotated
//! `.gz` siblings are unpacked once into a cache directory.

use crate::civil::Date;
use std::io;
use std::path::{Path, PathBuf};

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::sync::Mutex;

/// One file of a log set: the live file or a rotated sibling.
#[derive(Debug, Clone)]
pub struct LogFile {
    /// File name, the id the API uses (`maillog`, `maillog-20260913`, `….gz`).
    pub name: String,
    pub path: PathBuf,
    pub gz: bool,
    /// Modification time, Unix seconds.
    pub mtime: u64,
    pub len: u64,
}

/// `base` plus its rotated siblings in the same directory — `<name>-N…`,
/// `<name>.N…`, either optionally `.gz` — regular files only, oldest first by
/// mtime, the live file last. Missing files are simply absent.
pub fn log_files(base: &Path) -> Vec<LogFile> {
    let (Some(dir), Some(stem)) = (base.parent(), base.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    let is_sibling = |name: &str| {
        let plain = name.strip_suffix(".gz").unwrap_or(name);
        match plain.strip_prefix(stem) {
            Some("") => true,
            Some(rest) => {
                let digits = &rest[1..];
                (rest.starts_with('-') || rest.starts_with('.'))
                    && !digits.is_empty()
                    && digits.bytes().all(|b| b.is_ascii_digit())
            }
            None => false,
        }
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<LogFile> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            if !is_sibling(&name) {
                return None;
            }
            let meta = e.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            let mtime = meta
                .modified()
                .ok()?
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            Some(LogFile {
                gz: name.ends_with(".gz"),
                path: e.path(),
                name,
                mtime,
                len: meta.len(),
            })
        })
        .collect();
    files.sort_by_key(|f| (f.name == stem, f.mtime, f.name.clone()));
    files
}

/// Where unpacked `.gz` logs live: `/var/cache/msfe-ng/logs`, or
/// `MSFE_NG_LOG_CACHE` (tests, dev runs).
pub fn cache_dir() -> PathBuf {
    std::env::var_os("MSFE_NG_LOG_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/cache/msfe-ng/logs"))
}

/// Longest a `gzip -dc` of one rotated log may take.
const UNPACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// A plain, seekable path for `file`: itself, or for a `.gz` the unpacked copy
/// `<cache>/<name>-<mtime>-<len>` (made once with `gzip -dc`). Cache entries
/// whose source file is gone from the log directory are removed on the way.
pub fn plain_path(file: &LogFile, cache: &Path) -> io::Result<PathBuf> {
    if !file.gz {
        return Ok(file.path.clone());
    }
    std::fs::create_dir_all(cache)?;
    let _ = std::fs::set_permissions(cache, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    if let Some(dir) = file.path.parent() {
        prune_cache(cache, dir);
    }
    let out = cache.join(format!("{}-{}-{}", file.name, file.mtime, file.len));
    if out.is_file() {
        return Ok(out);
    }
    let tmp = cache.join(format!(".{}-{}.tmp", file.name, std::process::id()));
    let mut child = std::process::Command::new("gzip")
        .arg("-dc")
        .arg(&file.path)
        .stdin(std::process::Stdio::null())
        .stdout(std::fs::File::create(&tmp)?)
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + UNPACK_TIMEOUT;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    match status {
        Some(st) if st.success() => {
            std::fs::rename(&tmp, &out)?;
            Ok(out)
        }
        Some(st) => {
            let _ = std::fs::remove_file(&tmp);
            Err(io::Error::other(format!("gzip -dc {}: {st}", file.name)))
        }
        None => {
            let _ = std::fs::remove_file(&tmp);
            Err(io::Error::other(format!(
                "gzip -dc {}: timed out",
                file.name
            )))
        }
    }
}

/// Remove `<cache>/<name>-<mtime>-<len>` entries whose `<name>` no longer
/// exists in `src_dir` (rotated away), plus leftover temp files.
fn prune_cache(cache: &Path, src_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(cache) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let stale = if name.starts_with('.') && name.ends_with(".tmp") {
            true
        } else {
            // strip "-<len>" then "-<mtime>"
            let src = name
                .rsplit_once('-')
                .and_then(|(rest, _len)| rest.rsplit_once('-'))
                .map(|(src, _mtime)| src);
            src.is_some_and(|s| !src_dir.join(s).is_file())
        };
        if stale {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

fn two_digits(b: &[u8]) -> Option<u32> {
    match b {
        [b' ', d] | [b'0', d] if d.is_ascii_digit() => Some((d - b'0') as u32),
        [a, d] if a.is_ascii_digit() && d.is_ascii_digit() => {
            Some(((a - b'0') * 10 + (d - b'0')) as u32)
        }
        _ => None,
    }
}

/// The calendar date a log line starts with, or None. Understands syslog
/// `Mon DD HH:MM:SS` (no year: `year_hint` = (year, month) of the file's
/// mtime; a month later than the hint's belongs to the year before, e.g.
/// December lines in a file last written in January), Exim `YYYY-MM-DD ` and
/// rsyslog RFC 3339 `YYYY-MM-DDT…`.
pub fn line_date(line: &[u8], year_hint: (i32, u32)) -> Option<Date> {
    let valid = |d: Date| (Date::from_days(d.to_days()) == d).then_some(d);
    if line.len() >= 11
        && line[4] == b'-'
        && line[7] == b'-'
        && (line[10] == b' ' || line[10] == b'T')
    {
        let s = std::str::from_utf8(&line[..10]).ok()?;
        return Date::parse(s);
    }
    // "Sep 18 16:23:47 " — month, space, 2-char day, space, HH:MM:SS
    if line.len() >= 15 && line[3] == b' ' && line[6] == b' ' && line[9] == b':' && line[12] == b':'
    {
        let m = MONTHS.iter().position(|m| *m == &line[..3])? as u32 + 1;
        let d = two_digits(&line[4..6])?;
        let y = if m > year_hint.1 {
            year_hint.0 - 1
        } else {
            year_hint.0
        };
        return valid(Date::new(y, m, d));
    }
    None
}

/// The byte range of one day inside one log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaySpan {
    pub date: Date,
    pub file: String,
    pub start: u64,
    /// Exclusive; the next day's start or the file length.
    pub end: u64,
}

/// Longest line the probes will read, and how many unparsable lines they skip
/// looking for a dated one.
const PROBE_LINE: usize = 64 * 1024;
const PROBE_SKIP: usize = 64;

/// Random access into a log file for the day boundary search.
struct Probe {
    f: BufReader<std::fs::File>,
    len: u64,
    hint: (i32, u32),
}

impl Probe {
    /// Start offset of the first line beginning at or after `pos`.
    fn line_start(&mut self, pos: u64) -> io::Result<u64> {
        if pos == 0 {
            return Ok(0);
        }
        if pos >= self.len {
            return Ok(self.len);
        }
        // The byte before `pos` decides whether `pos` itself starts a line.
        self.f.seek(SeekFrom::Start(pos - 1))?;
        let mut skipped = Vec::new();
        let n = self.f.read_until(b'\n', &mut skipped)?;
        Ok((pos - 1 + n as u64).min(self.len))
    }

    /// Date of the first dated line at or after line start `start`, with the
    /// offset of that line; None when nothing dated follows within reach.
    fn date_from(&mut self, start: u64) -> io::Result<Option<(u64, Date)>> {
        self.f.seek(SeekFrom::Start(start))?;
        let mut pos = start;
        let mut line = Vec::new();
        for _ in 0..PROBE_SKIP {
            line.clear();
            let n = (&mut self.f)
                .take(PROBE_LINE as u64)
                .read_until(b'\n', &mut line)?;
            if n == 0 {
                return Ok(None);
            }
            if let Some(d) = line_date(&line, self.hint) {
                return Ok(Some((pos, d)));
            }
            pos += n as u64;
        }
        Ok(None)
    }

    /// Date of the last dated line in the file.
    fn last_date(&mut self) -> io::Result<Option<Date>> {
        const TAIL: u64 = 1024 * 1024;
        let from = self.len.saturating_sub(TAIL);
        self.f.seek(SeekFrom::Start(from))?;
        let mut buf = Vec::with_capacity((self.len - from) as usize);
        self.f.read_to_end(&mut buf)?;
        Ok(buf
            .split(|&b| b == b'\n')
            .rev()
            .find_map(|l| line_date(l, self.hint)))
    }

    /// Smallest line start at or after line start `lo` whose (next dated)
    /// line is on or after `day`.
    fn lower_bound(&mut self, lo: u64, day: Date) -> io::Result<u64> {
        // After a gap day the line at `lo` may already be on or past `day`.
        match self.date_from(lo)? {
            Some((_, d)) if d < day => {}
            _ => return Ok(lo),
        }
        let (mut lo, mut hi) = (lo, self.len);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            let p = self.line_start(mid)?;
            if p >= hi {
                hi = mid;
                continue;
            }
            match self.date_from(p)? {
                Some((at, d)) if d < day => lo = at.max(mid),
                _ => hi = mid,
            }
        }
        self.line_start(hi)
    }
}

/// The days present in one plain log file, with their byte ranges. The first
/// and last dated lines bound the range; every day in between is located by
/// binary search over byte offsets (logs are time-ordered), so a 300 MB file
/// costs a few dozen seeks per day rather than a scan. Days without lines
/// produce no span.
pub fn day_spans(plain: &Path, name: &str, year_hint: (i32, u32)) -> io::Result<Vec<DaySpan>> {
    let f = std::fs::File::open(plain)?;
    let len = f.metadata()?.len();
    let mut probe = Probe {
        f: BufReader::with_capacity(16 * 1024, f),
        len,
        hint: year_hint,
    };
    let (Some((first_off, first)), Some(last)) = (probe.date_from(0)?, probe.last_date()?) else {
        return Ok(Vec::new());
    };
    let mut spans = Vec::new();
    let (mut date, mut start) = (first, first_off);
    while date < last {
        let next = date.next();
        let off = probe.lower_bound(start, next)?;
        if off > start {
            spans.push(DaySpan {
                date,
                file: name.to_string(),
                start,
                end: off,
            });
        }
        date = next;
        start = off;
    }
    spans.push(DaySpan {
        date,
        file: name.to_string(),
        start,
        end: len,
    });
    Ok(spans)
}

/// A log set (live file + rotated siblings) with its day spans, ordered by
/// date then file age.
#[derive(Debug, Default)]
pub struct LogIndex {
    pub files: Vec<LogFile>,
    pub spans: Vec<DaySpan>,
}

impl LogIndex {
    /// One entry per date: where that day begins (its oldest span).
    pub fn days(&self) -> Vec<(Date, &DaySpan)> {
        let mut out: Vec<(Date, &DaySpan)> = Vec::new();
        for s in &self.spans {
            if out.last().map(|(d, _)| *d) != Some(s.date) {
                out.push((s.date, s));
            }
        }
        out
    }

    /// Every span of `day` — two when the day straddles a rotation.
    pub fn spans_for(&self, day: Date) -> Vec<&DaySpan> {
        self.spans.iter().filter(|s| s.date == day).collect()
    }

    pub fn file(&self, name: &str) -> Option<&LogFile> {
        self.files.iter().find(|f| f.name == name)
    }
}

type SpanKey = (PathBuf, u64, u64);
/// Day spans of rotated files, which never change once rotated.
static SPAN_CACHE: Mutex<Option<HashMap<SpanKey, Vec<DaySpan>>>> = Mutex::new(None);

/// Index `base` and its rotated siblings. Rotated files' spans come from a
/// process-wide cache keyed by (path, mtime, len); the live file is
/// re-indexed on every call (a handful of days, a few dozen seeks each).
pub fn index(base: &Path) -> io::Result<LogIndex> {
    let files = log_files(base);
    let cache = cache_dir();
    let live = base.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut spans = Vec::new();
    for (i, file) in files.iter().enumerate() {
        let key = (file.path.clone(), file.mtime, file.len);
        let cached = if file.name == live {
            None
        } else {
            let guard = SPAN_CACHE.lock().unwrap_or_else(|p| p.into_inner());
            guard.as_ref().and_then(|m| m.get(&key).cloned())
        };
        let file_spans = match cached {
            Some(s) => s,
            None => {
                let plain = plain_path(file, &cache)?;
                let mt = Date::from_unix(file.mtime);
                let s = day_spans(&plain, &file.name, (mt.y, mt.m))?;
                if file.name != live {
                    let mut guard = SPAN_CACHE.lock().unwrap_or_else(|p| p.into_inner());
                    guard
                        .get_or_insert_with(HashMap::new)
                        .insert(key, s.clone());
                }
                s
            }
        };
        spans.extend(file_spans.into_iter().map(|s| (s.date, i, s)));
    }
    spans.sort_by_key(|(d, i, _)| (*d, *i));
    Ok(LogIndex {
        files,
        spans: spans.into_iter().map(|(_, _, s)| s).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-logidx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn line_date_reads_syslog_iso_and_rfc3339_prefixes() {
        let hint = (2026, 9);
        assert_eq!(
            line_date(b"Sep 18 16:23:47 ncc dovecot[1]: x", hint),
            Some(Date::new(2026, 9, 18))
        );
        assert_eq!(
            line_date(b"Sep  8 03:37:38 ncc x", hint),
            Some(Date::new(2026, 9, 8)),
            "single-digit day is space padded"
        );
        // December lines in a file last written in January belong to the year before
        assert_eq!(
            line_date(b"Dec 31 23:59:59 h x", (2027, 1)),
            Some(Date::new(2026, 12, 31))
        );
        assert_eq!(
            line_date(b"2026-09-18 16:22:50 SMTP connection", hint),
            Some(Date::new(2026, 9, 18))
        );
        assert_eq!(
            line_date(b"2026-09-18T16:22:50.123456+02:00 ncc x", hint),
            Some(Date::new(2026, 9, 18))
        );
        for bad in [
            &b""[..],
            b"garbage line",
            b"Sep 18",
            b"2026-09-18",
            b"Xyz 18 16:23:47 h",
            b"Sep 99 16:23:47 h",
        ] {
            assert_eq!(
                line_date(bad, hint),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn log_files_lists_rotated_siblings_oldest_first_live_last() {
        let d = tmpdir("files");
        for (name, age) in [
            ("maillog", 0u64),
            ("maillog-20260913", 5),
            ("maillog-20260906", 12),
            ("maillog.1", 20),
            ("maillog-20260830.gz", 19),
            ("maillog.old-notes", 1),
            ("exim_mainlog", 0),
        ] {
            let p = d.join(name);
            std::fs::write(&p, "x\n").unwrap();
            let t = std::time::SystemTime::now() - std::time::Duration::from_secs(age * 86_400);
            std::fs::File::open(&p).unwrap().set_modified(t).unwrap();
        }
        std::fs::create_dir(d.join("maillog-dir")).unwrap();
        let files = log_files(&d.join("maillog"));
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "maillog.1",
                "maillog-20260830.gz",
                "maillog-20260906",
                "maillog-20260913",
                "maillog"
            ]
        );
        assert!(files[1].gz && !files[0].gz);
        assert!(files.iter().all(|f| f.len == 2));
        assert!(log_files(&d.join("missing")).is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn write_lines(p: &Path, lines: &[&str]) {
        std::fs::write(p, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn day_spans_finds_each_day_and_skips_missing_ones() {
        let d = tmpdir("spans");
        let f = d.join("maillog");
        // Sep 13 (2 lines), Sep 14 (3 lines), no Sep 15, Sep 16 (1 line)
        let lines = [
            "Sep 13 03:37:38 h a",
            "Sep 13 09:00:00 h b",
            "Sep 14 00:00:01 h c",
            "Sep 14 12:00:00 h d",
            "Sep 14 23:59:59 h e",
            "Sep 16 08:00:00 h f",
        ];
        write_lines(&f, &lines);
        let spans = day_spans(&f, "maillog", (2026, 9)).unwrap();
        let got: Vec<(String, u64, u64)> = spans
            .iter()
            .map(|s| (s.date.to_string(), s.start, s.end))
            .collect();
        let l = |i: usize| lines[..i].iter().map(|l| l.len() as u64 + 1).sum::<u64>();
        assert_eq!(
            got,
            [
                ("2026-09-13".to_string(), 0, l(2)),
                ("2026-09-14".to_string(), l(2), l(5)),
                ("2026-09-16".to_string(), l(5), l(6)),
            ]
        );
        assert!(spans.iter().all(|s| s.file == "maillog"));
        // single-day file
        write_lines(&f, &lines[2..5]);
        let spans = day_spans(&f, "maillog", (2026, 9)).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].start, spans[0].end), (0, l(5) - l(2)));
        // leading unparsable line is skipped, empty file has no spans
        std::fs::write(&f, "-- restarted --\nSep 14 00:00:01 h c\n").unwrap();
        let spans = day_spans(&f, "maillog", (2026, 9)).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start, 16);
        std::fs::write(&f, "").unwrap();
        assert!(day_spans(&f, "maillog", (2026, 9)).unwrap().is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn day_spans_binary_search_matches_a_linear_scan_on_a_big_file() {
        let d = tmpdir("spansbig");
        let f = d.join("exim_mainlog");
        let mut body = String::new();
        let mut expect: Vec<(Date, u64)> = Vec::new();
        for day in 1..=9u32 {
            if day == 4 {
                continue; // gap
            }
            for i in 0..(300 + day * 37) {
                let date = Date::new(2026, 9, day);
                if expect.last().map(|e| e.0) != Some(date) {
                    expect.push((date, body.len() as u64));
                }
                body.push_str(&format!(
                    "{date} 10:{:02}:{:02} 1abc-{i:05}-00 <= x@y S={i} padding\n",
                    (i / 60) % 60,
                    i % 60
                ));
            }
        }
        std::fs::write(&f, &body).unwrap();
        let spans = day_spans(&f, "exim_mainlog", (2026, 9)).unwrap();
        let got: Vec<(Date, u64)> = spans.iter().map(|s| (s.date, s.start)).collect();
        assert_eq!(got, expect);
        for w in spans.windows(2) {
            assert_eq!(w[0].end, w[1].start, "spans are contiguous");
        }
        assert_eq!(spans.last().unwrap().end, body.len() as u64);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn index_merges_a_day_that_straddles_two_files() {
        let d = tmpdir("index");
        let old = d.join("maillog-20260913");
        let live = d.join("maillog");
        write_lines(&old, &["Sep 12 10:00:00 h a", "Sep 13 01:00:00 h b"]);
        write_lines(&live, &["Sep 13 04:00:00 h c", "Sep 14 10:00:00 h d"]);
        let t = std::time::SystemTime::now() - std::time::Duration::from_secs(5 * 86_400);
        std::fs::File::open(&old).unwrap().set_modified(t).unwrap();
        let idx = index(&live).unwrap();
        let names: Vec<&str> = idx.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["maillog-20260913", "maillog"]);
        let days: Vec<(String, String, u64)> = idx
            .days()
            .iter()
            .map(|(d, s)| (d.to_string(), s.file.clone(), s.start))
            .collect();
        assert_eq!(
            days,
            [
                ("2026-09-12".into(), "maillog-20260913".into(), 0),
                ("2026-09-13".into(), "maillog-20260913".into(), 20),
                ("2026-09-14".into(), "maillog".into(), 20),
            ]
        );
        let sep13 = idx.spans_for(Date::new(2026, 9, 13));
        assert_eq!(sep13.len(), 2);
        assert_eq!(
            (sep13[0].file.as_str(), sep13[0].start, sep13[0].end),
            ("maillog-20260913", 20, 40)
        );
        assert_eq!(
            (sep13[1].file.as_str(), sep13[1].start, sep13[1].end),
            ("maillog", 0, 20)
        );
        assert!(idx.spans_for(Date::new(2026, 9, 15)).is_empty());
        assert!(idx.file("maillog-20260913").is_some() && idx.file("../etc/passwd").is_none());
        // Rotated files are indexed once: same path/mtime/len → cached spans,
        // even though the content changed underneath (never happens for real).
        write_lines(&old, &["Sep 10 10:00:00 h a", "Sep 11 01:00:00 h b"]);
        std::fs::File::open(&old).unwrap().set_modified(t).unwrap();
        let again = index(&live).unwrap();
        assert_eq!(
            again.days()[0].0,
            Date::new(2026, 9, 12),
            "served from the span cache"
        );
        // the live file is always re-read
        write_lines(&live, &["Sep 13 04:00:00 h c", "Sep 15 10:00:00 h d"]);
        assert_eq!(
            index(&live).unwrap().days().last().unwrap().0,
            Date::new(2026, 9, 15)
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn plain_path_unpacks_gz_once_and_prunes_stale_entries() {
        if std::process::Command::new("gzip")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("gzip not installed, skipping");
            return;
        }
        let d = tmpdir("gz");
        let cache = d.join("cache");
        let src = d.join("exim_mainlog-20260913");
        write_lines(&src, &["2026-09-13 10:00:00 a", "2026-09-13 11:00:00 b"]);
        assert!(std::process::Command::new("gzip")
            .arg(&src)
            .status()
            .unwrap()
            .success());
        let gz = log_files(&d.join("exim_mainlog"));
        assert_eq!(gz.len(), 1, "only the rotated file exists");
        let plain = plain_path(&gz[0], &cache).unwrap();
        assert_eq!(
            std::fs::read_to_string(&plain).unwrap(),
            "2026-09-13 10:00:00 a\n2026-09-13 11:00:00 b\n"
        );
        let first = std::fs::metadata(&plain).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(plain_path(&gz[0], &cache).unwrap(), plain);
        assert_eq!(
            std::fs::metadata(&plain).unwrap().modified().unwrap(),
            first,
            "not unpacked again"
        );
        // a stale entry from a file that has since been deleted disappears
        std::fs::write(cache.join("exim_mainlog-20260801.gz-1-1"), "old").unwrap();
        plain_path(&gz[0], &cache).unwrap();
        assert!(!cache.join("exim_mainlog-20260801.gz-1-1").exists());
        assert!(plain.exists());
        // a plain file is returned as is
        let live = d.join("exim_mainlog");
        write_lines(&live, &["2026-09-18 10:00:00 c"]);
        let files = log_files(&live);
        assert_eq!(plain_path(&files[1], &cache).unwrap(), live);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
