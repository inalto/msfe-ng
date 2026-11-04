//! Reads the table of contents of a zip file without unpacking it: the
//! member paths and whether each is encrypted. That is what MailScanner tests
//! `Archives: Filename Rules` against (it matches the member path as stored in
//! the archive, folders included) and what `Allow Password-Protected Archives`
//! looks at, so the chain tester can predict both without a zip library.
//!
//! Only the central directory is read. Zip64 archives (more than 65535
//! members or over 4 GB) are reported as unreadable rather than guessed at.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The path as stored in the archive, e.g. `folder/sub/name.jpg`.
    pub name: String,
    pub encrypted: bool,
    /// `true` for a directory entry (name ends in `/`, no content).
    pub dir: bool,
}

/// `true` when the bytes start like a zip (local file header or an empty
/// archive). Extensions are not consulted: MailScanner's `Find Archives By
/// Content` looks at the bytes too.
pub fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..2] == b"PK" && matches!(&bytes[2..4], b"\x03\x04" | b"\x05\x06")
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// The members listed in the archive's central directory, in order. `Err`
/// names why the archive could not be read (truncated, not a zip, zip64).
pub fn members(bytes: &[u8]) -> Result<Vec<Member>, String> {
    const EOCD: &[u8] = b"PK\x05\x06";
    const CDFH: &[u8] = b"PK\x01\x02";
    if bytes.len() < 22 {
        return Err("too short to be a zip archive".into());
    }
    // The end-of-central-directory record is the last 22 bytes plus an
    // optional comment of up to 65535 bytes: search backwards within that.
    let floor = bytes.len().saturating_sub(22 + 65535);
    let mut eocd = None;
    let mut i = bytes.len() - 22;
    loop {
        if &bytes[i..i + 4] == EOCD {
            eocd = Some(i);
            break;
        }
        if i == floor {
            break;
        }
        i -= 1;
    }
    let Some(e) = eocd else {
        return Err("no end-of-central-directory record (not a zip, or truncated)".into());
    };
    let count = u16_at(bytes, e + 10).unwrap_or(0) as usize;
    let cd_size = u32_at(bytes, e + 12).unwrap_or(0) as usize;
    let cd_off = u32_at(bytes, e + 16).unwrap_or(0) as usize;
    if count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF {
        return Err("zip64 archive: member list not read".into());
    }
    if cd_off
        .checked_add(cd_size)
        .map(|end| end > bytes.len())
        .unwrap_or(true)
    {
        return Err("central directory lies outside the file (truncated archive)".into());
    }
    let mut out = Vec::with_capacity(count);
    let mut p = cd_off;
    while out.len() < count {
        if p + 46 > bytes.len() || &bytes[p..p + 4] != CDFH {
            return Err(format!(
                "central directory entry {} is damaged",
                out.len() + 1
            ));
        }
        let flags = u16_at(bytes, p + 8).unwrap_or(0);
        let name_len = u16_at(bytes, p + 28).unwrap_or(0) as usize;
        let extra_len = u16_at(bytes, p + 30).unwrap_or(0) as usize;
        let comment_len = u16_at(bytes, p + 32).unwrap_or(0) as usize;
        let Some(raw) = bytes.get(p + 46..p + 46 + name_len) else {
            return Err(format!(
                "central directory entry {} is damaged",
                out.len() + 1
            ));
        };
        // Bit 11 says the name is UTF-8; older archivers store CP437 or the
        // local code page, which the lossy decode turns into U+FFFD. Rules
        // match on ASCII in practice, so that is good enough for a prediction.
        let name = String::from_utf8_lossy(raw).into_owned();
        out.push(Member {
            dir: name.ends_with('/'),
            name,
            encrypted: flags & 1 != 0,
        });
        p += 46 + name_len + extra_len + comment_len;
    }
    Ok(out)
}

/// Builds a minimal stored (uncompressed) zip holding the given members,
/// for tests and samples. `encrypted` only sets the flag bit; the bytes are
/// stored as given.
pub fn build(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
        !c
    }
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data, enc) in members {
        let off = out.len() as u32;
        let flags: u16 = if *enc { 1 } else { 0 } | (1 << 11);
        let crc = crc32(data);
        let n = name.as_bytes();
        let fixed = |v: &mut Vec<u8>| {
            v.extend_from_slice(&flags.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // stored
            v.extend_from_slice(&0u16.to_le_bytes()); // time
            v.extend_from_slice(&0u16.to_le_bytes()); // date
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(n.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        fixed(&mut out);
        out.extend_from_slice(n);
        out.extend_from_slice(data);
        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes()); // made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // needed
        fixed(&mut cd);
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk
        cd.extend_from_slice(&0u16.to_le_bytes()); // int attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(n);
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_members_with_paths_and_encryption_flag() {
        let z = build(&[
            ("2-EVENTI/", b"", false),
            (
                "2-EVENTI/3 Un’estate di incontri/2 Notte Bianca.jpg",
                b"jpeg",
                false,
            ),
            ("secret.docx", b"x", true),
        ]);
        assert!(looks_like_zip(&z));
        let m = members(&z).unwrap();
        assert_eq!(m.len(), 3);
        assert!(m[0].dir && !m[0].encrypted);
        assert_eq!(
            m[1].name,
            "2-EVENTI/3 Un’estate di incontri/2 Notte Bianca.jpg"
        );
        assert!(!m[1].encrypted && !m[1].dir);
        assert!(m[2].encrypted);
    }

    #[test]
    fn survives_a_trailing_comment_and_rejects_junk() {
        let mut z = build(&[("a.txt", b"hello", false)]);
        let comment = b"archive comment";
        let n = z.len();
        z[n - 2..].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        z.extend_from_slice(comment);
        assert_eq!(members(&z).unwrap()[0].name, "a.txt");
        assert!(members(b"not a zip at all, really not").is_err());
        assert!(!looks_like_zip(b"%PDF-1.4"));
        let truncated = &z[..z.len() - 30];
        assert!(members(truncated).is_err());
    }

    #[test]
    fn zip64_is_reported_not_guessed() {
        let mut z = build(&[("a.txt", b"hello", false)]);
        let n = z.len();
        // Force the central-directory offset to the zip64 marker.
        z[n - 6..n - 2].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(members(&z).unwrap_err().contains("zip64"));
    }
}
