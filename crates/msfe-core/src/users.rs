//! Which domains a control-panel account owns — the scope for the end-user UI.
//!
//! cPanel keeps the authoritative `domain: user` map in `/etc/userdomains`;
//! DirectAdmin lists a user's domains in `data/users/<user>/domains.list`.
//! `MSFE_NG_USERDOMAINS_FILE` overrides the source (a `domain: user` file) for
//! testing. The username is validated to a safe charset before any path use.

use crate::panel::detect_panel;
use msfe_api::PanelKind;
use std::path::Path;

/// True for a username safe to interpolate into a path.
pub fn valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && !user.contains("..")
}

/// The domains owned by `user`, sorted and de-duplicated. Empty if the user is
/// invalid or unknown.
pub fn user_domains(user: &str) -> Vec<String> {
    if !valid_username(user) {
        return Vec::new();
    }
    if let Ok(f) = std::env::var("MSFE_NG_USERDOMAINS_FILE") {
        return from_userdomains(&read(Path::new(&f)), user);
    }
    let mut d = match detect_panel().kind() {
        PanelKind::Cpanel => from_userdomains(&read(Path::new("/etc/userdomains")), user),
        PanelKind::DirectAdmin => read_lines(&read(Path::new(&format!(
            "/usr/local/directadmin/data/users/{user}/domains.list"
        )))),
        PanelKind::None => Vec::new(),
    };
    d.sort();
    d.dedup();
    d
}

/// True if `user` owns `domain` — the authorization check for every user route.
pub fn owns_domain(user: &str, domain: &str) -> bool {
    user_domains(user).iter().any(|d| d == domain)
}

/// The account name behind a uid (`/etc/passwd`), for callers authenticated
/// by socket peer credentials. None when unknown or unsafe as a username.
pub fn username_of_uid(uid: u32) -> Option<String> {
    username_from_passwd(&read(Path::new("/etc/passwd")), uid)
}

fn username_from_passwd(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        f.next(); // password field
        if f.next()?.parse::<u32>().ok()? != uid {
            return None;
        }
        valid_username(name).then(|| name.to_string())
    })
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Parse `/etc/userdomains` (`domain: user` per line), collecting `user`'s domains.
fn from_userdomains(text: &str, user: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let (domain, owner) = l.split_once(':')?;
            let domain = domain.trim();
            if owner.trim() == user && !domain.is_empty() && !domain.starts_with('*') {
                Some(domain.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn read_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_username_from_passwd_uid() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nbob:x:1001:1002::/home/bob:/bin/bash\nbad name:x:1003:1003::/x:/bin/sh\n";
        assert_eq!(username_from_passwd(passwd, 1001).as_deref(), Some("bob"));
        assert_eq!(username_from_passwd(passwd, 0).as_deref(), Some("root"));
        assert_eq!(username_from_passwd(passwd, 4242), None);
        // a name unsafe for path use is treated as unknown
        assert_eq!(username_from_passwd(passwd, 1003), None);
    }

    #[test]
    fn username_validation() {
        assert!(valid_username("bob"));
        assert!(valid_username("bob-1.co"));
        assert!(!valid_username("../etc"));
        assert!(!valid_username("a/b"));
        assert!(!valid_username(""));
    }

    #[test]
    fn parses_userdomains() {
        let text = "a.example: bob\nb.example: alice\nc.example: bob\n*: nobody\n";
        let mut d = from_userdomains(text, "bob");
        d.sort();
        assert_eq!(d, vec!["a.example", "c.example"]);
    }
}
