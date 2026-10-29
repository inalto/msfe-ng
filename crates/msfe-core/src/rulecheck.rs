//! Filename/filetype rules that can never fire. MailScanner reads those files
//! first-match-wins, so a rule placed after a broader one with a different
//! action is dead: `allow \.doc\.docx$` below the stock "possible filename
//! hiding" `deny` never allows anything.
//!
//! Each rule gets one or two example names generated from its own pattern
//! (`sample`), then one run of the engine's perl asks which rule matches each
//! example first — with `m//i`, as MailScanner and `msgtest` match.

use crate::msgrammar::FilenameRule;

/// Rule `index` is never reached: for names like `example`, the earlier rule
/// `by` (with a different action) matches first.
#[derive(Debug, Clone, PartialEq)]
pub struct Shadow {
    pub index: usize,
    pub by: usize,
    pub example: String,
}

// ---- sample generator ----------------------------------------------------------

#[derive(Debug, Clone)]
enum Node {
    Lit(char),
    /// alternatives, each a sequence
    Group(Vec<Vec<Node>>),
    Repeat(Box<Node>, usize, Option<usize>),
}

/// Longest run a sample may spell out; `.{255,}` is fine, `.{99999}` is not.
const MAX_REPEAT: usize = 1000;

struct Parser<'a> {
    s: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    /// Alternatives up to `)` or the end.
    fn alternation(&mut self) -> Option<Vec<Vec<Node>>> {
        let mut alts = vec![self.sequence()?];
        while self.peek() == Some('|') {
            self.i += 1;
            alts.push(self.sequence()?);
        }
        Some(alts)
    }

    fn sequence(&mut self) -> Option<Vec<Node>> {
        let mut seq = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let Some(atom) = self.atom()? else {
                continue; // an anchor or an inline flag: nothing to spell
            };
            let atom = self.quantified(atom)?;
            seq.push(atom);
        }
        Some(seq)
    }

    /// `Some(None)` for zero-width items that are skipped, `None` for syntax
    /// the generator does not handle.
    fn atom(&mut self) -> Option<Option<Node>> {
        let c = self.peek()?;
        self.i += 1;
        Some(Some(match c {
            '^' | '$' => return Some(None),
            '.' => Node::Lit('x'),
            '[' => Node::Lit(self.class()?),
            '(' => {
                if self.peek() == Some('?') {
                    let rest: String = self.s[self.i..].iter().take(4).collect();
                    if rest.starts_with("?:") {
                        self.i += 2;
                    } else if let Some(flags) = rest.strip_prefix('?') {
                        // (?i) and friends: inline flags, matching is /i anyway
                        let n = flags
                            .chars()
                            .take_while(|c| c.is_ascii_alphabetic())
                            .count();
                        if n == 0 || flags.chars().nth(n) != Some(')') {
                            return None; // lookarounds, named groups, …
                        }
                        self.i += 1 + n + 1;
                        return Some(None);
                    }
                }
                let alts = self.alternation()?;
                if self.peek() != Some(')') {
                    return None;
                }
                self.i += 1;
                Node::Group(alts)
            }
            ')' | '*' | '+' | '?' => return None,
            '\\' => {
                let e = self.peek()?;
                self.i += 1;
                match e {
                    'b' | 'B' | 'A' | 'z' | 'Z' => return Some(None),
                    _ => Node::Lit(escape(e)?),
                }
            }
            '{' if self.quantifier_at(self.i - 1).is_some() => return None,
            c => Node::Lit(c),
        }))
    }

    /// `[…]` → one character it accepts.
    fn class(&mut self) -> Option<char> {
        let negated = self.peek() == Some('^');
        if negated {
            self.i += 1;
        }
        let mut items: Vec<(char, char)> = Vec::new();
        let mut first = true;
        loop {
            let c = self.peek()?;
            self.i += 1;
            if c == ']' && !first {
                break;
            }
            first = false;
            let lo = if c == '\\' {
                let e = self.peek()?;
                self.i += 1;
                match e {
                    'd' => {
                        items.push(('0', '9'));
                        continue;
                    }
                    'w' => {
                        items.extend([('a', 'z'), ('0', '9'), ('_', '_')]);
                        continue;
                    }
                    's' => {
                        items.push((' ', ' '));
                        continue;
                    }
                    _ => escape(e)?,
                }
            } else if c == '[' && self.peek() == Some(':') {
                return None; // POSIX classes
            } else {
                c
            };
            if self.peek() == Some('-') && self.s.get(self.i + 1).is_some_and(|&n| n != ']') {
                self.i += 1;
                let mut hi = self.peek()?;
                self.i += 1;
                if hi == '\\' {
                    hi = escape(self.peek()?)?;
                    self.i += 1;
                }
                items.push((lo, hi));
            } else {
                items.push((lo, lo));
            }
        }
        if negated {
            let inside = |ch: char| {
                let l = ch.to_ascii_lowercase();
                let u = ch.to_ascii_uppercase();
                items
                    .iter()
                    .any(|&(a, b)| (a..=b).contains(&l) || (a..=b).contains(&u))
            };
            "xa0_-.Q".chars().find(|&ch| !inside(ch))
        } else {
            items.first().map(|&(a, _)| a)
        }
    }

    /// `{n}`, `{n,}`, `{n,m}` starting at `at`: (min, max, length).
    fn quantifier_at(&self, at: usize) -> Option<(usize, Option<usize>, usize)> {
        if self.s.get(at) != Some(&'{') {
            return None;
        }
        let close = self.s[at..].iter().position(|&c| c == '}')? + at;
        let body: String = self.s[at + 1..close].iter().collect();
        let (lo, hi) = match body.split_once(',') {
            Some((a, b)) => (a, Some(b)),
            None => (body.as_str(), None),
        };
        let min: usize = lo.parse().ok()?;
        let max = match hi {
            None => Some(min),
            Some("") => None,
            Some(b) => Some(b.parse().ok()?),
        };
        Some((min, max, close - at + 1))
    }

    fn quantified(&mut self, atom: Node) -> Option<Node> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.i += 1;
                (0, None)
            }
            Some('+') => {
                self.i += 1;
                (1, None)
            }
            Some('?') => {
                self.i += 1;
                (0, Some(1))
            }
            Some('{') => match self.quantifier_at(self.i) {
                Some((min, max, len)) => {
                    self.i += len;
                    (min, max)
                }
                None => return Some(atom),
            },
            _ => return Some(atom),
        };
        if min > MAX_REPEAT {
            return None;
        }
        // lazy / possessive suffixes change nothing for an example
        if matches!(self.peek(), Some('?') | Some('+')) {
            self.i += 1;
        }
        let stacked = match self.peek() {
            Some('*' | '+' | '?') => true,
            Some('{') => self.quantifier_at(self.i).is_some(),
            _ => false,
        };
        if stacked {
            return None;
        }
        Some(Node::Repeat(Box::new(atom), min, max))
    }
}

/// The character an escape stands for in an example; `None` for escapes the
/// generator does not spell (`\n`, `\x41`, `\p{…}`, backreferences, …).
fn escape(e: char) -> Option<char> {
    Some(match e {
        'd' => '7',
        'w' => 'a',
        's' => ' ',
        'D' | 'S' => 'x',
        'W' => '-',
        c if c.is_ascii_alphanumeric() => return None,
        c => c,
    })
}

fn spell(nodes: &[Node], second: bool, out: &mut String) {
    for n in nodes {
        match n {
            Node::Lit(c) => out.push(*c),
            Node::Group(alts) => {
                let alt = if second && alts.len() > 1 {
                    &alts[1]
                } else {
                    &alts[0]
                };
                spell(alt, second, out);
            }
            Node::Repeat(a, min, max) => {
                let n = if !second {
                    *min
                } else {
                    match max {
                        Some(m) if *m > *min => *min + 1,
                        Some(_) => *min,
                        None => *min + 1,
                    }
                };
                for _ in 0..n {
                    spell(std::slice::from_ref(a), second, out);
                }
            }
        }
    }
}

/// One or two example names spelled from `pattern`: the shortest choice
/// everywhere, then the second alternative / one more repetition. A pattern
/// not anchored with `^` gets a `file` prefix, so `\.ico$` → `file.ico`.
/// Empty for syntax the generator does not handle.
pub fn sample(pattern: &str) -> Vec<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut p = Parser { s: &chars, i: 0 };
    let Some(alts) = p.alternation() else {
        return Vec::new();
    };
    if p.i != chars.len() {
        return Vec::new(); // a stray `)`
    }
    let body = pattern.strip_prefix("(?i)").unwrap_or(pattern);
    let prefix = if body.starts_with('^') { "" } else { "file" };
    let top = vec![Node::Group(alts)];
    let mut out: Vec<String> = Vec::new();
    for second in [false, true] {
        let mut s = prefix.to_string();
        spell(&top, second, &mut s);
        if !s.is_empty() && !s.contains(['\t', '\n', '\r']) && !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

// ---- shadow check -----------------------------------------------------------------

/// Rules that never fire because an earlier rule with a different action
/// matches every example of theirs first. Same-action overlaps are merely
/// redundant and not reported. `None` when no perl can be run.
pub fn shadowed_filename_rules(perl: &[String], rules: &[FilenameRule]) -> Option<Vec<Shadow>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let exe = perl.first()?;
    let samples: Vec<(usize, String)> = rules
        .iter()
        .enumerate()
        .skip(1)
        .flat_map(|(k, r)| sample(&r.pattern).into_iter().map(move |s| (k, s)))
        .collect();
    if samples.is_empty() {
        // still prove perl runs, so "unavailable" stays distinguishable
        Command::new(exe)
            .args(perl.iter().skip(1))
            .arg("-e")
            .arg("1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        return Some(Vec::new());
    }
    // Per sample: the first rule (of all) that matches it, and whether its
    // own rule matches it at all — an example that misses its own pattern
    // proves nothing. Same matching as msgtest::first_match_perl: m//i.
    let script = r#"my $n = <STDIN>; chomp $n; my @re;
for (1 .. $n) { my $p = <STDIN>; chomp $p; push @re, scalar eval { qr/$p/i } }
while (my $l = <STDIN>) { chomp $l; my ($k, $s) = split /\t/, $l, 2;
  my $first = -1; for my $i (0 .. $#re) { next unless defined $re[$i]; if ($s =~ $re[$i]) { $first = $i; last } }
  my $self = (defined $re[$k] && $s =~ $re[$k]) ? 1 : 0; print "$first $self\n" }"#;
    let mut child = Command::new(exe)
        .args(perl.iter().skip(1))
        .arg("-e")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        let _ = writeln!(stdin, "{}", rules.len());
        for r in rules {
            let _ = writeln!(stdin, "{}", r.pattern.replace(['\n', '\r'], " "));
        }
        for (k, s) in &samples {
            let _ = writeln!(stdin, "{k}\t{s}");
        }
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let answers: Vec<(i64, bool)> = text
        .lines()
        .filter_map(|l| {
            let (a, b) = l.split_once(' ')?;
            Some((a.parse().ok()?, b == "1"))
        })
        .collect();
    if answers.len() != samples.len() {
        return None;
    }
    let mut shadows = Vec::new();
    let mut k = 0;
    while k < samples.len() {
        let rule = samples[k].0;
        let mut end = k;
        while end < samples.len() && samples[end].0 == rule {
            end += 1;
        }
        // every valid example must be taken first by a different-action rule
        let mut best: Option<(usize, &str)> = None;
        let mut valid = 0;
        let mut all = true;
        for j in k..end {
            let (first, own) = answers[j];
            if !own {
                continue;
            }
            valid += 1;
            match usize::try_from(first) {
                Ok(by) if by < rule && rules[by].action != rules[rule].action => {
                    if best.map_or(true, |(b, _)| by < b) {
                        best = Some((by, samples[j].1.as_str()));
                    }
                }
                _ => all = false,
            }
        }
        if valid > 0 && all {
            if let Some((by, ex)) = best {
                shadows.push(Shadow {
                    index: rule,
                    by,
                    example: ex.to_string(),
                });
            }
        }
        k = end;
    }
    Some(shadows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgrammar::Action;

    const HIDING: &str = r"\.[a-z][a-z0-9]{2,3}\s*\.[a-z0-9]{3,4}$";

    #[test]
    fn samples_of_stock_patterns() {
        assert_eq!(sample(r"\.ico$"), vec!["file.ico"]);
        assert_eq!(sample(HIDING), vec!["file.aaa.aaa", "file.aaaa .aaaa"]);
        assert_eq!(sample(r"\.doc\.docx$"), vec!["file.doc.docx"]);
        assert_eq!(
            sample(r"@[a-z0-9._-]+\.[a-z]{2,}\.eml$"),
            vec!["file@a.aa.eml", "file@aa.aaa.eml"]
        );
        let long = sample(".{255,}");
        assert_eq!(long[0].len(), 4 + 255);
        assert_eq!(long[1].len(), 4 + 256);
        assert_eq!(sample(r"^(?:abc|def)\.zip$"), vec!["abc.zip", "def.zip"]);
        assert_eq!(sample(r"(?i)\.exe$"), vec!["file.exe"]);
        assert_eq!(sample(r"\.(jpe?g|png)$"), vec!["file.jpg", "file.png"]);
        assert_eq!(sample(r"\d+[^a-z]\w"), vec!["file70a", "file770a"]);
        // unsupported syntax: no sample at all
        assert!(sample(r"(?=x)y").is_empty());
        assert!(sample(r"\x41").is_empty());
        assert!(sample(r"(unclosed").is_empty());
        assert!(sample(r"[[:alpha:]]").is_empty());
    }

    fn rule(action: Action, pattern: &str) -> FilenameRule {
        FilenameRule {
            action,
            pattern: pattern.into(),
            log_text: "-".into(),
            user_text: "-".into(),
        }
    }

    fn perl() -> Option<Vec<String>> {
        ["/usr/bin/perl", "/usr/local/bin/perl"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|p| vec![p.to_string()])
    }

    #[test]
    fn allow_below_hiding_deny_is_shadowed() {
        let Some(perl) = perl() else {
            return;
        };
        let rules = vec![
            rule(Action::Deny, HIDING),
            rule(Action::Allow, r"\.doc\.docx$"),
        ];
        let s = shadowed_filename_rules(&perl, &rules).expect("perl runs");
        assert_eq!(
            s,
            vec![Shadow {
                index: 1,
                by: 0,
                example: "file.doc.docx".into()
            }]
        );
        // the other way round nothing is hidden
        let rules = vec![
            rule(Action::Allow, r"\.doc\.docx$"),
            rule(Action::Deny, HIDING),
        ];
        assert_eq!(shadowed_filename_rules(&perl, &rules), Some(Vec::new()));
        // same action: redundant, not reported
        let rules = vec![
            rule(Action::Deny, HIDING),
            rule(Action::Deny, r"\.doc\.exe$"),
        ];
        assert_eq!(shadowed_filename_rules(&perl, &rules), Some(Vec::new()));
        // only partly covered: one example gets through, so it is reachable
        let rules = vec![
            rule(Action::Deny, r"\.jpg$"),
            rule(Action::Allow, r"\.(jpg|png)$"),
        ];
        assert_eq!(shadowed_filename_rules(&perl, &rules), Some(Vec::new()));
        assert_eq!(shadowed_filename_rules(&[], &rules), None);
    }
}
