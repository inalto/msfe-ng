//! Minimal XML reader for machine-written documents (DMARC aggregate reports).
//!
//! Builds a small element tree: names reduced to their local part (namespace
//! prefixes and `xmlns` declarations ignored), attributes dropped, text with
//! the five predefined entities, numeric character references and CDATA
//! decoded. Comments, processing instructions and the `<?xml?>` declaration
//! are skipped. It is deliberately strict where input is hostile: a DOCTYPE
//! (and so any entity definition) is refused, nesting is capped, and a
//! mismatched closing tag is an error rather than something to repair.

const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Element {
    pub name: String,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    /// First child named `name`.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }
    /// Every child named `name`, in order.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
    /// Trimmed text of the element reached by following `path`, or "".
    pub fn text_at(&self, path: &[&str]) -> String {
        let mut e = self;
        for p in path {
            match e.child(p) {
                Some(c) => e = c,
                None => return String::new(),
            }
        }
        e.text.trim().to_string()
    }
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn decode_entities(s: &str) -> Result<String, String> {
    if !s.contains('&') {
        return Ok(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let end = rest
            .find(';')
            .filter(|&e| e <= 12)
            .ok_or("unterminated entity reference")?;
        let ent = &rest[..end];
        let ch = match ent {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code =
                    if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                        u32::from_str_radix(h, 16).ok()
                    } else if let Some(d) = ent.strip_prefix('#') {
                        d.parse().ok()
                    } else {
                        None
                    };
                code.and_then(char::from_u32)
                    .ok_or_else(|| format!("unknown entity &{ent};"))?
            }
        };
        out.push(ch);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Parse a document and return its root element.
pub fn parse(input: &str) -> Result<Element, String> {
    let s = input.trim_start_matches('\u{feff}');
    let b = s.as_bytes();
    let mut i = 0;
    // stack of open elements; the finished root lands in `root`
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    while i < b.len() {
        if b[i] != b'<' {
            let end = s[i..].find('<').map(|n| i + n).unwrap_or(b.len());
            let text = &s[i..end];
            match stack.last_mut() {
                Some(top) => top.text.push_str(&decode_entities(text)?),
                None if text.trim().is_empty() => {}
                None => return Err("text outside the root element".into()),
            }
            i = end;
            continue;
        }
        let rest = &s[i..];
        if rest.starts_with("<!--") {
            let e = rest.find("-->").ok_or("unterminated comment")?;
            i += e + 3;
        } else if rest.starts_with("<![CDATA[") {
            let e = rest.find("]]>").ok_or("unterminated CDATA")?;
            let top = stack.last_mut().ok_or("CDATA outside the root element")?;
            top.text.push_str(&rest[9..e]);
            i += e + 3;
        } else if rest.starts_with("<?") {
            let e = rest
                .find("?>")
                .ok_or("unterminated processing instruction")?;
            i += e + 2;
        } else if rest.starts_with("<!") {
            return Err("DOCTYPE and entity declarations are not accepted".into());
        } else if let Some(r) = rest.strip_prefix("</") {
            let e = r.find('>').ok_or("unterminated closing tag")?;
            let name = local(r[..e].trim());
            let done = stack.pop().ok_or("closing tag without an open element")?;
            if done.name != name {
                return Err(format!("</{name}> closes <{}>", done.name));
            }
            match stack.last_mut() {
                Some(parent) => parent.children.push(done),
                None => root = Some(done),
            }
            i += 2 + e + 1;
        } else {
            // start tag: skip attributes, honouring quoted values that may hold '>'
            let mut j = i + 1;
            let mut quote: Option<u8> = None;
            while j < b.len() {
                match (quote, b[j]) {
                    (Some(q), c) if c == q => quote = None,
                    (Some(_), _) => {}
                    (None, b'"') | (None, b'\'') => quote = Some(b[j]),
                    (None, b'>') => break,
                    _ => {}
                }
                j += 1;
            }
            if j >= b.len() {
                return Err("unterminated start tag".into());
            }
            let inner = &s[i + 1..j];
            let empty = inner.ends_with('/');
            let inner = inner.trim_end_matches('/');
            let name = local(
                inner
                    .split(|c: char| c.is_whitespace())
                    .next()
                    .unwrap_or(""),
            );
            if name.is_empty() {
                return Err("empty tag name".into());
            }
            if root.is_some() {
                return Err("more than one root element".into());
            }
            let el = Element {
                name: name.to_string(),
                ..Default::default()
            };
            if empty {
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => root = Some(el),
                }
            } else {
                if stack.len() >= MAX_DEPTH {
                    return Err("elements nested too deeply".into());
                }
                stack.push(el);
            }
            i = j + 1;
        }
    }
    if let Some(open) = stack.last() {
        return Err(format!("<{}> is never closed", open.name));
    }
    root.ok_or_else(|| "no root element".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_attributes_and_no_declaration() {
        let r = parse(r#"<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema" a='x>y'><version>1.0</version><x:p>none</x:p></feedback>"#).unwrap();
        assert_eq!(r.name, "feedback");
        assert_eq!(r.text_at(&["version"]), "1.0");
        assert_eq!(r.text_at(&["p"]), "none");
    }

    #[test]
    fn declaration_comments_cdata_entities_empty() {
        let r = parse("\u{feff}<?xml version=\"1.0\"?>\n<!-- hi -->\n<a>\n <b>x &amp; &lt;y&gt; &#65;&#x42;</b>\n <c><![CDATA[<raw>]]></c><d/>\n</a>\n").unwrap();
        assert_eq!(r.text_at(&["b"]), "x & <y> AB");
        assert_eq!(r.text_at(&["c"]), "<raw>");
        assert!(r.child("d").is_some());
        assert_eq!(r.text_at(&["missing", "x"]), "");
    }

    #[test]
    fn hostile_input_refused() {
        assert!(parse("<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>").is_err());
        assert!(parse("<a>&x;</a>").is_err());
        assert!(parse(&"<a>".repeat(40)).is_err());
        assert!(parse("<a><b></a></b>").is_err());
        assert!(parse("<a>").is_err());
        assert!(parse("<a/><b/>").is_err());
        assert!(parse("").is_err());
    }
}
