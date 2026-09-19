//! Organizational domain without the Public Suffix List: two labels, or
//! three when the last two form a well-known second-level registry suffix
//! (`co.uk`, `com.au`, …). DMARC inheritance and alignment use it; the
//! result carries an "uncertain" flag for country codes not in the table so
//! a report can say the guess is a guess.

/// Second-level suffixes under which registrations happen (a bounded table
/// of the common ones; anything missing yields `uncertain`).
const TWO_LEVEL: &[&str] = &[
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk", "nhs.uk",
    "sch.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au", "co.nz",
    "net.nz", "org.nz", "ac.nz", "govt.nz", "geek.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "gr.jp", "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in",
    "gov.in", "com.br", "net.br", "org.br", "gov.br", "edu.br", "com.ar", "net.ar", "org.ar",
    "com.mx", "org.mx", "net.mx", "gob.mx", "edu.mx", "com.tr", "net.tr", "org.tr", "gov.tr",
    "edu.tr", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "co.za", "org.za",
    "net.za", "gov.za", "ac.za", "web.za", "co.kr", "ne.kr", "or.kr", "re.kr", "go.kr", "ac.kr",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "com.hk", "net.hk", "org.hk", "edu.hk",
    "gov.hk", "com.my", "net.my", "org.my", "edu.my", "gov.my", "com.tw", "net.tw", "org.tw",
    "edu.tw", "gov.tw", "co.il", "org.il", "net.il", "ac.il", "gov.il", "com.pl", "net.pl",
    "org.pl", "edu.pl", "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua", "in.ua", "co.id",
    "or.id", "net.id", "ac.id", "go.id", "web.id", "com.co", "net.co", "org.co", "edu.co",
    "com.pe", "net.pe", "org.pe", "com.ve", "net.ve", "org.ve", "com.eg", "net.eg", "org.eg",
    "com.ng", "net.ng", "org.ng", "com.ph", "net.ph", "org.ph", "com.vn", "net.vn", "org.vn",
    "com.pk", "net.pk", "org.pk", "com.bd", "net.bd", "org.bd", "com.sa", "net.sa", "org.sa",
    "com.ae", "net.ae", "org.ae", "ac.ae", "com.qa", "com.kw", "com.bh", "com.om", "com.lb",
    "com.jo", "com.uy", "com.py", "com.bo", "com.ec", "com.gt", "com.sv", "com.hn", "com.ni",
    "com.pa", "com.do", "com.pr", "com.cu", "com.jm", "com.tt", "com.na", "com.gh", "com.ke",
    "co.ke", "or.ke", "ne.ke", "co.tz", "or.tz", "co.ug", "or.ug", "co.zw", "co.zm", "co.mz",
    "co.bw", "com.et", "com.ly", "com.dz", "com.tn", "com.ma", "co.ma", "net.ma", "org.ma",
    "com.np", "org.np", "com.lk", "org.lk", "com.mm", "com.kh", "com.bn", "com.fj", "com.pg",
    "co.th", "or.th", "ac.th", "go.th", "in.th", "net.th", "co.nl", "com.ru", "org.ru", "net.ru",
    "msk.ru", "spb.ru", "com.by", "com.kz", "org.kz", "com.uz", "com.ge", "com.am", "com.az",
    "com.mt", "com.cy", "com.gr", "com.pt", "edu.pt", "com.es", "org.es", "nom.es", "gob.es",
    "com.fr", "asso.fr", "gouv.fr", "co.it", "com.de", "co.at", "or.at", "ac.at", "gv.at",
    "com.ee", "com.lv", "com.lt", "com.hr", "com.ba", "com.mk", "com.al", "com.ro", "org.ro",
    "com.bg", "com.rs", "org.rs", "co.rs", "edu.rs", "gov.rs", "com.si", "com.sk", "co.hu",
    "com.is", "co.no", "com.se", "com.fi", "com.dk", "co.dk", "com.ch", "co.ch", "com.be", "co.be",
    "com.lu", "co.ie", "com.ie", "co.gg", "co.je", "co.im", "com.mo", "com.mv", "com.mu", "co.mu",
    "com.sc", "co.ls", "co.sz", "com.na", "co.ao", "com.cm", "co.cm", "com.ci", "co.ci", "com.sn",
    "com.ml", "com.bf", "com.ne", "com.tg", "com.bj", "co.mg", "com.mg", "com.ga", "com.cd",
    "cd.cd", "com.mw", "co.mw", "com.rw", "co.rw", "com.bi", "co.bi", "com.dj", "com.so", "com.sd",
    "com.ss", "com.er", "com.sl", "com.lr", "com.gm", "com.gn", "com.gw", "com.cv", "com.st",
    "com.sh", "com.ac", "com.io", "co.io",
];

/// `(organizational domain, uncertain)` of a host name.
pub fn organizational_domain(host: &str) -> (String, bool) {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return (h, false);
    }
    let n = labels.len();
    let last2 = format!("{}.{}", labels[n - 2], labels[n - 1]);
    if TWO_LEVEL.contains(&last2.as_str()) {
        return (labels[n - 3..].join("."), false);
    }
    let cc = labels[n - 1].len() == 2;
    // a two-letter ccTLD whose second level is short and generic-looking
    // (com/co/net/org/gov/edu/ac/or/ne/go) is almost surely a registry suffix
    let generic = matches!(
        labels[n - 2],
        "com"
            | "co"
            | "net"
            | "org"
            | "gov"
            | "edu"
            | "ac"
            | "or"
            | "ne"
            | "go"
            | "gob"
            | "mil"
            | "nom"
            | "asso"
            | "info"
            | "biz"
    );
    if cc && generic {
        return (labels[n - 3..].join("."), true);
    }
    (labels[n - 2..].join("."), cc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organizational_domains() {
        assert_eq!(
            organizational_domain("mail.example.com"),
            ("example.com".into(), false)
        );
        assert_eq!(
            organizational_domain("example.com"),
            ("example.com".into(), false)
        );
        assert_eq!(
            organizational_domain("a.b.c.example.org."),
            ("example.org".into(), false)
        );
        assert_eq!(
            organizational_domain("mail.example.co.uk"),
            ("example.co.uk".into(), false)
        );
        assert_eq!(
            organizational_domain("www.example.com.au"),
            ("example.com.au".into(), false)
        );
        assert_eq!(
            organizational_domain("mail.example.it"),
            ("example.it".into(), true),
            "ccTLD not in the table: guessed"
        );
        assert_eq!(
            organizational_domain("mail.example.com.xy"),
            ("example.com.xy".into(), true),
            "generic second level under an unknown ccTLD"
        );
        assert_eq!(
            organizational_domain("ncc.transfervda.com"),
            ("transfervda.com".into(), false)
        );
        assert_eq!(
            organizational_domain("localhost"),
            ("localhost".into(), false)
        );
    }
}
