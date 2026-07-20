//! Placeholder view rendering for M0.
//!
//! Pages are loaded from the installed web root at runtime (so `install.sh` can
//! drop updated assets without a recompile). If a template is missing we fall
//! back to a compiled-in minimal page, so the daemon is always useful even on a
//! bare `cargo run`.

use msfe_api::{View, VERSION};
use msfe_core::Panel;

fn web_root() -> String {
    std::env::var("MSFE_NG_WEBROOT").unwrap_or_else(|_| "/opt/msfe-ng/web".to_string())
}

/// Load `web/<area>/index.html` from disk, or use the compiled-in fallback.
fn load_template(area: &str) -> String {
    let path = format!("{}/{}/index.html", web_root(), area);
    std::fs::read_to_string(&path).unwrap_or_else(|_| FALLBACK.to_string())
}

pub fn render(view: View, panel: &dyn Panel) -> String {
    let (area, title) = match view {
        View::Admin => ("whm", "MSFE-NG — Admin"),
        View::User => ("user", "MSFE-NG — Mail Settings"),
    };
    load_template(area)
        .replace("{{TITLE}}", title)
        .replace("{{VERSION}}", VERSION)
        .replace("{{PANEL}}", panel.display_name())
        .replace(
            "{{VIEW}}",
            if matches!(view, View::Admin) {
                "Admin"
            } else {
                "User"
            },
        )
}

pub fn not_found() -> String {
    FALLBACK
        .replace("{{TITLE}}", "MSFE-NG — Not Found")
        .replace("{{VERSION}}", VERSION)
        .replace("{{PANEL}}", "—")
        .replace("{{VIEW}}", "404 — page not found")
}

/// Compiled-in fallback shown when the web root isn't installed yet.
const FALLBACK: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; margin: 0; padding: 3rem 1.5rem;
         display: grid; place-items: center; min-height: 100vh; }
  main { max-width: 40rem; }
  h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
  .tag { display: inline-block; padding: .1rem .5rem; border-radius: 999px;
         background: #8883; font-size: .8rem; }
  .grid { margin-top: 1.5rem; border: 1px solid #8884; border-radius: 10px; }
  .grid div { display: flex; justify-content: space-between; gap: 1rem;
              padding: .6rem .9rem; border-top: 1px solid #8883; }
  .grid div:first-child { border-top: 0; }
  code { background: #8882; padding: .1rem .35rem; border-radius: 4px; }
  p.note { color: #8889; font-size: .85rem; margin-top: 1.5rem; }
</style></head>
<body><main>
  <span class="tag">MSFE-NG · placeholder</span>
  <h1>{{TITLE}}</h1>
  <p>Open-source MailScanner Front-End — installable skeleton (milestone M0).</p>
  <div class="grid">
    <div><span>Surface</span><span>{{VIEW}}</span></div>
    <div><span>Detected panel</span><span>{{PANEL}}</span></div>
    <div><span>Daemon version</span><span><code>{{VERSION}}</code></span></div>
  </div>
  <p class="note">This page is served by <code>msfe-ngd</code> over its Unix
  socket. Real UI and functionality arrive in milestones M1–M5.</p>
</main></body></html>
"#;
