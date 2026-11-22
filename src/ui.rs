use std::sync::LazyLock;

use askama::Template;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

pub const CSS: &str = r#"
:root{color-scheme:light dark;
--bg:#F3F4F6;--card:#FFFFFF;--card-border:#D1D5DB;--text:#111827;--muted:#4B5563;
--input-bg:#FFFFFF;--input-border:#6B7280;--accent:#1D4ED8;--accent-hover:#1E40AF;--on-accent:#FFFFFF;--ring:#BFDBFE;
--warn-bg:#FFFBEB;--warn-border:#F59E0B;--warn-text:#78350F;--warn-field:#B45309;--warn-ring:#FDE68A;
--err-bg:#FEF2F2;--err-border:#FCA5A5;--err-text:#991B1B;
--off-bg:#F3F4F6;--off-border:#9CA3AF;--off-text:#4B5563;--off-btn:#E5E7EB}
@media (prefers-color-scheme:dark){:root{
--bg:#0B0F17;--card:#111827;--card-border:#374151;--text:#F3F4F6;--muted:#9CA3AF;
--input-bg:#0B0F17;--input-border:#6B7280;--accent:#93C5FD;--accent-hover:#BFDBFE;--on-accent:#0B0F17;--ring:#1E3A8A;
--warn-bg:#2A1F0B;--warn-border:#B45309;--warn-text:#FCD34D;--warn-field:#F59E0B;--warn-ring:#78350F;
--err-bg:#2A1215;--err-border:#7F1D1D;--err-text:#FCA5A5;
--off-bg:#1F2937;--off-border:#4B5563;--off-text:#9CA3AF;--off-btn:#1F2937}}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;font-size:16px;line-height:1.5}
main{width:400px;max-width:100%}
.card{background:var(--card);border:1px solid var(--card-border);border-radius:12px;padding:32px;display:flex;flex-direction:column;gap:20px}
.head{display:flex;flex-direction:column;gap:8px}
h1{margin:0;font-size:24px;line-height:32px;font-weight:650}
.sub{margin:0;font-size:15px;line-height:22px;color:var(--muted)}
.hint{margin:0;font-size:14px;line-height:20px;color:var(--muted)}
.sub strong{color:var(--text);font-weight:600;overflow-wrap:anywhere}
form{margin:0;display:flex;flex-direction:column;gap:16px}
fieldset{border:0;margin:0;padding:0;min-width:0;display:flex;flex-direction:column;gap:16px}
.field{display:flex;flex-direction:column;gap:6px}
label{font-size:14px;font-weight:600}
.pw{position:relative;display:flex}
input{width:100%;height:44px;padding:0 12px;font:inherit;font-size:16px;color:var(--text);background:var(--input-bg);border:1px solid var(--input-border);border-radius:8px}
.pw input{padding-right:72px}
input:focus-visible{border:2px solid var(--accent);padding-left:11px;outline:3px solid var(--ring);outline-offset:0}
input[aria-invalid=true]{border:2px solid var(--warn-field);padding-left:11px;outline:3px solid var(--warn-ring);outline-offset:0}
.reveal{position:absolute;right:4px;top:4px;height:36px;min-width:60px;padding:0 10px;border:0;border-radius:6px;background:transparent;color:var(--accent);font:inherit;font-size:14px;font-weight:600;cursor:pointer}
.reveal:focus-visible{outline:3px solid var(--accent);outline-offset:0}
.btn{display:flex;align-items:center;justify-content:center;height:44px;width:100%;border:0;border-radius:8px;background:var(--accent);color:var(--on-accent);font:inherit;font-size:16px;font-weight:600;cursor:pointer;text-decoration:none}
.btn:hover{background:var(--accent-hover)}
.btn:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
form>.btn,fieldset>.btn{margin-top:8px}
.btn-secondary{background:transparent;color:var(--text);border:1px solid var(--input-border)}
.btn-secondary:hover{background:var(--bg)}
.actions{display:flex;flex-direction:column;gap:12px}
.alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:8px;font-size:15px;line-height:22px}
.alert svg{flex-shrink:0;margin-top:1px}
.alert strong{font-weight:600}
.warn{background:var(--warn-bg);border:1px solid var(--warn-border);color:var(--warn-text)}
.error{background:var(--err-bg);border:1px solid var(--err-border);color:var(--err-text)}
fieldset:disabled label{color:var(--off-text)}
fieldset:disabled input{color:var(--off-text);background:var(--off-bg);border-color:var(--off-border);cursor:not-allowed}
fieldset:disabled .btn{background:var(--off-btn);color:var(--off-text);cursor:not-allowed}
@media (max-width:480px){
body{align-items:flex-start;padding:0;background:var(--card)}
main{width:100%}
.card{border:0;border-radius:0;padding:72px 20px 32px;gap:24px}
h1{font-size:28px;line-height:36px}
.sub{font-size:16px;line-height:24px}
label{font-size:15px}
input,.btn{height:48px}
.btn{font-size:17px}
.reveal{height:44px;top:2px;min-width:64px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
"#;

pub const SCRIPT: &str = r#"
document.querySelectorAll('[data-reveal]').forEach(function(b){
var i=document.getElementById(b.getAttribute('data-reveal'));if(!i)return;b.hidden=false;
b.addEventListener('click',function(){var show=i.type==='password';i.type=show?'text':'password';
b.textContent=show?'Hide':'Show';b.setAttribute('aria-pressed',String(show));
b.setAttribute('aria-label',show?'Hide password':'Show password');i.focus();});});
"#;

fn sha256_b64(s: &str) -> String {
    STANDARD.encode(Sha256::digest(s.as_bytes()))
}

pub static CSP: LazyLock<String> = LazyLock::new(|| {
    format!(
        "default-src 'none'; style-src 'sha256-{}'; script-src 'sha256-{}'; img-src 'self'; \
         base-uri 'none'; frame-ancestors 'none'",
        sha256_b64(CSS),
        sha256_b64(SCRIPT)
    )
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginState {
    Normal,
    WrongPassword,
    FormExpired,
    LockedOut,
    Busy,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage<'a> {
    pub css: &'a str,
    pub script: &'a str,
    pub state: LoginState,
    pub target_host: Option<String>,
    pub rd: String,
    pub csrf: String,
    pub username: String,
    pub totp: bool,
}

impl LoginPage<'_> {
    fn is_wrong_password(&self) -> bool {
        self.state == LoginState::WrongPassword
    }
    fn is_expired(&self) -> bool {
        self.state == LoginState::FormExpired
    }
    fn is_locked(&self) -> bool {
        self.state == LoginState::LockedOut
    }
    fn is_busy(&self) -> bool {
        self.state == LoginState::Busy
    }
    fn focus_password(&self) -> bool {
        self.is_wrong_password() || (!self.username.is_empty() && !self.is_locked())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutNotice {
    None,
    Expired,
    NotSaved,
}

#[derive(Template)]
#[template(path = "logout.html")]
pub struct LogoutPage<'a> {
    pub css: &'a str,
    pub username: String,
    pub csrf: String,
    pub stay_url: String,
    pub notice: LogoutNotice,
}

impl LogoutPage<'_> {
    fn is_expired(&self) -> bool {
        self.notice == LogoutNotice::Expired
    }
    fn is_not_saved(&self) -> bool {
        self.notice == LogoutNotice::NotSaved
    }
}

#[derive(Template)]
#[template(path = "signed_in.html")]
pub struct SignedInPage<'a> {
    pub css: &'a str,
    pub display_name: String,
    pub username: String,
}

#[derive(Template)]
#[template(path = "forbidden.html")]
pub struct ForbiddenPage<'a> {
    pub css: &'a str,
    pub host: String,
    pub username: Option<String>,
    pub logout_url: String,
}

pub fn login_page(
    state: LoginState,
    target_host: Option<String>,
    rd: String,
    csrf: String,
    username: String,
    totp: bool,
) -> LoginPage<'static> {
    LoginPage {
        css: CSS,
        script: SCRIPT,
        state,
        target_host,
        rd,
        csrf,
        username,
        totp,
    }
}
