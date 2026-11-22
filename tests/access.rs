#![allow(clippy::unwrap_used, clippy::panic, clippy::string_slice)]
mod common;

use axum::http::StatusCode;
use common::*;
use rs_auth::config::Config;

const RULES: &str = r#"[access."grafana.example.com"]
groups = ["admins"]

[access."*.lab.example.com"]
groups = ["admins"]

[access."open.lab.example.com"]
groups = ["family"]

[access."photos.example.com"]
groups = ["family", "friends"]

"#;

fn with_rules(rules: &str, aaron_groups: &[&str]) -> String {
    let base = toml(1, aaron_groups, true);
    let start = base.find("[access.").unwrap();
    let end = base.find("[users.aaron]").unwrap();
    format!("{}{rules}{}", &base[..start], &base[end..])
}

fn err(text: &str) -> String {
    match Config::from_toml(text, &NoEnv) {
        Ok(_) => panic!("config should have been rejected:\n{text}"),
        Err(e) => e.to_string(),
    }
}

fn warnings(text: &str) -> Vec<String> {
    Config::from_toml(text, &NoEnv).unwrap().warnings
}

#[test]
fn bad_rules_are_rejected_with_the_reason() {
    let cases: &[(&str, &str)] = &[
        (
            "[access.\"grafana.other.net\"]\ngroups = [\"admins\"]\n",
            "must be a host inside example.com",
        ),
        (
            "[access.\"example.com.evil.net\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"10.0.0.1\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"*\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"*.\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"a.*.example.com\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"**.example.com\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"app..example.com\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"-app.example.com\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"app.example.com/path\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"app.example.com:8443\"]\ngroups = [\"admins\"]\n",
            "must be a host inside",
        ),
        (
            "[access.\"auth.example.com\"]\ngroups = [\"admins\"]\n",
            "is the portal itself",
        ),
        (
            "[access.\"app.example.com\"]\ngroups = []\n",
            "at least one group",
        ),
        (
            "[access.\"app.example.com\"]\ngroups = [\"a b\"]\n",
            "no commas or spaces",
        ),
        (
            "[access.\"app.example.com\"]\ngroups = [\"a,b\"]\n",
            "no commas or spaces",
        ),
        (
            "[access.\"app.example.com\"]\ngroups = [\"\"]\n",
            "no commas or spaces",
        ),
        (
            "[access.\"app.example.com\"]\ngroups = [\"admins\"]\n\n[access.\"APP.example.com\"]\ngroups = [\"family\"]\n",
            "more than once",
        ),
        ("[access.\"app.example.com\"]\n", "groups"),
        (
            "[access.\"app.example.com\"]\ngroups = [\"admins\"]\nusers = [\"aaron\"]\n",
            "users",
        ),
        (
            "[access.\"app.example.com\"]\ngroups = [\"admins\"]\npolicy = \"bypass\"\n",
            "policy",
        ),
    ];
    for (rules, want) in cases {
        let e = err(&with_rules(rules, &["admins"]));
        assert!(e.contains(want), "{rules}\nexpected {want:?} in {e:?}");
    }
}

#[test]
fn rules_load_and_warn_about_empty_groups_and_no_rules() {
    let c = config_from(&with_rules(RULES, &["admins"]));
    assert!(!c.access.is_empty());
    assert!(format!("{c:?}").contains("grafana.example.com"));

    let w = warnings(&with_rules(RULES, &["admins"]));
    assert!(
        w.iter()
            .any(|w| w.contains("\"friends\", but no user is in it")),
        "{w:?}"
    );
    assert!(
        !w.iter().any(|w| w.contains("\"family\", but")),
        "guest is in family: {w:?}"
    );

    let w = warnings(&with_rules("", &["admins"]));
    assert!(w.iter().any(|w| w.contains("every app gets 403")), "{w:?}");
    let c = config_from(&with_rules("", &["admins"]));
    assert!(c.access.is_empty());
}

#[test]
fn hosts_are_case_insensitive_and_wildcards_cover_the_whole_domain() {
    let c = config_from(&with_rules(
        "[access.\"Grafana.Example.com\"]\ngroups = [\"admins\"]\n\n[access.\"*.example.com\"]\ngroups = [\"family\"]\n",
        &["admins"],
    ));
    assert_eq!(
        c.access.groups_for("grafana.example.com"),
        Some(&["admins".to_owned()][..])
    );
    assert_eq!(
        c.access.groups_for("auth.example.com"),
        Some(&["family".to_owned()][..])
    );
    assert_eq!(c.access.groups_for("example.com"), None);
}

async fn status_and_body(app: &axum::Router, host: &str, cookies: &str) -> Resp {
    send(app, PROXY, verify_req("GET", host, "/", cookies)).await
}

#[tokio::test]
async fn hosts_without_a_rule_are_forbidden_to_everyone() {
    let app = app_with(&with_rules(RULES, &["admins", "family"]));
    let session = sign_in(&app, "aaron", "correct horse").await;

    let r = status_and_body(&app, "unlisted.example.com", "").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "anonymous");
    assert!(
        r.header("location").is_none(),
        "no sign-in for a host nobody can open"
    );
    assert!(r.body.contains("is not open to anyone"));
    assert!(!r.body.contains("Sign out"));

    let r = status_and_body(&app, "unlisted.example.com", &session).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "signed in");
    assert!(r.header("remote-user").is_none());
    assert!(
        r.body
            .contains("You are signed in as <strong>aaron</strong>")
    );
    assert!(r.body.contains("href=\"https://auth.example.com/logout\""));
    assert!(r.header("content-security-policy").is_some());
    assert_eq!(r.header("cache-control"), Some("no-store"));

    for host in [
        "lab.example.com",
        "example.com",
        "grafana.example.com.evil.net",
    ] {
        let r = status_and_body(&app, host, &session).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{host}");
    }
}

#[tokio::test]
async fn listed_hosts_send_anonymous_users_to_sign_in() {
    let app = app_with(&with_rules(RULES, &["admins"]));
    let r = status_and_body(&app, "grafana.example.com", "").await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(
        r.location(),
        "https://auth.example.com/login?rd=https%3A%2F%2Fgrafana.example.com%2F"
    );
    let r = send(
        &app,
        PROXY,
        verify_req("POST", "grafana.example.com", "/", ""),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn only_listed_groups_get_in() {
    let app = app_with(&with_rules(RULES, &["admins"]));
    let aaron = sign_in(&app, "aaron", "correct horse").await;
    let guest = sign_in(&app, "guest", "guest pass").await;

    let cases = [
        ("grafana.example.com", &aaron, StatusCode::OK),
        ("grafana.example.com", &guest, StatusCode::FORBIDDEN),
        ("photos.example.com", &aaron, StatusCode::FORBIDDEN),
        ("photos.example.com", &guest, StatusCode::OK),
        ("x.lab.example.com", &aaron, StatusCode::OK),
        ("a.b.lab.example.com", &aaron, StatusCode::OK),
        ("x.lab.example.com", &guest, StatusCode::FORBIDDEN),
        ("open.lab.example.com", &guest, StatusCode::OK),
        ("open.lab.example.com", &aaron, StatusCode::FORBIDDEN),
    ];
    for (host, session, want) in cases {
        let r = status_and_body(&app, host, session).await;
        assert_eq!(r.status, want, "{host}");
        if want == StatusCode::OK {
            assert!(r.header("remote-user").is_some(), "{host}");
        } else {
            assert!(r.header("remote-user").is_none(), "{host}");
            assert!(r.header("remote-groups").is_none(), "{host}");
            assert!(r.body.contains("does not have access to"), "{host}");
            assert!(
                r.body.contains(&format!("<strong>{host}</strong>")),
                "{host}"
            );
        }
    }
}

#[tokio::test]
async fn host_spelling_does_not_change_the_rule() {
    let app = app_with(&with_rules(RULES, &["admins"]));
    let guest = sign_in(&app, "guest", "guest pass").await;
    for host in [
        "GRAFANA.example.com",
        "grafana.example.com:8443",
        "grafana.example.com.",
        "Grafana.Example.Com.:443",
    ] {
        let r = status_and_body(&app, host, &guest).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{host}");
    }
    let aaron = sign_in(&app, "aaron", "correct horse").await;
    let r = status_and_body(&app, "GRAFANA.example.com:8443", &aaron).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn group_changes_apply_on_the_next_request() {
    let before = app_with(&with_rules(RULES, &["admins"]));
    let session = sign_in(&before, "aaron", "correct horse").await;
    let r = status_and_body(&before, "grafana.example.com", &session).await;
    assert_eq!(r.status, StatusCode::OK);

    let after = app_with(&with_rules(RULES, &["family"]));
    let r = status_and_body(&after, "grafana.example.com", &session).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = status_and_body(&after, "photos.example.com", &session).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("remote-groups"), Some("family"));
}

#[tokio::test]
async fn an_invalid_session_on_a_listed_host_still_goes_to_sign_in() {
    let app = app_with(&with_rules(RULES, &["admins"]));
    let r = status_and_body(&app, "grafana.example.com", "rs_auth_session=not.a.token").await;
    assert_eq!(r.status, StatusCode::FOUND);
}
