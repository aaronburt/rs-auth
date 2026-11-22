mod common;

use std::net::SocketAddr;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn raw(addr: SocketAddr, request: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn real_socket_round_trip() {
    let y = yaml(1, "[admins]", false).replace("[172.18.0.0/16, \"::1\"]", "[127.0.0.1/32]");
    let app = app_with(&y);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let health = raw(
        addr,
        "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.ends_with("ok"));

    let verify = raw(
        addr,
        "GET /api/verify HTTP/1.1\r\nHost: x\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: app.example.com\r\n\
         X-Forwarded-Uri: /\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(verify.starts_with("HTTP/1.1 302"), "{verify}");
    assert!(
        verify.to_lowercase().contains(
            "location: https://auth.example.com/login?rd=https%3a%2f%2fapp.example.com%2f"
        )
    );
}
