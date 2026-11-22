# syntax=docker/dockerfile:1
FROM rust:1.97-slim-bookworm AS build
ARG TARGETARCH
WORKDIR /src
RUN case "$TARGETARCH" in \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo x86_64-unknown-linux-musl ;; \
    esac > /rust-target && rustup target add "$(cat /rust-target)"
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
RUN cargo build --release --locked --target "$(cat /rust-target)" \
 && cp "target/$(cat /rust-target)/release/rs-auth" /rs-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /rs-auth /usr/local/bin/rs-auth
EXPOSE 9091
ENV RS_AUTH_CONFIG=/config/config.yaml
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/local/bin/rs-auth", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/rs-auth"]
CMD ["serve"]
