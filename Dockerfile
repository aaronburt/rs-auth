# syntax=docker/dockerfile:1
FROM rust:1.97-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/rs-auth /usr/local/bin/rs-auth
EXPOSE 9091
ENV RS_AUTH_CONFIG=/config/config.yaml
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/local/bin/rs-auth", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/rs-auth"]
CMD ["serve"]
