# syntax=docker/dockerfile:1

# ---- build: static musl binary ----
# Pinned by digest (multi-arch index of rust:1-alpine, 2026-11-21); bump it with Renovate/Dependabot.
FROM docker.io/library/rust:1-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
RUN apk add --no-cache musl-dev ca-certificates
# cargo-auditable embeds the dependency list in the binary, so image scanners
# (Trivy, `cargo audit bin`) can check the shipped binary, not just Cargo.lock.
RUN cargo install cargo-auditable --version 0.7.7 --locked
WORKDIR /src

# Dependency layer (cached while Cargo.toml/Cargo.lock don't change).
# Its stub main.rs uses no crate, so Cargo >= 1.100 would flag every dependency
# as unused: warnings are muted for this step only, the real build keeps them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src web && echo 'fn main() {}' > src/main.rs && touch web/index.html \
 && CARGO_BUILD_WARNINGS=allow cargo build --release --locked && rm -rf src web

COPY src ./src
COPY web ./web
RUN touch src/main.rs \
 && cargo auditable build --release --locked \
 && strip target/release/drydock

# Empty /tmp owned by nobody (reqwest/rustls don't need it, but some libs probe it).
RUN mkdir -p /rootfs/tmp && chmod 1777 /rootfs/tmp

# ---- runtime: nothing but the binary and CA roots ----
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /rootfs/tmp /tmp
COPY --from=build /src/target/release/drydock /drydock

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    LISTEN=0.0.0.0:8080
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["/drydock", "healthcheck"]
ENTRYPOINT ["/drydock"]
