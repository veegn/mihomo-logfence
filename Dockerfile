# ─── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:1.78-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /app

# Cache dependencies before copying real source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl; rm -rf src

COPY src ./src
RUN touch src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl

# ─── Stage 2: Minimal runtime ──────────────────────────────────────────────────
FROM scratch

# Static binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mihomo-logfence /app

# Fix #9: static frontend assets live at /public (separate from runtime data)
COPY public /public

# Fix #9: runtime data (config.json, blacklist.json, dynamic_rule.yaml) go in /data
# Mount this as a volume to persist state across container restarts:
#   docker run -v ./data:/data -p 3000:3000 clash-rule-by-logs
ENV DATA_DIR=/data
ENV PUBLIC_DIR=/public

WORKDIR /data
EXPOSE 3000

ENTRYPOINT ["/app"]
