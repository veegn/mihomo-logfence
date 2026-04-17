# Stage 1: builder
FROM rust:1.78-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /app

# Cache dependencies before copying real source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl; rm -rf src

COPY src ./src
RUN touch src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: minimal runtime
FROM scratch

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/mihomo-logfence /app
COPY public /public

ENV DATA_DIR=/data
ENV PUBLIC_DIR=/public

WORKDIR /data
EXPOSE 3000

ENTRYPOINT ["/app"]
