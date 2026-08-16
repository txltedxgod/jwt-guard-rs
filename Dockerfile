FROM rust:1.76-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.19
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/target/release/jwt-guard-rs /usr/local/bin/jwt-guard-rs

EXPOSE 8080
ENTRYPOINT ["jwt-guard-rs"]
