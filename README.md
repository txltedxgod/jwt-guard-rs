# jwt-guard-rs

[![Rust CI](https://github.com/txltedxgod/jwt-guard-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/txltedxgod/jwt-guard-rs/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-Axum-DEA584.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Redis](https://img.shields.io/badge/redis-revocation_cache-DC382D.svg?logo=redis&logoColor=white)](https://redis.io/)


> High-throughput **JWT Authentication & Token Revocation Gateway** with **Redis JTI blacklisting**, Argon2 hashing, and async **Axum** microservice routing written in **Rust 2021**.

[![Rust](https://img.shields.io/badge/Rust-2021-DEA584?style=flat-square&logo=rust)](https://rust-lang.org)
[![Axum](https://img.shields.io/badge/Web-Axum-000000?style=flat-square&logo=tokio)](https://github.com/tokio-rs/axum)
[![Redis](https://img.shields.io/badge/Cache-Redis-DC382D?style=flat-square&logo=redis)](https://redis.io)
[![CI](https://img.shields.io/badge/CI-Passing-238636?style=flat-square&logo=githubactions)](https://github.com/txltedxgod/jwt-guard-rs/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

`#rust` `#jwt` `#redis` `#axum` `#tokio` `#authentication` `#security` `#microservices`

---

## 🏛️ Token Verification & Revocation Flow

```mermaid
sequenceDiagram
    autonumber
    participant Client as API Client / Frontend
    participant Gateway as Axum JWT Guard
    participant Redis as Redis JTI Blacklist Store
    participant Service as Protected Upstream Microservice

    Client->>Gateway: Request with Bearer <JWT>
    Gateway->>Gateway: Validate Cryptographic Signature (HMAC / RSA)
    alt Signature Invalid / Expired
        Gateway-->>Client: 401 Unauthorized (Invalid Signature)
    else Signature Valid
        Gateway->>Redis: Check if JTI is in blacklist:<jti>
        alt JTI Found in Blacklist
            Redis-->>Gateway: Exists (Revoked)
            Gateway-->>Client: 401 Unauthorized (Token Revoked)
        else JTI Not Blacklisted
            Redis-->>Gateway: Does Not Exist (Active)
            Gateway->>Service: Forward Authenticated Request (Headers: X-User-Id, X-Role)
            Service-->>Client: 200 OK Response
        end
    end
```

---

## Features

- **Instant Token Revocation:** Instant JTI blacklist check via Redis with exact TTL expiration.
- **Asynchronous & Non-Blocking:** Powered by Tokio and Axum 0.7 for sub-millisecond authentication overhead.
- **Argon2id Password Security:** Memory-hard password verification algorithm preventing GPU cracking.

## Quick Start

```bash
# 1. Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# 2. Run Gateway
cargo run
```