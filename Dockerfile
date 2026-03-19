# ---------- BUILD ----------
FROM rust:latest AS builder

WORKDIR /app

COPY scanner_compliance ./scanner_compliance

WORKDIR /app/scanner_compliance

RUN cargo build --release


# ---------- RUNTIME ----------
FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/scanner_compliance/target/release/scanner_compliance_http .

EXPOSE 3001

CMD ["./scanner_compliance_http"]