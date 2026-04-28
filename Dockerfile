# ---------- BUILD ----------
FROM rust:latest as builder

WORKDIR /app
COPY scanner_cve ./scanner_cve

WORKDIR /app/scanner_cve
RUN cargo build --release

# ---------- RUNTIME ----------
FROM debian:trixie

RUN apt-get update && \
    apt-get install -y wget ca-certificates && \
    wget https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-64bit.tar.gz && \
    tar zxvf trivy_0.70.0_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin/ && \
    rm trivy_0.70.0_Linux-64bit.tar.gz && \
    apt-get clean

WORKDIR /app

COPY --from=builder /app/scanner_cve/target/release/scanner_cve_http .

EXPOSE 3002

CMD ["./scanner_cve_http"]