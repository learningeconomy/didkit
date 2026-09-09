FROM rust:1.98.0-bookworm AS builder
WORKDIR /app
COPY didkit/ ./didkit/
COPY ssi/ ./ssi/
WORKDIR /app/didkit
RUN cargo build --locked --release --package didkit-http --bin didkit-http

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates libssl3 wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system didkit-http \
    && useradd --system --gid didkit-http didkit-http
COPY --from=builder /app/didkit/target/release/didkit-http /usr/local/bin/didkit-http
USER didkit-http
EXPOSE 3000
ENV DIDKIT_HTTP_HTTP_ADDRESS=[0,0,0,0]
CMD ["didkit-http"]
HEALTHCHECK --interval=5s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/healthz || exit 1
LABEL org.opencontainers.image.source="https://github.com/learningeconomy/didkit"
