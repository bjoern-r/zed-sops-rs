# syntax=docker/dockerfile:1
#
# Build targets:
#   artifacts  -> static sops-ls binary + extension.wasm  (default)
#   test       -> unit tests + end-to-end tests against real sops/age
#
#   docker buildx build --target artifacts --output type=local,dest=dist .
#   docker buildx build --target test .

ARG RUST_VERSION=1.91
ARG SOPS_VERSION=3.13.3
ARG AGE_VERSION=1.2.1

# ------------------------------------------------------------- language server
# Alpine = musl target, which Rust links statically by default: the resulting
# binary runs on any Linux distribution regardless of glibc version.
FROM rust:${RUST_VERSION}-alpine AS sops-ls
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY sops-ls/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && mkdir -p /out && cp target/release/sops-ls /out/sops-ls

# ------------------------------------------------------------- Zed extension
FROM rust:${RUST_VERSION}-slim AS extension
RUN rustup target add wasm32-wasip2
WORKDIR /src
COPY Cargo.toml extension.toml ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --target wasm32-wasip2 \
 && mkdir -p /out && cp target/wasm32-wasip2/release/zed_sops.wasm /out/extension.wasm \
 && cp extension.toml /out/extension.toml

# ------------------------------------------------------------- tests
FROM rust:${RUST_VERSION}-alpine AS test
ARG SOPS_VERSION
ARG AGE_VERSION
ARG TARGETARCH
RUN apk add --no-cache musl-dev bash python3 curl \
 && curl -fsSLo /usr/local/bin/sops \
      https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.${TARGETARCH} \
 && chmod +x /usr/local/bin/sops \
 && curl -fsSL https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-${TARGETARCH}.tar.gz \
    | tar xz -C /tmp && mv /tmp/age/age /tmp/age/age-keygen /usr/local/bin/
WORKDIR /src
COPY sops-ls/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --release --locked \
 && cargo build --release --locked \
 && tests/setup_fixtures.sh /tmp/e2e \
 && SOPS_AGE_KEY_FILE=/tmp/e2e/key.txt python3 tests/e2e.py target/release/sops-ls /tmp/e2e

# ------------------------------------------------------------- export
FROM scratch AS artifacts
COPY --from=sops-ls /out/sops-ls /sops-ls
COPY --from=extension /out/extension.wasm /extension.wasm
COPY --from=extension /out/extension.toml /extension.toml
