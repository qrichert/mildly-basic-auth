# Build stage: compile a release binary. `src/template.html` is embedded
# at compile time (`include_str!`), so the runtime image needs no assets.
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --all-features

# Runtime stage: Debian slim (not Alpine/musl — musl's allocator degrades
# under the proxy's multi-threaded allocation, and the stack is pure-Rust
# rustls so Alpine's usual payoff doesn't apply). `ca-certificates` is for
# future HTTPS upstreams.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/mildly-basic-auth /usr/local/bin/mildly-basic-auth

# Run unprivileged as a fixed non-root `10001`. Group is created
# explicitly first (as in ../hoplageiss/backend); no home or shell — this
# is a single static binary, not an interactive app. Not a `--system`
# account: that expects a UID below 1000 and would warn.
RUN groupadd --gid 10001 mba \
    && useradd --uid 10001 --gid 10001 --no-create-home mba
USER 10001

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/mildly-basic-auth"]
