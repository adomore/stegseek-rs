# Build
FROM rust:1.75-slim AS build
COPY . /src
WORKDIR /src
RUN cargo build --release --locked

# Runtime (no C library dependencies — pure Rust)
FROM debian:bookworm-slim
COPY --from=build /src/target/release/stegseek-rs /usr/bin/stegseek-rs
WORKDIR /steg
ENTRYPOINT ["stegseek-rs"]
CMD ["--help"]
