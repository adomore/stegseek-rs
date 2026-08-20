# Build
FROM rust:1.75-slim AS build
COPY . /src
WORKDIR /src
RUN cargo build --release --locked

# Runtime (no C library dependencies — pure Rust)
FROM debian:bookworm-slim
COPY --from=build /src/target/release/stegseek /usr/bin/stegseek
WORKDIR /steg
ENTRYPOINT ["stegseek"]
CMD ["--help"]
