# Build stage: the Rust toolchain of this repository (rustc 1.95) on Debian trixie.
FROM rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY assets ./assets
RUN cargo build --release --locked \
    && install -d -m 0700 -o 65532 -g 65532 /data

# Runtime: no shell and no package manager; the CA bundle comes with the base image.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2
COPY --from=build /src/target/release/doorward /usr/local/bin/doorward
COPY --from=build --chown=65532:65532 /data /data
# The image sets no DOORWARD_ variables: the environment and the mounted files decide.
VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/doorward"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/doorward", "health"]
