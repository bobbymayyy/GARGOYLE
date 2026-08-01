FROM rust:1.97.1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml rust-toolchain.toml ./
COPY src ./src
COPY schemas ./schemas
RUN cargo build --release

FROM debian:trixie-slim
RUN useradd --system --uid 991 --no-create-home --shell /usr/sbin/nologin gargoyle
COPY --from=builder /src/target/release/gargoyle /usr/local/bin/gargoyle
COPY config/gargoyle.container.toml /etc/gargoyle/gargoyle.toml
USER root
ENTRYPOINT ["/usr/local/bin/gargoyle"]
CMD ["run", "--config", "/etc/gargoyle/gargoyle.toml"]
