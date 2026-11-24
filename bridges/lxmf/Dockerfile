# Build from this folder, with the submodules checked out:
#   git submodule update --init --recursive
#   docker build -t lxmf-bridge bridges/lxmf
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY deps ./deps
COPY src ./src
RUN cargo build --release --locked
# The data folder, made here so that it belongs to the unprivileged user (65532) and a named
# volume mounted on it starts out writable.
RUN mkdir /data-skel

# Distroless: no shell and no package manager. glibc and libgcc are all the binary needs.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/lxmf-bridge /usr/local/bin/lxmf-bridge
COPY --from=build --chown=65532:65532 /data-skel /data
USER 65532:65532
VOLUME /data
EXPOSE 8742
# The identity and Reticulum's files are the only thing written, all in /data, so the root file
# system can be read-only.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/lxmf-bridge", "--healthcheck", "/config/bridge.toml"]
ENTRYPOINT ["/usr/local/bin/lxmf-bridge"]
CMD ["/config/bridge.toml"]
