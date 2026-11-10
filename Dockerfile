# syntax=docker/dockerfile:1

# Which architecture the musl build is for (named before the first FROM so a FROM can use it).
ARG TARGETARCH

# The compiler always runs natively on the build machine and cross-compiles for the target, so a
# multi-architecture build does not pay for emulated compilation. Building on Debian 11 keeps the
# binary's glibc requirement low (2.31), which also makes the release binaries widely usable.
FROM --platform=$BUILDPLATFORM rust:1-bullseye AS build

ARG BUILDARCH
ARG TARGETARCH

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu;  gcc_pkg=gcc-x86-64-linux-gnu;  gcc_bin=x86_64-linux-gnu-gcc ;; \
      arm64) triple=aarch64-unknown-linux-gnu; gcc_pkg=gcc-aarch64-linux-gnu; gcc_bin=aarch64-linux-gnu-gcc ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    rustup target add "$triple"; \
    if [ "$BUILDARCH" != "$TARGETARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends "$gcc_pkg" "libc6-dev-$TARGETARCH-cross"; \
      rm -rf /var/lib/apt/lists/*; \
      upper="$(echo "$triple" | tr 'a-z-' 'A-Z_')"; lower="$(echo "$triple" | tr '-' '_')"; \
      export "CARGO_TARGET_${upper}_LINKER=$gcc_bin" "CC_${lower}=$gcc_bin"; \
    fi; \
    cargo build --release --locked --target "$triple"; \
    mkdir -p /out/state; \
    cp "target/$triple/release/ipping-node" /out/ipping-node

# `docker buildx build --target binary --output type=local,dest=out` extracts the plain binary;
# the release workflow uses this to publish downloadable executables.
FROM scratch AS binary
COPY --from=build /out/ipping-node /ipping-node

# A static musl build for Alpine Linux, which cannot run the glibc binary above. These images carry musl cross
# toolchains for the target and run on the build machine, so nothing is emulated. Not part of the runtime image:
# `--target binary-musl` extracts it, the release workflow publishes it as ipping-node-linux-<arch>-musl.
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS musl-amd64
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:aarch64-musl AS musl-arm64
FROM musl-${TARGETARCH} AS build-musl
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN set -eu; \
    cargo build --release --locked; \
    cp "target/${RUST_MUSL_CROSS_TARGET}/release/ipping-node" /ipping-node

FROM scratch AS binary-musl
COPY --from=build-musl /ipping-node /ipping-node

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# The state directory (identity + credential) must belong to the unprivileged user (65532).
COPY --from=build --chown=65532:65532 /out/state /var/lib/ipping-node
COPY --from=build /out/ipping-node /usr/local/bin/ipping-node

ENV IPPING_NODE_STATE_DIR=/var/lib/ipping-node
VOLUME ["/var/lib/ipping-node"]

ENTRYPOINT ["/usr/local/bin/ipping-node"]
CMD ["run"]
