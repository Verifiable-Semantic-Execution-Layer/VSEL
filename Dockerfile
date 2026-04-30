# VSEL Protocol — Multi-Stage Production Dockerfile
# Task 23.5 | Requirements: 17.4
#
# Stages:
#   1. lean-builder   — Lean 4 formal proofs (elan + lake build)
#   2. rust-builder   — Rust workspace (cargo build --release)
#   3. tla-tools      — TLA+ model checker (Java + tla2tools.jar)
#   4. python-tools   — Python adversarial tooling (pytest)
#   5. production     — Minimal final image combining all artifacts
#
# Build:
#   docker build -t vsel-protocol .
#
# Run examples:
#   docker run --rm vsel-protocol lake env printPaths
#   docker run --rm vsel-protocol cargo --version
#   docker run --rm vsel-protocol java -cp /opt/tla/tla2tools.jar tlc2.TLC --help
#   docker run --rm vsel-protocol python3 -m pytest --version

# ─────────────────────────────────────────────
# Stage 1: Lean 4 Builder
# ─────────────────────────────────────────────
FROM ubuntu:22.04 AS lean-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install elan (Lean 4 toolchain manager)
ENV ELAN_HOME="/root/.elan"
ENV PATH="${ELAN_HOME}/bin:${PATH}"
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
    | sh -s -- -y --default-toolchain none

WORKDIR /build/formal
COPY formal/lean-toolchain formal/lakefile.lean ./

# Install the pinned Lean 4 toolchain from lean-toolchain
RUN elan install "$(cat lean-toolchain)"

# Copy Lean 4 source and build
COPY formal/ ./
RUN lake build

# ─────────────────────────────────────────────
# Stage 2: Rust Builder
# ─────────────────────────────────────────────
FROM rust:1.82-slim-bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/protocol
COPY protocol/Cargo.toml protocol/Cargo.lock ./

# Copy all crate manifests for dependency caching
COPY protocol/crates/ crates/

# Build dependencies first (cache layer)
RUN cargo fetch

# Build release
RUN cargo build --release

# ─────────────────────────────────────────────
# Stage 3: TLA+ Tools
# ─────────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy AS tla-tools

RUN mkdir -p /opt/tla && \
    apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -sSL -o /opt/tla/tla2tools.jar \
      "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar" && \
    rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────
# Stage 4: Python Tooling
# ─────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS python-tools

WORKDIR /build/tools
COPY tools/ ./

# Install Python dependencies
RUN pip install --no-cache-dir pytest hypothesis && \
    if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# ─────────────────────────────────────────────
# Stage 5: Production Image
# ─────────────────────────────────────────────
FROM ubuntu:22.04 AS production

LABEL maintainer="VSEL Protocol Team"
LABEL description="VSEL Protocol — Verifiable Semantic Execution Layer"
LABEL org.opencontainers.image.source="https://github.com/vsel-protocol/vsel"

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    python3 \
    python3-pip \
    openjdk-17-jre-headless \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# ── Lean 4 artifacts ──
COPY --from=lean-builder /root/.elan /root/.elan
COPY --from=lean-builder /build/formal /opt/vsel/formal
ENV ELAN_HOME="/root/.elan"
ENV PATH="${ELAN_HOME}/bin:${PATH}"

# ── Rust artifacts ──
COPY --from=rust-builder /build/protocol/target/release/ /opt/vsel/bin/
COPY protocol/Cargo.toml /opt/vsel/protocol/Cargo.toml
ENV PATH="/opt/vsel/bin:${PATH}"

# ── TLA+ tools ──
COPY --from=tla-tools /opt/tla/tla2tools.jar /opt/tla/tla2tools.jar
ENV TLA2TOOLS="/opt/tla/tla2tools.jar"

# ── Python tooling ──
COPY --from=python-tools /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/dist-packages
COPY tools/ /opt/vsel/tools/
RUN pip3 install --no-cache-dir --break-system-packages pytest hypothesis

# ── Project files ──
COPY tla/ /opt/vsel/tla/
COPY scripts/ /opt/vsel/scripts/
COPY docs/ /opt/vsel/docs/
COPY audit/ /opt/vsel/audit/

RUN chmod +x /opt/vsel/scripts/*.sh

WORKDIR /opt/vsel

# Healthcheck: verify all toolchains are available
HEALTHCHECK --interval=60s --timeout=10s --retries=3 CMD \
    lean --version && \
    java -version && \
    python3 --version

CMD ["bash"]
