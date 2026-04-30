# VSEL Protocol — Dev Container Dockerfile
# Task 23.5 | Requirements: 17.4
#
# Full development environment with all four toolchains:
#   - Lean 4 (elan + lake)
#   - Rust (rustup + cargo, clippy, rustfmt)
#   - TLA+ (Java 17 + tla2tools.jar)
#   - Python 3.12 (pytest, hypothesis)
#
# Based on the VS Code dev containers base image for a consistent
# development experience with non-root user support.

FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

ARG LEAN_TOOLCHAIN="leanprover/lean4:v4.8.0"

# ─────────────────────────────────────────────
# System dependencies
# ─────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    git \
    openjdk-17-jdk-headless \
    python3 \
    python3-pip \
    python3-venv \
    jq \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────
# Lean 4 (elan)
# ─────────────────────────────────────────────
USER vscode
ENV ELAN_HOME="/home/vscode/.elan"
ENV PATH="${ELAN_HOME}/bin:${PATH}"

RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
    | sh -s -- -y --default-toolchain none && \
    elan install "${LEAN_TOOLCHAIN}" && \
    elan default "${LEAN_TOOLCHAIN}"

# ─────────────────────────────────────────────
# Rust (rustup)
# ─────────────────────────────────────────────
ENV CARGO_HOME="/home/vscode/.cargo"
ENV RUSTUP_HOME="/home/vscode/.rustup"
ENV PATH="${CARGO_HOME}/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --component clippy,rustfmt && \
    cargo install cargo-watch cargo-nextest

# ─────────────────────────────────────────────
# TLA+ tools
# ─────────────────────────────────────────────
USER root
RUN mkdir -p /opt/tla && \
    curl -sSL -o /opt/tla/tla2tools.jar \
      "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar" && \
    chmod 644 /opt/tla/tla2tools.jar

ENV TLA2TOOLS="/opt/tla/tla2tools.jar"

# ─────────────────────────────────────────────
# Python tooling
# ─────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages \
    pytest \
    hypothesis \
    mypy \
    ruff

# ─────────────────────────────────────────────
# Workspace setup
# ─────────────────────────────────────────────
USER vscode
WORKDIR /workspaces/vsel
