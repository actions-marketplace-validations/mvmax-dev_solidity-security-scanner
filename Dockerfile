FROM python:3.11-slim

LABEL maintainer="Maxwell VOSS"
LABEL description="AI-powered smart contract scanner for Ethereum, Base & Solana"
LABEL version="3.2"

# Install solc and system dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common \
    git \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN pip install --no-cache-dir slither-analyzer solc-select

# Install common solc versions for Slither
RUN solc-select install 0.8.20 && \
    solc-select install 0.8.24 && \
    solc-select use 0.8.24

# Install Foundry
ENV FOUNDRY_DIR=/opt/foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup -b master && \
    cp /root/.foundry/bin/* /usr/local/bin/

# Install Rust for Solana/Anchor support
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    cargo install cargo-audit

# Copy the scanner code
COPY . /app
WORKDIR /app

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

