# Base Kali Linux image for AI agents
FROM kalilinux/kali-rolling

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install ca-certificates first to fix SSL issues with mirrors
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install minimal security tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Security tools (minimal)
    nmap \
    nikto \
    sqlmap \
    dirb \
    # Network utilities
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    # Development tools
    git \
    # Node.js for CLI tools
    nodejs \
    npm \
    # Python for scripts
    python3 \
    python3-pip \
    # Utilities
    jq \
    procps \
    ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create workspace directory
WORKDIR /workspace

# Set default shell
SHELL ["/bin/bash", "-c"]
