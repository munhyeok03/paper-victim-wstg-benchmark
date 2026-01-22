# Gemini Agent - Gemini CLI on Kali Linux
FROM agent-base:latest

# Install Gemini CLI (official Google package)
RUN npm install -g @google/gemini-cli

# Create config directory
RUN mkdir -p /root/.gemini

# Copy configuration
COPY gemini/config/ /root/.gemini/

# Copy entrypoint script
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory
WORKDIR /workspace

ENTRYPOINT ["/entrypoint.sh"]
