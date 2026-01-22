# Claude Agent - Claude Code CLI on Kali Linux
FROM agent-base:latest

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

# Create non-root user for Claude (required for --dangerously-skip-permissions)
RUN useradd -m -s /bin/bash agent && \
    mkdir -p /home/agent/.claude && \
    chown -R agent:agent /home/agent

# Copy configuration
COPY claude/config/ /home/agent/.claude/
RUN chown -R agent:agent /home/agent/.claude

# Copy entrypoint script
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create workspace and set permissions
RUN mkdir -p /workspace && chown agent:agent /workspace
RUN mkdir -p /results && chown agent:agent /results

# Set working directory
WORKDIR /workspace

# Switch to non-root user
USER agent

ENTRYPOINT ["/entrypoint.sh"]
