#!/bin/bash
set -e

# ===========================================
# AI Agent Attack Automation - Entrypoint
# ===========================================

# Configuration from environment
PROMPT_FILE="${PROMPT_FILE:-/prompts/attack.txt}"
OUTPUT_MODE="${OUTPUT_MODE:-report}"
AGENT_TYPE="${AGENT_TYPE:-unknown}"
VICTIM_HOST="${VICTIM_HOST:-victim}"
VICTIM_PORT="${VICTIM_PORT:-3000}"

# Output format template file (default based on mode)
if [[ -z "$OUTPUT_FORMAT_FILE" ]]; then
    if [[ "$OUTPUT_MODE" == "struct" ]]; then
        OUTPUT_FORMAT_FILE="/output_formats/example_struct.txt"
    else
        OUTPUT_FORMAT_FILE="/output_formats/example_report.txt"
    fi
fi

# Generate output filename with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_EXT=$([[ "$OUTPUT_MODE" == "struct" ]] && echo "jsonl" || echo "md")

# Separate log file (raw model output) and result file (structured findings)
LOG_FILE="/logs/${TIMESTAMP}_${AGENT_TYPE}.txt"
RESULT_FILE="/results/${TIMESTAMP}_${AGENT_TYPE}.${OUTPUT_EXT}"

echo "=========================================="
echo "AI Agent Attack Automation"
echo "=========================================="
echo "Agent Type: $AGENT_TYPE"
echo "Output Mode: $OUTPUT_MODE"
echo "Format Template: $OUTPUT_FORMAT_FILE"
echo "Victim: http://${VICTIM_HOST}:${VICTIM_PORT}"
echo "Log File: $LOG_FILE"
echo "Result File: $RESULT_FILE"
echo "=========================================="

# Verify prompt file exists
if [[ ! -f "$PROMPT_FILE" ]]; then
    echo "ERROR: Prompt file not found: $PROMPT_FILE"
    exit 1
fi

# Read prompt
PROMPT=$(cat "$PROMPT_FILE")

# Add victim target information to prompt
PROMPT="Target: http://${VICTIM_HOST}:${VICTIM_PORT}

${PROMPT}"

# Load output format instructions from template file
if [[ ! -f "$OUTPUT_FORMAT_FILE" ]]; then
    echo "ERROR: Output format file not found: $OUTPUT_FORMAT_FILE"
    exit 1
fi

# Read template and replace {{RESULT_FILE}} placeholder
FORMAT_INSTRUCTION=$(cat "$OUTPUT_FORMAT_FILE" | sed "s|{{RESULT_FILE}}|${RESULT_FILE}|g")
FORMAT_INSTRUCTION="

${FORMAT_INSTRUCTION}"

FULL_PROMPT="${PROMPT}${FORMAT_INSTRUCTION}"

# Wait for victim to be reachable
echo "Waiting for victim to be reachable..."
MAX_RETRIES=30
RETRY_COUNT=0
while ! curl -sf "http://${VICTIM_HOST}:${VICTIM_PORT}" > /dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [[ $RETRY_COUNT -ge $MAX_RETRIES ]]; then
        echo "ERROR: Victim not reachable after $MAX_RETRIES attempts"
        exit 1
    fi
    echo "  Attempt $RETRY_COUNT/$MAX_RETRIES..."
    sleep 2
done
echo "Victim is reachable!"

# Execute based on agent type
echo "Starting attack with $AGENT_TYPE agent..."
echo ""

# Create empty result file (model will write to it)
touch "$RESULT_FILE"

case "$AGENT_TYPE" in
    codex)
        # OpenAI Codex CLI with GPT-5.2-Codex model
        # Login with API key first
        echo "$OPENAI_API_KEY" | codex login --with-api-key
        # Using exec subcommand for non-interactive execution
        # --model gpt-5.2-codex: Use GPT-5.2 Codex model
        # --yolo: Bypass all approvals and sandbox (for containerized execution)
        # --skip-git-repo-check: Skip git repository check for containerized execution
        # Raw output goes to LOG_FILE, model writes results to RESULT_FILE
        codex exec --model gpt-5.2-codex --yolo --skip-git-repo-check "$FULL_PROMPT" 2>&1 | tee "$LOG_FILE"
        ;;
    claude)
        # Claude Code CLI with Opus 4.5 model
        # --model: Use Claude Opus 4.5 for state-of-the-art software engineering
        # Using print mode for non-interactive execution
        # Raw output goes to LOG_FILE, model writes results to RESULT_FILE
        claude --model claude-opus-4-5-20251101 --print --dangerously-skip-permissions "$FULL_PROMPT" 2>&1 | tee "$LOG_FILE"
        ;;
    gemini)
        # Gemini CLI with Gemini 3 Pro model
        # --model gemini-3-pro: Use Gemini 3 Pro for complex reasoning
        # -p: Non-interactive mode, --yolo: Auto-approve tool calls
        # GEMINI_API_KEY env var is set by docker-compose
        # Raw output goes to LOG_FILE, model writes results to RESULT_FILE
        gemini --model gemini-3-pro-preview -p "$FULL_PROMPT" --yolo 2>&1 | tee "$LOG_FILE"
        ;;
    *)
        echo "ERROR: Unknown agent type: $AGENT_TYPE"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Attack completed!"
echo "Log saved to: $LOG_FILE"
echo "Results saved to: $RESULT_FILE"
echo "=========================================="
