#!/bin/bash
# ===========================================
# AI Agent Attack Automation - Main Script
# ===========================================
# Usage: ./run.sh --prompt <file> --agent <codex|claude|gemini|all> [options]

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
PROMPT_FILE=""
AGENTS=()
MODE="report"
OUTPUT_FORMAT_FILE=""
PARALLEL=true
KEEP_CONTAINERS=false
BUILD_IMAGES=false
VICTIM_TYPE="juice-shop"
CUSTOM_VICTIM_PORT=""
CUSTOM_VICTIM_HEALTHCHECK=""

# Print colored message
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Usage information
usage() {
    cat << EOF
${GREEN}AI Agent Attack Automation${NC}
===========================

Usage: $0 --prompt <file> [AGENT OPTIONS] [OPTIONS]

${YELLOW}Required:${NC}
  --prompt <file>           Path to prompt file

${YELLOW}Agent Selection (at least one required):${NC}
  --codex                   Use Codex agent (OpenAI)
  --claude                  Use Claude agent (Anthropic)
  --gemini                  Use Gemini agent (Google)
  --all                     Use all agents

${YELLOW}Options:${NC}
  --victim <type|image>     Victim server (default: juice-shop)
                            Presets: juice-shop, webgoat, vuln-shop
                            Or any Docker image tag (e.g., nginx:latest, myapp:v1)
  --victim-port <port>      Port for custom victim image (default: 3000)
  --victim-healthcheck <url> Healthcheck URL for custom image
                            (default: http://localhost:<port>)
  --mode <report|struct>    Output format (default: report)
                            report = Markdown report
                            struct = JSONL structured data
  --output-format <file>    Custom output format template file
                            (default: output_formats/example_struct.txt or example_report.txt)
  --sequential              Run agents sequentially (default: parallel)
  --keep                    Keep containers after execution
  --build                   Force rebuild Docker images
  --help                    Show this help message

${YELLOW}Examples:${NC}
  $0 --prompt prompts/sqli.txt --claude --mode report
  $0 --prompt prompts/recon.txt --all --mode struct
  $0 --prompt prompts/full.txt --all --sequential --keep
  $0 --prompt prompts/test.txt --claude --victim nginx:latest --victim-port 80
  $0 --prompt prompts/test.txt --claude --victim myapp:v1 --victim-port 8080

${YELLOW}Notes:${NC}
  - Each agent runs in an isolated Docker network with its own victim container
  - Results are saved to ./results/ directory
  - Ensure .env file exists with API keys (copy from .env.example)

EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --prompt)
                PROMPT_FILE="$2"
                shift 2
                ;;
            --codex)
                AGENTS+=("codex")
                shift
                ;;
            --claude)
                AGENTS+=("claude")
                shift
                ;;
            --gemini)
                AGENTS+=("gemini")
                shift
                ;;
            --all)
                AGENTS=("codex" "claude" "gemini")
                shift
                ;;
            --victim)
                VICTIM_TYPE="$2"
                shift 2
                ;;
            --victim-port)
                CUSTOM_VICTIM_PORT="$2"
                shift 2
                ;;
            --victim-healthcheck)
                CUSTOM_VICTIM_HEALTHCHECK="$2"
                shift 2
                ;;
            --mode)
                MODE="$2"
                if [[ "$MODE" != "report" && "$MODE" != "struct" ]]; then
                    log_error "Invalid mode: $MODE (must be 'report' or 'struct')"
                    exit 1
                fi
                shift 2
                ;;
            --output-format)
                OUTPUT_FORMAT_FILE="$2"
                if [[ ! -f "$OUTPUT_FORMAT_FILE" ]]; then
                    log_error "Output format file not found: $OUTPUT_FORMAT_FILE"
                    exit 1
                fi
                shift 2
                ;;
            --sequential)
                PARALLEL=false
                shift
                ;;
            --keep)
                KEEP_CONTAINERS=true
                shift
                ;;
            --build)
                BUILD_IMAGES=true
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Validate inputs
validate_inputs() {
    # Check prompt file
    if [[ -z "$PROMPT_FILE" ]]; then
        log_error "--prompt is required"
        echo "Use --help for usage information"
        exit 1
    fi

    if [[ ! -f "$PROMPT_FILE" ]]; then
        log_error "Prompt file not found: $PROMPT_FILE"
        exit 1
    fi

    # Check agents
    if [[ ${#AGENTS[@]} -eq 0 ]]; then
        log_error "At least one agent must be specified (--codex, --claude, --gemini, or --all)"
        exit 1
    fi

    # Check .env file
    if [[ ! -f ".env" ]]; then
        log_error ".env file not found"
        echo "Please copy .env.example to .env and fill in your API keys:"
        echo "  cp .env.example .env"
        exit 1
    fi

    # Validate API keys for selected agents
    source .env
    for agent in "${AGENTS[@]}"; do
        case $agent in
            codex)
                if [[ -z "$OPENAI_API_KEY" || "$OPENAI_API_KEY" == "sk-..." ]]; then
                    log_warn "OPENAI_API_KEY not set in .env (required for Codex agent)"
                fi
                ;;
            claude)
                if [[ -z "$ANTHROPIC_API_KEY" || "$ANTHROPIC_API_KEY" == "sk-ant-..." ]]; then
                    log_warn "ANTHROPIC_API_KEY not set in .env (required for Claude agent)"
                fi
                ;;
            gemini)
                if [[ -z "$GOOGLE_API_KEY" || "$GOOGLE_API_KEY" == "AIza..." ]]; then
                    log_warn "GOOGLE_API_KEY not set in .env (required for Gemini agent)"
                fi
                ;;
        esac
    done
}

# Configure victim server settings
configure_victim() {
    case "$VICTIM_TYPE" in
        juice-shop)
            export VICTIM_IMAGE="bkimminich/juice-shop"
            export VICTIM_PORT="3000"
            export VICTIM_HEALTHCHECK="http://localhost:3000"
            ;;
        webgoat)
            export VICTIM_IMAGE="webgoat/webgoat"
            export VICTIM_PORT="8080"
            export VICTIM_HEALTHCHECK="http://localhost:8080/WebGoat"
            ;;
        vuln-shop)
            export VICTIM_IMAGE="vuln-shop:latest"
            export VICTIM_PORT="3000"
            export VICTIM_HEALTHCHECK="http://localhost:3000"
            # Build vuln-shop image if not exists
            if ! docker images | grep -q "vuln-shop"; then
                log_info "Building vuln-shop image from ./victims/vuln-shop..."
                docker build -t vuln-shop:latest ./victims/vuln-shop
            fi
            ;;
        *)
            # Custom Docker image
            export VICTIM_IMAGE="$VICTIM_TYPE"
            export VICTIM_PORT="${CUSTOM_VICTIM_PORT:-3000}"
            export VICTIM_HEALTHCHECK="${CUSTOM_VICTIM_HEALTHCHECK:-http://localhost:$VICTIM_PORT}"
            log_info "Using custom victim image: $VICTIM_IMAGE"
            ;;
    esac
    log_info "Victim: $VICTIM_TYPE ($VICTIM_IMAGE:$VICTIM_PORT)"
}

# Build Docker images
build_images() {
    log_step "Building Docker images..."

    # Build base image first
    log_info "Building base image..."
    docker compose build agent-base

    # Build agent images
    for agent in "${AGENTS[@]}"; do
        log_info "Building agent-$agent image..."
        docker compose build "agent-$agent"
    done

    log_info "All images built successfully"
}

# Extract results from a container using docker cp
extract_results() {
    local agent=$1
    log_info "[$agent] Extracting results from container..."

    # Extract results from the container's tmpfs
    # Note: Conversation logs are captured via LiteLLM proxy (metrics/logs/usage.jsonl)
    docker cp "agent-$agent:/results/." "./results/" 2>/dev/null || true

    log_info "[$agent] Results extracted"
}

# Remove agent container
remove_agent_container() {
    local agent=$1
    log_info "[$agent] Removing container..."
    docker compose rm -f "agent-$agent" 2>/dev/null || true
}

# Extract metrics from LiteLLM proxy
extract_metrics() {
    local timestamp=$1
    log_step "Extracting metrics from proxy..."

    # Extract proxy logs to file for debugging
    docker logs metrics-proxy 2>&1 > "./metrics/logs/${timestamp}_proxy.log" || true

    # Copy usage.jsonl from proxy container (written by custom_logger.py)
    docker cp metrics-proxy:/app/logs/usage.jsonl "./metrics/logs/usage.jsonl" 2>/dev/null || true

    # Use aggregate_metrics.py script if available, otherwise inline Python
    if [[ -f "./scripts/aggregate_metrics.py" ]]; then
        python3 ./scripts/aggregate_metrics.py "./metrics/logs" --output "./metrics/${timestamp}_summary.json" \
            --start "$SESSION_START_TIME" --end "$SESSION_END_TIME"
    else
        # Fallback: inline aggregation with time filtering
        python3 - << 'PYEOF' "./metrics/logs" "./metrics/${timestamp}_summary.json" "$SESSION_START_TIME" "$SESSION_END_TIME"
import sys
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

log_dir = sys.argv[1]
output_file = sys.argv[2]
start_time = sys.argv[3] if len(sys.argv) > 3 else None
end_time = sys.argv[4] if len(sys.argv) > 4 else None

metrics = defaultdict(lambda: {
    "calls": 0,
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cache_read_tokens": 0,
    "total_cost_usd": 0.0
})

try:
    usage_file = Path(log_dir) / "usage.jsonl"
    if usage_file.exists():
        for line in usage_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                # Time filtering
                timestamp = entry.get("timestamp", "")
                if start_time and timestamp < start_time:
                    continue
                if end_time and timestamp > end_time:
                    continue
                model = entry.get("model", "unknown")
                metrics[model]["calls"] += 1
                metrics[model]["input_tokens"] += entry.get("prompt_tokens", 0)
                metrics[model]["output_tokens"] += entry.get("completion_tokens", 0)
                metrics[model]["total_tokens"] += entry.get("total_tokens", 0)
                metrics[model]["cache_read_tokens"] += entry.get("cache_read_tokens", 0)
                metrics[model]["total_cost_usd"] += entry.get("cost_usd", 0.0)
            except json.JSONDecodeError:
                continue

    result = {
        "generated_at": datetime.now().isoformat(),
        "session_start": start_time,
        "session_end": end_time,
        "models": dict(metrics),
        "totals": {
            "total_calls": sum(m["calls"] for m in metrics.values()),
            "total_input_tokens": sum(m["input_tokens"] for m in metrics.values()),
            "total_output_tokens": sum(m["output_tokens"] for m in metrics.values()),
            "total_tokens": sum(m["total_tokens"] for m in metrics.values()),
            "total_cost_usd": round(sum(m["total_cost_usd"] for m in metrics.values()), 6)
        }
    }

    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"Metrics saved to {output_file}", file=sys.stderr)
except Exception as e:
    print(f"Error extracting metrics: {e}", file=sys.stderr)
    with open(output_file, 'w') as f:
        json.dump({"error": str(e), "models": {}, "totals": {}}, f)
PYEOF
    fi

    log_info "Metrics extracted to ./metrics/"
}

# Run a single agent with its isolated victim
run_agent() {
    local agent=$1
    log_step "[$agent] Starting isolated environment..."

    # Start victim for this agent
    docker compose up -d "victim-$agent"

    # Wait for victim to be reachable (entrypoint.sh also waits, but we check here for early failure detection)
    log_info "[$agent] Waiting for victim to start..."
    local max_wait=120
    local waited=0
    while ! docker exec "victim-$agent" sh -c "wget -q --spider http://localhost:${VICTIM_PORT}/ 2>/dev/null || curl -sf http://localhost:${VICTIM_PORT}/ >/dev/null 2>&1" 2>/dev/null; do
        # For distroless containers, just check if the container is running
        if [[ "$(docker inspect --format='{{.State.Running}}' "victim-$agent" 2>/dev/null)" != "true" ]]; then
            log_error "[$agent] Victim container stopped unexpectedly"
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
        if [[ $waited -ge $max_wait ]]; then
            log_warn "[$agent] Victim check timed out, proceeding (entrypoint will wait)"
            break
        fi
    done
    log_info "[$agent] Victim container is running"

    # Run agent
    log_info "[$agent] Executing attack..."
    docker compose up "agent-$agent"

    # Extract results from container (tmpfs)
    extract_results "$agent"

    # Remove agent container if not keeping
    if [[ "$KEEP_CONTAINERS" == "false" ]]; then
        remove_agent_container "$agent"
    fi

    log_info "[$agent] Completed"
}

# Main execution
main() {
    parse_args "$@"
    validate_inputs

    # Generate session timestamp (shared across all output files)
    export SESSION_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  AI Agent Attack Automation${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "Prompt:     $PROMPT_FILE"
    echo -e "Agents:     ${AGENTS[*]}"
    echo -e "Victim:     $VICTIM_TYPE"
    echo -e "Mode:       $MODE"
    if [[ -n "$OUTPUT_FORMAT_FILE" ]]; then
        echo -e "Format:     $OUTPUT_FORMAT_FILE"
    else
        echo -e "Format:     (default)"
    fi
    echo -e "Parallel:   $PARALLEL"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    # Load environment
    source .env
    export OUTPUT_MODE="$MODE"

    # Export custom output format file path (convert to container path)
    if [[ -n "$OUTPUT_FORMAT_FILE" ]]; then
        # Get filename and construct container path
        local format_filename=$(basename "$OUTPUT_FORMAT_FILE")
        local format_realpath=$(realpath "$OUTPUT_FORMAT_FILE")
        local target_realpath=$(realpath "output_formats/$format_filename" 2>/dev/null || echo "")
        # Copy custom format file to output_formats directory (skip if same file)
        if [[ "$format_realpath" != "$target_realpath" ]]; then
            cp "$OUTPUT_FORMAT_FILE" "output_formats/$format_filename"
        fi
        export OUTPUT_FORMAT_FILE="/output_formats/$format_filename"
    fi

    # Configure victim server
    configure_victim

    # Create output directories
    mkdir -p results         # Structured findings (JSONL/Markdown)
    mkdir -p prompts
    mkdir -p output_formats  # Output format templates
    mkdir -p metrics/logs    # Token/cost/conversation metrics from LiteLLM proxy

    # Copy prompt to prompts directory (skip if same file)
    local prompt_realpath=$(realpath "$PROMPT_FILE")
    local target_realpath=$(realpath "prompts/attack.txt" 2>/dev/null || echo "")
    if [[ "$prompt_realpath" != "$target_realpath" ]]; then
        cp "$PROMPT_FILE" prompts/attack.txt
    fi

    # Build images if needed or requested
    if [[ "$BUILD_IMAGES" == "true" ]] || ! docker images | grep -q "agent-base"; then
        build_images
    fi

    # Record session start time for filtering logs
    SESSION_START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    export SESSION_START_TIME

    # Start metrics proxy
    log_step "Starting metrics proxy..."
    docker compose up -d metrics-proxy

    # Wait for metrics proxy to be healthy
    log_info "Waiting for metrics proxy to be healthy..."
    local proxy_wait=0
    local proxy_max_wait=60
    while [[ "$(docker inspect --format='{{.State.Health.Status}}' "metrics-proxy" 2>/dev/null)" != "healthy" ]]; do
        sleep 2
        proxy_wait=$((proxy_wait + 2))
        if [[ $proxy_wait -ge $proxy_max_wait ]]; then
            log_error "Metrics proxy did not become healthy after ${proxy_max_wait}s"
            docker logs metrics-proxy --tail 20
            exit 1
        fi
    done
    log_info "Metrics proxy is ready!"

    # Run agents
    if [[ "$PARALLEL" == "true" && ${#AGENTS[@]} -gt 1 ]]; then
        log_step "Running agents in parallel (each with isolated victim)..."

        # Start all victims first
        for agent in "${AGENTS[@]}"; do
            docker compose up -d "victim-$agent"
        done

        # Wait for all victim containers to start (entrypoint.sh handles actual connectivity check)
        log_info "Waiting for all victim containers to start..."
        for agent in "${AGENTS[@]}"; do
            local max_wait=60
            local waited=0
            while [[ "$(docker inspect --format='{{.State.Running}}' "victim-$agent" 2>/dev/null)" != "true" ]]; do
                sleep 2
                waited=$((waited + 2))
                if [[ $waited -ge $max_wait ]]; then
                    log_error "victim-$agent did not start after ${max_wait}s"
                    exit 1
                fi
            done
            log_info "  victim-$agent: started"
        done

        # Run all agents in parallel
        PIDS=()
        for agent in "${AGENTS[@]}"; do
            log_info "Starting agent-$agent..."
            docker compose up "agent-$agent" &
            PIDS+=($!)
        done

        # Wait for all to complete
        local failed=0
        for i in "${!PIDS[@]}"; do
            if ! wait "${PIDS[$i]}"; then
                log_error "Agent ${AGENTS[$i]} failed"
                failed=1
            fi
        done

        if [[ $failed -eq 1 ]]; then
            log_warn "Some agents failed"
        fi

        # Extract results from all containers (tmpfs)
        log_step "Extracting results from all agents..."
        for agent in "${AGENTS[@]}"; do
            extract_results "$agent"
        done

        # Remove agent containers if not keeping
        if [[ "$KEEP_CONTAINERS" == "false" ]]; then
            log_step "Removing agent containers..."
            for agent in "${AGENTS[@]}"; do
                remove_agent_container "$agent"
            done
        fi
    else
        log_step "Running agents sequentially (each with isolated victim)..."
        for agent in "${AGENTS[@]}"; do
            run_agent "$agent"
        done
    fi

    # Record session end time
    SESSION_END_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Extract metrics before cleanup (use session timestamp for consistency)
    extract_metrics "$SESSION_TIMESTAMP"

    # Extract session-specific conversation logs from usage.jsonl (per agent)
    log_step "Extracting session conversation logs..."
    if [[ -f "./metrics/logs/usage.jsonl" ]]; then
        for agent in "${AGENTS[@]}"; do
            jq -c --arg s "$SESSION_START_TIME" --arg e "$SESSION_END_TIME" --arg a "$agent" \
                'select(.timestamp >= $s and .timestamp <= $e and .agent == $a)' \
                "./metrics/logs/usage.jsonl" > "./results/${SESSION_TIMESTAMP}_${agent}_conversations.jsonl" 2>/dev/null || true
            if [[ -s "./results/${SESSION_TIMESTAMP}_${agent}_conversations.jsonl" ]]; then
                log_info "Session conversations saved to ./results/${SESSION_TIMESTAMP}_${agent}_conversations.jsonl"
            else
                rm -f "./results/${SESSION_TIMESTAMP}_${agent}_conversations.jsonl"
            fi
        done
    fi

    # Cleanup
    if [[ "$KEEP_CONTAINERS" == "false" ]]; then
        log_step "Cleaning up containers..."
        docker compose down --remove-orphans
    else
        log_info "Containers kept running (use 'docker compose down' to stop)"
    fi

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Execution Complete${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "Results:       ${BLUE}./results/${NC}"
    echo -e "Conversations: ${BLUE}./results/${SESSION_TIMESTAMP}_*_conversations.jsonl${NC}"
    echo -e "Metrics:       ${BLUE}./metrics/${NC}"
    echo ""
    echo "Results:"
    ls -la results/ 2>/dev/null || echo "(no results yet)"
    echo ""
    echo "Metrics summary:"
    if [[ -f "./metrics/${SESSION_TIMESTAMP}_summary.json" ]]; then
        cat "./metrics/${SESSION_TIMESTAMP}_summary.json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if d.get('note'):
        print(f\"  Note: {d['note']}\")
    for m, v in d.get('models', {}).items():
        cost = v.get('total_cost_usd', 0)
        cost_str = f\", \${cost:.4f}\" if cost > 0 else ''
        print(f\"  {m}: {v['calls']} calls, {v['total_tokens']} tokens{cost_str}\")
    t = d.get('totals', {})
    total_cost = t.get('total_cost_usd', 0)
    cost_str = f\", \${total_cost:.4f}\" if total_cost > 0 else ''
    print(f\"  TOTAL: {t.get('total_calls', 0)} calls, {t.get('total_tokens', 0)} tokens{cost_str}\")
except Exception as e:
    print(f\"  Error: {e}\")
" 2>/dev/null || echo "(no metrics available)"
    else
        echo "(no metrics summary generated)"
    fi
    echo ""
}

# Run main function
main "$@"
