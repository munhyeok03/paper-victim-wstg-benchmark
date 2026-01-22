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
  --victim <type>           Victim server type (default: juice-shop)
                            juice-shop = OWASP Juice Shop
                            webgoat    = OWASP WebGoat
                            vuln-shop  = Custom vulnerable shop
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
                if [[ "$VICTIM_TYPE" != "juice-shop" && "$VICTIM_TYPE" != "webgoat" && "$VICTIM_TYPE" != "vuln-shop" ]]; then
                    log_error "Invalid victim type: $VICTIM_TYPE (must be 'juice-shop', 'webgoat', or 'vuln-shop')"
                    exit 1
                fi
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

# Run a single agent with its isolated victim
run_agent() {
    local agent=$1
    log_step "[$agent] Starting isolated environment..."

    # Start victim for this agent
    docker compose up -d "victim-$agent"

    # Wait for victim to be healthy (using Docker's built-in healthcheck)
    log_info "[$agent] Waiting for victim to be healthy..."
    local max_wait=120
    local waited=0
    while [[ "$(docker inspect --format='{{.State.Health.Status}}' "victim-$agent" 2>/dev/null)" != "healthy" ]]; do
        sleep 2
        waited=$((waited + 2))
        if [[ $waited -ge $max_wait ]]; then
            log_error "[$agent] Victim did not become healthy after ${max_wait}s"
            return 1
        fi
    done
    log_info "[$agent] Victim is healthy"

    # Run agent
    log_info "[$agent] Executing attack..."
    docker compose up "agent-$agent"

    log_info "[$agent] Completed"
}

# Main execution
main() {
    parse_args "$@"
    validate_inputs

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
    mkdir -p logs            # Raw model output (debugging)
    mkdir -p prompts
    mkdir -p output_formats  # Output format templates

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

    # Run agents
    if [[ "$PARALLEL" == "true" && ${#AGENTS[@]} -gt 1 ]]; then
        log_step "Running agents in parallel (each with isolated victim)..."

        # Start all victims first
        for agent in "${AGENTS[@]}"; do
            docker compose up -d "victim-$agent"
        done

        # Wait for all victims to be healthy (using Docker's built-in healthcheck)
        log_info "Waiting for all victims to be healthy..."
        for agent in "${AGENTS[@]}"; do
            local max_wait=120
            local waited=0
            while [[ "$(docker inspect --format='{{.State.Health.Status}}' "victim-$agent" 2>/dev/null)" != "healthy" ]]; do
                sleep 2
                waited=$((waited + 2))
                if [[ $waited -ge $max_wait ]]; then
                    log_error "victim-$agent did not become healthy after ${max_wait}s"
                    exit 1
                fi
            done
            log_info "  victim-$agent: ready"
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
    else
        log_step "Running agents sequentially (each with isolated victim)..."
        for agent in "${AGENTS[@]}"; do
            run_agent "$agent"
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
    echo -e "Results saved in: ${BLUE}./results/${NC}"
    echo ""
    ls -la results/ 2>/dev/null || echo "(no results yet)"
    echo ""
}

# Run main function
main "$@"
