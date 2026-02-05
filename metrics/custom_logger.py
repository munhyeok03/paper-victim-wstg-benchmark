"""
Custom LiteLLM Logger for Token/Cost Metrics with Limit Enforcement
=====================================================================
Logs every API call's usage data to a JSONL file for analysis.
Enforces per-agent execution limits (tokens, calls, cost) for fair comparison.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from litellm.integrations.custom_logger import CustomLogger
from typing import Optional, Literal, Union


class MetricsFileLogger(CustomLogger):
    """Logs LiteLLM usage metrics to a JSONL file with limit enforcement."""

    def __init__(self):
        self.log_dir = Path(os.environ.get("METRICS_LOG_DIR", "/app/logs"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "usage.jsonl"

        # Execution limits from environment (0 = unlimited)
        self.token_limit = int(os.environ.get("AGENT_TOKEN_LIMIT", "0"))
        self.call_limit = int(os.environ.get("AGENT_CALL_LIMIT", "0"))
        self.cost_limit = float(os.environ.get("AGENT_COST_LIMIT", "0.0"))

        # Per-agent state tracking
        # Structure: {agent_id: {total_tokens, calls, cost_usd, terminated}}
        self._agent_state = {}

        # Log limit configuration
        if self.token_limit > 0 or self.call_limit > 0 or self.cost_limit > 0:
            print(f"[MetricsFileLogger] Limits configured:")
            print(f"  Token limit: {self.token_limit if self.token_limit > 0 else 'unlimited'}")
            print(f"  Call limit: {self.call_limit if self.call_limit > 0 else 'unlimited'}")
            print(f"  Cost limit: ${self.cost_limit if self.cost_limit > 0 else 'unlimited'}")

    def _get_agent_id(self, data: dict) -> str:
        """Extract agent identifier from request data."""
        # Try metadata first
        metadata = data.get("metadata", {}) or {}
        agent_id = metadata.get("agent_id")
        if agent_id:
            return agent_id

        # Infer from model name
        model = data.get("model", "unknown")
        return self._infer_agent(model)

    def _get_agent_state(self, agent_id: str) -> dict:
        """Get or initialize state for an agent."""
        if agent_id not in self._agent_state:
            self._agent_state[agent_id] = {
                "total_tokens": 0,
                "calls": 0,
                "cost_usd": 0.0,
                "terminated": False
            }
        return self._agent_state[agent_id]

    def _update_agent_state(self, agent_id: str, tokens: int, cost: float):
        """Update cumulative metrics for an agent."""
        state = self._get_agent_state(agent_id)
        state["total_tokens"] += tokens
        state["calls"] += 1
        state["cost_usd"] += cost

    def _check_limits(self, agent_id: str) -> tuple[bool, str, dict]:
        """
        Check if agent has exceeded any limit.
        Returns: (exceeded: bool, reason: str, details: dict)
        """
        state = self._get_agent_state(agent_id)

        # Check call limit
        if self.call_limit > 0 and state["calls"] >= self.call_limit:
            return True, "call_limit", {
                "limit": self.call_limit,
                "current": state["calls"],
                "type": "calls"
            }

        # Check token limit
        if self.token_limit > 0 and state["total_tokens"] >= self.token_limit:
            return True, "token_limit", {
                "limit": self.token_limit,
                "current": state["total_tokens"],
                "type": "tokens"
            }

        # Check cost limit
        if self.cost_limit > 0 and state["cost_usd"] >= self.cost_limit:
            return True, "cost_limit", {
                "limit": self.cost_limit,
                "current": state["cost_usd"],
                "type": "cost_usd"
            }

        return False, "", {}

    async def async_pre_call_hook(
        self,
        user_api_key_dict,
        cache,
        data: dict,
        call_type: Literal[
            "completion",
            "text_completion",
            "embeddings",
            "image_generation",
            "moderation",
            "audio_transcription",
            "responses",
        ]
    ) -> Optional[Union[dict, str, Exception]]:
        """
        Pre-call hook to enforce execution limits.
        Returns string to reject request, data dict to proceed.
        """
        agent_id = self._get_agent_id(data)
        state = self._get_agent_state(agent_id)

        # Check if already terminated
        if state["terminated"]:
            error_msg = f"limit_exceeded: Agent '{agent_id}' has been terminated due to execution limits"
            print(f"[MetricsFileLogger] Rejecting request: {error_msg}")
            return error_msg

        # Check limits based on previous calls
        exceeded, reason, details = self._check_limits(agent_id)
        if exceeded:
            state["terminated"] = True
            error_msg = f"limit_exceeded: Agent '{agent_id}' exceeded {reason} ({details['current']}/{details['limit']} {details['type']})"
            print(f"[MetricsFileLogger] {error_msg}")
            return error_msg

        # Request can proceed
        return data

    def _write_log(self, entry: dict):
        """Append a log entry to the JSONL file."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[MetricsFileLogger] Error writing log: {e}")

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Synchronous success callback."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=True)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Async success callback - called for streaming responses."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=True)

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Synchronous failure callback."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=False)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Async failure callback."""
        self._log_event(kwargs, response_obj, start_time, end_time, success=False)

    def _infer_agent(self, model: str) -> str:
        """Infer agent type from model name."""
        model_lower = model.lower()
        if "claude" in model_lower:
            return "claude"
        elif "gemini" in model_lower:
            return "gemini"
        elif "gpt" in model_lower or "codex" in model_lower:
            return "codex"
        return "unknown"

    def _log_event(self, kwargs, response_obj, start_time, end_time, success: bool):
        """Extract and log usage metrics with full conversation content."""
        try:
            # Extract model info
            model = kwargs.get("model", "unknown")
            litellm_params = kwargs.get("litellm_params", {})
            custom_llm_provider = litellm_params.get("custom_llm_provider", "")

            # Infer agent type from model
            agent = self._infer_agent(model)

            # Calculate latency
            latency_ms = 0
            if start_time and end_time:
                latency_ms = (end_time - start_time).total_seconds() * 1000

            # Extract usage from response
            usage = {}
            if response_obj:
                if hasattr(response_obj, "usage") and response_obj.usage:
                    usage_obj = response_obj.usage
                    if hasattr(usage_obj, "model_dump"):
                        usage = usage_obj.model_dump()
                    elif hasattr(usage_obj, "dict"):
                        usage = usage_obj.dict()
                    elif isinstance(usage_obj, dict):
                        usage = usage_obj
                    else:
                        # Manual extraction
                        usage = {
                            "prompt_tokens": getattr(usage_obj, "prompt_tokens", 0),
                            "completion_tokens": getattr(usage_obj, "completion_tokens", 0),
                            "total_tokens": getattr(usage_obj, "total_tokens", 0),
                        }
                elif isinstance(response_obj, dict) and "usage" in response_obj:
                    usage = response_obj["usage"]

            # Extract standard logging payload if available
            standard_payload = kwargs.get("standard_logging_object", {})
            response_cost = standard_payload.get("response_cost", 0) if standard_payload else 0

            # Update agent state with this call's metrics
            total_tokens = usage.get("total_tokens", 0)
            self._update_agent_state(agent, total_tokens, response_cost)

            # Extract input messages (full conversation history)
            # OpenAI/Anthropic use "messages", Gemini uses "contents"
            messages = kwargs.get("messages", [])

            # Check for Gemini format (contents with parts)
            if not messages:
                contents = kwargs.get("contents", [])
                if contents:
                    # Convert Gemini format to OpenAI-style messages
                    messages = []
                    for content in contents:
                        if isinstance(content, dict):
                            role = content.get("role", "user")
                            parts = content.get("parts", [])
                            # Extract text from parts
                            text_parts = []
                            for part in parts:
                                if isinstance(part, dict) and "text" in part:
                                    text_parts.append(part["text"])
                                elif isinstance(part, str):
                                    text_parts.append(part)
                            if text_parts:
                                messages.append({"role": role, "content": "\n".join(text_parts)})

            # Serialize messages for logging (handle non-serializable content)
            serializable_messages = []
            for msg in messages:
                if isinstance(msg, dict):
                    serializable_messages.append(msg)
                elif hasattr(msg, "model_dump"):
                    serializable_messages.append(msg.model_dump())
                elif hasattr(msg, "dict"):
                    serializable_messages.append(msg.dict())
                else:
                    serializable_messages.append({"role": "unknown", "content": str(msg)})

            # Extract response text
            response_text = None
            if response_obj:
                # Try Chat Completions format first (Claude, Gemini via LiteLLM)
                if hasattr(response_obj, "choices") and response_obj.choices:
                    choice = response_obj.choices[0]
                    if hasattr(choice, "message") and choice.message:
                        if hasattr(choice.message, "content"):
                            response_text = choice.message.content
                # Try Responses API format (OpenAI Codex)
                elif hasattr(response_obj, "output") and response_obj.output:
                    for output_item in response_obj.output:
                        if hasattr(output_item, "type") and output_item.type == "message":
                            content_list = getattr(output_item, "content", [])
                            for content_item in content_list:
                                if hasattr(content_item, "type") and content_item.type == "output_text":
                                    response_text = getattr(content_item, "text", None)
                                    break
                            if response_text:
                                break
                # Dict fallbacks
                elif isinstance(response_obj, dict):
                    # Chat Completions dict format
                    choices = response_obj.get("choices", [])
                    if choices and isinstance(choices[0], dict):
                        message = choices[0].get("message", {})
                        response_text = message.get("content")
                    # Responses API dict format
                    elif "output" in response_obj:
                        for output_item in response_obj.get("output", []):
                            if isinstance(output_item, dict) and output_item.get("type") == "message":
                                for content_item in output_item.get("content", []):
                                    if isinstance(content_item, dict) and content_item.get("type") == "output_text":
                                        response_text = content_item.get("text")
                                        break
                                if response_text:
                                    break

            # Get current agent state for logging
            agent_state = self._get_agent_state(agent)

            # Build log entry
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "agent": agent,
                "model": model,
                "provider": custom_llm_provider,
                "success": success,
                "latency_ms": round(latency_ms, 2),
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": total_tokens,
                "cache_read_tokens": usage.get("cache_read_input_tokens", 0),
                "cache_creation_tokens": usage.get("cache_creation_input_tokens", 0),
                "cost_usd": response_cost,
                "messages": serializable_messages,
                "response": response_text,
                # Add cumulative state for tracking
                "cumulative_tokens": agent_state["total_tokens"],
                "cumulative_calls": agent_state["calls"],
                "cumulative_cost_usd": agent_state["cost_usd"],
            }

            self._write_log(entry)

        except Exception as e:
            print(f"[MetricsFileLogger] Error logging event: {e}")
            import traceback
            traceback.print_exc()


# Instance for LiteLLM to use
metrics_logger = MetricsFileLogger()
