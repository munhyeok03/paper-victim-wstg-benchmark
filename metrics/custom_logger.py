"""
Custom LiteLLM Logger for Token/Cost Metrics
=============================================
Logs every API call's usage data to a JSONL file for analysis.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from litellm.integrations.custom_logger import CustomLogger


class MetricsFileLogger(CustomLogger):
    """Logs LiteLLM usage metrics to a JSONL file."""

    def __init__(self):
        self.log_dir = Path(os.environ.get("METRICS_LOG_DIR", "/app/logs"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "usage.jsonl"

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
                if hasattr(response_obj, "choices") and response_obj.choices:
                    choice = response_obj.choices[0]
                    if hasattr(choice, "message") and choice.message:
                        if hasattr(choice.message, "content"):
                            response_text = choice.message.content
                elif isinstance(response_obj, dict):
                    choices = response_obj.get("choices", [])
                    if choices and isinstance(choices[0], dict):
                        message = choices[0].get("message", {})
                        response_text = message.get("content")

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
                "total_tokens": usage.get("total_tokens", 0),
                "cache_read_tokens": usage.get("cache_read_input_tokens", 0),
                "cache_creation_tokens": usage.get("cache_creation_input_tokens", 0),
                "cost_usd": response_cost,
                "messages": serializable_messages,
                "response": response_text,
            }

            self._write_log(entry)

        except Exception as e:
            print(f"[MetricsFileLogger] Error logging event: {e}")
            import traceback
            traceback.print_exc()


# Instance for LiteLLM to use
metrics_logger = MetricsFileLogger()
