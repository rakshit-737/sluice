"""Build an ``LLMClient`` from a ``provider:model`` spec (reads API keys from the environment)."""

from __future__ import annotations

from sluice.llm import LLMClient


def llm_from_spec(spec: str) -> LLMClient:
    provider, sep, model = spec.partition(":")
    if not sep or not model:
        raise ValueError(f"expected provider:model, got {spec!r}")
    if provider == "anthropic":
        import anthropic

        from sluice.monitor.adapters.anthropic import AnthropicLLM

        return AnthropicLLM(anthropic.Anthropic(), model)
    if provider == "openai":
        import openai

        from sluice.monitor.adapters.openai import OpenAILLM

        return OpenAILLM(openai.OpenAI(), model)
    if provider == "ollama":
        import ollama

        from sluice.monitor.adapters.ollama import OllamaLLM

        return OllamaLLM(ollama.Client(), model)
    raise ValueError(f"unknown provider {provider!r} (anthropic, openai, ollama)")
