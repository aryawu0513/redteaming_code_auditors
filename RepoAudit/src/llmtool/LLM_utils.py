# Imports
from openai import OpenAI
import anthropic as anthropic_sdk
from pathlib import Path
from typing import Tuple
import tiktoken
import time
import os
import concurrent.futures
import threading

from ui.logger import Logger


class LLM:
    """
    An online inference model that routes all LLM calls through OpenRouter.
    Set OPENROUTER_API_KEY and pass an OpenRouter model string (e.g.
    "anthropic/claude-3.5-sonnet", "openai/gpt-4o", "deepseek/deepseek-chat").
    """

    def __init__(
        self,
        online_model_name: str,
        logger: Logger,
        temperature: float = 0.0,
        system_role: str = "You are an experienced programmer and good at understanding programs written in mainstream programming languages.",
        max_output_length: int = 4096,
    ) -> None:
        self.online_model_name = online_model_name
        self.encoding = tiktoken.encoding_for_model(
            "gpt-3.5-turbo-0125"
        )  # We only use gpt-3.5 to measure token cost
        self.temperature = temperature
        self.systemRole = system_role
        self.logger = logger
        self.max_output_length = max_output_length
        return

    def infer(
        self, message: str, is_measure_cost: bool = False
    ) -> Tuple[str, int, int]:
        self.logger.print_log(self.online_model_name, "is running")
        _openrouter_prefixes = ("anthropic/", "openai/", "deepseek/", "google/", "meta-llama/", "mistralai/", "cohere/", "x-ai/")
        _is_openrouter_model = self.online_model_name.startswith(_openrouter_prefixes)
        _openai_prefixes = ("gpt-", "o1", "o3", "o4")
        _is_openai_model = self.online_model_name.startswith(_openai_prefixes)
        if os.environ.get("ANTHROPIC_API_KEY") and not _is_openrouter_model and not _is_openai_model:
            output = self.infer_with_anthropic(message)
        elif os.environ.get("OPENAI_API_KEY") and _is_openai_model and not _is_openrouter_model:
            output = self.infer_with_openai(message)
        else:
            output = self.infer_with_openrouter(message)

        input_token_cost = (
            0
            if not is_measure_cost
            else len(self.encoding.encode(self.systemRole))
            + len(self.encoding.encode(message))
        )
        output_token_cost = (
            0 if not is_measure_cost else len(self.encoding.encode(output))
        )
        return output, input_token_cost, output_token_cost

    def run_with_timeout(self, func, timeout):
        """Run a function with timeout that works in multiple threads"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                self.logger.print_log("Operation timed out")
                return ""
            except Exception as e:
                self.logger.print_log(f"Operation failed: {e}")
                return ""

    def infer_with_anthropic(self, message: str) -> str:
        """Infer using Anthropic's native API directly via the anthropic SDK."""
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "Please set the ANTHROPIC_API_KEY environment variable."
            )

        def call_api():
            client = anthropic_sdk.Anthropic(api_key=api_key)
            response = client.messages.create(
                model=self.online_model_name,
                max_tokens=self.max_output_length,
                system=self.systemRole,
                messages=[{"role": "user", "content": message}],
                temperature=self.temperature,
            )
            return response.content[0].text

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=120)
                if output:
                    self.logger.print_log("Inference succeeded...")
                    return output
            except Exception as e:
                self.logger.print_log(f"API error (attempt {tryCnt}/5): {e}")
            time.sleep(2)

        return ""

    def infer_with_openai(self, message: str) -> str:
        """Infer using OpenAI's native API directly via the openai SDK."""
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "Please set the OPENAI_API_KEY environment variable."
            )

        # gpt-5 and newer o-series models use max_completion_tokens and don't support temperature=0
        _is_new_openai = self.online_model_name.startswith(("gpt-5", "o1", "o3", "o4"))

        def call_api():
            client = OpenAI(api_key=api_key)
            kwargs = dict(
                model=self.online_model_name,
                messages=[
                    {"role": "system", "content": self.systemRole},
                    {"role": "user", "content": message},
                ],
            )
            if _is_new_openai:
                kwargs["max_completion_tokens"] = self.max_output_length
                kwargs["reasoning_effort"] = "minimal"
            else:
                kwargs["max_tokens"] = self.max_output_length
                kwargs["temperature"] = self.temperature
            response = client.chat.completions.create(**kwargs)
            return response.choices[0].message.content

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=120)
                if output:
                    self.logger.print_log("Inference succeeded...")
                    return output
            except Exception as e:
                self.logger.print_log(f"API error (attempt {tryCnt}/5): {e}")
            time.sleep(2)

        return ""

    def infer_with_openrouter(self, message: str) -> str:
        """Infer using any model via the OpenRouter API (OpenAI-compatible)."""
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "Please set the OPENROUTER_API_KEY environment variable."
            )

        model_input = [
            {"role": "system", "content": self.systemRole},
            {"role": "user", "content": message},
        ]

        def call_api():
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=api_key,
            )
            response = client.chat.completions.create(
                model=self.online_model_name,
                messages=model_input,
                temperature=self.temperature,
                max_tokens=self.max_output_length,
            )
            return response.choices[0].message.content

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=120)
                if output:
                    self.logger.print_log("Inference succeeded...")
                    return output
            except Exception as e:
                self.logger.print_log(f"API error (attempt {tryCnt}/5): {e}")
            time.sleep(2)

        return ""
