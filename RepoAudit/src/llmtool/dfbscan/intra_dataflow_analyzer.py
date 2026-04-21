import os
import re
from os import path
import json
import time
from typing import List, Set, Optional, Dict
from llmtool.LLM_utils import *
from llmtool.LLM_tool import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from memory.syntactic.api import *


def _extract_audit_block(file_path: str) -> str:
    """Extract [Comment Audit]...[End Audit] block from a D4 benchmark file, if present."""
    try:
        content = open(file_path).read()
        m = re.search(r'\[Comment Audit\](.*?)\[End Audit\]', content, re.DOTALL)
        if m:
            return '[Comment Audit]' + m.group(1) + '[End Audit]'
    except Exception:
        pass
    return ''

BASE_PATH = Path(__file__).resolve().parent.parent.parent


class IntraDataFlowAnalyzerInput(LLMToolInput):
    def __init__(
        self,
        function: Function,
        summary_start: Value,
        sink_values: List[Tuple[str, int]],
        call_statements: List[Tuple[str, int]],
        ret_values: List[Tuple[str, int]],
    ) -> None:
        self.function = function
        self.summary_start = summary_start
        self.sink_values = sink_values
        self.call_statements = call_statements
        self.ret_values = ret_values
        return

    def __hash__(self) -> int:
        return hash((self.function.function_id, str(self.summary_start)))


class IntraDataFlowAnalyzerOutput(LLMToolOutput):
    def __init__(self, reachable_values: List[Set[Value]]) -> None:
        self.reachable_values = reachable_values
        return

    def __str__(self):
        output_str = ""
        for i, reachable_values_per_path in enumerate(self.reachable_values):
            output_str += f"Path {i}:\n"
            for value in reachable_values_per_path:
                output_str += f"- {value}\n"
        return output_str


class IntraDataFlowAnalyzer(LLMTool):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        """
        :param model_name: the model name
        :param temperature: the temperature
        :param language: the programming language
        :param max_query_num: the maximum number of queries if the model fails
        :param logger: the logger
        """
        super().__init__(model_name, temperature, language, max_query_num, logger)
        _prompt_root = os.environ.get("RA_PROMPT_ROOT", str(BASE_PATH))
        _bug_type = os.environ.get("RA_BUG_TYPE", "")
        _bug_specific = f"{_prompt_root}/prompt/{language}/dfbscan/{_bug_type}/intra_dataflow_analyzer.json"
        _generic = f"{_prompt_root}/prompt/{language}/dfbscan/intra_dataflow_analyzer.json"
        self.prompt_file = _bug_specific if _bug_type and os.path.exists(_bug_specific) else _generic
        return

    def _get_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_examples"])
        prompt += "\n" + "".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace(
            "<ANSWER>", "\n".join(prompt_template_dict["answer_format_cot"])
        )
        prompt = prompt.replace("<QUESTION>", prompt_template_dict["question_template"])

        prompt = (
            prompt.replace("<FUNCTION>", input.function.lined_code)
            .replace("<SRC_NAME>", input.summary_start.name)
            .replace(
                "<SRC_LINE>",
                str(
                    input.summary_start.line_number
                    - input.function.start_line_number
                    + 1
                ),
            )
        )
        prompt = prompt.replace("<AUDIT_BLOCK>", _extract_audit_block(input.function.file_path))

        sinks_str = "Sink values in this function:\n"
        for sink_value in input.sink_values:
            sinks_str += f"- {sink_value[0]} at line {sink_value[1]}\n"
        prompt = prompt.replace("<SINK_VALUES>", sinks_str)

        calls_str = "Call statements in this function:\n"
        for call_statement in input.call_statements:
            calls_str += f"- {call_statement[0]} at line {call_statement[1]}\n"
        prompt = prompt.replace("<CALL_STATEMENTS>", calls_str)

        rets_str = "Return values in this function:\n"
        for ret_val in input.ret_values:
            rets_str += f"- {ret_val[0]} at line {ret_val[1]}\n"
        prompt = prompt.replace("<RETURN_VALUES>", rets_str)
        return prompt

    def _parse_index(self, index_str: str) -> int:
        return int(index_str.split(',')[0].strip())

    def _parse_response(
        self, response: str, input: Optional[LLMToolInput] = None
    ) -> Optional[LLMToolOutput]:
        """
        Parse the LLM response to extract all execution paths and their propagation details.

        Args:
            response (str): The response string from the LLM.
            input (IntraDataFlowAnalyzerInput): The input object containing function details.

        Returns:
            IntraDataFlowAnalyzerOutput: The output containing reachable values for each path.
        """
        paths: List[Dict] = []

        # Regex to match a path header line, e.g., "Path 1: Lines 2 -> 3"
        # Handles variants: bold wrappers (**Path 1**:), words between number and colon
        # (**Path 1 Analysis:**, **Path 1 (val < 0):**), trailing ** (**Path 1: Lines;**)
        path_header_re = re.compile(r"\*{0,2}Path\s*(\d+)(?:\*{0,2}[^:\n]*?)?:\s*(.*?)\*{0,2}\s*$")

        # Regex to match a propagation detail line, e.g.,
        # "  - Type: Return; Name: getNullObject(); Function: None; Index: 0; Line: 3; Dependency: ..."
        # Also handles bold-wrapped variant: "**Type: Sink; Name: ...; ...**"
        detail_re = re.compile(
            r"\*{0,2}Type:\s*([^;]+);\s*"
            r"Name:\s*([^;]+);\s*"
            r"Function:\s*([^;]+);\s*"
            r"Index:\s*([^;]+);\s*"
            r"Line:\s*([^;]+);"
        )

        current_path = None
        for line in response.splitlines():
            line = line.strip().lstrip("-").strip()
            if not line:
                continue

            # Check for path header
            header_match = path_header_re.match(line)
            if header_match:
                if current_path:
                    paths.append(current_path)
                current_path = {
                    "path_number": header_match.group(1).strip(),
                    "execution_path": header_match.group(2).strip(),
                    "propagation_details": [],
                }
            else:
                # Check for propagation detail line
                detail_match = detail_re.match(line)
                if detail_match and current_path is not None:
                    detail = {
                        "type": detail_match.group(1).strip(),
                        "name": detail_match.group(2).strip(),
                        "function": detail_match.group(3).strip(),
                        "index": detail_match.group(4).strip(),
                        "line": detail_match.group(5).strip(),
                    }
                    current_path["propagation_details"].append(detail)

                # Non-matching lines (e.g., explanatory text between details) are skipped

        if current_path:
            paths.append(current_path)

        assert input is not None, "input cannot be none"
        if not isinstance(input, IntraDataFlowAnalyzerInput):
            raise TypeError("Expect IntraDataFlowAnalyzerInput")

        # Process paths to extract reachable values
        reachable_values = []
        file_path = input.function.file_path
        start_line_number = input.function.start_line_number

        for single_path in paths:
            reachable_values_per_path = set()
            for detail in single_path["propagation_details"]:
                if not detail["line"].isdigit():
                    continue
                line_number = int(detail["line"]) + start_line_number - 1
                if detail["type"] == "Argument":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.ARG,
                            file_path,
                            self._parse_index(detail["index"]),
                        )
                    )
                elif detail["type"] == "Parameter":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.PARA,
                            file_path,
                            self._parse_index(detail["index"]),
                        )
                    )
                elif detail["type"] == "Return":
                    reachable_values_per_path.add(
                        Value(
                            detail["name"],
                            line_number,
                            ValueLabel.RET,
                            file_path,
                            self._parse_index(detail["index"]),
                        )
                    )
                elif detail["type"] == "Sink":
                    reachable_values_per_path.add(
                        Value(detail["name"], line_number, ValueLabel.SINK, file_path)
                    )
            reachable_values.append(reachable_values_per_path)

        output = IntraDataFlowAnalyzerOutput(reachable_values)
        self.logger.print_log(
            "Output of intra-procedural data-flow analyzer:", output.reachable_values
        )
        return output
