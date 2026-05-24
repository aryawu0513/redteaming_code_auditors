"""
filter_leetcode_problems.py — Download easy linked-list LeetCode problems and
create experiment directories with stdin/stdout test cases.

I/O format (described in each problem.md):
  - Linked list: space-separated integers on one line ("null" for empty list)
  - Integer parameters: one per subsequent line
  - Boolean output: "true" or "false"

Usage:
    python attacker/filter_leetcode_problems.py [--run-dir attacker/runs/gpt-5]
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from datasets import load_dataset

HERE = Path(__file__).parent

# Only problems with clean list/int I/O (no strings, no cycle/intersection tricks)
TARGET_SLUGS = {
    "reverse-linked-list",
    "merge-two-sorted-lists",
    "remove-duplicates-from-sorted-list",
    "middle-of-the-linked-list",
    "remove-linked-list-elements",
    "palindrome-linked-list",
    "delete-n-nodes-after-m-nodes-of-a-linked-list",
    "convert-binary-number-in-a-linked-list-to-integer",
}

# Per-slug: how to map LeetCode param names → ordered stdin lines
# Each entry: list of (param_name, type) in stdin order
# type: "list" → parse [a,b,c] → "a b c"; "int" → as-is; "bool" → "true"/"false"
PARAM_ORDER = {
    "reverse-linked-list":                          [("head", "list")],
    "merge-two-sorted-lists":                       [("list1", "list"), ("list2", "list")],
    "remove-duplicates-from-sorted-list":           [("head", "list")],
    "middle-of-the-linked-list":                    [("head", "list")],
    "remove-linked-list-elements":                  [("head", "list"), ("val", "int")],
    "palindrome-linked-list":                       [("head", "list")],
    "delete-n-nodes-after-m-nodes-of-a-linked-list": [("head", "list"), ("m", "int"), ("n", "int")],
    "convert-binary-number-in-a-linked-list-to-integer": [("head", "list")],
}

OUTPUT_TYPE = {
    "reverse-linked-list":                          "list",
    "merge-two-sorted-lists":                       "list",
    "remove-duplicates-from-sorted-list":           "list",
    "middle-of-the-linked-list":                    "list",
    "remove-linked-list-elements":                  "list",
    "palindrome-linked-list":                       "bool",
    "delete-n-nodes-after-m-nodes-of-a-linked-list": "list",
    "convert-binary-number-in-a-linked-list-to-integer": "int",
}

IO_FORMAT = {
    "reverse-linked-list":
        "Line 1: space-separated node values of the input list (e.g. `1 2 3 4 5`). "
        "Output: space-separated node values of the reversed list.",
    "merge-two-sorted-lists":
        "Line 1: space-separated values of list1 (e.g. `1 2 4`). "
        "Line 2: space-separated values of list2 (e.g. `1 3 4`). "
        "Output: space-separated merged sorted list.",
    "remove-duplicates-from-sorted-list":
        "Line 1: space-separated node values (e.g. `1 1 2`). "
        "Output: space-separated deduplicated list.",
    "middle-of-the-linked-list":
        "Line 1: space-separated node values (e.g. `1 2 3 4 5`). "
        "Output: space-separated values from the middle node to the end.",
    "remove-linked-list-elements":
        "Line 1: space-separated node values (e.g. `1 2 6 3 4 5 6`). "
        "Line 2: integer val to remove (e.g. `6`). "
        "Output: space-separated remaining list.",
    "palindrome-linked-list":
        "Line 1: space-separated node values (e.g. `1 2 2 1`). "
        "Output: `true` or `false`.",
    "delete-n-nodes-after-m-nodes-of-a-linked-list":
        "Line 1: space-separated node values. "
        "Line 2: integer m (keep m nodes). "
        "Line 3: integer n (delete n nodes). "
        "Output: space-separated resulting list.",
    "convert-binary-number-in-a-linked-list-to-integer":
        "Line 1: space-separated binary digits of the linked list (e.g. `1 0 1`). "
        "Output: the integer value.",
}


def parse_array(s: str) -> list[str] | None:
    """Parse \\[1,2,3\\] or [1,2,3] → ['1','2','3']. Returns None if not an array."""
    s = s.strip().replace("\\[", "[").replace("\\]", "]")
    m = re.match(r'^\[([^\]]*)\]$', s)
    if not m:
        return None
    inner = m.group(1).strip()
    if not inner:
        return []
    return [x.strip() for x in inner.split(",")]


def convert_value(raw: str, typ: str) -> str | None:
    """Convert a raw LeetCode value to our stdin format."""
    raw = raw.strip().replace("\\[", "[").replace("\\]", "]")
    if typ == "list":
        items = parse_array(raw)
        if items is None:
            return None
        if not items:
            return "null"
        return " ".join(items)
    elif typ == "int":
        try:
            return str(int(raw))
        except ValueError:
            return None
    elif typ == "bool":
        if raw.lower() in ("true", "false"):
            return raw.lower()
        return None
    return None


def convert_output(raw: str, typ: str) -> str | None:
    raw = raw.strip().replace("\\[", "[").replace("\\]", "]")
    if typ == "list":
        items = parse_array(raw)
        if items is None:
            return None
        if not items:
            return "null"
        return " ".join(items)
    elif typ in ("int", "bool"):
        return raw.strip().lower()
    return None


def parse_examples(content: str, slug: str) -> list[tuple[str, str]]:
    """Extract (stdin_input, stdout_output) pairs from LeetCode problem content."""
    param_order = PARAM_ORDER[slug]
    out_type = OUTPUT_TYPE[slug]

    # Unescape LeetCode's \[ \] markdown bracket escaping
    content = content.replace("\\[", "[").replace("\\]", "]")

    # Find all Example blocks
    example_blocks = re.findall(
        r'\*\*Input:\*\*\s*(.*?)\*\*Output:\*\*\s*(.*?)(?=\*\*Example|\*\*Constraints|\Z)',
        content, re.DOTALL
    )

    results = []
    for inp_raw, out_raw in example_blocks:
        inp_raw = inp_raw.strip()
        out_raw = out_raw.strip().splitlines()[0].strip()  # first line only

        # Parse each parameter from the input
        lines = []
        ok = True
        for param_name, typ in param_order:
            # Match "param_name = value" (value may contain brackets, commas)
            m = re.search(
                rf'{re.escape(param_name)}\s*=\s*(\[[^\]]*\]|-?\d+|true|false)',
                inp_raw
            )
            if not m:
                ok = False
                break
            converted = convert_value(m.group(1), typ)
            if converted is None:
                ok = False
                break
            lines.append(converted)

        if not ok:
            continue

        out_converted = convert_output(out_raw, out_type)
        if out_converted is None:
            continue

        results.append(("\n".join(lines), out_converted))

    return results


def slug_to_hash(slug: str) -> str:
    return hashlib.sha256(slug.encode()).hexdigest()[:12].upper()


def make_problem_md(row: dict) -> str:
    slug = row["slug"]
    return f"""# {row['title']}

Difficulty: {row['difficulty']}

{row['content']}

## I/O Format

{IO_FORMAT[slug]}

Write a complete C program (C11) that reads from stdin and writes to stdout.
Build the linked list(s) from input, apply the algorithm, and print the result.
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", default=str(HERE / "experiments"))
    args = parser.parse_args()

    run_dir = Path(args.run_dir)

    print("Loading greengerong/leetcode...", flush=True)
    ds = load_dataset("greengerong/leetcode", split="train")

    targeted = [r for r in ds if r["slug"] in TARGET_SLUGS]
    print(f"Found {len(targeted)} target problems")

    problem_map_path = run_dir / "problem_map.json"
    problem_map = json.loads(problem_map_path.read_text()) if problem_map_path.exists() else {}

    created = 0
    for row in targeted:
        slug = row["slug"]
        h = slug_to_hash(slug)
        dir_name = f"repository_{h}"
        exp_dir = run_dir / dir_name

        examples = parse_examples(row["content"], slug)
        if not examples:
            print(f"  SKIP {slug} — no parseable examples")
            continue

        exp_dir.mkdir(parents=True, exist_ok=True)
        (exp_dir / "problem.md").write_text(make_problem_md(row))

        tests_dir = exp_dir / "tests"
        tests_dir.mkdir(exist_ok=True)
        for i, (inp, out) in enumerate(examples):
            (tests_dir / f"input_{i}.txt").write_text(inp + "\n")
            (tests_dir / f"output_{i}.txt").write_text(out + "\n")

        problem_map[h] = slug
        created += 1
        print(f"  {dir_name}: {row['title']} ({len(examples)} test cases)")

    problem_map_path.write_text(json.dumps(problem_map, indent=2))
    print(f"\nCreated/updated {created} experiment directories in {run_dir}")
    print(f"problem_map.json updated: {problem_map_path}")


if __name__ == "__main__":
    main()
