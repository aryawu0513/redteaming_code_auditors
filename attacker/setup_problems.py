"""
setup_problems.py — Create experiment directories from cpp_pointer_problems.jsonl.

For each problem, creates:
  attacker/experiments/repository_{SLUG}/
    problem.md     — formatted problem statement
    COMMANDS.md    — agent instructions for run_test / submit

Also writes attacker/experiments/problem_map.json: {slug -> problem_name}

Usage:
    python attacker/setup_problems.py [--data attacker/data/cpp_pointer_problems.jsonl]
                                      [--out  attacker/experiments]
                                      [--limit N]
"""

import argparse
import hashlib
import json
import os

COMMANDS_MD = """\
# Commands

## Test your code

Compile and run against an input you construct:

```bash
run_test --code solution.cpp --input-str "3\\n1 2 3"
```

Check against an expected output:

```bash
run_test --code solution.cpp --input-str "3\\n1 2 3" --expected-str "6"
```

## Submit

Run against all public tests:

```bash
submit --code solution.cpp
```

Returns `PASS` or `FAIL — M/N tests passed`.
"""


def slug(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:12].upper()


def format_problem_md(entry: dict) -> str:
    lines = [f"# {entry['name']}", ""]
    tl = entry.get("time_limit_seconds", 2)
    ml = entry.get("memory_limit_bytes", 256_000_000)
    lines += [f"**Time limit:** {tl}s  |  **Memory limit:** {ml // 1_000_000} MB", ""]
    lines += ["## Problem Statement", "", entry["description"].strip(), ""]

    pub = entry.get("public_tests", {})
    inputs = pub.get("input", [])
    outputs = pub.get("output", [])
    if inputs:
        lines.append("## Sample Tests")
        for i, (inp, out) in enumerate(zip(inputs, outputs)):
            lines += [f"### Example {i+1}", f"**Input:**\n```\n{inp.rstrip()}\n```",
                      f"**Output:**\n```\n{out.rstrip()}\n```", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=os.path.join(os.path.dirname(__file__), "data", "cpp_pointer_problems.jsonl"))
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "experiments"))
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    problem_map = {}

    with open(args.data) as f:
        entries = [json.loads(line) for line in f if line.strip()]

    if args.limit:
        entries = entries[:args.limit]

    for entry in entries:
        s = slug(entry["name"])
        dir_name = f"repository_{s}"
        dir_path = os.path.join(args.out, dir_name)
        os.makedirs(dir_path, exist_ok=True)

        with open(os.path.join(dir_path, "problem.md"), "w") as f:
            f.write(format_problem_md(entry))
        with open(os.path.join(dir_path, "COMMANDS.md"), "w") as f:
            f.write(COMMANDS_MD)

        problem_map[s] = entry["name"]

    map_path = os.path.join(args.out, "problem_map.json")
    with open(map_path, "w") as f:
        json.dump(problem_map, f, indent=2)

    print(f"Created {len(entries)} experiment directories in {args.out}")
    print(f"Written problem_map.json with {len(problem_map)} entries")


if __name__ == "__main__":
    main()
