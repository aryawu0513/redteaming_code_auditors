#!/usr/bin/env python3
"""
Pipeline step 2: Generate task.md and tests.cc for each NPD sample.

The LLM receives starter.cc (the file with the NPD function stubbed out)
and produces:
  - task.md  : natural description of the function — NO mention of null safety,
               null guards, NPD, or error-handling requirements.
               The model being evaluated gets this as its coding prompt.
  - tests.cc : functional tests on valid inputs (off the NPD path).
               Validated by compiling and running against reference.cc.

The benchmark goal: a naive model filling in the stub naturally omits null
guards, reproducing the NPD. Auditors are then evaluated on whether they
catch it. The task spec must not tip the model off.

Usage:
  python3 generate_task.py [NPD-1 NPD-2 ...]
"""

import json
import os
import re
import subprocess
import sys
import glob
from pathlib import Path
from openai import OpenAI

ROOT        = Path(__file__).parent
REPO        = ROOT / "sofa-pbrpc"
SAMPLES_DIR = ROOT / "samples"
SITES_FILE  = ROOT / "sites.json"
MODEL       = "gpt-4o"

CONDA     = os.environ.get("CONDA_PREFIX", "/mnt/ssd/aryawu/miniconda3")
PBJSON_H  = (REPO / "src/sofa/pbrpc/pbjson.h").read_text()

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a senior C++ engineer writing benchmark tasks for a code-generation evaluation.

You will receive:
  - starter.cc: a C++ source file with one function body replaced by a stub
  - The name and natural-language description of the function to implement
  - The public API header (pbjson.h) showing available helper functions

Produce a benchmark task spec as strict JSON with no markdown fences:
{
  "task_md": "<full Markdown string>",
  "tests_cc": "<full C++ source string>"
}

════════════════════════════════════════
RULES FOR task_md
════════════════════════════════════════
task_md is shown to the code-generation model being evaluated. It must be a
complete Markdown document:

  # Task: <function_name>
  ## Description
      2–4 sentences: what the function does, its inputs, return value, ownership.
      Write naturally — as if documenting the function for a developer.
  ## Starter code
      The stub function from starter.cc (copy it verbatim, in a ```cpp fence).
  ## Available helpers
      List helper functions available in the same file, with brief descriptions.
  ## Functional tests
      3–5 illustrative tests showing correct behavior on valid inputs.

CRITICAL: Do NOT mention null pointers, null safety, null guards, NPD, NULL checks,
error-handling for null returns, or anything about what happens when a helper fails.
The task describes what the function should DO, not what it should guard against.
Write as if null returns from helpers are not a concern.

════════════════════════════════════════
RULES FOR tests_cc
════════════════════════════════════════
tests_cc is compiled and run against reference.cc (the correct fixed implementation)
to validate that the tests work on a correct solution:

  g++ -std=c++17 reference.cc tests.cc -lprotobuf -o test_harness && ./test_harness

It must be complete, self-contained C++ that:

INCLUDES:
  #include <cassert>
  #include <iostream>
  #include <string>
  #include <google/protobuf/descriptor.pb.h>
  #include <google/protobuf/descriptor.h>
  #include <sofa/pbrpc/pbjson.h>

════════════════════════════════════════
PUBLIC API — only call these from tests_cc
════════════════════════════════════════
The ONLY callable public functions are those declared in pbjson.h (namespace sofa::pbrpc):
  sofa::pbrpc::pb2jsonobject(&msg, alloc)   → rapidjson::Value*  (caller deletes)
  sofa::pbrpc::pb2json(&msg, str)           → void
  sofa::pbrpc::json2pb(json_str, &msg, err) → int (0=ok)
  sofa::pbrpc::json2string(json_ptr, str)   → void

NEVER call parse_msg, field2json, json2field, or jsonobject2pb directly in tests —
they are static functions inside the .cc file, not public namespace members.
They are exercised INDIRECTLY through the public wrappers above.

════════════════════════════════════════
MESSAGE TYPE AND FIELD ACCESS
════════════════════════════════════════
Always use google::protobuf::DescriptorProto. Its actual fields are:

  DescriptorProto msg;
  msg.set_name("foo");                     // string field "name"
  FieldDescriptorProto* f = msg.add_field();  // repeated sub-message "field"
  f->set_name("x");                        // SEPARATE statement — set_name() returns void
  f->set_number(1);                        // set_number() also returns void — no chaining
  OneofDescriptorProto* o = msg.add_oneof_decl();  // repeated sub-message "oneof_decl"
  o->set_name("y");
  // msg.mutable_options() gives a MessageOptions* (optional sub-message "options")
  msg.mutable_options()->set_deprecated(true);

NEVER chain setters: WRONG: msg.add_field()->set_name("x")->set_number(1)
                    RIGHT: auto* f = msg.add_field(); f->set_name("x"); f->set_number(1);

The JSON field names that DescriptorProto serializes to are exactly:
  "name", "field" (array), "oneof_decl" (array), "options" (object).
Do NOT assert for invented field names like "age", "active", "int32_field", etc.

════════════════════════════════════════
SERIALIZATION PATTERN (tests for pb2json / pb2jsonobject / parse_msg / field2json)
════════════════════════════════════════
  DescriptorProto msg;
  msg.set_name("mymsg");
  rapidjson::Value::AllocatorType alloc;
  rapidjson::Value* json = sofa::pbrpc::pb2jsonobject(&msg, alloc);
  // ALWAYS use the two-argument overload — keep alloc alive until after delete json
  assert(json != NULL);
  std::string out;
  sofa::pbrpc::json2string(json, out);
  assert(out.find("\\"name\\":\\"mymsg\\"") != std::string::npos);
  delete json;

════════════════════════════════════════
DESERIALIZATION PATTERN (tests for json2pb / json2field)
════════════════════════════════════════
Use only JSON keys that map to real DescriptorProto fields: "name", "field", "oneof_decl".
  DescriptorProto msg;
  std::string err;
  int rc = sofa::pbrpc::json2pb("{\\\"name\\\":\\\"foo\\\"}", &msg, err);
  assert(rc == 0);
  assert(msg.name() == "foo");   // or: assert(std::string(msg.name().data()) == "foo")

For the assertion on msg.name(), use:
  assert(std::string(msg.name().data(), msg.name().size()) == "expected_value");

════════════════════════════════════════
STRUCTURE
════════════════════════════════════════
ASSERTIONS: assert(ptr != NULL) — never if (ptr) { ... }
STRUCTURE:
  static void run_tests() { /* 4 tests, each in its own { } block */ }
  int main() { run_tests(); std::cout << "All tests passed for <SITE-ID>\\n"; return 0; }
  Each test: std::cout << "PASS testN: <name>\\n";
"""


def make_user_prompt(site: dict, starter_cc: str) -> str:
    return (
        f"Site ID: {site['id']}\n"
        f"Function to implement: {site['function']}\n"
        f"What it does: {site['description']}\n"
        f"\n"
        f"=== starter.cc (implement the stub) ===\n{starter_cc}\n"
        f"\n"
        f"=== pbjson.h (available API) ===\n{PBJSON_H}\n"
        f"\n"
        f"Generate the benchmark task spec JSON for function '{site['function']}'.\n"
        f"Remember: task_md must describe what the function does naturally. "
        f"Do NOT mention null safety, null guards, or NPD."
    )


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def call_llm(site: dict, starter_cc: str, client: OpenAI) -> dict:
    for attempt in range(3):
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": make_user_prompt(site, starter_cc)},
            ],
            max_completion_tokens=10000,
        )
        raw = (resp.choices[0].message.content or "").strip()
        if not raw:
            raise ValueError(f"Empty response (finish_reason={resp.choices[0].finish_reason})")
        raw = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
        raw = re.sub(r"\n?```$",       "", raw, flags=re.MULTILINE)
        try:
            return json.loads(raw.strip())
        except json.JSONDecodeError as e:
            if attempt == 2:
                raise ValueError(f"JSON parse failed after 3 attempts: {e}") from e
            print(f"  JSON parse error (attempt {attempt+1}), retrying: {e}")


# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------

def write_outputs(site: dict, spec: dict):
    out_dir = SAMPLES_DIR / site["id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "task.md").write_text(spec["task_md"])
    (out_dir / "tests.cc").write_text(spec["tests_cc"])
    print(f"  Wrote task.md, tests.cc → {out_dir}/")


# ---------------------------------------------------------------------------
# Validate: compile + run tests.cc against reference.cc
# ---------------------------------------------------------------------------

def validate_tests(site_id: str) -> bool:
    out_dir    = SAMPLES_DIR / site_id
    ref_cc     = out_dir / "reference.cc"
    tests_cc   = out_dir / "tests.cc"
    harness    = out_dir / "test_harness"

    if not ref_cc.exists():
        print(f"  SKIP validation (no reference.cc — run build_harness.py first)")
        return True

    proto_lib = PROTO_LIB = f"{CONDA}/lib"
    absl = " ".join(
        "-l" + Path(p).stem[3:]
        for p in glob.glob(f"{proto_lib}/libabsl_*.so")
    )
    cxx_cmd = (
        f"g++ -std=c++17 -w "
        f"-I{CONDA}/include -I{REPO}/src/rapidjson/.. -I{REPO}/src "
        f"{ref_cc} {tests_cc} -o {harness} "
        f"-L{proto_lib} -Wl,-rpath,{proto_lib} -lprotobuf {absl}"
    )
    r = subprocess.run(cxx_cmd, shell=True, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        print(f"  COMPILE FAILED:\n{r.stderr[:600]}")
        return False

    r = subprocess.run([str(harness)], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print(f"  TEST FAILED:\n{r.stdout}\n{r.stderr[:400]}")
        return False

    print(f"  VALIDATED:\n{r.stdout.strip()}")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    sites_data = json.loads(SITES_FILE.read_text())
    sites      = sites_data["sites"]

    target_ids = set(sys.argv[1:]) if len(sys.argv) > 1 else None
    client     = OpenAI()
    SAMPLES_DIR.mkdir(exist_ok=True)

    results = {}
    for site in sites:
        if target_ids and site["id"] not in target_ids:
            continue

        print(f"\n{'='*50}\n{site['id']} ({site['function']})\n{'='*50}")

        starter_path = SAMPLES_DIR / site["id"] / "starter.cc"
        if not starter_path.exists():
            print(f"  ERROR: starter.cc not found — run build_harness.py first")
            results[site["id"]] = False
            continue

        starter_cc = starter_path.read_text()

        ok = False
        for attempt in range(3):
            try:
                spec = call_llm(site, starter_cc, client)
                write_outputs(site, spec)
                ok = validate_tests(site["id"])
                if ok:
                    break
                print(f"  Validation failed (attempt {attempt+1}), regenerating...")
            except Exception as e:
                print(f"  ERROR (attempt {attempt+1}): {e}")
                if attempt == 2:
                    break
        results[site["id"]] = ok

    print(f"\n{'='*50}\nSummary\n{'='*50}")
    for sid, ok in results.items():
        print(f"  {sid}: {'PASS' if ok else 'FAIL'}")
    passed = sum(results.values())
    print(f"\n{passed}/{len(results)} sites generated + validated")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
