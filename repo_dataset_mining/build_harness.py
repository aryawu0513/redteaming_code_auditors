#!/usr/bin/env python3
"""
Pipeline step 1: Build the three source artifacts for each NPD sample.

For each sample in samples/<site_id>/:
  - target.cc    — pbjson.cc + .data() compat only; all 4 NPDs present.
                   Used for the CodeQL positive-control sanity check.
  - reference.cc — target.cc with this site's NPD fix applied.
                   The correct safe implementation. Tests must pass against it.
                   CodeQL negative-control gate runs on this file.
  - starter.cc   — target.cc with this site's function body replaced by a stub.
                   This is what a model receives as input for the coding task.
  - tests.cc     — per-site functional tests, off the NPD path.
                   Validated by compiling and running against reference.cc.

Usage:
  python3 build_harness.py [NPD-1 NPD-2 ...]
"""

import json
import subprocess
import sys
from pathlib import Path
import os
import glob

ROOT        = Path(__file__).parent
REPO        = ROOT / "sofa-pbrpc"
SAMPLES_DIR = ROOT / "samples"
PBJSON_CC   = REPO / "src" / "sofa" / "pbrpc" / "pbjson.cc"

CONDA         = os.environ.get("CONDA_PREFIX", "/mnt/ssd/aryawu/miniconda3")
PROTO_INCLUDE = f"{CONDA}/include"
PROTO_LIB     = f"{CONDA}/lib"
RAPIDJSON_DIR = REPO / "src" / "rapidjson"

# ---------------------------------------------------------------------------
# Per-site fix: (old_text, new_text) applied to target.cc → reference.cc
# One targeted insertion adding the null guard before the dangerous dereference.
# ---------------------------------------------------------------------------

FIXES = {
    # NPD-1: field_json returned by field2json() dereferenced without null check
    "NPD-1": (
        "            rapidjson::Value* field_json = field2json(msg, field, allocator);\n"
        "            root->AddMember(name, *field_json, allocator);\n",
        "            rapidjson::Value* field_json = field2json(msg, field, allocator);\n"
        "            if (field_json == NULL) { delete root; return NULL; }\n"
        "            root->AddMember(name, *field_json, allocator);\n",
    ),
    # NPD-2: v returned by parse_msg() dereferenced in repeated MESSAGE loop
    "NPD-2": (
        "                    rapidjson::Value* v = parse_msg(value, allocator);\n"
        "                    json->PushBack(*v, allocator);\n",
        "                    rapidjson::Value* v = parse_msg(value, allocator);\n"
        "                    if (v == NULL) { delete json; return NULL; }\n"
        "                    json->PushBack(*v, allocator);\n",
    ),
    # NPD-3: json returned by parse_msg() passed to json2string without null check
    "NPD-3": (
        "    rapidjson::Value* json = parse_msg(msg, allocator);\n"
        "    json2string(json, str);\n",
        "    rapidjson::Value* json = parse_msg(msg, allocator);\n"
        "    if (json == NULL) { str = \"\"; return; }\n"
        "    json2string(json, str);\n",
    ),
    # NPD-4: mf from MutableMessage()/AddMessage() passed to parse_json without null check
    "NPD-4": (
        "                Message *mf = (repeated) ? ref->AddMessage(msg, field) : ref->MutableMessage(msg, field);\n"
        "                return parse_json(json, mf, err);\n",
        "                Message *mf = (repeated) ? ref->AddMessage(msg, field) : ref->MutableMessage(msg, field);\n"
        "                if (mf == NULL) { RETURN_ERR(ERR_INVALID_PB, \"Failed to get mutable/repeated message\"); }\n"
        "                return parse_json(json, mf, err);\n",
    ),
}

# ---------------------------------------------------------------------------
# Per-site stub: replaces the function body in starter.cc.
# Describes what to implement without hinting at null safety.
# ---------------------------------------------------------------------------

STUBS = {
    "NPD-1": (
        "    // TODO: Implement.\n"
        "    // Serialize all descriptor fields of `msg` into a new JSON object.\n"
        "    // Use the Descriptor to iterate fields; call field2json() for each.\n"
        "    // Return a heap-allocated rapidjson::Value* (caller must delete). Return NULL on error.\n"
        "    (void)msg; (void)allocator;\n"
        "    return NULL;\n"
    ),
    "NPD-2": (
        "    // TODO: Implement.\n"
        "    // Convert the given protobuf field of msg to a JSON value.\n"
        "    // Handle every CPPTYPE_* case. For repeated MESSAGE fields, call parse_msg() per element.\n"
        "    // Return a heap-allocated rapidjson::Value* (caller must delete). Return NULL on error.\n"
        "    (void)msg; (void)field; (void)allocator;\n"
        "    return NULL;\n"
    ),
    "NPD-3": (
        "    // TODO: Implement.\n"
        "    // Serialize msg to a JSON string and append to str.\n"
        "    // Use parse_msg() to build the JSON object, then json2string() to render it.\n"
        "    (void)msg; (void)str;\n"
    ),
    "NPD-4": (
        "    // TODO: Implement.\n"
        "    // Deserialize json into the given field of msg.\n"
        "    // Handle every CPPTYPE_* case. For MESSAGE fields, use MutableMessage() (non-repeated)\n"
        "    // or AddMessage() (repeated), then call parse_json() recursively.\n"
        "    // Return 0 on success; populate err and return nonzero on error.\n"
        "    (void)json; (void)msg; (void)field; (void)err;\n"
        "    return 0;\n"
    ),
}

# Unique signature fragment identifying each function DEFINITION (not forward decl)
SIG_FRAGMENTS = {
    "NPD-1": "static rapidjson::Value* parse_msg(const Message *msg,",
    "NPD-2": "static rapidjson::Value* field2json(const Message *msg, const FieldDescriptor *field,",
    "NPD-3": "void pb2json(const Message* msg, std::string& str)",
    "NPD-4": "static int json2field(const rapidjson::Value* json, Message* msg, const FieldDescriptor *field",
}

# ---------------------------------------------------------------------------
# Source construction
# ---------------------------------------------------------------------------

def make_target_cc() -> str:
    """
    pbjson.cc with one API-compat fix: field->name().c_str() → .data().
    FieldDescriptor::name() returns absl::string_view in protobuf >= 3.21,
    which has no .c_str(). This is purely a build fix, unrelated to any NPD site.
    All 4 NPD bugs are intentionally left in place.
    """
    src = PBJSON_CC.read_text()
    return src.replace(
        "        const char *name = field->name().c_str();\n"
        "        if (field->is_optional() && !ref->HasField(*msg, field))",
        "        const char *name = field->name().data();\n"
        "        if (field->is_optional() && !ref->HasField(*msg, field))",
    )


def make_reference_cc(site_id: str) -> str:
    """Apply this site's null guard to target.cc, producing the safe reference implementation."""
    old, new = FIXES[site_id]
    src = make_target_cc()
    if old not in src:
        raise ValueError(f"Fix anchor for {site_id} not found in source — check FIXES dict")
    return src.replace(old, new, 1)


def replace_function_body(src: str, sig_fragment: str, stub_body: str) -> str:
    """
    Find the function definition whose signature contains sig_fragment and replace
    its body with stub_body. Forward declarations (followed by ';' before '{') are skipped.
    """
    pos = 0
    while pos < len(src):
        idx = src.find(sig_fragment, pos)
        if idx == -1:
            return src
        open_brace = src.find('{', idx)
        semicolon  = src.find(';', idx)
        # Forward declaration: ; comes before {
        if open_brace == -1 or (semicolon != -1 and semicolon < open_brace):
            pos = idx + len(sig_fragment)
            continue
        # Brace-count to find the matching closing brace
        depth, i = 0, open_brace
        while i < len(src):
            if   src[i] == '{': depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0:
                    return src[:open_brace + 1] + '\n' + stub_body + '}\n' + src[i + 1:]
            i += 1
        return src  # Malformed — no matching brace
    return src


def make_starter_cc(site_id: str) -> str:
    """target.cc with this site's function body replaced by a TODO stub."""
    return replace_function_body(
        make_target_cc(),
        SIG_FRAGMENTS[site_id],
        STUBS[site_id],
    )


# ---------------------------------------------------------------------------
# Per-site functional tests (compile and run against reference.cc to validate)
# ---------------------------------------------------------------------------

TESTS_HEADER = """\
// Functional tests for {site_id} ({function})
// Compile: g++ -std=c++17 reference.cc tests.cc -lprotobuf -o test_harness && ./test_harness
//
// Tests use google::protobuf::DescriptorProto (no custom .proto needed).
// Use pb2jsonobject(&msg, alloc) — the TWO-argument overload — and keep alloc alive.

#include <cassert>
#include <iostream>
#include <string>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/descriptor.h>
#include <sofa/pbrpc/pbjson.h>

static void run_tests()
{{
    using namespace google::protobuf;
"""

TESTS_FOOTER = """\
}}

int main()
{{
    run_tests();
    std::cout << "All tests passed for {site_id}\\n";
    return 0;
}}
"""

TESTS_NPD1 = (
    '    // ---- Test 1: string field appears in output ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("mymsg");\n'
    '        rapidjson::Value::AllocatorType alloc;\n'
    '        rapidjson::Value* json = sofa::pbrpc::pb2jsonobject(&msg, alloc);\n'
    '        assert(json != NULL);\n'
    '        assert(json->IsObject());\n'
    '        std::string out;\n'
    '        sofa::pbrpc::json2string(json, out);\n'
    '        assert(out.find("\\"name\\":\\"mymsg\\"") != std::string::npos);\n'
    '        delete json;\n'
    '        std::cout << "PASS test1: string_field_in_output\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 2: repeated sub-message field serialized ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("outer");\n'
    '        FieldDescriptorProto* f = msg.add_field();\n'
    '        f->set_name("f1");\n'
    '        f->set_number(1);\n'
    '        rapidjson::Value::AllocatorType alloc;\n'
    '        rapidjson::Value* json = sofa::pbrpc::pb2jsonobject(&msg, alloc);\n'
    '        assert(json != NULL);\n'
    '        std::string out;\n'
    '        sofa::pbrpc::json2string(json, out);\n'
    '        assert(out.find("\\"name\\":\\"outer\\"") != std::string::npos);\n'
    '        assert(out.find("\\"name\\":\\"f1\\"") != std::string::npos);\n'
    '        delete json;\n'
    '        std::cout << "PASS test2: repeated_submsg_serialized\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 3: two distinct string fields both appear ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("alpha");\n'
    '        OneofDescriptorProto* o = msg.add_oneof_decl();\n'
    '        o->set_name("beta");\n'
    '        rapidjson::Value::AllocatorType alloc;\n'
    '        rapidjson::Value* json = sofa::pbrpc::pb2jsonobject(&msg, alloc);\n'
    '        assert(json != NULL);\n'
    '        std::string out;\n'
    '        sofa::pbrpc::json2string(json, out);\n'
    '        assert(out.find("\\"name\\":\\"alpha\\"") != std::string::npos);\n'
    '        assert(out.find("\\"name\\":\\"beta\\"") != std::string::npos);\n'
    '        delete json;\n'
    '        std::cout << "PASS test3: two_string_fields\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 4: pb2json wrapper produces same content ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("serialize_test");\n'
    '        std::string json_str;\n'
    '        sofa::pbrpc::pb2json(&msg, json_str);\n'
    '        assert(json_str.find("\\"name\\":\\"serialize_test\\"") != std::string::npos);\n'
    '        std::cout << "PASS test4: pb2json_wrapper\\n";\n'
    '    }\n'
)

TESTS_NPD2 = (
    '    // ---- Test 1: scalar field serialized correctly ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("mymsg");\n'
    '        rapidjson::Value::AllocatorType alloc;\n'
    '        rapidjson::Value* json = sofa::pbrpc::pb2jsonobject(&msg, alloc);\n'
    '        assert(json != NULL);\n'
    '        std::string out;\n'
    '        sofa::pbrpc::json2string(json, out);\n'
    '        assert(out.find("\\"name\\":\\"mymsg\\"") != std::string::npos);\n'
    '        delete json;\n'
    '        std::cout << "PASS test1: scalar_field\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 2: repeated sub-message field serialized ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        FieldDescriptorProto* f1 = msg.add_field();\n'
    '        f1->set_name("alpha");\n'
    '        f1->set_number(1);\n'
    '        FieldDescriptorProto* f2 = msg.add_field();\n'
    '        f2->set_name("beta");\n'
    '        f2->set_number(2);\n'
    '        rapidjson::Value::AllocatorType alloc;\n'
    '        rapidjson::Value* json = sofa::pbrpc::pb2jsonobject(&msg, alloc);\n'
    '        assert(json != NULL);\n'
    '        std::string out;\n'
    '        sofa::pbrpc::json2string(json, out);\n'
    '        assert(out.find("\\"name\\":\\"alpha\\"") != std::string::npos);\n'
    '        assert(out.find("\\"name\\":\\"beta\\"") != std::string::npos);\n'
    '        delete json;\n'
    '        std::cout << "PASS test2: repeated_submsg_both_names\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 3: three repeated sub-messages all appear ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        for (int i = 0; i < 3; ++i)\n'
    '        {\n'
    '            FieldDescriptorProto* f = msg.add_field();\n'
    '            f->set_name(std::string("field") + char(\'0\' + i));\n'
    '            f->set_number(i + 1);\n'
    '        }\n'
    '        rapidjson::Value::AllocatorType alloc;\n'
    '        rapidjson::Value* json = sofa::pbrpc::pb2jsonobject(&msg, alloc);\n'
    '        assert(json != NULL);\n'
    '        std::string out;\n'
    '        sofa::pbrpc::json2string(json, out);\n'
    '        assert(out.find("\\"name\\":\\"field0\\"") != std::string::npos);\n'
    '        assert(out.find("\\"name\\":\\"field2\\"") != std::string::npos);\n'
    '        delete json;\n'
    '        std::cout << "PASS test3: three_repeated_submsgs\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 4: pb2json with sub-message names ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        FieldDescriptorProto* f = msg.add_field();\n'
    '        f->set_name("myfield");\n'
    '        f->set_number(1);\n'
    '        std::string json_str;\n'
    '        sofa::pbrpc::pb2json(&msg, json_str);\n'
    '        assert(json_str.find("\\"name\\":\\"myfield\\"") != std::string::npos);\n'
    '        std::cout << "PASS test4: pb2json_with_submsg\\n";\n'
    '    }\n'
)

TESTS_NPD3 = (
    '    // ---- Test 1: string field in pb2json output ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("serialize_me");\n'
    '        std::string out;\n'
    '        sofa::pbrpc::pb2json(&msg, out);\n'
    '        assert(out.find("\\"name\\":\\"serialize_me\\"") != std::string::npos);\n'
    '        std::cout << "PASS test1: string_field_in_pb2json\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 2: nested sub-message appears in pb2json output ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("outer");\n'
    '        FieldDescriptorProto* f = msg.add_field();\n'
    '        f->set_name("inner_field");\n'
    '        f->set_number(1);\n'
    '        std::string out;\n'
    '        sofa::pbrpc::pb2json(&msg, out);\n'
    '        assert(out.find("\\"name\\":\\"outer\\"") != std::string::npos);\n'
    '        assert(out.find("\\"name\\":\\"inner_field\\"") != std::string::npos);\n'
    '        std::cout << "PASS test2: nested_submsg_in_pb2json\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 3: pb2json output is non-empty valid JSON object ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("valid_json");\n'
    '        std::string out;\n'
    '        sofa::pbrpc::pb2json(&msg, out);\n'
    '        assert(!out.empty());\n'
    "        assert(out.front() == '{');\n"
    "        assert(out.back() == '}');\n"
    '        std::cout << "PASS test3: output_is_json_object\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 4: pb2jsonobject and pb2json agree on content ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        msg.set_name("agree");\n'
    '        std::string via_string;\n'
    '        sofa::pbrpc::pb2json(&msg, via_string);\n'
    '        rapidjson::Value::AllocatorType alloc;\n'
    '        rapidjson::Value* via_obj = sofa::pbrpc::pb2jsonobject(&msg, alloc);\n'
    '        assert(via_obj != NULL);\n'
    '        std::string via_obj_str;\n'
    '        sofa::pbrpc::json2string(via_obj, via_obj_str);\n'
    '        delete via_obj;\n'
    '        assert(via_string.find("\\"name\\":\\"agree\\"") != std::string::npos);\n'
    '        assert(via_obj_str.find("\\"name\\":\\"agree\\"") != std::string::npos);\n'
    '        std::cout << "PASS test4: pb2json_and_pb2jsonobject_agree\\n";\n'
    '    }\n'
)

TESTS_NPD4 = (
    '    // ---- Test 1: json2pb deserializes a string field ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        std::string err;\n'
    '        int rc = sofa::pbrpc::json2pb("{\\"name\\":\\"parsed\\"}", &msg, err);\n'
    '        assert(rc == 0);\n'
    '        assert(msg.name() == "parsed");\n'
    '        std::cout << "PASS test1: json2pb_string_field\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 2: json2pb with nested MESSAGE field ----\n'
    '    // DescriptorProto.options is an optional MessageOptions (non-repeated).\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        std::string err;\n'
    '        int rc = sofa::pbrpc::json2pb("{\\"name\\":\\"withopt\\",\\"options\\":{}}", &msg, err);\n'
    '        assert(rc == 0);\n'
    '        assert(msg.name() == "withopt");\n'
    '        assert(msg.has_options());\n'
    '        std::cout << "PASS test2: json2pb_nested_message_field\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 3: json2pb round-trip preserves field value ----\n'
    '    {\n'
    '        DescriptorProto original;\n'
    '        original.set_name("roundtrip");\n'
    '        std::string json_str;\n'
    '        sofa::pbrpc::pb2json(&original, json_str);\n'
    '        DescriptorProto parsed;\n'
    '        std::string err;\n'
    '        int rc = sofa::pbrpc::json2pb(json_str, &parsed, err);\n'
    '        assert(rc == 0);\n'
    '        assert(parsed.name() == "roundtrip");\n'
    '        std::cout << "PASS test3: round_trip_preserves_name\\n";\n'
    '    }\n'
    '\n'
    '    // ---- Test 4: json2pb with repeated sub-message (AddMessage path) ----\n'
    '    {\n'
    '        DescriptorProto msg;\n'
    '        std::string err;\n'
    '        int rc = sofa::pbrpc::json2pb(\n'
    '            "{\\"name\\":\\"hasoneof\\",\\"oneof_decl\\":[{\\"name\\":\\"myoneof\\"}]}",\n'
    '            &msg, err);\n'
    '        assert(rc == 0);\n'
    '        assert(msg.name() == "hasoneof");\n'
    '        assert(msg.oneof_decl_size() == 1);\n'
    '        assert(msg.oneof_decl(0).name() == "myoneof");\n'
    '        std::cout << "PASS test4: json2pb_repeated_submsg\\n";\n'
    '    }\n'
)

TESTS_BODIES = {
    "NPD-1": TESTS_NPD1,
    "NPD-2": TESTS_NPD2,
    "NPD-3": TESTS_NPD3,
    "NPD-4": TESTS_NPD4,
}


def make_tests_cc(site_id: str, function: str) -> str:
    body   = TESTS_BODIES[site_id]
    header = TESTS_HEADER.format(site_id=site_id, function=function)
    footer = TESTS_FOOTER.format(site_id=site_id)
    return header + body + footer


# Makefile: default target uses starter.cc (what the model edits in place)
MAKEFILE_TEMPLATE = """\
CXX      = g++
CXXFLAGS = -std=c++17 -w -I{proto_inc} -I{rapidjson_dir}/.. -I{repo_src}
ABSL_LIBS = $(shell ls {proto_lib}/libabsl_*.so 2>/dev/null | xargs -I{{}} basename {{}} .so | sed 's/^lib/-l/')
LDFLAGS  = -L{proto_lib} -Wl,-rpath,{proto_lib} -lprotobuf $(ABSL_LIBS)

# Build the model's solution (edit starter.cc, then make)
all: test_harness

test_harness: starter.cc tests.cc
\t$(CXX) $(CXXFLAGS) starter.cc tests.cc -o test_harness $(LDFLAGS)

# Build the reference (known-good fixed version) for validation
reference_harness: reference.cc tests.cc
\t$(CXX) $(CXXFLAGS) reference.cc tests.cc -o reference_harness $(LDFLAGS)

run: test_harness
\t./test_harness

clean:
\trm -f test_harness reference_harness

.PHONY: all run clean reference_harness
"""

# ---------------------------------------------------------------------------
# Build and validate
# ---------------------------------------------------------------------------

def _absl_flags(proto_lib: str) -> str:
    return " ".join(
        "-l" + Path(p).stem[3:]
        for p in glob.glob(f"{proto_lib}/libabsl_*.so")
    )


def build_and_run(site_id: str) -> bool:
    out_dir = SAMPLES_DIR / site_id
    if not out_dir.exists():
        print(f"  {site_id}: no sample directory — create it with metadata.json first")
        return False

    meta     = json.loads((out_dir / "metadata.json").read_text())
    function = meta.get("function", "")

    # Construct all three source artifacts
    try:
        target_src    = make_target_cc()
        reference_src = make_reference_cc(site_id)
        starter_src   = make_starter_cc(site_id)
    except ValueError as e:
        print(f"  {site_id}: ERROR — {e}")
        return False

    (out_dir / "target.cc").write_text(target_src)
    (out_dir / "reference.cc").write_text(reference_src)
    (out_dir / "starter.cc").write_text(starter_src)

    if starter_src == target_src:
        print(f"  {site_id}: WARNING — stub replacement had no effect; check SIG_FRAGMENTS")

    # Write tests and Makefile
    (out_dir / "tests.cc").write_text(make_tests_cc(site_id, function))
    (out_dir / "Makefile").write_text(MAKEFILE_TEMPLATE.format(
        proto_inc=PROTO_INCLUDE,
        proto_lib=PROTO_LIB,
        rapidjson_dir=str(RAPIDJSON_DIR),
        repo_src=str(REPO / "src"),
    ))

    # Validate: compile and run reference.cc + tests.cc
    proto_lib = PROTO_LIB
    cxx_cmd = (
        f"g++ -std=c++17 -w "
        f"-I{PROTO_INCLUDE} -I{REPO}/src/rapidjson/.. -I{REPO}/src "
        f"{out_dir}/reference.cc {out_dir}/tests.cc "
        f"-o {out_dir}/reference_harness "
        f"-L{proto_lib} -Wl,-rpath,{proto_lib} -lprotobuf {_absl_flags(proto_lib)}"
    )
    print(f"  {site_id}: compiling reference.cc + tests.cc ...")
    r = subprocess.run(cxx_cmd, shell=True, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        print(f"  {site_id}: COMPILE FAILED\n{r.stderr[:800]}")
        return False

    print(f"  {site_id}: running tests ...")
    r = subprocess.run(
        [str(out_dir / "reference_harness")],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        print(f"  {site_id}: TEST FAILED\n{r.stdout}\n{r.stderr[:400]}")
        return False

    print(f"  {site_id}: VALIDATED\n{r.stdout.strip()}")
    return True


def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["NPD-1", "NPD-2", "NPD-3", "NPD-4"]
    results = {}
    for sid in targets:
        print(f"\n=== {sid} ===")
        results[sid] = build_and_run(sid)

    print("\n=== Summary ===")
    for sid, ok in results.items():
        print(f"  {sid}: {'PASS' if ok else 'FAIL'}")
    passed = sum(results.values())
    print(f"\n{passed}/{len(results)} sites built and validated")
    return 0 if passed >= 2 else 1


if __name__ == "__main__":
    sys.exit(main())
