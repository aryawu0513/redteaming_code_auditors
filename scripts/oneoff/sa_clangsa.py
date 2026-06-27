"""
Clang Static Analyzer catch-rate on 128 CVE NPD samples.

Approach: splice attacker's function into the ORIGINAL repo file (using
tree-sitter for surgical precision), build the repo in-place to generate
headers (config.h, etc.), use compile_commands.json for exact compile flags,
then run clang --analyze on the patched file.

Mode 1 (file-level, all samples):
  Uses exact compile flags from compile_commands.json + Clang's stdlib null
  model. Covers: null_literal (HIGH), stdlib_alloc (HIGH), stdlib_other (MEDIUM).

Mode 2 (CTU, mode-1 misses only):
  Builds a cross-translation-unit index and re-analyzes.
  Covers: callee_return across files, unknown/cross-file (VERY_LOW).

Prerequisites:
  Run sa_build_repos.py first to build all repos and generate compile_commands.json.
  Or pass --build to have this script auto-build repos on demand.

Usage:
    python scripts/oneoff/sa_clangsa.py [--resume] [--build] [--skip-ctu]

Output:
    results/sa_clangsa.json
"""

import argparse
import json
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "cvebench"))
from splice_target import splice_function, find_function_spans   # tree-sitter based
from patch_and_test import extract_body, splice_body             # body-only splice (keeps repo signature)

BENCH_ROOT = Path("/mnt/ssd/aryawu/redteaming_code_auditors/benchmark/cvebench_full/baseline")
MANIFEST   = Path("/mnt/ssd/aryawu/cve_repos_fix/clone_manifest.json")
OUT_PATH   = Path("/mnt/ssd/aryawu/redteaming_code_auditors/results/sa_clangsa.json")
CTU_CACHE  = Path("/tmp/cve_sa_clangsa_ctu")

CLANG         = "clang-14"
LIBCLANG_SO   = "/usr/lib/x86_64-linux-gnu/libclang-14.so.1"
CMAKE         = "/usr/bin/cmake"

CHECKERS = [
    "core.NullDereference",
    "core.CallAndMessage",
    # alpha.core.NullDereference does not exist in clang-14; omit
]

TIMEOUT_MODE1  = 120   # seconds per sample
TIMEOUT_CTU    = 600   # seconds per sample (CTU is slower)
TIMEOUT_BUILD  = 300   # seconds for repo build


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def load_samples():
    manifest = json.loads(MANIFEST.read_text())
    samples = []
    for repo_dir in sorted(BENCH_ROOT.iterdir()):
        for f in sorted(repo_dir.iterdir()):
            if f.name.endswith("_CLEAN.json"):
                item = json.loads(f.read_text())[0]
                slug = item["slug"]
                m    = manifest.get(slug, {})
                item["clone_dir"]      = m.get("clone_dir")
                item["vuln_file_path"] = m.get("file")
                samples.append(item)
    return samples


# ---------------------------------------------------------------------------
# Build support: ensure repo has generated headers + compile_commands.json
# ---------------------------------------------------------------------------

def _run_quiet(cmd, cwd, timeout):
    try:
        return subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


_CMAKE_FLAG_SETS = [
    # Try progressively more permissive cmake options
    [],
    ["-DBUILD_TESTS=OFF", "-DENABLE_TESTS=OFF"],
    ["-DBUILD_TESTS=OFF", "-DENABLE_TESTS=OFF", "-DBUILD_TESTING=OFF"],
    ["-DBUILD_TESTS=OFF", "-DENABLE_TESTS=OFF", "-DBUILD_TESTING=OFF",
     "-DBUILD_SHARED_LIBS=OFF"],
]


def ensure_built(repo_path: Path) -> bool:
    """
    Run cmake or configure on the repo if not already built.
    cmake: generates _cmake_build/compile_commands.json + built headers.
    autoconf/make: generates config.h and other in-tree headers.
    Returns True if build ran (or was already done).
    """
    # cmake: check if already configured (compile_commands.json exists)
    if (repo_path / "CMakeLists.txt").exists():
        build_dir = repo_path / "_cmake_build"
        cc_path   = build_dir / "compile_commands.json"
        if cc_path.exists():
            return True   # already built
        build_dir.mkdir(exist_ok=True)
        # Try multiple cmake flag sets until compile_commands.json appears
        base_flags = [CMAKE, "-S", str(repo_path), "-B", str(build_dir),
                      "-DCMAKE_BUILD_TYPE=Debug",
                      "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                      "--no-warn-unused-cli"]
        for extra in _CMAKE_FLAG_SETS:
            _run_quiet(base_flags + extra, cwd=repo_path, timeout=120)
            if cc_path.exists():
                break
        _run_quiet([CMAKE, "--build", str(build_dir), "--parallel", "4"],
                   cwd=repo_path, timeout=TIMEOUT_BUILD)
        return cc_path.exists()

    # autoconf
    if (repo_path / "configure.ac").exists() or (repo_path / "configure").exists():
        if (repo_path / "configure.h").exists() or (repo_path / "config.h").exists():
            return True   # already configured
        if (repo_path / "configure.ac").exists() and not (repo_path / "configure").exists():
            _run_quiet(["autoreconf", "-fi"], cwd=repo_path, timeout=120)
        if (repo_path / "autogen.sh").exists():
            _run_quiet(["bash", "autogen.sh"], cwd=repo_path, timeout=120)
        if (repo_path / "configure").exists():
            _run_quiet(["./configure", "--quiet"], cwd=repo_path, timeout=180)
        _run_quiet(["make", "-j4", "-k", "--keep-going"],
                   cwd=repo_path, timeout=TIMEOUT_BUILD)
        return True

    # plain Makefile
    if (repo_path / "Makefile").exists():
        _run_quiet(["make", "-j4", "-k", "--keep-going"],
                   cwd=repo_path, timeout=TIMEOUT_BUILD)
        return True

    return False


def find_compile_commands(repo_path: Path) -> Path | None:
    """Return path to compile_commands.json if it exists."""
    for candidate in [repo_path / "_cmake_build" / "compile_commands.json",
                      repo_path / "compile_commands.json"]:
        if candidate.exists():
            return candidate
    return None


def get_compile_flags(cc_path: Path, target_file: Path) -> list[str]:
    """
    Extract -I, -D, -std flags for target_file from compile_commands.json.
    Resolves relative -I paths relative to the build directory.
    """
    entries = json.loads(cc_path.read_text())
    target_str  = str(target_file)
    target_name = target_file.name

    entry = None
    for e in entries:
        ef = e.get("file", "")
        if ef == target_str or target_str.endswith(ef) or ef.endswith(target_str):
            entry = e; break
    if entry is None:
        for e in entries:
            if Path(e.get("file", "")).name == target_name:
                entry = e; break
    if entry is None:
        return []

    build_dir = Path(entry.get("directory", str(cc_path.parent)))
    flags: list[str] = []
    parts = entry.get("command", "").split()
    i = 0
    while i < len(parts):
        p = parts[i]
        if p.startswith("-I") and len(p) > 2:
            inc = p[2:]
            if not Path(inc).is_absolute():
                inc = str(build_dir / inc)
            flags += ["-I", inc]
        elif p == "-I" and i + 1 < len(parts):
            inc = parts[i + 1]; i += 1
            if not Path(inc).is_absolute():
                inc = str(build_dir / inc)
            flags += ["-I", inc]
        elif p.startswith("-D") or p.startswith("-std") or p.startswith("-f"):
            flags.append(p)
        elif p == "-D" and i + 1 < len(parts):
            flags += ["-D", parts[i + 1]]; i += 1
        i += 1
    return flags


def heuristic_include_dirs(repo_path: Path, target_file: Path) -> list[str]:
    """Fallback heuristic -I paths when compile_commands.json is unavailable."""
    dirs = [str(repo_path)]
    for name in ("include", "Include", "src", "lib", "source", "common", "public"):
        d = repo_path / name
        if d.is_dir():
            dirs.append(str(d))
    # Add cmake/build dirs for generated headers (config.h etc.)
    for bd in ["_cmake_build", "build", "Build"]:
        d = repo_path / bd
        if d.is_dir():
            dirs.append(str(d))
    dirs.append(str(target_file.parent))
    if target_file.parent != repo_path:
        dirs.append(str(target_file.parent.parent))
    # Deep scan: find all include/ dirs in source tree (covers e.g. src/libjasper/include/)
    seen = set(dirs)
    try:
        for p in repo_path.rglob("include"):
            if (p.is_dir() and ".git" not in str(p)
                    and "_cmake_build" not in str(p) and str(p) not in seen):
                dirs.append(str(p))
                seen.add(str(p))
                if len(dirs) > 40:
                    break
    except Exception:
        pass
    return dirs


def _pkgconfig_flags(*packages: str) -> list[str]:
    """Return -I flags from pkg-config for the given packages (silently skips missing ones)."""
    flags: list[str] = []
    for pkg in packages:
        r = subprocess.run(["pkg-config", "--cflags-only-I", pkg],
                           capture_output=True, text=True)
        if r.returncode == 0:
            flags += r.stdout.split()
    return flags


def _scan_build_include_dirs(repo_path: Path) -> list[str]:
    """
    Scan the cmake build tree for 'include' directories that may contain
    headers from ExternalProject downloads (e.g. spdlog, abseil) that are
    not listed in compile_commands.json (generated before ExternalProjects build).
    Also includes the build root itself (for generated headers like jconfig.h).
    Caps at 30 directories to avoid noise.
    """
    build_dir = repo_path / "_cmake_build"
    if not build_dir.exists():
        return []
    dirs = [str(build_dir)]
    count = 0
    try:
        for p in build_dir.rglob("include"):
            if p.is_dir() and ".git" not in str(p) and count < 30:
                dirs.append(str(p))
                count += 1
    except Exception:
        pass
    return dirs


def _gcc_stdlib_flags(lang: str) -> list[str]:
    """
    Clang-14 on this machine expects GCC-12 stdlib but only GCC-11 is installed.
    Return explicit -I flags for the GCC-11 C++ headers for C++ files.
    """
    if lang not in ("c++", "c++-header"):
        return []
    flags = []
    for d in ["/usr/include/c++/11",
              "/usr/include/x86_64-linux-gnu/c++/11",
              "/usr/include/c++/11/backward"]:
        if Path(d).exists():
            flags += ["-I", d]
    return flags


def get_include_flags(repo_path: Path, target_file: Path,
                      lang: str = "") -> list[str]:
    """
    Get compiler flags for target_file.
    Prefers compile_commands.json; falls back to heuristic include discovery.
    Prepends GCC-11 stdlib paths for C++ files (clang-14 ↔ GCC-12 mismatch).
    """
    if not lang:
        lang = "c++" if target_file.suffix in (".cpp", ".cc", ".cxx") else "c"

    cc_path = find_compile_commands(repo_path)
    if cc_path:
        flags = get_compile_flags(cc_path, target_file)
        if flags:
            # Append build-tree scan for ExternalProject headers not in compile_commands.json
            extra_dirs = _scan_build_include_dirs(repo_path)
            extra_flags = [flag for d in extra_dirs for flag in ("-I", d)]
            return _gcc_stdlib_flags(lang) + flags + extra_flags

    # Fallback: turn heuristic dirs into -I flags (also scan build tree)
    base_dirs = heuristic_include_dirs(repo_path, target_file)
    extra_dirs = _scan_build_include_dirs(repo_path)
    all_dirs = base_dirs + [d for d in extra_dirs if d not in base_dirs]
    pkg_flags = _pkgconfig_flags("glib-2.0", "ogg", "libogg", "libpcre")
    return _gcc_stdlib_flags(lang) + [flag for d in all_dirs for flag in ("-I", d)] + pkg_flags


# ---------------------------------------------------------------------------
# Function extraction and surgical patching
# ---------------------------------------------------------------------------

def find_function_line_range(source: str, fn: str):
    """
    Return (start_line, end_line) of the function DEFINITION (1-based).
    Skips forward declarations (lines with fn( but no opening brace before ';').
    """
    lines     = source.splitlines()
    start     = None
    depth     = 0
    seen_open = False
    for i, line in enumerate(lines, 1):
        if start is None and re.search(rf'\b{re.escape(fn)}\s*\(', line):
            # Require this to be a definition, not a declaration.
            # A declaration ends with ';' before any '{'.
            # Scan forward from here until we hit '{' or ';' (or both on same line).
            scan = line
            j = i
            found_open = '{' in scan and (';' not in scan or scan.index('{') < scan.index(';'))
            while not found_open and ';' not in scan and j < len(lines):
                j += 1
                scan = lines[j - 1]
                found_open = '{' in scan
            if not found_open:
                continue   # this is a declaration — skip it
            start = i
        if start is not None:
            depth += line.count('{') - line.count('}')
            if depth > 0:
                seen_open = True
            if seen_open and depth <= 0:
                return start, i
    return (start or 1), len(lines)


def patch_function(full_file: str, vuln_src: str, fn: str, lang: str = "c") -> str | None:
    """
    Splice only the attacker's function BODY into the repo file, keeping the
    repo's original function signature. This is identical to what patch_and_test.py
    does, so the result is guaranteed to compile (it was already tested there).

    vuln_src is primary_file, which is splice_body(fn, starter_src, attacker_body).
    We extract the body from vuln_src and put it into full_file's function.
    """
    body = extract_body(fn, vuln_src)
    if body is None:
        return None
    result = splice_body(fn, full_file, body)
    return result


def parse_plist(plist_path: Path, target_fname: str,
                fstart: int, fend: int) -> tuple[list, list]:
    """Return (in_func_hits, in_file_hits) from a clang plist report."""
    if not plist_path.exists():
        return [], []
    try:
        data = plistlib.loads(plist_path.read_bytes())
    except Exception:
        return [], []

    files = data.get("files", [])
    in_func, in_file = [], []

    for diag in data.get("diagnostics", []):
        check = diag.get("check_name", "")
        if "NullDereference" not in check and "NullPointer" not in check:
            continue
        loc  = diag.get("location", {})
        fidx = loc.get("file", -1)
        line = loc.get("line", 0)
        fname = str(files[fidx]) if 0 <= fidx < len(files) else ""
        hit  = {"check": check, "file": fname, "line": line,
                "desc": diag.get("description", "")}
        if target_fname in fname:
            in_file.append(hit)
            if fstart <= line <= fend:
                in_func.append(hit)

    return in_func, in_file


# ---------------------------------------------------------------------------
# Mode 1: file-level analysis
# ---------------------------------------------------------------------------

def run_mode1(sample: dict, tmp_dir: Path, auto_build: bool = False) -> dict:
    slug      = sample["slug"]
    fn        = sample["function_name"]
    src       = sample["primary_file"]    # primary_file = attacker's full spliced file
    clone_dir = sample["clone_dir"]
    vuln_fp   = sample["vuln_file_path"]

    if not clone_dir or not Path(clone_dir).exists():
        return {"slug": slug, "mode1": None, "error": f"clone_dir missing: {clone_dir}"}

    repo_path   = Path(clone_dir)
    target_file = repo_path / vuln_fp
    if not target_file.exists():
        return {"slug": slug, "mode1": None, "error": f"file not found: {vuln_fp}"}

    # Build repo to generate headers + compile_commands.json
    if auto_build:
        ensure_built(repo_path)

    lang        = "c++" if target_file.suffix in (".cpp", ".cc", ".cxx") else "c"
    inc_flags   = get_include_flags(repo_path, target_file, lang=lang)
    plist_out   = tmp_dir / f"{slug}_m1.plist"
    fstart, fend = find_function_line_range(src, fn)

    cmd = [CLANG, "--analyze",
           "--analyzer-output", "plist",
           "-o", str(plist_out),
           "-w", "-x", lang]
    cmd += inc_flags
    for checker in CHECKERS:
        cmd += ["-Xanalyzer", f"-analyzer-checker={checker}"]
    cmd.append(str(target_file))

    original = target_file.read_text(errors="replace")
    patched  = patch_function(original, src, fn, lang=lang)
    if patched is None:
        return {"slug": slug, "mode1": None,
                "error": f"function {fn} not found in repo file"}
    try:
        target_file.write_text(patched)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_MODE1)
        in_func, in_file = parse_plist(plist_out, Path(vuln_fp).name, fstart, fend)

        # Record which flag source was used for diagnostics
        cc_path = find_compile_commands(repo_path)
        flags_source = str(cc_path) if cc_path and get_compile_flags(cc_path, target_file) else "heuristic"

        return {
            "slug":             slug,
            "function_name":    fn,
            "func_range":       [fstart, fend],
            "flags_source":     flags_source,
            "mode1": {
                "hit_in_function":    bool(in_func),
                "hit_in_target_file": bool(in_file),
                "hits_in_func":       in_func[:5],
                "hits_in_file":       in_file[:5],
            },
        }
    except subprocess.TimeoutExpired:
        return {"slug": slug, "mode1": None, "error": "timeout_mode1"}
    except Exception as e:
        return {"slug": slug, "mode1": None, "error": str(e)}
    finally:
        target_file.write_text(original)
        plist_out.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Mode 2: CTU analysis
# ---------------------------------------------------------------------------

def _init_libclang():
    """Initialize libclang once. Returns Index or None."""
    try:
        import clang.cindex as ci
        if not ci.Config.loaded:
            ci.Config.set_library_file(LIBCLANG_SO)
        return ci.Index.create(), ci
    except Exception:
        return None, None



def build_ctu_index(repo_path: Path, ctu_dir: Path,
                    inc_dirs: list[str]) -> bool:
    """
    Build CTU index using libclang Python bindings (pip install libclang==14.0.6).
    No clang-extdef-mapping needed.
    Returns True on success.
    """
    idx, ci = _init_libclang()
    if idx is None:
        return False

    ast_dir = ctu_dir / "ast"
    ast_dir.mkdir(parents=True, exist_ok=True)

    exts = {".c", ".cpp", ".cc", ".cxx"}
    src_files = [f for f in repo_path.rglob("*")
                 if f.suffix in exts and f.is_file()
                 and "test" not in f.parts and "Test" not in f.parts][:200]
    if not src_files:
        return False

    inc_flags = [flag for inc in inc_dirs for flag in ("-I", inc)]

    extdef_map: dict[str, str] = {}   # mangled_name → ast_path (first wins, no dups)
    for sf in src_files:
        lang = "c++" if sf.suffix in (".cpp", ".cc", ".cxx") else "c"
        ast_out = ast_dir / (sf.stem + f"_{sf.parent.name}.ast")
        # Use libclang to parse (tolerates errors) and save AST
        try:
            tu = idx.parse(str(sf), args=["-x", lang] + inc_flags)
            tu.save(str(ast_out))   # writes .ast even if there were parse errors
        except Exception:
            continue
        if not ast_out.exists():
            continue
        # Walk the TU we already parsed to extract function defs
        for cursor in tu.cursor.walk_preorder():
            if (cursor.kind in (ci.CursorKind.FUNCTION_DECL, ci.CursorKind.CXX_METHOD)
                    and cursor.is_definition()
                    and cursor.location.file
                    and Path(str(cursor.location.file)) == sf
                    and cursor.mangled_name
                    and cursor.mangled_name not in extdef_map):   # first definition wins
                extdef_map[cursor.mangled_name] = str(ast_out)

    if not extdef_map:
        return False

    extdef_lines = [f"{name} {path}" for name, path in extdef_map.items()]
    (ctu_dir / "externalDefMap.txt").write_text("\n".join(extdef_lines) + "\n")
    return True


def run_mode2(sample: dict, ctu_dir: Path, tmp_dir: Path) -> dict:
    """Run CTU analysis on a sample using a pre-built CTU index."""
    slug      = sample["slug"]
    fn        = sample["function_name"]
    src       = sample["primary_file"]
    clone_dir = sample["clone_dir"]
    vuln_fp   = sample["vuln_file_path"]

    repo_path   = Path(clone_dir)
    target_file = repo_path / vuln_fp
    lang        = "c++" if target_file.suffix in (".cpp", ".cc", ".cxx") else "c"
    inc_flags   = get_include_flags(repo_path, target_file, lang=lang)
    plist_out   = tmp_dir / f"{slug}_m2.plist"
    fstart, fend = find_function_line_range(src, fn)  # compute from attacker's code, same as mode1

    cmd = [CLANG, "--analyze",
           "--analyzer-output", "plist",
           "-o", str(plist_out),
           "-w", "-x", lang]
    cmd += inc_flags
    for checker in CHECKERS:
        cmd += ["-Xanalyzer", f"-analyzer-checker={checker}"]
    cmd += [
        "-Xanalyzer", "-analyzer-config",
        "-Xanalyzer", "experimental-enable-naive-ctu-analysis=true",
        "-Xanalyzer", "-analyzer-config",
        "-Xanalyzer", f"ctu-dir={ctu_dir}",
    ]
    cmd.append(str(target_file))

    original = target_file.read_text(errors="replace")
    patched  = patch_function(original, src, fn, lang=lang)
    if patched is None:
        return {"hit_in_function": None, "error": f"function {fn} not found in repo file"}
    try:
        target_file.write_text(patched)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_CTU)
        in_func, in_file = parse_plist(plist_out, Path(vuln_fp).name, fstart, fend)
        return {
            "hit_in_function":    bool(in_func),
            "hit_in_target_file": bool(in_file),
            "hits_in_func":       in_func[:5],
            "hits_in_file":       in_file[:5],
        }
    except subprocess.TimeoutExpired:
        return {"hit_in_function": None, "error": "timeout_ctu"}
    except Exception as e:
        return {"hit_in_function": None, "error": str(e)}
    finally:
        target_file.write_text(original)
        plist_out.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true",
                        help="Skip slugs where mode1 is already done")
    parser.add_argument("--skip-ctu", action="store_true",
                        help="Run mode1 only, skip CTU mode2")
    parser.add_argument("--build", action="store_true",
                        help="Auto-build each repo before analysis (cmake/configure). "
                             "Needed on first run; subsequent runs can skip with --resume.")
    args = parser.parse_args()

    idx, ci = _init_libclang()
    ctu_available = idx is not None
    if not ctu_available and not args.skip_ctu:
        print(f"[warn] libclang not available — Mode 2 (CTU) will be skipped.")
        print(f"       Install with: pip install libclang==14.0.6")

    samples = load_samples()
    results: dict[str, dict] = {}
    if OUT_PATH.exists():
        for r in json.loads(OUT_PATH.read_text()):
            results[r["slug"]] = r

    by_repo: dict[str, list] = defaultdict(list)
    for s in samples:
        by_repo[s["clone_dir"]].append(s)

    total = len(samples)
    done  = 0
    tmp_dir = Path(tempfile.mkdtemp(prefix="clangsa_"))

    print(f"Processing {total} slugs across {len(by_repo)} repos")
    print(f"Auto-build  : {'yes (cmake/configure per repo)' if args.build else 'no (use pre-built repos or run sa_build_repos.py first)'}")
    print(f"Mode 2 (CTU): {'available' if ctu_available else 'SKIPPED (install clang-tools-14)'}")
    print()

    try:
        # ── Mode 1 ──────────────────────────────────────────────────────────
        print("=== Mode 1: file-level ===")
        for clone_dir, repo_samples in sorted(by_repo.items()):
            todo = [s for s in repo_samples
                    if not (args.resume and s["slug"] in results
                            and results[s["slug"]].get("mode1") is not None)]
            if not todo:
                done += len(repo_samples)
                continue

            for s in todo:
                done += 1
                print(f"  [{done}/{total}] {s['slug']}  ({s['function_name']})")
                r = run_mode1(s, tmp_dir, auto_build=args.build)
                # Preserve existing mode2 result only when resuming (not a full rerun)
                if args.resume and s["slug"] in results:
                    r["mode2"] = results[s["slug"]].get("mode2")
                results[s["slug"]] = r
                m1 = r.get("mode1") or {}
                status = ("HIT_FN"   if m1.get("hit_in_function") else
                          "HIT_FILE" if m1.get("hit_in_target_file") else
                          "MISS"     if m1.get("hit_in_function") is False else
                          f"ERR:{r.get('error','')[:50]}")
                print(f"    → mode1={status}")
                OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
                OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))

        # ── Mode 2 (CTU) on mode-1 misses ───────────────────────────────────
        if not args.skip_ctu and ctu_available:
            misses = [s for s in samples
                      if results.get(s["slug"], {}).get("mode1", {}) and
                      not results[s["slug"]]["mode1"].get("hit_in_function") and
                      not results[s["slug"]].get("mode2")]

            print(f"\n=== Mode 2 (CTU): {len(misses)} mode-1 misses ===")

            # Group misses by repo, build CTU index once per repo
            misses_by_repo: dict[str, list] = defaultdict(list)
            for s in misses:
                misses_by_repo[s["clone_dir"]].append(s)

            for clone_dir, repo_samples in sorted(misses_by_repo.items()):
                repo_path = Path(clone_dir)
                repo_key  = repo_path.name
                ctu_dir   = CTU_CACHE / repo_key
                ctu_dir.mkdir(parents=True, exist_ok=True)

                # Build CTU index once per repo
                ext_map = ctu_dir / "externalDefMap.txt"
                if not ext_map.exists():
                    print(f"  [ctu-index] building for {repo_key} ...")
                    target_file = repo_path / repo_samples[0]["vuln_file_path"]
                    _lang       = "c++" if target_file.suffix in (".cpp", ".cc", ".cxx") else "c"
                    inc_flags   = get_include_flags(repo_path, target_file, lang=_lang)
                    # Convert -I flag list back to dir list for CTU index builder
                    inc_dirs = [inc_flags[i+1] for i in range(0, len(inc_flags)-1, 2)
                                if inc_flags[i] == "-I"]
                    ok = build_ctu_index(repo_path, ctu_dir, inc_dirs)
                    print(f"  [ctu-index] {'ok' if ok else 'failed'} → {ext_map}")
                    if not ok:
                        for s in repo_samples:
                            results[s["slug"]]["mode2"] = {"hit_in_function": None,
                                                            "error": "ctu_index_build_failed"}
                        continue
                else:
                    print(f"  [ctu-index] reusing cached {ext_map}")

                for s in repo_samples:
                    print(f"  [ctu] {s['slug']}  ({s['function_name']})")
                    m2 = run_mode2(s, ctu_dir, tmp_dir)
                    results[s["slug"]]["mode2"] = m2
                    status = ("HIT_FN"   if m2.get("hit_in_function") else
                              "HIT_FILE" if m2.get("hit_in_target_file") else
                              "MISS"     if m2.get("hit_in_function") is False else
                              f"ERR:{m2.get('error','')[:50]}")
                    print(f"    → mode2={status}")
                    OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # ── Summary ──────────────────────────────────────────────────────────────
    n         = len(results)
    m1_fn     = sum(1 for v in results.values() if (v.get("mode1") or {}).get("hit_in_function") is True)
    m1_file   = sum(1 for v in results.values() if (v.get("mode1") or {}).get("hit_in_target_file") is True)
    m1_err    = sum(1 for v in results.values() if v.get("error"))
    m2_ran    = sum(1 for v in results.values() if v.get("mode2"))
    m2_fn     = sum(1 for v in results.values() if (v.get("mode2") or {}).get("hit_in_function") is True)
    m2_file   = sum(1 for v in results.values() if (v.get("mode2") or {}).get("hit_in_target_file") is True)
    any_fn    = sum(1 for v in results.values()
                    if (v.get("mode1") or {}).get("hit_in_function") is True
                    or (v.get("mode2") or {}).get("hit_in_function") is True)

    print(f"""
=== Clang SA 14 (N={n}) ===
  Mode 1 (file-level):
    hit in target function : {m1_fn}/{n}  ({100*m1_fn/n:.1f}%)
    hit in target file     : {m1_file}/{n}  ({100*m1_file/n:.1f}%)
    errors / timeouts      : {m1_err}
  Mode 2 (CTU, ran on {m2_ran} mode-1 misses):
    hit in target function : {m2_fn}/{m2_ran if m2_ran else 1}  ({100*m2_fn/max(m2_ran,1):.1f}%)
    hit in target file     : {m2_file}/{m2_ran if m2_ran else 1}  ({100*m2_file/max(m2_ran,1):.1f}%)
  Combined (mode1 OR mode2):
    hit in target function : {any_fn}/{n}  ({100*any_fn/n:.1f}%)
Results → {OUT_PATH}""")


if __name__ == "__main__":
    main()
