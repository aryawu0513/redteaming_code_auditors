"""
build_manifest.py — Per-site build/test manifest loader.

Each benchmark site directory may contain a build.yaml describing how to
compile, test, and statically analyze solutions for that site. The attacker
helper tools (submit.py, run_test.py, static_check.py) consult this manifest
when present, and fall back to the original hardcoded behavior when absent —
so existing leetcode-style problems keep working unchanged.

Schema (all fields optional except `compile.command`):

    language:   "c" | "cpp" | ...        # used for analyzer language selection
    file_ext:   ".c" | ".cc" | ...       # default extension for solution files
    compile:
      command:  str                       # template with {solution} {test_driver} {binary}
      vars:                               # site-defined values, substituted last
        key: value                        # value may be a string or `!sh "<cmd>"`
    test:
      kind:     "exit_code" | "stdin_stdout"
      driver:   str                       # for exit_code: path to test source file
      timeout:  int                       # seconds
      cases:                              # for stdin_stdout
        - input:  path
          output: path
    static_analysis:
      include_flags: [str, ...]           # extra flags for ClangSA / cppcheck / CodeQL

Substitutions, in resolution order:
  ${VAR} or ${VAR:-default}  — environment variable (with optional default)
  ${SITE_DIR}                — directory containing build.yaml
  !sh "cmd"                  — yaml tag that runs cmd in a shell and uses its stdout
  {vars-key}                 — value from `compile.vars` (resolved recursively)
  {solution}/{test_driver}/{binary}  — runtime substitutions made by the caller
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# YAML !sh tag — captures shell-command stdout into the value
# ---------------------------------------------------------------------------

class _Shell(str):
    """Marker subclass: string is a shell command to run lazily."""


def _sh_constructor(loader, node):
    return _Shell(loader.construct_scalar(node))


yaml.SafeLoader.add_constructor("!sh", _sh_constructor)


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_VAR_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _substitute_env(s: str, extra_env: dict[str, str]) -> str:
    """Resolve ${VAR} and ${VAR:-default}, with extra_env overlaid on os.environ."""
    env = {**os.environ, **extra_env}

    def repl(m: re.Match) -> str:
        name = m.group(1)
        default = m.group(2) or ""
        return env.get(name, default)

    return _ENV_RE.sub(repl, s)


def _run_shell(cmd: str) -> str:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def _resolve_value(value: Any, env: dict[str, str], cache: dict[str, str]) -> str:
    """Resolve a single vars value: env subst → !sh → strip whitespace."""
    if isinstance(value, _Shell):
        cmd = _substitute_env(str(value), env)
        return _run_shell(cmd)
    if isinstance(value, str):
        return _substitute_env(value, env)
    return str(value)


def _resolve_vars(vars_block: dict[str, Any], env: dict[str, str]) -> dict[str, str]:
    """Resolve compile.vars. Each entry may reference {other_key} or ${ENV}.
    Resolution iterates until fixpoint (handles forward refs within the block)."""
    resolved: dict[str, str] = {}
    pending = dict(vars_block or {})
    progress = True
    while pending and progress:
        progress = False
        for k in list(pending):
            v = pending[k]
            try:
                # First env-substitute (with resolved values overlaid)
                merged = {**env, **resolved}
                if isinstance(v, _Shell):
                    cmd = _substitute_env(str(v), merged)
                    # Expand {key} refs whose values are known; leave {} (xargs) and
                    # forward refs alone. Run the shell command only when no known
                    # {key} placeholder is still unresolved.
                    cmd = _VAR_RE.sub(lambda m: resolved.get(m.group(1), m.group(0)), cmd)
                    unresolved = [m.group(1) for m in _VAR_RE.finditer(cmd)
                                  if m.group(1) in pending]
                    if not unresolved:
                        resolved[k] = _run_shell(cmd)
                        del pending[k]
                        progress = True
                else:
                    s = _substitute_env(str(v), merged)
                    s = _VAR_RE.sub(lambda m: resolved.get(m.group(1), m.group(0)), s)
                    unresolved = [m.group(1) for m in _VAR_RE.finditer(s)
                                  if m.group(1) in pending]
                    if not unresolved:
                        resolved[k] = s
                        del pending[k]
                        progress = True
            except Exception:
                pass
    # Any leftover: best-effort flatten (so caller sees the unresolved {})
    for k, v in pending.items():
        resolved[k] = str(v)
    return resolved


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class BuildManifest:
    """A loaded build.yaml. Use the classmethod to load from a site directory."""

    def __init__(self, site_dir: Path, raw: dict):
        self.site_dir = site_dir.resolve()
        self.raw = raw or {}

        env = {"SITE_DIR": str(self.site_dir)}
        self._env = env

        compile_block = self.raw.get("compile") or {}
        self._compile_template = compile_block.get("command", "")
        self._vars = _resolve_vars(compile_block.get("vars") or {}, env)

    # ------ Identity ------
    @property
    def language(self) -> str:
        return self.raw.get("language", "cpp")

    @property
    def file_ext(self) -> str:
        return self.raw.get("file_ext", ".cc" if self.language == "cpp" else ".c")

    # ------ Test config ------
    @property
    def test_kind(self) -> str:
        return ((self.raw.get("test") or {}).get("kind")) or "exit_code"

    @property
    def test_timeout(self) -> int:
        return int((self.raw.get("test") or {}).get("timeout", 30))

    @property
    def test_driver(self) -> str | None:
        d = (self.raw.get("test") or {}).get("driver")
        if not d:
            return None
        return _substitute_env(d, self._env)

    @property
    def test_cases(self) -> list[tuple[str, str]]:
        """For stdin_stdout: returns [(input_path, output_path), ...]."""
        cases = (self.raw.get("test") or {}).get("cases") or []
        out = []
        for c in cases:
            inp = _substitute_env(str(c.get("input", "")), self._env)
            outp = _substitute_env(str(c.get("output", "")), self._env)
            out.append((inp, outp))
        return out

    # ------ Static analysis ------
    @property
    def static_include_flags(self) -> list[str]:
        flags = (self.raw.get("static_analysis") or {}).get("include_flags") or []
        return [_substitute_env(str(f), self._env) for f in flags]

    @property
    def static_build_compiler(self) -> str:
        """Compiler the static analyzer uses for DB-build invocations.
        Defaults to clang for C and g++ for C++ (clang lacks conda libstdc++ paths)."""
        v = (self.raw.get("static_analysis") or {}).get("build_compiler")
        if v:
            return _substitute_env(str(v), self._env)
        return "clang" if self.language == "c" else "g++"

    # ------ Compile ------
    def compile_command(
        self,
        solution: str,
        binary: str,
        test_driver: str | None = None,
    ) -> str:
        """Substitute {solution}, {test_driver}, {binary}, and all vars.
        Returns a shell command string ready to run."""
        merged = {**self._env, **self._vars}
        cmd = _substitute_env(self._compile_template, merged)

        # Substitute {vars-key} first (longest matches), then runtime placeholders
        cmd = _VAR_RE.sub(lambda m: self._vars.get(m.group(1), m.group(0)), cmd)
        cmd = cmd.replace("{solution}", solution)
        cmd = cmd.replace("{binary}",   binary)
        cmd = cmd.replace("{test_driver}", test_driver or self.test_driver or "")

        # Normalize multi-line YAML > block to single line
        return " ".join(cmd.split())

    # ------ Loader ------
    @classmethod
    def from_dir(cls, site_dir: Path) -> "BuildManifest | None":
        """Load build.yaml from site_dir if it exists; else return None."""
        path = site_dir / "build.yaml"
        if not path.is_file():
            return None
        with open(path) as f:
            raw = yaml.load(f, Loader=yaml.SafeLoader)
        return cls(site_dir, raw)
