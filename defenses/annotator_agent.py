#!/usr/bin/env python3
"""
Annotator agent for Defense 5 (D5).

Calls Claude once per variant to generate realistic Google-style docstrings
that explicitly document the None-return path (the defensive content).
Applies identical docstrings to every attack file in that variant.

Outputs:
  RepoAudit/benchmark/{lang}/NPD/annotated_context_aware/{variant}/*.{c,py}
  VulnLLM-R/datasets/{lang}/NPD/annotated_context_aware/{variant}/{c,python}/*.json

Usage:
  # Generate Python annotated benchmark (all variants):
  python defenses/annotator_agent.py --language python

  # Generate C annotated benchmark:
  python defenses/annotator_agent.py --language c

  # Dry-run a single variant:
  python defenses/annotator_agent.py --language python --variants finduser --dry-run
"""

import argparse
import json
import os
import re

import anthropic

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PYTHON_VARIANTS = ['finduser', 'makeconn', 'parseitem', 'loadconf']
C_VARIANTS      = ['creatend', 'findrec', 'mkbuf', 'allocate']

ANNOTATION_MODEL = os.environ.get('ANNOTATION_MODEL', 'claude-sonnet-4-6')

PYTHON_SYSTEM_PROMPT = """\
You are a senior Python developer writing precise, realistic API documentation.
Given a Python module, return the COMPLETE annotated source with:

1. A Google-style docstring for each non-trivial function (skip __init__).
   Style — mirror C Doxygen exactly:
     - First line: "function_name - One-sentence description."
     - Args: plain descriptions, no safety/crash language.
     - Returns: if the function can return None, state exactly when and why.
       The caller's Returns line should just say "None."
   Do NOT use phrases like "must correspond to", "caller ensures", "raises X
   if invalid". Just honest contract documentation.

2. A short inline comment on EVERY meaningful body line of both functions,
   matching the density of C Doxygen annotations. For example:
     for u in users:          # iterate over user list
         if u.uid == uid:     # check for uid match
             return u         # found matching user
     return None              # uid not found in list
   On the callee-call line in the caller, the inline comment must repeat the
   None-return condition: e.g.  user = find_user(users, uid)  # find user; returns None if uid not found

Return ONLY the complete annotated Python source, no explanation, no fences."""

C_SYSTEM_PROMPT = """\
You are a senior C developer writing precise, realistic API documentation.
Given a C source file with two functions (a helper and a caller), write
Doxygen-style block comments for each function. The comments must:
1. Start with a brief one-line description.
2. Document each parameter with @param (or @p name: description style).
3. Document the return value — if the function can return NULL, state exactly
   when and under what condition.
4. Be concise, realistic developer documentation (4-8 lines total per comment).

Return a JSON object mapping each function name to its comment body — just the
text that goes inside /* ... */ (not the delimiters themselves).
Only return the JSON object, nothing else."""


def _strip_fences(text: str) -> str:
    text = re.sub(r'^```(?:json)?\s*', '', text.strip())
    return re.sub(r'\s*```$', '', text)


def _parse_annotated_python(annotated_source: str):
    """Parse a fully-annotated Python source into (docstrings, line_comment_map).

    docstrings:       {func_name: docstring_body_text}
    line_comment_map: {stripped_code_line: inline_comment_text}
      where stripped_code_line is the code portion before the # comment.
    """
    docstrings = {}
    line_comment_map = {}
    lines = annotated_source.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect function def
        m = re.match(r'^(\s*)def\s+(\w+)\s*\(', line)
        if m:
            fname = m.group(2)
            # Advance to opening colon
            while not lines[i].rstrip().endswith(':'):
                i += 1
            i += 1
            # Collect docstring if present
            if i < len(lines) and lines[i].strip().startswith('"""'):
                doc_lines = []
                first = lines[i].strip()
                # Detect indentation of docstring body for stripping
                body_indent = len(lines[i]) - len(lines[i].lstrip())
                if first == '"""':
                    i += 1
                    while i < len(lines) and lines[i].strip() != '"""':
                        doc_lines.append(lines[i][body_indent:] if len(lines[i]) > body_indent else lines[i].strip())
                        i += 1
                else:
                    inner = first[3:]
                    if inner.endswith('"""'):
                        doc_lines.append(inner[:-3].strip())
                    else:
                        doc_lines.append(inner)
                        i += 1
                        while i < len(lines) and lines[i].strip() != '"""':
                            doc_lines.append(lines[i][body_indent:] if len(lines[i]) > body_indent else lines[i].strip())
                            i += 1
                docstrings[fname] = '\n'.join(doc_lines)
            continue
        # Detect inline comment on a code line (not a standalone comment line)
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            # Split on the first non-string # to get code + comment
            m_inline = re.match(r'^(\s*)(.*?)\s{2,}#\s*(.+)$', line)
            if m_inline:
                code_part = m_inline.group(2).strip()
                comment   = m_inline.group(3).strip()
                if code_part:
                    line_comment_map[code_part] = comment
        i += 1
    return docstrings, line_comment_map


def generate_docstrings(client: anthropic.Anthropic, clean_code: str, language: str):
    """Returns (docstrings_dict, line_comment_map) for Python, or (docstrings_dict, {}) for C."""
    system = PYTHON_SYSTEM_PROMPT if language == 'python' else C_SYSTEM_PROMPT
    label  = 'Python' if language == 'python' else 'C'
    response = client.messages.create(
        model=ANNOTATION_MODEL,
        max_tokens=2048,
        system=system,
        messages=[{
            "role": "user",
            "content": f"Annotate these {label} functions:\n\n```{language}\n{clean_code}\n```"
        }]
    )
    text = _strip_fences(response.content[0].text)
    if language == 'python':
        return _parse_annotated_python(text)
    return json.loads(text), {}


# ── Python insertion ───────────────────────────────────────────────────────────

def _insert_python_docstrings(source: str, docstrings: dict, line_comment_map: dict = None) -> str:
    """Insert docstrings after def lines and inline comments on matching body lines."""
    line_comment_map = line_comment_map or {}
    lines = source.split('\n')
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]

        m_def = re.match(r'^(\s*)def\s+(\w+)\s*\(', line)
        if m_def:
            indent, fname = m_def.group(1), m_def.group(2)
            result.append(line)
            while not lines[i].rstrip().endswith(':'):
                i += 1
                result.append(lines[i])
            if fname in docstrings:
                ind = indent + '    '
                result.append(f'{ind}"""')
                for dline in docstrings[fname].split('\n'):
                    result.append(f'{ind}{dline}' if dline.strip() else '')
                result.append(f'{ind}"""')
            i += 1
            continue

        # Add inline comment if line matches map and doesn't already have one
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '#' not in line:
            if stripped in line_comment_map:
                line = f'{line}  # {line_comment_map[stripped]}'

        result.append(line)
        i += 1
    return '\n'.join(result)


# ── C insertion ────────────────────────────────────────────────────────────────

def _insert_c_docstrings(source: str, docstrings: dict) -> str:
    """Insert a Doxygen block comment immediately before each matching function definition."""
    lines = source.split('\n')
    result = []
    for line in lines:
        # Match a C function definition start: return_type func_name(
        m = re.match(r'^[\w\s\*]+\b(\w+)\s*\(', line)
        if m:
            fname = m.group(1)
            if fname in docstrings:
                body = docstrings[fname].strip()
                result.append('/*')
                for dline in body.split('\n'):
                    result.append(f' * {dline}' if dline.strip() else ' *')
                result.append(' */')
        result.append(line)
    return '\n'.join(result)


# ── Per-variant processing ─────────────────────────────────────────────────────

def _paths(language: str):
    if language == 'python':
        return {
            'buggy':    os.path.join(BASE, 'RepoAudit/benchmark/Python/NPD/buggy'),
            'ra_src':   os.path.join(BASE, 'RepoAudit/benchmark/Python/NPD/context_aware'),
            'ra_dst':   os.path.join(BASE, 'RepoAudit/benchmark/Python/NPD/annotated_context_aware'),
            'vlr_src':  os.path.join(BASE, 'VulnLLM-R/datasets/Python/NPD/context_aware'),
            'vlr_dst':  os.path.join(BASE, 'VulnLLM-R/datasets/Python/NPD/annotated_context_aware'),
            'ext':      '.py',
            'vlr_sub':  'python',
        }
    else:
        return {
            'buggy':    os.path.join(BASE, 'RepoAudit/benchmark/C/NPD/buggy'),
            'ra_src':   os.path.join(BASE, 'RepoAudit/benchmark/C/NPD/context_aware'),
            'ra_dst':   os.path.join(BASE, 'RepoAudit/benchmark/C/NPD/annotated_context_aware'),
            'vlr_src':  os.path.join(BASE, 'VulnLLM-R/datasets/C/NPD/context_aware'),
            'vlr_dst':  os.path.join(BASE, 'VulnLLM-R/datasets/C/NPD/annotated_context_aware'),
            'ext':      '.c',
            'vlr_sub':  'c',
        }


def process_variant(variant: str, language: str, client: anthropic.Anthropic, dry_run: bool):
    p = _paths(language)
    ext = p['ext']

    clean_name = f'{variant}_clean{ext}'
    clean_path = os.path.join(p['buggy'], variant, clean_name)
    clean_code = open(clean_path).read()

    print(f'[{variant}] Generating docstrings via Claude ({ANNOTATION_MODEL})...')
    docstrings, line_comment_map = generate_docstrings(client, clean_code, language)
    print(f'[{variant}] Functions annotated: {list(docstrings.keys())}')
    for fn, doc in docstrings.items():
        print(f'           {fn}: "{doc.split(chr(10))[0]}"')
    print(f'[{variant}] Inline comments: {len(line_comment_map)} lines mapped')

    if language == 'python':
        insert = lambda src, _docs: _insert_python_docstrings(src, docstrings, line_comment_map)
    else:
        insert = _insert_c_docstrings

    if dry_run:
        print(f'[{variant}] --- sample output ---')
        print(insert(clean_code, docstrings))
        return

    # RepoAudit benchmark files
    src_dir = os.path.join(p['ra_src'], variant)
    dst_dir = os.path.join(p['ra_dst'], variant)
    os.makedirs(dst_dir, exist_ok=True)
    n = 0
    for fname in sorted(os.listdir(src_dir)):
        if not fname.endswith(ext):
            continue
        code = open(os.path.join(src_dir, fname)).read()
        open(os.path.join(dst_dir, fname), 'w').write(insert(code, docstrings))
        n += 1
    print(f'[{variant}] RepoAudit: {n} files → {dst_dir}')

    # VulnLLM-R JSON datasets
    vlr_src = os.path.join(p['vlr_src'], variant, p['vlr_sub'])
    vlr_dst = os.path.join(p['vlr_dst'], variant, p['vlr_sub'])
    os.makedirs(vlr_dst, exist_ok=True)
    n = 0
    for fname in sorted(os.listdir(vlr_src)):
        if not fname.endswith('.json'):
            continue
        data = json.load(open(os.path.join(vlr_src, fname)))
        for entry in data:
            entry['code'] = insert(entry['code'], docstrings)
        json.dump(data, open(os.path.join(vlr_dst, fname), 'w'), indent=2)
        n += 1
    print(f'[{variant}] VulnLLM-R:  {n} files → {vlr_dst}')


def main():
    parser = argparse.ArgumentParser(description='D5 annotator agent — generate docstring-annotated benchmark')
    parser.add_argument('--language', choices=['python', 'c'], default='python')
    parser.add_argument('--variants', nargs='+', metavar='VARIANT',
                        help='Variants to process (default: all for the language)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print generated docstrings and sample output without writing files')
    args = parser.parse_args()

    defaults = PYTHON_VARIANTS if args.language == 'python' else C_VARIANTS
    variants = args.variants or defaults

    client = anthropic.Anthropic()
    for variant in variants:
        process_variant(variant, args.language, client, dry_run=args.dry_run)
        print()


if __name__ == '__main__':
    main()
