Fix defects in tools/llm.py (full current file below). Output the COMPLETE corrected file.

Defects to fix:
1. Reasoning model: every request body must include "chat_template_kwargs": {"enable_thinking": false} unless env LLM_THINKING=1. Also read max_tokens from env LLM_MAX_TOKENS (default 8000).
2. extract_code_block must return the text between the FIRST line starting with three backticks and the LAST line that is exactly three backticks (the generated code may itself contain fences). If no fence, return whole text. If the reply content is None or empty, treat it as failure: ledger ok=false, print an error mentioning finish_reason, exit 1.
3. Record finish_reason in each ledger line, and record reasoning tokens if the response reports them (field reasoning_tokens inside usage completion_tokens_details, else 0).
4. IMPORTANT: your source code must NOT contain a literal run of three backtick characters, because the reply is parsed by fences. Build it as FENCE = chr(96) * 3.
5. Keep everything else, including --report, working. Standard library only.

CURRENT FILE:
#!/usr/bin/env python3
"""
tools/llm.py — single-file CLI for OpenAI-compatible chat completions.

Usage:
  python3 tools/llm.py --task TASK_ID [--system-file F] [--prompt-file F] [--out F] [--attempt N]
  python3 tools/llm.py --report
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import request, error


def load_env():
    """Load LLM_URL, LLM_MODEL, LLM_API_KEY from environment or LLM_ENV_FILE."""
    env_file = os.environ.get("LLM_ENV_FILE")
    if env_file:
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip()
                        if key not in os.environ:
                            os.environ[key] = value
        except Exception as e:
            print(f"Warning: could not read LLM_ENV_FILE: {e}", file=sys.stderr)

    return {
        "url": os.environ.get("LLM_URL"),
        "model": os.environ.get("LLM_MODEL"),
        "api_key": os.environ.get("LLM_API_KEY"),
    }


def extract_code_block(text):
    """Extract the first fenced code block, or return the whole text if none."""
    pattern = r"```(?:\w+)?\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1)
    return text


def append_ledger(entry):
    """Append a JSON line to ledger/ledger.jsonl relative to repo root."""
    repo_root = Path(__file__).resolve().parent.parent
    ledger_path = repo_root / "ledger" / "ledger.jsonl"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_prompt(prompt_file):
    """Read prompt from file or stdin."""
    if prompt_file:
        with open(prompt_file, "r", encoding="utf-8") as f:
            return f.read()
    return sys.stdin.read()


def read_system(system_file):
    """Read system prompt from file."""
    if system_file:
        with open(system_file, "r", encoding="utf-8") as f:
            return f.read()
    return None


def do_chat(env, system, prompt, task, attempt, out_path):
    """Send chat completion request and handle response."""
    url = env["url"]
    model = env["model"]
    api_key = env["api_key"]

    if not url or not model or not api_key:
        print("Error: LLM_URL, LLM_MODEL, LLM_API_KEY must be set", file=sys.stderr)
        append_ledger({
            "ts": datetime.now(timezone.utc).isoformat(),
            "task": task,
            "attempt": attempt,
            "model": model or "",
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "seconds": 0,
            "out": str(out_path) if out_path else None,
            "ok": False,
        })
        sys.exit(1)

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 8000,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    start_time = time.time()
    try:
        req = request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        resp = request.urlopen(req, timeout=900)
        resp_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"Error: {e}", file=sys.stderr)
        append_ledger({
            "ts": datetime.now(timezone.utc).isoformat(),
            "task": task,
            "attempt": attempt,
            "model": model,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "seconds": round(elapsed, 3),
            "out": str(out_path) if out_path else None,
            "ok": False,
        })
        sys.exit(1)

    elapsed = time.time() - start_time

    try:
        content = resp_data["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        print("Error: unexpected response structure", file=sys.stderr)
        append_ledger({
            "ts": datetime.now(timezone.utc).isoformat(),
            "task": task,
            "attempt": attempt,
            "model": model,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "seconds": round(elapsed, 3),
            "out": str(out_path) if out_path else None,
            "ok": False,
        })
        sys.exit(1)

    usage = resp_data.get("usage", {})
    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)
    total_tokens = usage.get("total_tokens", 0)

    if out_path:
        code = extract_code_block(content)
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(code, encoding="utf-8")
    else:
        print(content)

    append_ledger({
        "ts": datetime.now(timezone.utc).isoformat(),
        "task": task,
        "attempt": attempt,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "seconds": round(elapsed, 3),
        "out": str(out_path) if out_path else None,
        "ok": True,
    })


def do_report():
    """Print totals from the ledger."""
    repo_root = Path(__file__).resolve().parent.parent
    ledger_path = repo_root / "ledger" / "ledger.jsonl"

    if not ledger_path.exists():
        print("No ledger found.", file=sys.stderr)
        sys.exit(1)

    entries = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    calls = len(entries)
    retries = sum(1 for e in entries if e.get("attempt", 1) > 1)
    prompt_tokens = sum(e.get("prompt_tokens", 0) for e in entries)
    completion_tokens = sum(e.get("completion_tokens", 0) for e in entries)
    total_tokens = sum(e.get("total_tokens", 0) for e in entries)

    print(f"Total calls: {calls}")
    print(f"Retries: {retries}")
    print(f"Prompt tokens: {prompt_tokens}")
    print(f"Completion tokens: {completion_tokens}")
    print(f"Total tokens: {total_tokens}")

    per_task = {}
    for e in entries:
        task = e.get("task", "")
        if task not in per_task:
            per_task[task] = {"calls": 0, "retries": 0, "prompt": 0, "completion": 0, "total": 0}
        per_task[task]["calls"] += 1
        if e.get("attempt", 1) > 1:
            per_task[task]["retries"] += 1
        per_task[task]["prompt"] += e.get("prompt_tokens", 0)
        per_task[task]["completion"] += e.get("completion_tokens", 0)
        per_task[task]["total"] += e.get("total_tokens", 0)

    print("\nPer task:")
    for task, stats in sorted(per_task.items()):
        print(f"  {task}: calls={stats['calls']}, retries={stats['retries']}, "
              f"prompt={stats['prompt']}, completion={stats['completion']}, total={stats['total']}")


def main():
    parser = argparse.ArgumentParser(description="OpenAI-compatible chat completion CLI")
    parser.add_argument("--task", help="Task ID for ledger")
    parser.add_argument("--system-file", help="Path to system prompt file")
    parser.add_argument("--prompt-file", help="Path to user prompt file (or stdin)")
    parser.add_argument("--out", help="Output file path")
    parser.add_argument("--attempt", type=int, default=1, help="Attempt number")
    parser.add_argument("--report", action="store_true", help="Print ledger totals")

    args = parser.parse_args()

    if args.report:
        do_report()
        return

    if not args.task:
        parser.error("--task is required unless --report is used")

    env = load_env()
    system = read_system(args.system_file)
    prompt = read_prompt(args.prompt_file)

    do_chat(env, system, prompt, args.task, args.attempt, args.out)


if __name__ == "__main__":
    main()
