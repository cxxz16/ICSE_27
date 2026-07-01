
import os
import random
import time
from threading import Lock
from typing import List, Optional, Sequence

import openai

BASE_URL  = os.environ.get("VIPER_LLM_BASE_URL", "https://api.openai.com/v1")
DEFAULT_MODEL = os.environ.get("VIPER_LLM_MODEL", "gpt-4o")
API_KEYS  = [k for k in os.environ.get("VIPER_LLM_API_KEYS", os.environ.get("OPENAI_API_KEY", "")).split(",") if k]


class _KeyPool:
    def __init__(self, keys: Sequence[str]):
        self._keys = list(keys)
        self._idx  = 0
        self._lock = Lock()

    def next(self) -> str:
        with self._lock:
            key = self._keys[self._idx]
            self._idx = (self._idx + 1) % len(self._keys)
            return key

    def snapshot(self) -> List[str]:
        return list(self._keys)


_pool = _KeyPool(API_KEYS)


def _retryable(exc: Exception) -> bool:
    if isinstance(exc, (openai.RateLimitError, openai.APITimeoutError,
                        openai.APIConnectionError, openai.PermissionDeniedError)):
        return True
    if isinstance(exc, openai.APIStatusError):
        msg = str(exc).lower()
        if any(t in msg for t in ("quota", "rate", "limit", "exhaust", "too many")):
            return True
    return False


def chat(
    prompt: str,
    model: str = DEFAULT_MODEL,
    system: str = "You are an expert in web application security and PHP source code analysis.",
    temperature: float = 0.1,
    max_attempts: int = 4,
    stage: str = "viper",
) -> dict:
    start = _pool.next()
    keys  = [start] + [k for k in _pool.snapshot() if k != start]

    last_exc = None
    call_t0 = time.perf_counter()
    for attempt in range(max_attempts):
        key = keys[attempt % len(keys)]
        try:
            client   = openai.OpenAI(api_key=key, base_url=BASE_URL, timeout=120.0)
            response = client.chat.completions.create(
                model=model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt},
                ],
            )
            content = response.choices[0].message.content or ""
            usage = {
                "prompt_tokens":     int(getattr(response.usage, "prompt_tokens",     0) or 0),
                "completion_tokens": int(getattr(response.usage, "completion_tokens", 0) or 0),
                "total_tokens":      int(getattr(response.usage, "total_tokens",      0) or 0),
            }
            elapsed = time.perf_counter() - call_t0
            _log(stage, model, usage, prompt, content, elapsed)
            return {"content": content, "usage": usage, "model": model, "stage": stage,
                    "elapsed_sec": elapsed}
        except Exception as exc:
            last_exc = exc
            print(f"[llm] attempt {attempt+1}/{max_attempts} key=...{key[-6:]} err={exc!s:.120}")
            if not _retryable(exc):
                try:
                    from common.metrics import collector as _mc
                    _mc.add_event("llm_error", stage=stage, model=model,
                                  err=str(exc)[:200],
                                  elapsed_sec=time.perf_counter() - call_t0)
                except Exception:
                    pass
                raise
            time.sleep(0.5 + random.random() * 0.5)

    try:
        from common.metrics import collector as _mc
        _mc.add_event("llm_error", stage=stage, model=model,
                      err=f"all_attempts_failed: {last_exc!s:.200}",
                      elapsed_sec=time.perf_counter() - call_t0)
    except Exception:
        pass
    raise last_exc


_GPT4O_IN_USD_PER_1K  = float(os.environ.get("VIPER_LLM_PRICE_IN",  "0.005"))
_GPT4O_OUT_USD_PER_1K = float(os.environ.get("VIPER_LLM_PRICE_OUT", "0.015"))


def _log(stage: str, model: str, usage: dict, prompt: str, content: str,
         elapsed_sec: float = 0.0):
    print(
        f"[llm] stage={stage} model={model} "
        f"tokens={usage['prompt_tokens']}+{usage['completion_tokens']}"
        f"={usage['total_tokens']} ({elapsed_sec:.2f}s)"
    )
    cost = (usage["prompt_tokens"]     / 1000.0 * _GPT4O_IN_USD_PER_1K
            + usage["completion_tokens"] / 1000.0 * _GPT4O_OUT_USD_PER_1K)

    try:
        from common.metrics import collector as _mc
        _mc.add_event("llm_call",
                      stage=stage, model=model,
                      prompt_tokens=usage["prompt_tokens"],
                      completion_tokens=usage["completion_tokens"],
                      total_tokens=usage["total_tokens"],
                      cost_usd=round(cost, 6),
                      elapsed_sec=round(elapsed_sec, 3))
        _mc.add_time(f"llm/{stage}", elapsed_sec)
        _mc.inc_count(f"llm/{stage}/calls")
        _mc.inc_count(f"llm/{stage}/prompt_tokens", usage["prompt_tokens"])
        _mc.inc_count(f"llm/{stage}/completion_tokens", usage["completion_tokens"])
    except Exception:
        pass

    log_path = os.environ.get("VIPER_LLM_LOG")
    if not log_path:
        return
    import json as _json, time as _time
    record = {
        "ts": _time.time(),
        "stage": stage,
        "model": model,
        "prompt_tokens": usage["prompt_tokens"],
        "completion_tokens": usage["completion_tokens"],
        "total_tokens": usage["total_tokens"],
        "cost_usd": round(cost, 6),
        "elapsed_sec": round(elapsed_sec, 3),
        "prompt": prompt,
        "response": content,
    }
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(_json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as e:
        print(f"[llm] WARN: failed to append to VIPER_LLM_LOG={log_path}: {e}")
