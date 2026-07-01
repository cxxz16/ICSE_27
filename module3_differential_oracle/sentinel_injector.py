
from __future__ import annotations

import shutil
import uuid as _uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SentinelInjector:
    sink_file: str
    sink_line: int
    uuid: str = ""
    backup_path: str = ""

    def __post_init__(self):
        if not self.uuid:
            self.uuid = "VIPER_SENTINEL_" + _uuid.uuid4().hex

    def __enter__(self) -> "SentinelInjector":
        src = Path(self.sink_file)
        if not src.exists():
            raise FileNotFoundError(self.sink_file)
        self.backup_path = str(src) + ".viper_bak"
        shutil.copy2(src, self.backup_path)

        lines = src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        if self.sink_line < 1 or self.sink_line > len(lines):
            raise ValueError(
                f"sink_line {self.sink_line} out of range (file has {len(lines)} lines)"
            )

        injection_line = self.sink_line
        for probe in range(self.sink_line - 1, 0, -1):
            prev = lines[probe - 1].rstrip()
            stripped = prev
            for marker in ("//", "#"):
                if marker in stripped:
                    stripped = stripped.split(marker, 1)[0].rstrip()
            if stripped.endswith((";", "{", "}", "*/", ":")) or not stripped:
                injection_line = probe + 1
                break

        target = lines[injection_line - 1] if injection_line <= len(lines) else lines[-1]
        indent = target[: len(target) - len(target.lstrip())]
        sentinel_stmt = (
            f'{indent}@header("X-VIPER-Sentinel: {self.uuid}"); '
            f'echo "{self.uuid}";  /* VIPER sentinel */\n'
        )
        lines.insert(injection_line - 1, sentinel_stmt)
        src.write_text("".join(lines), encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.backup_path and Path(self.backup_path).exists():
            shutil.move(self.backup_path, self.sink_file)
        return False

    def was_seen(self, response_text: str) -> bool:
        return self.uuid in (response_text or "")


def main():
    import argparse, sys
    ap = argparse.ArgumentParser(description="Inject a VIPER sentinel echo before a sink line.")
    ap.add_argument("--sink-file", required=True)
    ap.add_argument("--sink-line", type=int, required=True)
    ap.add_argument("--show", action="store_true",
                    help="Inject, print the patched file region, hold for ENTER, then restore.")
    args = ap.parse_args()
    with SentinelInjector(args.sink_file, args.sink_line) as sent:
        print(f"injected sentinel uuid: {sent.uuid}")
        if args.show:
            lines = Path(args.sink_file).read_text(encoding="utf-8").splitlines()
            for i in range(max(1, args.sink_line - 3),
                            min(len(lines), args.sink_line + 3) + 1):
                print(f"  {i:>4}: {lines[i-1]}")
            input("press ENTER to restore...")
        else:
            print(f"backup: {sent.backup_path}")
            print("pre-restoring; pass --show to hold the patched file in place.")


if __name__ == "__main__":
    main()
