
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_VIPER_ROOT = Path(__file__).resolve().parent
_PRED_ROOT = _VIPER_ROOT.parent
_SCRIPTS = _PRED_ROOT / "scripts"


def _ensure_scripts_on_path() -> None:
    s = str(_SCRIPTS)
    if s not in sys.path:
        sys.path.insert(0, s)


@dataclass(frozen=True)
class SyntheticEdge:
    site_id: int
    callee_id: int
    site_loc: str
    callee_name: str


_DISPATCH_LEAF_TYPES = (
    "AST_CALL", "AST_NEW", "AST_METHOD_CALL", "AST_STATIC_CALL"
)


class RuntimeFeedbackEngine:

    def __init__(
        self,
        *,
        working_dir: Path,
        instr_info_host: Path,
        target_spec: str,
        container: str,
        project_root_host: str,
        project_root_in_container: str = "/app/sqli_chain_demo",
    ):
        self.working_dir = Path(working_dir)
        self.instr_info_host = Path(instr_info_host)
        self.target_spec = target_spec
        self.container = container
        self.project_root_host = project_root_host.rstrip("/")
        self.project_root_in_container = project_root_in_container.rstrip("/")

        self._nodes_cache: Optional[dict[int, dict]] = None
        self._callee_idx_cache: Optional[dict[str, int]] = None
        self._known_edge_keys: Optional[set[tuple[int, int]]] = None
        self._funcs_by_file: Optional[dict[str, set[int]]] = None
        self._injected: set[tuple[int, int]] = set()


    def _nodes(self) -> dict[int, dict]:
        if self._nodes_cache is None:
            from module1_static_analysis.dispatch_resolver.fig_builder import _read_nodes
            self._nodes_cache = _read_nodes(self.working_dir / "nodes.csv")
        return self._nodes_cache

    def _callee_idx(self) -> dict[str, int]:
        if self._callee_idx_cache is None:
            from module1_static_analysis.dispatch_resolver.edge_injector import _build_callee_index
            self._callee_idx_cache = _build_callee_index(self._nodes())
        return self._callee_idx_cache

    def _file_index(self) -> dict[str, set[int]]:
        if self._funcs_by_file is None:
            from module1_static_analysis.dispatch_resolver.fig_builder import build_fig
            from module1_static_analysis.dispatch_resolver.narrow import _containing_file
            fig = build_fig(self.working_dir)
            idx: dict[str, set[int]] = defaultdict(set)
            for nid, n in self._nodes().items():
                try:
                    funcid = int(n.get("funcid") or 0)
                except (ValueError, TypeError):
                    continue
                if not funcid:
                    continue
                cf = _containing_file(funcid, fig, self._nodes())
                if cf:
                    idx[os.path.basename(cf)].add(funcid)
            self._funcs_by_file = idx
        return self._funcs_by_file

    def _augmented_path(self) -> Path:
        return self.working_dir / "cpg_edges_augmented.csv"

    def _ensure_augmented_exists(self) -> None:
        aug = self._augmented_path()
        if not aug.exists():
            src = self.working_dir / "cpg_edges.csv"
            shutil.copyfile(src, aug)
        if self._known_edge_keys is None:
            keys: set[tuple[int, int]] = set()
            with aug.open("r", encoding="utf-8") as f:
                next(f, None)
                for raw in f:
                    parts = raw.rstrip("\n").split("\t")
                    if len(parts) < 3 or parts[2] != "CALLS":
                        continue
                    try:
                        keys.add((int(parts[0]), int(parts[1])))
                    except ValueError:
                        continue
            self._known_edge_keys = keys


    def _container_to_host(self, container_path: str) -> str:
        cont = self.project_root_in_container
        if container_path.startswith(cont + "/"):
            rel = container_path[len(cont) + 1:]
            return f"{self.project_root_host}/{rel}"
        return container_path

    def _find_site_id(self, host_file_basename: str, line: int) -> Optional[int]:
        target_funcs = self._file_index().get(host_file_basename, set())
        if not target_funcs:
            return None
        for nid, n in self._nodes().items():
            if n.get("type") not in _DISPATCH_LEAF_TYPES:
                continue
            try:
                ln = int(n.get("lineno") or 0)
                funcid = int(n.get("funcid") or 0)
            except (ValueError, TypeError):
                continue
            if ln == line and funcid in target_funcs:
                return nid
        return None

    def _resolve_callee(self, callee_name: str) -> Optional[int]:
        idx = self._callee_idx()
        tgt = idx.get(callee_name)
        if tgt is None and "::" in callee_name:
            tgt = idx.get(callee_name.rsplit("::", 1)[1])
        return tgt


    def harvest_new_edges(
        self, runtime_discoveries: list[dict]
    ) -> list[SyntheticEdge]:
        self._ensure_augmented_exists()
        assert self._known_edge_keys is not None
        out: list[SyntheticEdge] = []
        for d in runtime_discoveries:
            container_file = d.get("file", "") or ""
            host_file = self._container_to_host(container_file)
            basename = os.path.basename(host_file)
            try:
                ln = int(d.get("line", 0) or 0)
            except (ValueError, TypeError):
                continue
            if not basename or ln <= 0:
                continue
            site_id = self._find_site_id(basename, ln)
            if site_id is None:
                continue
            for callee_name in d.get("callees", []):
                callee_id = self._resolve_callee(callee_name)
                if callee_id is None:
                    continue
                key = (site_id, callee_id)
                if key in self._known_edge_keys or key in self._injected:
                    continue
                self._injected.add(key)
                self._known_edge_keys.add(key)
                out.append(SyntheticEdge(
                    site_id=site_id, callee_id=callee_id,
                    site_loc=f"{basename}:{ln}",
                    callee_name=callee_name,
                ))
        return out

    def _append_edges(self, edges: list[SyntheticEdge]) -> None:
        with self._augmented_path().open("a", encoding="utf-8") as f:
            for e in edges:
                f.write(f"{e.site_id}\t{e.callee_id}\tCALLS\t\n")


    def _refresh_distance(self) -> bool:
        _ensure_scripts_on_path()
        os.environ["VIPER_USE_AUGMENTED"] = "1"
        os.environ["VIPER_DENSE_DIST"] = "1"
        from csv_manager import CSVManager
        from batch_main import precompute_shared, process_one_target

        csv_manager = CSVManager(str(self.working_dir))
        nodes_df, rels_df, cpg_edges_df, _ = csv_manager.read_csvs()
        sw, sa, cfg_e, cg_e = precompute_shared(cpg_edges_df, rels_df)
        with tempfile.TemporaryDirectory(prefix="viper_p6_") as tmpd:
            res = process_one_target(
                self.target_spec, nodes_df, rels_df, cpg_edges_df,
                sw, sa, cfg_e, cg_e,
                tmpd, csv_manager,
            )
            if res.get("status") != "OK":
                return False
            new_instr = Path(tmpd) / "instr-info.csv"
            if not new_instr.exists():
                return False
            shutil.copyfile(new_instr, self.instr_info_host)
        return True


    def _install_to_container(self) -> bool:
        text = self.instr_info_host.read_text(encoding="utf-8", errors="replace")
        rewritten = text.replace(self.project_root_host,
                                  self.project_root_in_container)
        tmp = Path("/tmp/viper_instr_info_for_container.csv")
        tmp.write_text(rewritten)
        cp = subprocess.run(
            ["docker", "cp", str(tmp),
             f"{self.container}:/tmp/instr-info.csv"],
            capture_output=True, text=True,
        )
        if cp.returncode != 0:
            return False
        subprocess.run(
            ["docker", "exec", self.container, "bash", "-c",
             "supervisorctl restart apache2 >/dev/null 2>&1"],
            capture_output=True, text=True,
        )
        return True


    def maybe_refresh(
        self, runtime_discoveries: list[dict], *, verbose: bool = True,
        dry_run: bool = False
    ) -> bool:
        if dry_run:
            if verbose:
                print(f"  [P6] dry-run: {len(runtime_discoveries)} "
                      f"runtime_discovery event(s) collected; SKIPPING "
                      f"harvest + augmented CSV + distance refresh + "
                      f"container sync (skip cost: minutes on large CPGs)")
            return False
        edges = self.harvest_new_edges(runtime_discoveries)
        if not edges:
            if verbose and runtime_discoveries:
                print(f"  [P6] {len(runtime_discoveries)} discovery event(s) "
                      f"— all (site, callee) edges already present, no refresh")
            return False
        if verbose:
            for e in edges:
                print(f"  [P6] new synthetic CALLS edge: {e.site_loc} → "
                      f"{e.callee_name} (site_id={e.site_id} → callee_id={e.callee_id})")
        self._append_edges(edges)
        if verbose:
            print(f"  [P6] re-running distance_calculator on augmented graph "
                  f"(dense=1, target={self.target_spec}) ...")
        if not self._refresh_distance():
            if verbose:
                print("  [P6] ✗ distance refresh FAILED")
            return False
        if verbose:
            print(f"  [P6] installing refreshed instr-info.csv → "
                  f"{self.container}:/tmp/instr-info.csv and restarting apache2")
        if not self._install_to_container():
            if verbose:
                print("  [P6] ✗ container install FAILED")
            return False
        if verbose:
            print(f"  [P6] ✓ closed loop complete; {len(edges)} new edge(s) "
                  f"now visible to next iter's distance signal")
        return True
