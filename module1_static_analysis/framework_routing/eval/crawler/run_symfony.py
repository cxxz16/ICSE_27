from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

BACSCAN_ROOT = Path("/home/user/research/AC/BACScan")
os.environ.setdefault("BACSCAN_CMS", "symfony-demo")
sys.path.insert(0, str(BACSCAN_ROOT))

from config.config import vuln_scan_config

vuln_scan_config.ES_ADDR = os.environ.get("ES_ADDR", "http://localhost:9200")
vuln_scan_config.ES_USER = None
vuln_scan_config.ES_PASS = None

import vuln_detection.utils.es_util as _es_util
from elasticsearch import Elasticsearch as _ESClient


def _patched_es_init(self):
    try:
        self.client = _ESClient(vuln_scan_config.ES_ADDR, verify_certs=False)
        self.client.info()
    except Exception as e:
        logging.warning(f"[run_symfony] ES unreachable ({e}); using stub")
        self.client = _NoOpES()


class _NoOpES:
    def __getattr__(self, name):
        def _noop(*a, **kw):
            return {}
        return _noop


_es_util.ElasticsearchClient.__init__ = _patched_es_init
_es_util.ElasticsearchClient.get_client = lambda self: self.client

from config.crawl_config import crawler_config
from crawler.models.nav_graph import NavigationGraph
from crawler.task import Task
from crawler.utils import init_logging

(BACSCAN_ROOT / "vuln_detection" / "input" / "nav_graphs" / "symfony-demo").mkdir(parents=True, exist_ok=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8089/en")
    ap.add_argument("--role", default="visitor")
    ap.add_argument("--storage-state", default=None)
    ap.add_argument("--layer", type=int, default=2)
    ap.add_argument("--max-pages", type=int, default=30)
    ap.add_argument("--tabs", type=int, default=4)
    ap.add_argument("--log-level", choices=["debug", "info"], default="info")
    args = ap.parse_args()

    init_logging(args.log_level)
    if args.storage_state and Path(args.storage_state).exists():
        crawler_config.COOKIE_PATH = args.storage_state
        print(f"[*] Storage state: {args.storage_state}")
    crawler_config.LAYER = args.layer
    crawler_config.MAX_PAGE_NUM = args.tabs
    crawler_config.HEADLESS_MODE = True
    crawler_config.FILTER_MODE = "smart"

    import crawler.task as _task_mod
    OriginalTask = _task_mod.Task

    class CappedTask(OriginalTask):
        async def run(self):
            from crawler.models.request import Request as _Req
            if isinstance(self._init_url, list):
                for u in self._init_url:
                    await self.add_to_urlpool(_Req(u.strip(), base_url=u.strip()))
            else:
                for u in self._init_url.split(","):
                    await self.add_to_urlpool(_Req(u, base_url=u))
            if self._crawler is None:
                logging.info("[*] Start crawling...")
                from crawler.crawl.crawl import Crawler as _Crawler
                self._crawler = await _Crawler.create()
                self._browser_handler = self._crawler.browser_handler

            schedule_task = asyncio.create_task(self._task_schedule())
            t0 = time.time()
            while True:
                await asyncio.sleep(1)
                if (self._url_pool.empty() and self.finish_count == self.task_count) \
                        or self.finish_count > args.max_pages:
                    for task in self._tasks:
                        task.cancel()
                    schedule_task.cancel()
                    logging.info(f"[+] Crawling stopped after {self.finish_count} pages "
                                 f"({time.time()-t0:.1f}s)")
                    break
            await self._crawler.browser_handler.safe_close_browser()

    navigraph = NavigationGraph(role=args.role)
    print(f"[*] Target  : {args.url}")
    print(f"[*] Layer={args.layer} max_pages={args.max_pages} tabs={args.tabs}")
    asyncio.run(CappedTask(args.url, navigraph).run())
    print("[*] Crawl done.")


if __name__ == "__main__":
    main()
