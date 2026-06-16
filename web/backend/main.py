"""Travis Web API — FastAPI backend.

包住 cripto_analyst 引擎，提供异步分析任务 + 地址结果缓存。
配置全部走环境变量（部署到 Railway 用）：
  ETHERSCAN_API_KEY   已由引擎的 .env / 环境读取
  MONGODB_URI         可选；不设则缓存与任务退回内存（本地开发即可跑）
  CORS_ORIGINS        逗号分隔的前端域名，默认 http://localhost:5173
  CACHE_TTL_SECONDS   结果缓存存活秒数，默认 3600
"""

import os
import uuid
import dataclasses
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# 引擎现在是已安装的包（pip install -e .），不再需要 sys.path hack。
import cripto_analyst.analyzer as eng
from cripto_analyst.analyzer import AMLAnalyzer
from cripto_analyst.chains import EVMClient, TronScanClient, EVM_CHAIN_REGISTRY
from cripto_analyst.bridge_tracer import BridgeTracer
from cripto_analyst.utils import load_blacklist
from cripto_analyst.config import BLACKLIST_CSV

# ── 环境配置 ─────────────────────────────────────────────────
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
MONGODB_URI = os.getenv("MONGODB_URI", "")
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))

# ── 可选 MongoDB 缓存（没连就退回内存）─────────────────────────
_reports_col = None
if MONGODB_URI:
    try:
        from pymongo import MongoClient
        _mongo = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        _mongo.admin.command("ping")
        _reports_col = _mongo.get_database("travis").get_collection("reports")
        # TTL 索引：结果文档到期自动删除，强制重算（解决缓存过期）
        _reports_col.create_index("generated_at", expireAfterSeconds=CACHE_TTL_SECONDS)
        print("[cache] MongoDB 已连接，结果缓存启用")
    except Exception as e:  # noqa: BLE001
        print(f"[cache] MongoDB 不可用，退回内存缓存：{e}")
        _reports_col = None

_mem_cache: dict = {}   # 内存回退：cache_key -> report dict
_tasks: dict = {}       # 任务状态（内存；生产可同样迁 MongoDB）

# ── 应用 + 引擎 ──────────────────────────────────────────────
app = FastAPI(title="Travis API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

_blacklist = load_blacklist(BLACKLIST_CSV)
_evm_clients = {name: EVMClient(cfg) for name, cfg in EVM_CHAIN_REGISTRY.items()}
_analyzer = AMLAnalyzer(_blacklist, _evm_clients, TronScanClient(), BridgeTracer())


def _cache_key(address: str, chain: Optional[str]) -> str:
    return f"{address.lower().strip()}:{chain or 'auto'}"


def _cache_get(key: str) -> Optional[dict]:
    if _reports_col is not None:
        doc = _reports_col.find_one({"_id": key})
        return doc.get("report") if doc else None
    return _mem_cache.get(key)


def _cache_put(key: str, report: dict) -> None:
    if _reports_col is not None:
        _reports_col.replace_one(
            {"_id": key},
            {"_id": key, "report": report, "generated_at": datetime.now(timezone.utc)},
            upsert=True,
        )
    else:
        _mem_cache[key] = report


# ── 请求 / 响应模型 ──────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    address: str
    chain: Optional[str] = None
    chains: Optional[list[str]] = None
    no_hop2: bool = False
    days: int = 0


class TaskStatus(BaseModel):
    task_id: str
    status: str          # pending / running / done / error / cached
    result: Optional[dict] = None
    error: Optional[str] = None


# ── 后台分析任务 ─────────────────────────────────────────────
def _run_analysis(task_id: str, req: AnalyzeRequest):
    _tasks[task_id]["status"] = "running"
    try:
        orig_hop2 = eng.HOP2_ENABLED
        if req.no_hop2:
            eng.HOP2_ENABLED = False
        if req.days > 0:
            _analyzer.time_window_days = req.days

        report = _analyzer.analyze(address=req.address, chain=req.chain, chains=req.chains)

        eng.HOP2_ENABLED = orig_hop2
        _analyzer.time_window_days = 0

        result = dataclasses.asdict(report)
        _cache_put(_cache_key(req.address, req.chain), result)
        _tasks[task_id]["status"] = "done"
        _tasks[task_id]["result"] = result
    except Exception as e:  # noqa: BLE001
        eng.HOP2_ENABLED = True
        _analyzer.time_window_days = 0
        _tasks[task_id]["status"] = "error"
        _tasks[task_id]["error"] = str(e)


# ── 路由 ─────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"name": "Travis", "desc": "TRAceable Verification Intelligence System",
            "cache": "mongodb" if _reports_col is not None else "memory"}


@app.get("/chains")
def get_chains():
    return [
        {"id": name, "name": cfg.name, "native_token": cfg.native_token,
         "explorer": cfg.explorer_url}
        for name, cfg in EVM_CHAIN_REGISTRY.items()
    ] + [{"id": "tron", "name": "Tron", "native_token": "TRX", "explorer": "https://tronscan.org"}]


@app.get("/blacklist/{address}")
def check_blacklist(address: str):
    addr = address.lower().strip()
    if addr in _blacklist:
        return {"blacklisted": True, **_blacklist[addr]}
    return {"blacklisted": False}


@app.post("/analyze", response_model=TaskStatus)
def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    # 命中缓存直接返回（秒回）
    cached = _cache_get(_cache_key(req.address, req.chain))
    if cached is not None:
        return TaskStatus(task_id="cached", status="cached", result=cached)

    task_id = str(uuid.uuid4())
    _tasks[task_id] = {"status": "pending", "result": None, "error": None}
    background_tasks.add_task(_run_analysis, task_id, req)
    return TaskStatus(task_id=task_id, status="pending")


@app.get("/task/{task_id}", response_model=TaskStatus)
def get_task(task_id: str):
    if task_id not in _tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    t = _tasks[task_id]
    return TaskStatus(task_id=task_id, status=t["status"],
                      result=t.get("result"), error=t.get("error"))
