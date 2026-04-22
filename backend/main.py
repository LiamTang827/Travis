import sys
import uuid
import asyncio
import dataclasses
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# 把项目根目录加到 sys.path，这样才能 import aml_analyzer
sys.path.insert(0, str(Path(__file__).parent.parent))

from aml_analyzer import (
    AMLAnalyzer, EVMClient, TronScanClient, BridgeTracer,
    EVM_CHAIN_REGISTRY, load_blacklist, BLACKLIST_CSV,
)

app = FastAPI(title="Travis API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite 默认端口
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 全局初始化 ───────────────────────────────────────────────
_blacklist = load_blacklist(BLACKLIST_CSV)
_evm_clients = {name: EVMClient(cfg) for name, cfg in EVM_CHAIN_REGISTRY.items()}
_tronscan = TronScanClient()
_tracer = BridgeTracer()
_analyzer = AMLAnalyzer(_blacklist, _evm_clients, _tronscan, _tracer)
_executor = ThreadPoolExecutor(max_workers=4)

# ── 任务状态存储（内存，生产环境换 Redis）───────────────────
_tasks: dict = {}


# ── 请求 / 响应模型 ──────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    address: str
    chain: Optional[str] = None
    chains: Optional[list[str]] = None
    no_hop2: bool = False
    days: int = 0


class TaskStatus(BaseModel):
    task_id: str
    status: str          # pending / running / done / error
    progress: str = ""
    result: Optional[dict] = None
    error: Optional[str] = None


# ── 后台分析任务 ─────────────────────────────────────────────
def _run_analysis(task_id: str, req: AnalyzeRequest):
    import aml_analyzer as eng
    _tasks[task_id]["status"] = "running"
    try:
        # 临时控制全局开关
        orig_hop2 = eng.HOP2_ENABLED
        if req.no_hop2:
            eng.HOP2_ENABLED = False
        if req.days > 0:
            _analyzer.time_window_days = req.days

        report = _analyzer.analyze(
            address=req.address,
            chain=req.chain,
            chains=req.chains,
        )

        eng.HOP2_ENABLED = orig_hop2
        _analyzer.time_window_days = 0

        _tasks[task_id]["status"] = "done"
        _tasks[task_id]["result"] = dataclasses.asdict(report)
    except Exception as e:
        _tasks[task_id]["status"] = "error"
        _tasks[task_id]["error"] = str(e)


# ── 路由 ─────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"name": "Travis", "desc": "TRAceable Verification Intelligence System"}


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
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {"status": "pending", "result": None, "error": None}
    background_tasks.add_task(_run_analysis, task_id, req)
    return TaskStatus(task_id=task_id, status="pending")


@app.get("/task/{task_id}", response_model=TaskStatus)
def get_task(task_id: str):
    if task_id not in _tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    t = _tasks[task_id]
    return TaskStatus(
        task_id=task_id,
        status=t["status"],
        result=t.get("result"),
        error=t.get("error"),
    )
