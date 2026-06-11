# ============================================================
# db.py
# 本地数据库
#   1. SQLite — 存储分析结果（analyzed_addresses）
#   2. JSON   — 黑名单缓存（blacklist_cache.json）
#
# 用法：
#   from db import DB
#   db = DB()
#   db.save(report)
#   db.get("0x1234...")
#   db.list_all()
# ============================================================

import sqlite3, json, os
from datetime import datetime

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "..", "chain_sentinel.db")
BL_PATH    = os.path.join(BASE_DIR, "..", "blacklist_cache.json")


# ============================================================
# SQLite — 分析结果
# ============================================================

class DB:
    def __init__(self, db_path=DB_PATH):
        self.path = db_path
        self._init()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _init(self):
        """建表"""
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    address     TEXT PRIMARY KEY,
                    risk_level  TEXT,
                    risk_score  INTEGER,
                    taint_rate  REAL,
                    triggered   TEXT,   -- JSON array
                    tokens      TEXT,   -- JSON object
                    graph_nodes INTEGER,
                    graph_edges INTEGER,
                    analyzed_at TEXT,
                    hops        INTEGER,
                    full_report TEXT    -- full JSON (compressed)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS watchlist (
                    address     TEXT PRIMARY KEY,
                    label       TEXT,
                    added_at    TEXT,
                    notes       TEXT
                )
            """)

    def save(self, report: dict):
        """保存一次分析结果"""
        risk = report.get("risk", {})
        meta = report.get("meta", {})
        gs   = report.get("graph", {}).get("summary", {})

        addr = (meta.get("address") or risk.get("address", "")).lower()
        if not addr:
            return

        with self._conn() as c:
            c.execute("""
                INSERT OR REPLACE INTO analyses
                  (address, risk_level, risk_score, taint_rate,
                   triggered, tokens, graph_nodes, graph_edges,
                   analyzed_at, hops, full_report)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                addr,
                risk.get("risk_level", "LOW"),
                risk.get("risk_score", 0),
                risk.get("taint_rate", 0.0),
                json.dumps(risk.get("triggered", []),  ensure_ascii=False),
                json.dumps(report.get("tokens", {}),   ensure_ascii=False),
                gs.get("total_nodes", 0),
                gs.get("total_edges", 0),
                meta.get("analyzed_at", datetime.now().isoformat()),
                meta.get("hops", 2),
                json.dumps(report, ensure_ascii=False, default=str),
            ))
        print(f"  [DB] 已保存 {addr[:16]}... → {risk.get('risk_level')}")

    def get(self, address: str) -> dict | None:
        """读取一个地址的最新分析结果"""
        with self._conn() as c:
            row = c.execute(
                "SELECT full_report FROM analyses WHERE address=?",
                (address.lower(),)
            ).fetchone()
        if row:
            return json.loads(row[0])
        return None

    def get_summary(self, address: str) -> dict | None:
        """只读摘要（不读全量 JSON，快）"""
        with self._conn() as c:
            row = c.execute("""
                SELECT address, risk_level, risk_score, taint_rate,
                       triggered, tokens, graph_nodes, graph_edges,
                       analyzed_at, hops
                FROM analyses WHERE address=?
            """, (address.lower(),)).fetchone()
        if not row:
            return None
        return {
            "address":     row[0],
            "risk_level":  row[1],
            "risk_score":  row[2],
            "taint_rate":  row[3],
            "triggered":   json.loads(row[4]),
            "tokens":      json.loads(row[5]),
            "graph_nodes": row[6],
            "graph_edges": row[7],
            "analyzed_at": row[8],
            "hops":        row[9],
        }

    def list_all(self) -> list[dict]:
        """列出所有已分析地址（摘要）"""
        with self._conn() as c:
            rows = c.execute("""
                SELECT address, risk_level, risk_score, taint_rate,
                       triggered, graph_nodes, analyzed_at
                FROM analyses
                ORDER BY analyzed_at DESC
            """).fetchall()
        return [
            {
                "address":     r[0],
                "risk_level":  r[1],
                "risk_score":  r[2],
                "taint_rate":  r[3],
                "triggered":   json.loads(r[4]),
                "graph_nodes": r[5],
                "analyzed_at": r[6],
            }
            for r in rows
        ]

    def delete(self, address: str):
        with self._conn() as c:
            c.execute("DELETE FROM analyses WHERE address=?", (address.lower(),))

    def exists(self, address: str) -> bool:
        with self._conn() as c:
            row = c.execute(
                "SELECT 1 FROM analyses WHERE address=?",
                (address.lower(),)
            ).fetchone()
        return bool(row)

    # ── Watchlist ──────────────────────────────────────────
    def add_watchlist(self, address: str, label: str = "", notes: str = ""):
        with self._conn() as c:
            c.execute("""
                INSERT OR REPLACE INTO watchlist (address, label, added_at, notes)
                VALUES (?,?,?,?)
            """, (address.lower(), label, datetime.now().isoformat(), notes))

    def get_watchlist(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT address, label, added_at, notes FROM watchlist ORDER BY added_at DESC"
            ).fetchall()
        return [{"address": r[0], "label": r[1], "added_at": r[2], "notes": r[3]} for r in rows]

    def stats(self) -> dict:
        """数据库统计"""
        with self._conn() as c:
            total    = c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            critical = c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='CRITICAL'").fetchone()[0]
            high     = c.execute("SELECT COUNT(*) FROM analyses WHERE risk_level='HIGH'").fetchone()[0]
            watch    = c.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
        return {
            "total":    total,
            "critical": critical,
            "high":     high,
            "medium":   total - critical - high,
            "watchlist": watch,
        }


# ============================================================
# JSON — 黑名单缓存
# ============================================================

class BlacklistCache:
    def __init__(self, path=BL_PATH):
        self.path = path
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"addresses": {}, "updated_at": None}

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def add(self, address: str, label: str, source: str = "manual"):
        self._data["addresses"][address.lower()] = {
            "label":      label,
            "source":     source,
            "added_at":   datetime.now().isoformat(),
        }
        self._data["updated_at"] = datetime.now().isoformat()
        self._save()

    def remove(self, address: str):
        self._data["addresses"].pop(address.lower(), None)
        self._save()

    def check(self, address: str) -> dict | None:
        return self._data["addresses"].get(address.lower())

    def all(self) -> dict:
        return self._data["addresses"]

    def count(self) -> int:
        return len(self._data["addresses"])

    def export_to_config_format(self) -> dict:
        """导出为 config.py BLACKLIST 格式"""
        return {
            addr: info["label"]
            for addr, info in self._data["addresses"].items()
        }


# ============================================================
# Flask API（给前端调用）
# ============================================================

def create_api(analyze_fn):
    """
    创建 Flask API 服务
    用法：
        from db import create_api
        from analyze import analyze
        app = create_api(analyze)
        app.run(port=5001)
    """
    try:
        from flask import Flask, request, jsonify
        from flask_cors import CORS
    except ImportError:
        print("需要安装: pip install flask flask-cors")
        return None

    app  = Flask(__name__)
    CORS(app)
    db   = DB()
    blc  = BlacklistCache()

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        data    = request.json or {}
        address = data.get("address", "").strip()
        hops    = int(data.get("hops", 2))
        force   = data.get("force", False)

        if not address:
            return jsonify({"error": "address required"}), 400

        # 如果已有缓存且不强制重新分析
        if not force and db.exists(address):
            cached = db.get(address)
            cached["_cached"] = True
            return jsonify(cached)

        try:
            report = analyze_fn(address, hops=hops, save_json=False)
            db.save(report)
            return jsonify(report)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/db/list", methods=["GET"])
    def api_list():
        return jsonify(db.list_all())

    @app.route("/api/db/stats", methods=["GET"])
    def api_stats():
        return jsonify(db.stats())

    @app.route("/api/db/get/<address>", methods=["GET"])
    def api_get(address):
        report = db.get(address)
        if not report:
            return jsonify({"error": "not found"}), 404
        return jsonify(report)

    @app.route("/api/db/delete/<address>", methods=["DELETE"])
    def api_delete(address):
        db.delete(address)
        return jsonify({"ok": True})

    @app.route("/api/blacklist", methods=["GET"])
    def api_blacklist():
        return jsonify(blc.all())

    @app.route("/api/blacklist/add", methods=["POST"])
    def api_blacklist_add():
        data = request.json or {}
        blc.add(data.get("address",""), data.get("label",""), data.get("source","manual"))
        return jsonify({"ok": True, "total": blc.count()})

    @app.route("/api/watchlist", methods=["GET"])
    def api_watchlist():
        return jsonify(db.get_watchlist())

    @app.route("/api/watchlist/add", methods=["POST"])
    def api_watchlist_add():
        data = request.json or {}
        db.add_watchlist(data.get("address",""), data.get("label",""), data.get("notes",""))
        return jsonify({"ok": True})

    return app


# ============================================================
# 启动入口
# ============================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from analyze import analyze

    app = create_api(analyze)
    if app:
        print("\n ChainSentinel API 启动中...")
        print(" 地址: http://localhost:5001")
        print(" 前端直接调用 /api/analyze\n")
        app.run(port=5001, debug=False)
