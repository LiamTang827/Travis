# Travis Web — 设计与构建计划

> 2026-06-16 锁定。结构沿用恢复的 React 前端（交互：输入→分析→仪表盘），
> 视觉采用 make_pretty_v2 notebook 浅色研究报告美学（用户确认）。

## 视觉 token（来自 experiments/notebooks/make_pretty_v2.py）

```
墨色字     #172033        地址 monospace  #445064
卡片底     #fff           淡底/输入框      #fbfcfe
解释框底   #f8fafc        表头底          #f2f5f9
边框       #d8dee9        次级边框        #edf0f5
muted 文字 #647084 / #3d4758
强调（按钮/链接） #4f46e5（靛蓝）
等级色     MEDIUM #d97706 · HIGH #dc2626 · CRITICAL #7f1d1d · LOW #647084
方向色     IN #0e7a4d · OUT #b91c1c · token #6b21a8
警告       左边框 #d97706 / 底 #fff7ed / 字 #7c2d12
机制语义色 混币器 #d97706 · 黑名单 #dc2626 · 透明桥 #1f8a5b
圆角 8px（卡片）/ 999px（pill 徽章）
字体 -apple-system sans；地址用 ui-monospace
```

## 架构

```
[Vercel · React/Vite 前端]  →  [Railway · FastAPI 后端]  →  [MongoDB Atlas]
```

## 现状（从 git 2f0ff13 恢复）

- `web/frontend/`：Vite + React + TS。App/AddressInput/RiskDashboard/TraceGraph(React Flow)/EvidenceList/api/types。
- `web/backend/main.py`：FastAPI，**已实现异步任务**（POST /analyze→task_id，GET /task/{id} 轮询）。

## 现代化清单（恢复后要改的）

**后端 web/backend/main.py**
- [ ] import：`from aml_analyzer import` → `from cripto_analyst.aml_analyzer import`；删 sys.path hack（已是 pip 包）
- [ ] 校验 `analyzer.analyze(...)` 签名 / `time_window_days` 属性仍存在
- [ ] 接 MongoDB 缓存层（transactions / sync_state / reports 三 collection + TTL）
- [ ] 任务状态从内存 `_tasks` 改存 MongoDB（Railway 重启不丢）
- [ ] CORS：localhost:5173 → 加 Vercel 域名（用环境变量）
- [ ] 环境变量：ETHERSCAN_API_KEY、MONGODB_URI

**前端 web/frontend/**
- [ ] `src/App.css`：换成上面的 notebook 浅色 token（当前是暗色 slate）
- [ ] `src/types.ts`：补新字段 risk_basis / score_breakdown / usdt_blacklist_time / ofac_* / per_asset
- [ ] `src/api.ts`：BASE 写死 localhost:8000 → 改 `import.meta.env.VITE_API_URL`
- [ ] RiskDashboard：展示 risk_basis（list_based / flow_based），名单命中不显示"污染比例"

**部署（用户浏览器已连，最后一步）**
- [ ] 后端 → Railway（连 GitHub、填 env、部署）
- [ ] 前端 → Vercel（连 GitHub、填 VITE_API_URL、部署）

## 慢查询策略（已在后端异步基础上）
- demo：预缓存几个演示地址 → 瞬间出结果
- 真用户：异步任务 + 轮询（后端已具备）+ MongoDB 缓存增量
