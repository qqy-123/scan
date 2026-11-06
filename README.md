# scan · 网站指纹识别平台

批量 URL 存活探测 + 指纹识别 + 网页截图的资产梳理平台。

- **项目制**：扫描前新建项目，URL 归属项目；支持对项目内存活目标二次扫描
- **存活探测**：httpx 高并发探测（默认 50），无协议 URL 自动尝试 HTTPS → HTTP
- **指纹识别**：Wappalyzer 风格规则引擎 — headers / cookies / meta / html /
  scriptSrc / JS 全局变量 / DOM / favicon mmh3 / 主动探测路径，
  置信度加权（≥100 确认，40-99 疑似），implies/excludes 推断，版本提取
- **截图**：Playwright 持久化 Chromium，截图同时采集渲染后 DOM/JS 信号二次匹配
- **输入**：粘贴 URL 或上传 xlsx（自动提取全部 URL）
- **前端**：Vue3 + Ant Design Vue，遵循 T/CIDADS 00032—2026 SaaS 界面规范

## 快速开始

```bash
# 后端
pip install -r requirements.txt
playwright install chromium

# 前端（开发期）
cd frontend && npm install && npm run dev

# 生产：构建后由后端直接托管
cd frontend && npm run build && cd ..
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

打开 http://localhost:8000 （开发模式下前端在 http://localhost:5173）

## 使用流程

1. **新建项目**
2. **导入目标**：粘贴 URL（每行一个）或上传 xlsx/txt
3. **发起扫描**：全量扫描（默认）或仅存活目标（二次扫描）
   - 主动探测开关（默认开）：对规则中的特征路径发请求二次确认
   - 截图开关（默认开）：并发 4
4. **查看结果**：目标表实时状态 / 扫描记录展开详情 / 单目标证据页

## 指纹规则

`rules/*.json`，每个文件一类。规则格式（Wappalyzer 超集）：

```json
{
  "name": "WordPress",
  "category": "CMS",
  "meta": { "generator": ["WordPress\\s*([0-9.]*)\\;version:\\1"] },
  "html": ["wp-content/", "wp-includes/\\;confidence:80"],
  "headers": { "x-pingback": ".*" },
  "cookies": { "^wp-": ".*" },
  "scriptSrc": ["wp-includes/js/"],
  "js": { "window.GLOBAL_VAR": "pattern" },
  "dom": { "css selector": { "text": ["pattern"] } },
  "favicon": ["-1006320717"],
  "probe": { "/wp-login.php": ["wp-submit"] },
  "implies": ["PHP"],
  "excludes": []
}
```

- pattern 后缀 `\;confidence:N` 权重、`\;version:\1` 版本提取
- `js`/`dom` 由 Playwright 在渲染后页面上采集
- `favicon` 为 mmh3 hash（`mmh3.hash(base64.encodebytes(content))`）
- `probe` 主动请求该路径，body 命中即确认

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | /api/projects | 新建项目 |
| GET | /api/projects/{id} | 项目详情（目标+最新结果+轮次） |
| POST | /api/projects/{id}/targets | 粘贴 URL 导入 `{urls: "..."}` |
| POST | /api/projects/{id}/targets/upload | xlsx/txt 文件导入 |
| POST | /api/projects/{id}/scans | 发起扫描 `{scope, active_probe, screenshot, concurrency}` |
| GET | /api/scans/{id} | 轮次状态+全部结果 |
| GET | /api/scans/{id}/stats | 指纹分布统计 |
| GET | /api/results/{id} | 单目标详情（含证据） |
