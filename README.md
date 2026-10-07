# ⚡ OmniAgent Studio
> **Autonomous Web Intelligence & Analytics Canvas with Human-in-the-Loop**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Architecture](https://img.shields.io/badge/Architecture-Monorepo-emerald)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20CDP-cyan)
![React Flow](https://img.shields.io/badge/Frontend-React%20Flow%20%7C%20ECharts-pink)
![OmniAgent Studio Canvas](./qa-desktop.png)
OmniAgent Studio là nền tảng điều phối Agent trực quan trên Infinite Canvas. Hệ thống giải quyết triệt để bài toán CAPTCHA và Cloudflare nhờ cơ chế **Human Takeover** thời gian thực qua giao thức Chrome DevTools Protocol (CDP).

---

## 🏗️ Kiến trúc hệ thống

```text
[User Browser]
      │  (WebSocket / Screencast & Input Relay)
      ▼
[FastAPI Backend: apps/api]
      │  (CDP Session / Page.startScreencast)
      ▼
[Chromium Sandbox: infra/sandbox-browser] ──(Extracted Data)──► [Analyst LLM] ──► [ECharts Canvas]
