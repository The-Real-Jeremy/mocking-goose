# proxy_app.py
import asyncio
import base64
import hmac
import hashlib
import os
import socket
import subprocess
import time
import tempfile
import shutil
import json
import secrets
from typing import Dict, List, Optional, Tuple

import httpx
import uvicorn
import websockets
from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

# Optional system/process metrics (psutil)
try:
    import psutil
    PSUTIL = True
    PROC = psutil.Process(os.getpid())
except Exception:
    psutil = None
    PSUTIL = False
    PROC = None

# ----------------- Config -----------------
APP_HOST = "0.0.0.0"
APP_PORT = 8000
BACKEND_HOST = "127.0.0.1"

LOCAL_REPO_DIR = os.environ.get(
    "LOCAL_MOCK_AND_ROLL_DIR",
    "/app/python/source_code/mock-and-roll",
)
UV_BIN_CANDIDATES = ["/home/app/.local/bin/uv", "uv"]

GOOSE_BIN_ENV = os.environ.get("GOOSE_BIN")
GOOSE_BIN_DIR = os.environ.get("GOOSE_BIN_DIR", "/app/python/source_code")

# Cookies
CK_HOST  = "goose_host"     # HTTP-only
CK_TOKEN = "goose_token"    # HTTP-only (PAT)
CK_SID   = "goose_sid"      # readable (not HTTP-only)
CK_SIG   = "goose_sig"      # HMAC for sid

INACTIVITY_SECS = 60 * 60  # 60 minutes

# ----------------- State -----------------
class BackendInfo:
    def __init__(self, port: int, proc: subprocess.Popen, workdir: str):
        self.port = port
        self.proc = proc
        self.workdir = workdir
        self.last_seen = time.monotonic()

backends: Dict[str, BackendInfo] = {}
lock = asyncio.Lock()

# sid -> (host, token, expires_at)
SESSIONS: Dict[str, Tuple[str, str, float]] = {}

PROCESS_START_TS = time.time()
WS_CONNECTIONS = 0

# ----------------- In-process circular debug log -----------------
_MAX_LOG = 2000
_debug_lines: List[str] = []

def _dbg(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = f"[DBG {ts}] {msg}"
    print(line)
    _debug_lines.append(line)
    if len(_debug_lines) > _MAX_LOG:
        del _debug_lines[: len(_debug_lines) // 2]

def _mask_pat(pat: Optional[str]) -> str:
    if not pat:
        return "<none>"
    if len(pat) <= 8:
        return pat[:2] + "…" + pat[-2:]
    return pat[:4] + "…" + pat[-4:]

# ----------------- HMAC secret -----------------
def _secret_path() -> str:
    cfg = os.path.join(os.path.expanduser("~"), ".config", "goose")
    os.makedirs(cfg, exist_ok=True)
    return os.path.join(cfg, "proxy_secret")

def _load_or_create_secret() -> bytes:
    p = _secret_path()
    if os.path.exists(p):
        with open(p, "rb") as f:
            data = f.read()
            if data:
                return data
    key = secrets.token_bytes(32)
    with open(p, "wb") as f:
        f.write(key)
    _dbg("Created new HMAC secret at ~/.config/goose/proxy_secret")
    return key

HMAC_KEY = _load_or_create_secret()

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _sign_sid(sid: str) -> str:
    mac = hmac.new(HMAC_KEY, sid.encode("utf-8"), hashlib.sha256).digest()
    return _b64u(mac[:16])

def _verify_sid(sid: str, sig: str) -> bool:
    try:
        expected = _sign_sid(sid)
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False

def _new_sid() -> str:
    raw = secrets.token_bytes(16) + int(time.time()).to_bytes(4, "big")
    return _b64u(raw)

# ----------------- Helpers -----------------
def session_key(host: str, token: str) -> str:
    return f"{host}::{token}"

def has_live_session(host: str, token: str) -> bool:
    key = session_key(host, token)
    info = backends.get(key)
    return bool(info and info.proc.poll() is None)

def touch_session(host: str, token: str):
    key = session_key(host, token)
    info = backends.get(key)
    if info:
        info.last_seen = time.monotonic()

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((BACKEND_HOST, 0))
        return s.getsockname()[1]

async def wait_for_port(host: str, port: int, timeout_s: float = 30.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout_s
    while True:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except Exception:
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError(f"Timed out waiting for {host}:{port}")
            await asyncio.sleep(0.2)

def normalize_host(h: str) -> str:
    h = (h or "").strip()
    if not h:
        raise ValueError("DATABRICKS_HOST is required")
    if not (h.startswith("http://") or h.startswith("https://")):
        h = "https://" + h
    if not h.endswith("/"):
        h += "/"
    return h

def _which(cmds: List[str]) -> Optional[str]:
    for c in cmds:
        if os.path.isabs(c) and os.access(c, os.X_OK):
            return c
        found = shutil.which(c)
        if found:
            return found
    return None

def _locate_uv() -> str:
    uv = _which(UV_BIN_CANDIDATES)
    if not uv:
        raise RuntimeError("Could not find 'uv'. Ensure /home/app/.local/bin/uv or 'uv' is on PATH.")
    return uv

def _locate_goose_bin(workdir: str) -> str:
    if GOOSE_BIN_ENV:
        if (os.path.isabs(GOOSE_BIN_ENV) and os.access(GOOSE_BIN_ENV, os.X_OK)) or shutil.which(GOOSE_BIN_ENV):
            return GOOSE_BIN_ENV
        raise RuntimeError(f"GOOSE_BIN set but not executable: {GOOSE_BIN_ENV}")

    if GOOSE_BIN_DIR:
        candidate = os.path.join(GOOSE_BIN_DIR, "goose")
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate

    g = shutil.which("goose")
    if g:
        return g

    maybe = os.path.abspath(os.path.join(workdir, "..", "goose"))
    if os.path.exists(maybe) and os.access(maybe, os.X_OK):
        return maybe

    raise RuntimeError("Could not find 'goose'. Set GOOSE_BIN or GOOSE_BIN_DIR.")

def _session_copy_and_sync() -> str:
    if not os.path.isdir(LOCAL_REPO_DIR):
        raise RuntimeError(f"Local repo not found: {LOCAL_REPO_DIR}")

    workdir = tempfile.mkdtemp(prefix="mock-and-roll-")
    try:
        shutil.rmtree(workdir, ignore_errors=True)
        ignore = shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache",
            ".ruff_cache", ".idea", ".vscode"
        )
        shutil.copytree(LOCAL_REPO_DIR, workdir, ignore=ignore)

        uv = _locate_uv()

        subprocess.check_call([uv, "python", "pin", "3.13"], cwd=workdir)

        env = os.environ.copy()
        env.setdefault("UV_PYTHON", "3.13")
        env.setdefault("PYO3_USE_ABI3_FORWARD_COMPATIBILITY", "1")

        subprocess.check_call([uv, "sync"], cwd=workdir, env=env)
        return workdir
    except Exception as e:
        shutil.rmtree(workdir, ignore_errors=True)
        raise RuntimeError(f"Failed to prepare session copy: {e}") from e

def start_backend(host: str, token: str) -> BackendInfo:
    port = get_free_port()
    workdir = _session_copy_and_sync()

    env = os.environ.copy()
    env["DATABRICKS_HOST"] = host
    env["DATABRICKS_TOKEN"] = token
    env.pop("DATABRICKS_CLIENT_ID", None)
    env.pop("DATABRICKS_CLIENT_SECRET", None)

    goose_bin = _locate_goose_bin(workdir)
    cmd = [goose_bin, "web", "--host", BACKEND_HOST, "--port", str(port)]
    proc = subprocess.Popen(
        cmd, cwd=workdir, env=env, stdout=None, stderr=None, text=True,
    )
    _dbg(f"Started Goose backend at {BACKEND_HOST}:{port} for host={host} token={_mask_pat(token)}")
    return BackendInfo(port=port, proc=proc, workdir=workdir)

async def ensure_backend(host: str, token: str) -> BackendInfo:
    key = session_key(host, token)
    async with lock:
        info = backends.get(key)
        if info and info.proc.poll() is None:
            return info
        info = start_backend(host, token)
        backends[key] = info
    await wait_for_port(BACKEND_HOST, info.port)
    return info

def stop_backend_by_key(key: str) -> None:
    info = backends.pop(key, None)
    if not info:
        return
    if info.proc.poll() is None:
        try:
            info.proc.terminate()
            info.proc.wait(timeout=5)
        except Exception:
            try:
                info.proc.kill()
            except Exception:
                pass
    try:
        shutil.rmtree(info.workdir, ignore_errors=True)
    except Exception:
        pass
    _dbg(f"Stopped Goose backend and cleaned workdir for key={key}")

def is_hop_by_hop(h: str) -> bool:
    return h.lower() in {
        "connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade",
    }

def _system_metrics():
    if not PSUTIL:
        return {}
    vm = psutil.virtual_memory()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.0),
        "mem_percent": vm.percent,
        "mem_used_bytes": vm.used,
        "mem_total_bytes": vm.total,
    }

def _process_metrics():
    if not PROC:
        return {}
    try:
        with PROC.oneshot():
            return {
                "cpu_percent": PROC.cpu_percent(interval=0.0),
                "rss_bytes": PROC.memory_info().rss,
                "threads": PROC.num_threads(),
            }
    except Exception:
        return {}

def _goose_metrics():
    live = 0
    cpu_sum = 0.0
    rss_sum = 0
    for info in list(backends.values()):
        if info.proc.poll() is None:
            live += 1
            if PSUTIL:
                try:
                    p = psutil.Process(info.proc.pid)
                    cpu_sum += p.cpu_percent(interval=0.0)
                    rss_sum += p.memory_info().rss
                except Exception:
                    pass
    data = {"instances": live}
    if PSUTIL:
        data.update({"cpu_percent_sum": cpu_sum, "rss_bytes_sum": rss_sum})
    return data

# ----------------- App & static -----------------
app = FastAPI()

UI_STATIC_DIR = os.path.join(os.path.dirname(__file__), "ui-static")
os.makedirs(UI_STATIC_DIR, exist_ok=True)
app.mount("/ui-static", StaticFiles(directory=UI_STATIC_DIR), name="ui-static")

@app.on_event("startup")
async def _start_tasks():
    async def idle_reaper():
        while True:
            try:
                now = time.monotonic()
                for sid, (host, token, exp) in list(SESSIONS.items()):
                    if time.time() > exp:
                        _dbg(f"[reaper] expiring sid={sid} host={host} token={_mask_pat(token)}")
                        _kill_session(sid)
                for key, info in list(backends.items()):
                    if info.proc.poll() is None and (now - info.last_seen) > INACTIVITY_SECS:
                        _dbg(f"[reaper] stopping idle backend key={key}")
                        stop_backend_by_key(key)
            except Exception as e:
                _dbg(f"[reaper] exception: {e}")
            await asyncio.sleep(60)
    asyncio.create_task(idle_reaper())

@app.on_event("shutdown")
async def shutdown():
    for sid in list(SESSIONS.keys()):
        _kill_session(sid)
    for key in list(backends.keys()):
        stop_backend_by_key(key)

# ----------------- Cookie utilities -----------------
def _scheme_from_request(req: Request) -> str:
    xf_proto = req.headers.get("x-forwarded-proto")
    if xf_proto:
        return xf_proto.split(",")[0].strip().lower()
    return req.url.scheme.lower()

def _set_login_cookies(resp: Response, host: str, token: str, https: bool) -> Tuple[str, str]:
    sid = _new_sid()
    sig = _sign_sid(sid)
    expires_at = time.time() + INACTIVITY_SECS
    SESSIONS[sid] = (host, token, expires_at)

    resp.set_cookie(CK_TOKEN, token, max_age=8*60*60, httponly=True,
                    secure=https, samesite=("none" if https else "lax"), path="/")
    resp.set_cookie(CK_HOST, host,  max_age=8*60*60, httponly=True,
                    secure=https, samesite=("none" if https else "lax"), path="/")
    resp.set_cookie(CK_SID, sid, max_age=INACTIVITY_SECS, httponly=False,
                    secure=https, samesite=("none" if https else "lax"), path="/")
    resp.set_cookie(CK_SIG, sig, max_age=INACTIVITY_SECS, httponly=False,
                    secure=https, samesite=("none" if https else "lax"), path="/")

    _dbg(f"Issued session: sid={sid} https={https} host={host} token={_mask_pat(token)} samesite={'None' if https else 'Lax'} secure={https}")
    return sid, sig

def _refresh_session(resp: Optional[Response], sid: str):
    if sid not in SESSIONS:
        return
    host, token, _ = SESSIONS[sid]
    SESSIONS[sid] = (host, token, time.time() + INACTIVITY_SECS)
    if resp is not None:
        for name in (CK_SID, CK_SIG):
            val = sid if name == CK_SID else _sign_sid(sid)
            resp.set_cookie(name, val, max_age=INACTIVITY_SECS, path="/")

def _kill_session(sid: Optional[str]):
    if not sid:
        return
    info = SESSIONS.pop(sid, None)
    if not info:
        return
    host, token, _ = info
    stop_backend_by_key(session_key(host, token))
    _dbg(f"Killed session sid={sid} host={host} token={_mask_pat(token)}")

# ----------------- UI -----------------
def render_page(host_val: Optional[str], show_iframe: bool) -> str:
    host_val_safe = (host_val or "").replace('"', "&quot;")

    header_when_active = """
  <div class="header">
    <div class="header-left">
      <div class="logo-wrap">
        <img class="logo" src="/ui-static/logo.png" alt="Mocking Goose logo" />
      </div>
    </div>
    <div class="header-right">
      <p class="instructions">
        Ask your Goose for a demo with any context you might want, and mention which
        catalog and schema to make the demo in. Just make sure that the catalog you
        want to use already exists in the workspace.
      </p>
      <div class="reset-wrap">
        <a class="reset" href="/_debug" title="Open session status">Session status</a>
        <a class="reset" href="/logout" title="End this session">Reset session</a>
      </div>
    </div>
  </div>
"""

    sidepanel_right = """
  <aside class="sidepanel right" role="complementary" aria-label="Examples">
    <h3 class="sp-title">Try asking:</h3>

    <div class="sp-body">
      <section class="sample">
        <h4 class="sample-h">Scentre Group demo</h4>
        <p>
          Hi! Can you please make me a demo of the Databricks platform for
          <b>Scentre Group</b> using the schema <code>goose_scent</code> in the
          catalog <code>jeremy_goose_test</code>? From the eventual gold tables,
          I should be able to derive: average sqr footage of each space, the revenue
          per store category, and currently vacant spaces. Please include:
        </p>
        <ul class="sample-steps">
          <li>Raw data uploaded to a volume that simulates three sources
              (<b>BigQuery</b>, <b>Salesforce</b>, and a 3rd system). Limit to ≤5 raw tables.</li>
          <li>A <b>Lakeflow</b> declarative pipeline that transforms data
              <b>bronze → silver → gold</b>.</li>
          <li>A <b>Lakeview</b> dashboard with KPIs (avg sqr footage, revenue by category, vacancies).</li>
        </ul>
      </section>
    </div>

    <p class="sp-hint">Don't put your laptop to sleep or your session will end! Sessions expire after 1 hour of inactivity or if the tab looses connectivity.</p>
  </aside>
"""

    form_when_inactive = """
  <form class="card" method="POST" action="/start">
    <div class="logo-wrap">
      <img class="logo" src="/ui-static/logo.png" alt="Mocking Goose logo" />
    </div>
    <h2>Welcome to Mocking Goose!</h2>
    <p>Enter your <b>Databricks environment</b> and <b>PAT</b>. We’ll start your per-session Goose and proxy it here — the Goose UI appears below.</p>

    <div class="stack">
      <div>
        <label for="host">Databricks Host (DATABRICKS_HOST)</label>
        <input id="host" name="host" type="url"
               placeholder="https://xxxxxxxx.cloud.databricks.com/"
               value="__HOST_VAL__" required />
      </div>
      <div>
        <label for="token">Databricks Token (PAT)</label>
        <input id="token" name="token" type="password" placeholder="dapiXXXXXXXX..." required />
      </div>
    </div>

    <div class="row">
      <button type="submit" id="launch">Launch Goose</button>
      <a href="/logout" class="muted">Clear Session</a>
    </div>

    <div class="footer">
      <p class="muted">Values stored as <b>HTTP-only cookies</b> on this host. You can clear them via <a href="/logout">/logout</a>.</p>
      <p class="muted">Powered by <a href="https://github.com/zaxier/mock-and-roll">mock-and-roll</a> , <a href="https://github.com/PulkitXChadha/awesome-databricks-mcp">awesome-databricks-mcp</a> and <a href="https://block.github.io/goose/">Goose</a>. <br>Created by Jeremy Herbert, Maaz Rahman &amp; Xavier Armitage.</p>
    </div>
  </form>
"""

    iframe_html = (
        '<div class="embed-wrap">'
        '  <iframe id="goose-iframe" class="embed" src="/goose/" title="Goose"></iframe>'
        "</div>"
        if show_iframe else ""
    )

    layout_when_active = (
        header_when_active +
        '<div class="layout">'
        f'{iframe_html}'
        f'{sidepanel_right}'
        '</div>'
    )

    body_html = layout_when_active if show_iframe else form_when_inactive

    template = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Welcome to Mocking Goose!</title>
  <style>
    *,*::before,*::after { box-sizing: border-box; }
    :root { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, "Helvetica Neue", Arial; }

    body {
      display:flex; flex-direction:column; gap:16px;
      min-height:100vh; margin:0; padding:16px 16px 20px;
      background:#0b1020; color:#f6f7fb;
      align-items:center;
    }

    a { color:#ff4d4f; text-decoration:none; }
    a:hover { text-decoration:underline; color:#ff6b6b; }

    .card {
      background:#121a32; padding:24px; border-radius:16px;
      width:100%; max-width:820px; box-shadow:0 8px 30px rgba(0,0,0,.35);
    }
    .card .logo-wrap { display:flex; justify-content:center; margin-bottom:16px; }
    .logo { height:96px; width:auto; display:block; }
    .card .logo { height:192px; }

    h1,h2 { margin:0 0 12px; }
    p { opacity:.85; margin:0 0 16px; line-height:1.4; }
    label { display:block; font-size:.9rem; margin:0 0 8px; opacity:.9; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; background:#0d142b; padding:1px 6px; border-radius:8px; border:1px solid #2a345a; }
    input[type="password"], input[type="url"], input[type="text"] {
      width:100%; padding:12px 14px; border-radius:12px;
      border:1px solid #2a345a; background:#0d142b; color:#e8ecff; outline:none;
    }
    input::placeholder { color:#8ea1d1; }
    .row { display:flex; gap:10px; align-items:center; margin-top:14px; flex-wrap:wrap; }
    button {
      appearance:none; border:0; padding:12px 16px; border-radius:12px;
      background:#3a6df0; color:white; font-weight:600; cursor:pointer;
    }
    button:disabled { opacity:.6; cursor:not-allowed; }
    .muted { font-size:.85rem; opacity:.8; }
    .stack { display:grid; gap:12px; }
    .footer { margin-top:12px; }

    .header {
      width:100%; max-width:1200px;
      display:flex; align-items:center; justify-content:space-between; gap:16px;
      padding:16px; background:#121a32; border-radius:14px;
      border:1px solid #2a345a; box-shadow:0 8px 30px rgba(0,0,0,.35);
      flex-wrap:wrap;
    }
    .header-left { display:flex; align-items:center; }
    .logo-wrap { display:flex; align-items:center; gap:10px; }
    .header .logo { height:120px; }

    .header-right {
      flex:1; min-width:260px;
      display:flex; flex-direction:column; align-items:flex-end; gap:8px;
    }
    .instructions {
      margin:0; max-width:560px;
      font-size:.95rem; line-height:1.5; opacity:.95;
      text-align:justify; text-justify:inter-word; hyphens:auto;
    }
    .reset-wrap { display: flex; gap: 8px; align-self:flex-end; }
    .reset {
      color:#ff4d4f; font-weight:600; text-decoration:none; padding:6px 10px;
      border:1px solid #2a345a; border-radius:10px; background:#0d142b;
      display:inline-block;
    }
    .reset:hover { text-decoration:underline; color:#ff6b6b; }

    .layout {
      width:100%; max-width:1200px;
      display:flex; align-items:stretch; gap:16px;
    }

    .embed-wrap {
      flex:1 1 auto;
      display:flex; flex-direction:column;
      min-height:clamp(520px, 70vh, 900px);
      border-radius:16px; overflow:hidden;
      box-shadow:0 8px 40px rgba(0,0,0,.45);
      border:1px solid #2a345a; background:#0d142b;
      min-width:0;
    }
    .embed {
      width:100%;
      height:auto;
      flex:1 1 auto;
      min-height:0;
      border:0; background:#0d142b; display:block;
    }

    .sidepanel.right {
      flex:0 0 340px;
      display:flex; flex-direction:column; gap:12px;
      padding:16px;
      background:#121a32; border-radius:16px;
      border:1px solid #2a345a; box-shadow:0 8px 30px rgba(0,0,0,.35);
      min-width:260px;
    }
    .sp-title { margin:0; font-size:1.05rem; }

    .sp-body { flex:1 1 auto; display:grid; gap:12px; }
    .sample {
      background:#0f1730;
      border:1px solid #2a345a;
      border-radius:12px;
      padding:12px 14px;
    }
    .sample-h { color:#ff8a1f; margin:0 0 8px; font-size:1rem; font-weight:700; }
    .sample-steps { list-style: disc; padding-left:18px; margin:8px 0 0; display:grid; gap:6px; }

    .sp-hint {
      margin-top:auto;
      font-size:.85rem; opacity:.8;
      border-top:1px dashed #2a345a;
      padding-top:10px;
    }

    @media (max-width: 1100px) { .sidepanel.right { flex-basis:300px; } }
    @media (max-width: 980px) {
      .layout { flex-direction:column; align-items:stretch; }
      .embed-wrap, .sidepanel.right { width:100%; }
      .embed-wrap { display:block; min-height:unset; }
      .embed { height:clamp(480px, 72vh, 980px); flex:none; }
    }
  </style>
</head>
<body>

__BODY__

  <script>
    (function(){
      const IDLE_MS = 60 * 60 * 1000;
      const HB_MS   = 5 * 60 * 1000;

      let idleTimer = null;
      let hbTimer = null;
      let paused = false;

      const form = document.querySelector("form");
      const btn  = document.getElementById("launch");
      const LS_KEY = "goose_last_act";

      function nowMs(){ return Date.now(); }
      function setLast(){ try { localStorage.setItem(LS_KEY, String(nowMs())); } catch(e){} }
      function getLast(){
        try { const v = parseInt(localStorage.getItem(LS_KEY)||"0", 10); return isNaN(v)?0:v; }
        catch(e){ return 0; }
      }

      function startIdleTimer(){
        clearTimeout(idleTimer);
        idleTimer = setTimeout(()=>{
          paused = true;
          clearInterval(hbTimer);
          window.location.href = "/logout?idle=1";
        }, IDLE_MS);
      }
      function activity(){
        if (paused) return;
        setLast();
        startIdleTimer();
      }
      function startHeartbeat(){
        clearInterval(hbTimer);
        hbTimer = setInterval(async ()=>{
          if (document.hidden || paused) return;
          try { await fetch("/heartbeat", {method:"POST", credentials:"same-origin"}); }
          catch(e){}
        }, HB_MS);
      }
      function checkResumeIdle(){
        const gap = nowMs() - getLast();
        if (gap > IDLE_MS) { window.location.href = "/logout?idle=1"; return true; }
        return false;
      }

      ["pointermove","keydown","click","scroll","touchstart","wheel"].forEach(ev =>
        window.addEventListener(ev, activity, {passive:true})
      );
      window.addEventListener("focus", ()=>{ if (!checkResumeIdle()) activity(); });
      document.addEventListener("visibilitychange", ()=>{
        if (!document.hidden) {
          if (!checkResumeIdle()) {
            activity();
            fetch("/heartbeat", {method:"POST", credentials:"same-origin"}).catch(()=>{});
          }
        }
      });
      window.addEventListener("pageshow", ()=>{ if (!checkResumeIdle()) activity(); });

      setLast();
      startIdleTimer();
      startHeartbeat();

      if (form && btn) {
        form.addEventListener("submit", ()=>{
          btn.disabled = true;
          btn.textContent = "Starting…";
          setLast();
        });
      }
    })();
  </script>
</body>
</html>
"""
    return (
        template
        .replace("__BODY__", body_html)
        .replace("__HOST_VAL__", host_val_safe)
    )

# ----------------- Routes -----------------
@app.get("/_health")
async def health():
    uptime = int(time.time() - PROCESS_START_TS)
    live_sessions = sum(1 for info in backends.values() if info.proc.poll() is None)
    payload = {
        "status": "ok",
        "uptime_seconds": uptime,
        "server": _system_metrics(),
        "proxy_process": _process_metrics(),
        "goose": _goose_metrics(),
        "ws_connections": WS_CONNECTIONS,
        "live_sessions": live_sessions,
        "active_users": len(SESSIONS),
    }
    return Response(content=json.dumps(payload, indent=2, sort_keys=True) + "\n", media_type="application/json")

@app.get("/_debug")
async def debug_html(request: Request):
    sid = request.cookies.get(CK_SID)
    sig = request.cookies.get(CK_SIG)
    host = request.cookies.get(CK_HOST)
    tok  = request.cookies.get(CK_TOKEN)
    ok_sig = bool(sid and sig and _verify_sid(sid, sig))
    sess = SESSIONS.get(sid) if sid else None
    sess_host = sess[0] if sess else None
    sess_tok  = sess[1] if sess else None
    sess_exp  = sess[2] if sess else None
    live = bool(sess and has_live_session(sess_host, sess_tok))
    port = backends.get(session_key(sess_host, sess_tok)).port if live else None
    now = time.time()
    exp_in = (sess_exp - now) if sess_exp else None

    html = f"""
    <html><head><title>Session debug</title>
      <style>
        body {{ font-family: ui-sans-serif, system-ui; padding:20px; background:#0b1020; color:#e9ecff; }}
        code {{ background:#0d142b; padding:2px 6px; border-radius:6px; border:1px solid #2a345a; }}
        .wrap {{ display:grid; gap:12px; max-width:1100px; }}
        .card {{ background:#121a32; border:1px solid #2a345a; border-radius:12px; padding:16px; }}
        h2 {{ margin:0 0 8px; color:#ff8a1f; }}
        pre {{ white-space:pre-wrap; word-break:break-word; }}
      </style>
    </head><body>
      <div class="wrap">
        <div class="card">
          <h2>Cookies</h2>
          <div>CK_SID: <code>{sid or '<none>'}</code></div>
          <div>CK_SIG valid: <code>{ok_sig}</code></div>
          <div>CK_HOST: <code>{host or '<none>'}</code></div>
          <div>CK_TOKEN: <code>{_mask_pat(tok)}</code></div>
        </div>
        <div class="card">
          <h2>Server session</h2>
          <div>exists: <code>{bool(sess)}</code></div>
          <div>sess.host: <code>{sess_host or '<none>'}</code></div>
          <div>sess.token: <code>{_mask_pat(sess_tok)}</code></div>
          <div>expires in (s): <code>{None if exp_in is None else int(exp_in)}</code></div>
          <div>has_live_session: <code>{live}</code></div>
          <div>backend.port: <code>{port or '<none>'}</code></div>
        </div>
        <div class="card">
          <h2>Recent debug log (last 20)</h2>
          <pre>{chr(10).join(_debug_lines[-20:])}</pre>
        </div>
      </div>
    </body></html>
    """
    return HTMLResponse(html)

@app.get("/_debug.json")
async def debug_json(request: Request):
    sid = request.cookies.get(CK_SID)
    sig = request.cookies.get(CK_SIG)
    host = request.cookies.get(CK_HOST)
    tok  = request.cookies.get(CK_TOKEN)
    ok_sig = bool(sid and sig and _verify_sid(sid, sig))
    sess = SESSIONS.get(sid) if sid else None
    sess_host = sess[0] if sess else None
    sess_tok  = sess[1] if sess else None
    sess_exp  = sess[2] if sess else None
    live = bool(sess and has_live_session(sess_host, sess_tok))
    port = backends.get(session_key(sess_host, sess_tok)).port if live else None
    now = time.time()
    exp_in = (sess_exp - now) if sess_exp else None

    return Response(
        content=json.dumps({
            "cookies": { CK_SID: sid, CK_SIG: sig, CK_HOST: host, CK_TOKEN: _mask_pat(tok), "sig_valid": ok_sig },
            "session": {
                "exists": bool(sess),
                "host": sess_host,
                "token_masked": _mask_pat(sess_tok),
                "expires_in_seconds": None if exp_in is None else int(exp_in),
                "has_live_session": live,
                "backend_port": port,
            },
            "recent_debug": _debug_lines[-50:],
        }, indent=2),
        media_type="application/json"
    )

@app.get("/")
async def home(request: Request):
    token = request.cookies.get(CK_TOKEN)
    host  = request.cookies.get(CK_HOST)
    show_iframe = bool(token and host and has_live_session(host, token))
    if show_iframe:
        touch_session(host, token)

    sid = request.cookies.get(CK_SID)
    sig = request.cookies.get(CK_SIG)
    resp = HTMLResponse(render_page(request.cookies.get(CK_HOST), show_iframe))
    if sid and sig and _verify_sid(sid, sig) and sid in SESSIONS:
        _refresh_session(resp, sid)
    return resp

@app.post("/start")
async def start(request: Request, host: str = Form(...), token: str = Form(...)):
    try:
        host = normalize_host(host)
    except Exception as e:
        return PlainTextResponse(str(e), status_code=400)

    try:
        await ensure_backend(host, token)
        touch_session(host, token)
    except Exception as e:
        return PlainTextResponse(f"Failed to start backend: {e}", status_code=502)

    https = (_scheme_from_request(request) == "https")
    resp = RedirectResponse("/", status_code=303)
    sid, sig = _set_login_cookies(resp, host, token, https=https)
    _dbg(f"/start -> sid={sid} cookies set (https={https})")
    return resp

@app.get("/logout")
async def logout(request: Request):
    sid = request.cookies.get(CK_SID)
    _kill_session(sid)

    resp = RedirectResponse("/", status_code=303)
    for name in (CK_TOKEN, CK_HOST, CK_SID, CK_SIG):
        resp.delete_cookie(name, path="/")
    return resp

@app.post("/heartbeat")
async def heartbeat(request: Request):
    sid = request.cookies.get(CK_SID)
    sig = request.cookies.get(CK_SIG)
    if sid and sig and _verify_sid(sid, sig) and sid in SESSIONS:
        host, token, _ = SESSIONS[sid]
        if has_live_session(host, token):
            touch_session(host, token)
            _refresh_session(None, sid)
    return Response(status_code=204)

# ----------------- HTTP proxy under /goose/... -----------------
@app.api_route("/goose", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.api_route("/goose/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.api_route("/goose/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def http_proxy(request: Request, path: str = ""):
    sid = request.cookies.get(CK_SID)
    sig = request.cookies.get(CK_SIG)
    if not (sid and sig and _verify_sid(sid, sig) and sid in SESSIONS):
        _dbg(f"[http_proxy] no/invalid sid for path='/{path}' -> redirect")
        return RedirectResponse("/", status_code=303)

    host, token, exp = SESSIONS[sid]
    if time.time() > exp or not has_live_session(host, token):
        _dbg(f"[http_proxy] expired or no live session. host={host} token={_mask_pat(token)}")
        return RedirectResponse("/", status_code=303)

    backend = backends[session_key(host, token)]
    touch_session(host, token)

    target = f"http://{BACKEND_HOST}:{backend.port}/{path}"
    if request.url.query:
        target += f"?{request.url.query}"

    headers = {
        k: v
        for k, v in request.headers.items()
        if not is_hop_by_hop(k) and k.lower() not in {"content-length", "accept-encoding"}
    }
    headers["host"] = f"{BACKEND_HOST}:{backend.port}"
    headers.pop("expect", None)

    body = await request.body()
    async with httpx.AsyncClient(timeout=None) as client:
        try:
            req = client.build_request(request.method, target, headers=headers, content=body)
            upstream = await client.send(req, stream=False)
        except httpx.HTTPError as e:
            _dbg(f"[http_proxy] upstream error: {e}")
            return PlainTextResponse(f"Upstream error: {e}", status_code=502)

        resp = Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
        )
        _refresh_session(resp, sid)

        for k_bytes, v_bytes in upstream.headers.raw:
            k = k_bytes.decode("latin-1")
            v = v_bytes.decode("latin-1")
            if is_hop_by_hop(k) or k.lower() == "content-length":
                continue
            resp.raw_headers.append((k.encode("latin-1"), v.encode("latin-1")))
        return resp

# ----------------- WebSocket proxies -----------------
def _parse_subprotocols(header_val: Optional[str]) -> List[str]:
    if not header_val:
        return []
    return [p.strip() for p in header_val.split(",") if p.strip()]

@app.websocket("/ws")
async def ws_root(websocket: WebSocket):
    await _ws_bridge(websocket, upstream_path="ws")

@app.websocket("/goose/{path:path}")
async def ws_under_goose(websocket: WebSocket, path: str):
    await _ws_bridge(websocket, upstream_path=path)

async def _ws_bridge(websocket: WebSocket, upstream_path: str):
    sid = websocket.cookies.get(CK_SID)
    sig = websocket.cookies.get(CK_SIG)
    have_sid = sid is not None
    have_sig = sig is not None
    sig_ok = bool(have_sid and have_sig and _verify_sid(sid, sig))
    sess = SESSIONS.get(sid) if sig_ok else None

    if not sig_ok or not sess:
        _dbg(f"[ws] 403 sid_present={have_sid} sig_present={have_sig} sig_ok={sig_ok} sess_exists={bool(sess)} path='/{upstream_path}'")
        await websocket.close(code=4401)
        return

    host, token, exp = sess
    live = has_live_session(host, token)
    if time.time() > exp or not live:
        _dbg(f"[ws] 403 live={live} expired={time.time()>exp} host={host} token={_mask_pat(token)}")
        await websocket.close(code=4401)
        return

    backend = backends[session_key(host, token)]
    target = f"ws://{BACKEND_HOST}:{backend.port}/{upstream_path}"
    if websocket.url.query:
        target += f"?{websocket.url.query}"

    offered = _parse_subprotocols(websocket.headers.get("sec-websocket-protocol"))

    # Try with headers first (for modern websockets lib), then fall back without them.
    try:
        upstream = await websockets.connect(
            target,
            # Some websockets versions accept extra_headers; others don't.
            extra_headers=[("Host", f"{BACKEND_HOST}:{backend.port}")],
            subprotocols=offered if offered else None,
            open_timeout=15,
            ping_interval=None,
            max_size=None,
        )
    except TypeError as e:
        # Old or different lib: retry without extra_headers.
        _dbg(f"[ws] connect kwargs incompatible; retrying without extra_headers: {e}")
        try:
            upstream = await websockets.connect(
                target,
                subprotocols=offered if offered else None,
                open_timeout=15,
                ping_interval=None,
                max_size=None,
            )
        except Exception as e2:
            _dbg(f"[ws] upstream connect error -> 1013 (no-headers path): {e2}")
            await websocket.close(code=1013)
            return
    except Exception as e:
        _dbg(f"[ws] upstream connect error -> 1013: {e}")
        await websocket.close(code=1013)
        return

    global WS_CONNECTIONS
    try:
        await websocket.accept(subprotocol=upstream.subprotocol)
        WS_CONNECTIONS += 1
        touch_session(host, token)
        SESSIONS[sid] = (host, token, time.time() + INACTIVITY_SECS)
        _dbg(f"[ws] accepted; bridged to {BACKEND_HOST}:{backend.port} path='/{upstream_path}' sid={sid}")
    except Exception as e:
        _dbg(f"[ws] accept error: {e}")
        await upstream.close()
        return

    async def client_to_upstream():
        try:
            while True:
                msg = await websocket.receive()
                t = msg.get("type")
                if t == "websocket.receive":
                    if msg.get("text") is not None:
                        await upstream.send(msg["text"])
                    elif msg.get("bytes") is not None:
                        await upstream.send(msg["bytes"])
                    touch_session(host, token)
                    SESSIONS[sid] = (host, token, time.time() + INACTIVITY_SECS)
                elif t == "websocket.disconnect":
                    try:
                        await upstream.close()
                    finally:
                        break
        except WebSocketDisconnect:
            try:
                await upstream.close()
            except Exception:
                pass

    async def upstream_to_client():
        try:
            async for data in upstream:
                if isinstance(data, str):
                    await websocket.send_text(data)
                else:
                    await websocket.send_bytes(data)
                touch_session(host, token)
                SESSIONS[sid] = (host, token, time.time() + INACTIVITY_SECS)
        except Exception:
            try:
                await websocket.close()
            except Exception:
                pass

    try:
        await asyncio.gather(client_to_upstream(), upstream_to_client())
    finally:
        WS_CONNECTIONS -= 1

# ----------------- Absolute-path asset proxy -----------------
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def absolute_proxy(request: Request, path: str):
    sid = request.cookies.get(CK_SID)
    sig = request.cookies.get(CK_SIG)
    if not (sid and sig and _verify_sid(sid, sig) and sid in SESSIONS):
        if path == "" or "text/html" in request.headers.get("accept", ""):
            _dbg(f"[abs] redirect (no session) path='/{path}'")
            return RedirectResponse("/", status_code=303)
        return PlainTextResponse("Not found", status_code=404)

    host, token, exp = SESSIONS[sid]
    if time.time() > exp or not has_live_session(host, token):
        _dbg(f"[abs] expired/no-live redirect path='/{path}'")
        return RedirectResponse("/", status_code=303)

    backend = backends[session_key(host, token)]
    touch_session(host, token)

    target = f"http://{BACKEND_HOST}:{backend.port}/{path}"
    if request.url.query:
        target += f"?{request.url.query}"

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower()
        not in {
            "connection","keep-alive","proxy-authenticate","proxy-authorization",
            "te","trailers","transfer-encoding","upgrade","content-length","accept-encoding",
        }
    }
    headers["host"] = f"{BACKEND_HOST}:{backend.port}"
    headers.pop("expect", None)

    body = await request.body()

    async with httpx.AsyncClient(timeout=None) as client:
        try:
            req = client.build_request(request.method, target, headers=headers, content=body)
            upstream = await client.send(req, stream=False)
        except httpx.HTTPError as e:
            _dbg(f"[abs] upstream error: {e}")
            return PlainTextResponse(f"Upstream error: {e}", status_code=502)

        resp = Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
        )
        _refresh_session(resp, sid)
        for k_bytes, v_bytes in upstream.headers.raw:
            k = k_bytes.decode("latin-1")
            v = v_bytes.decode("latin-1")
            if k.lower() in {
                "connection","keep-alive","proxy-authenticate","proxy-authorization",
                "te","trailers","transfer-encoding","upgrade","content-length",
            }:
                continue
            resp.raw_headers.append((k.encode("latin-1"), v.encode("latin-1")))
        return resp

# ----------------- MCP prep -----------------
MCP_DIR = "/app/python/source_code/awesome-databricks-mcp"

def _locate_uv_or_warn() -> Optional[str]:
    try:
        return _locate_uv()
    except Exception as e:
        _dbg(f"[warn] uv not found: {e}")
        return None

def prepare_mcp_env() -> None:
    if not os.path.isdir(MCP_DIR):
        return
    uv = _locate_uv_or_warn()
    if not uv:
        return
    env = os.environ.copy()
    env.setdefault("UV_PYTHON", "3.13")
    env.setdefault("PYO3_USE_ABI3_FORWARD_COMPATIBILITY", "1")
    try:
        subprocess.check_call([uv, "python", "pin", "3.13"], cwd=MCP_DIR, env=env)
        subprocess.check_call([uv, "sync"], cwd=MCP_DIR, env=env)
    except subprocess.CalledProcessError as e:
        _dbg(f"[warn] MCP env prep failed: {e}")

config_text = """GOOSE_MODEL: databricks-claude-sonnet-4
extensions:
  developer:
    enabled: true
    type: builtin
    name: developer
    display_name: Developer
    description: null
    timeout: 300
    bundled: true
    available_tools: []
  awesomedatabricksmcp:
    enabled: true
    type: stdio
    name: awesomedatabricksmcp
    cmd: /home/app/.local/bin/uv
    args:
    - run
    - --directory
    - /app/python/source_code/awesome-databricks-mcp
    - run_mcp_stdio.py
    envs: {}
    env_keys: []
    timeout: 300
    description: ''
    bundled: null
    available_tools: []
  computercontroller:
    enabled: false
    type: builtin
    name: computercontroller
    display_name: Computer Controller
    description: null
    timeout: 300
    bundled: true
    available_tools: []
  memory:
    enabled: false
    type: builtin
    name: memory
    display_name: Memory
    description: null
    timeout: 300
    bundled: true
    available_tools: []
  autovisualiser:
    enabled: false
    type: builtin
    name: autovisualiser
    display_name: Auto Visualiser
    description: null
    timeout: 300
    bundled: true
    available_tools: []
  tutorial:
    enabled: false
    type: builtin
    name: tutorial
    display_name: Tutorial
    description: null
    timeout: 300
    bundled: true
    available_tools: []
DATABRICKS_HOST: https://e2-demo-field-eng.cloud.databricks.com/
GOOSE_PROVIDER: databricks
"""

if __name__ == "__main__":
    config_dir = "/home/app/.config/goose"
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "config.yaml"), "w") as f:
        f.write(config_text)

    subprocess.run(
        """
        unset DATABRICKS_CLIENT_ID;
        unset DATABRICKS_CLIENT_SECRET;
        curl -fsSL https://github.com/block/goose/releases/download/v1.10.3/download_cli.sh | CONFIGURE=false GOOSE_BIN_DIR=/app/python/source_code bash;
        curl -LsSf https://astral.sh/uv/install.sh | sh;
        """,
        shell=True,
        text=True
    )

    prepare_mcp_env()
    uvicorn.run("proxy_app:app", host=APP_HOST, port=APP_PORT, reload=False)
