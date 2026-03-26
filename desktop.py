"""桌面版启动入口（pywebview）。"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import time
from contextlib import closing

import uvicorn

try:
    import webview
except ModuleNotFoundError as exc:
    missing_module_error = exc
    webview = None
else:
    missing_module_error = None

from webui import create_uvicorn_config, setup_application


logger = logging.getLogger(__name__)


def _is_port_open(host: str, port: int) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((host, port)) == 0


def _find_available_port(host: str, preferred_port: int, max_attempts: int = 20) -> int:
    for port in range(preferred_port, preferred_port + max_attempts):
        if not _is_port_open(host, port):
            return port
    raise RuntimeError(f"无法为桌面版找到可用端口，起始端口: {preferred_port}")


def _wait_for_server(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _is_port_open(host, port):
            return
        time.sleep(0.2)
    raise RuntimeError(f"本地服务启动超时: http://{host}:{port}")


def _build_server(host: str, port: int) -> uvicorn.Server:
    settings = setup_application()

    # 桌面模式强制使用本地回环地址，避免暴露到局域网。
    os.environ["APP_HOST"] = host
    os.environ["APP_PORT"] = str(port)

    from src.config.settings import update_settings
    from src.web.app import app

    update_settings(webui_host=host, webui_port=port, debug=False)
    config = uvicorn.Config(**create_uvicorn_config(settings, app=app, host=host, port=port, reload=False))
    return uvicorn.Server(config)


def main():
    if webview is None:
        raise SystemExit(
            "缺少依赖 pywebview，请先安装后再启动桌面版：\n"
            "  /usr/bin/pip3 install pywebview\n"
            "或安装项目依赖后重试。"
        ) from missing_module_error

    host = "127.0.0.1"
    preferred_port = int(os.environ.get("APP_PORT", "8000"))
    port = _find_available_port(host, preferred_port)
    server = _build_server(host, port)

    server_thread = threading.Thread(target=server.run, name="desktop-webui-server", daemon=True)
    server_thread.start()
    _wait_for_server(host, port)

    window_title = os.environ.get("APP_WINDOW_TITLE", "CPA-Codex-Manager")
    url = f"http://{host}:{port}"
    logger.info("桌面版已启动: %s", url)

    try:
        webview.create_window(window_title, url, width=1440, height=960, min_size=(1100, 720))
        webview.start()
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)


if __name__ == "__main__":
    main()