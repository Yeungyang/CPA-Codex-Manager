"""
Web UI 启动入口
"""

import uvicorn
import logging
import sys
from pathlib import Path
import platform

# 添加项目根目录到 Python 路径
# PyInstaller 打包后 __file__ 在临时解压目录，需要用 sys.executable 所在目录作为数据目录
import os
if getattr(sys, 'frozen', False):
    # 打包后：使用可执行文件所在目录
    project_root = Path(sys.executable).parent
    _src_root = Path(sys._MEIPASS)
else:
    project_root = Path(__file__).parent
    _src_root = project_root
sys.path.insert(0, str(_src_root))

from src.core.utils import setup_logging
from src.database.init_db import initialize_database
from src.config.settings import get_settings


def _get_runtime_dirs() -> tuple[Path, Path]:
    """返回运行时数据目录和日志目录。

    - 开发模式：项目根目录下的 data/、logs/
    - 打包模式：
      - macOS：~/Library/Application Support/CPA-Codex-Manager/
      - Windows：%LOCALAPPDATA%/CPA-Codex-Manager/
      - 其它平台：可执行文件同级目录
    """
    if not getattr(sys, 'frozen', False):
        return project_root / "data", project_root / "logs"

    if platform.system() == "Darwin":
        app_support = Path.home() / "Library" / "Application Support" / "CPA-Codex-Manager"
        return app_support / "data", app_support / "logs"

    if platform.system() == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            app_root = Path(local_app_data) / "CPA-Codex-Manager"
        else:
            app_root = Path.home() / "AppData" / "Local" / "CPA-Codex-Manager"
        return app_root / "data", app_root / "logs"

    return project_root / "data", project_root / "logs"


def _load_dotenv():
    """加载 .env 文件（可执行文件同目录或项目根目录）"""
    env_path = project_root / ".env"
    if not env_path.exists():
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def setup_application():
    """设置应用程序"""
    # 加载 .env 文件（优先级低于已有环境变量）
    _load_dotenv()

    # 确保数据目录和日志目录存在
    data_dir, logs_dir = _get_runtime_dirs()
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    # 将数据目录路径注入环境变量，供数据库配置使用
    os.environ.setdefault("APP_DATA_DIR", str(data_dir))
    os.environ.setdefault("APP_LOGS_DIR", str(logs_dir))

    # 初始化数据库（必须先于获取设置）
    try:
        initialize_database()
    except Exception as e:
        print(f"数据库初始化失败: {e}")
        raise

    # 获取配置（需要数据库已初始化）
    settings = get_settings()

    # 配置日志（日志文件写到实际 logs 目录）
    log_file = str(logs_dir / Path(settings.log_file).name)
    setup_logging(
        log_level=settings.log_level,
        log_file=log_file
    )

    logger = logging.getLogger(__name__)

    # 简单检测数据库类型逻辑
    db_url = os.environ.get("DATABASE_URL") or os.environ.get("APP_DATABASE_URL") or ""
    is_local_sqlite = not db_url or db_url.startswith("sqlite")

    if is_local_sqlite:
        logger.info("数据库初始化成功 (本地 SQLite 模式)")
        logger.info(f"数据存储路径: {data_dir}")
    else:
        logger.info("数据库初始化成功 (外部数据库模式)")
        
    logger.info(f"日志存储路径: {logs_dir}")
    logger.info("系统配置加载完成")
    return settings


def start_webui():
    """启动 Web UI"""
    # 设置应用程序
    settings = setup_application()

    # 导入 FastAPI 应用（延迟导入以避免循环依赖）
    from src.web.app import app

    # 配置 uvicorn
    uvicorn_config = create_uvicorn_config(settings)

    logger = logging.getLogger(__name__)
    
    # 打印可访问地址
    if settings.webui_host == "0.0.0.0":
        import socket
        try:
            # 改进局域网 IP 获取逻辑 (通过 UDP 连接获取出网网卡)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            candidate_ip = s.getsockname()[0]
            s.close()
            
            # 如果获取到的是 VPN/Loon/Surge 的虚拟网卡 IP (198.18.x.x 或 198.19.x.x)
            # 或者获取到的是回环 IP，则尝试寻找 192.168 / 10 / 172 等物理网卡 IP
            if candidate_ip.startswith("198.18.") or candidate_ip.startswith("198.19.") or candidate_ip.startswith("127."):
                # 获取主机名对应出的所有 IP
                try:
                    host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
                    # 优先级：192.168 > 10. > 172. > 其它非 127/198
                    physical_ips = [ip for ip in host_ips if not (ip.startswith("127.") or ip.startswith("198.18.") or ip.startswith("198.19."))]
                    if physical_ips:
                        # 查找第一个 192.168 或 10/172
                        lan_ip = next((ip for ip in physical_ips if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")), physical_ips[0])
                        local_ip = lan_ip
                    else:
                        local_ip = candidate_ip
                except:
                    local_ip = candidate_ip
            else:
                local_ip = candidate_ip
        except:
            local_ip = "localhost"
        logger.info(f"Web UI 服务启动成功:")
        logger.info(f"  - 本地访问: http://localhost:{settings.webui_port}")
        logger.info(f"  - 局域网访问: http://{local_ip}:{settings.webui_port}")
    else:
        logger.info(f"Web UI 服务启动成功: http://{settings.webui_host}:{settings.webui_port}")
        
    logger.info(f"模式: {'Debug' if settings.debug else 'Production'}")

    # 启动服务器
    uvicorn.run(**uvicorn_config)


def create_uvicorn_config(settings, app=None, host=None, port=None, reload=None):
    """创建 uvicorn 配置，供 CLI/WebView 共用。"""
    app_target = app if app is not None else "src.web.app:app"
    enable_reload = settings.debug if reload is None else reload
    return {
        "app": app_target,
        "host": host or settings.webui_host,
        "port": port or settings.webui_port,
        "reload": enable_reload,
        "log_level": "info" if settings.debug else "warning",
        "access_log": settings.debug,
        "ws": "websockets",
        # 防止注册线程繁忙时前端请求超时断开
        "timeout_keep_alive": 120,   # Keep-Alive 连接保持 120 秒
        "timeout_graceful_shutdown": 30,
    }


def main():
    """主函数"""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Codex 自动化注册+CPA 账号管理系统")
    parser.add_argument("--host", help="监听主机 (也可通过 WEBUI_HOST 环境变量设置)")
    parser.add_argument("--port", type=int, help="监听端口 (也可通过 WEBUI_PORT 环境变量设置)")
    parser.add_argument("--debug", action="store_true", help="启用调试模式 (也可通过 DEBUG=1 环境变量设置)")
    parser.add_argument("--reload", action="store_true", help="启用热重载")
    parser.add_argument("--log-level", help="日志级别 (也可通过 LOG_LEVEL 环境变量设置)")
    parser.add_argument("--access-password", help="Web UI 访问密钥 (也可通过 WEBUI_ACCESS_PASSWORD 环境变量设置)")
    args = parser.parse_args()

    # 更新配置
    from src.config.settings import update_settings

    updates = {}
    
    # 优先使用命令行参数，如果没有则尝试从环境变量获取
    host = args.host or os.environ.get("WEBUI_HOST")
    if host:
        updates["webui_host"] = host
        
    port = args.port or os.environ.get("WEBUI_PORT")
    if port:
        updates["webui_port"] = int(port)
        
    debug = args.debug or os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    if debug:
        updates["debug"] = debug
        
    log_level = args.log_level or os.environ.get("LOG_LEVEL")
    if log_level:
        updates["log_level"] = log_level
        
    access_password = args.access_password or os.environ.get("WEBUI_ACCESS_PASSWORD")
    if access_password:
        updates["webui_access_password"] = access_password

    if updates:
        update_settings(**updates)

    # 启动 Web UI
    start_webui()


if __name__ == "__main__":
    main()
