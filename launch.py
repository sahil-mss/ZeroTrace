"""
ZeroTrace - Unified Application Launcher
Starts both the FastAPI backend and the Vite frontend, checks health,
and automatically opens the ZeroTrace web dashboard in your default browser.
"""

import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT_DIR / "frontend"
VENV_PYTHON = ROOT_DIR / ".venv" / "Scripts" / "python.exe"

if not VENV_PYTHON.exists():
    # Fallback to standard virtualenv path on Unix / Linux
    VENV_PYTHON = ROOT_DIR / ".venv" / "bin" / "python"

if not VENV_PYTHON.exists():
    VENV_PYTHON = Path(sys.executable)

# Determine correct npm executable for the OS
NPM_CMD = "npm.cmd" if sys.platform == "win32" else "npm"


def print_banner():
    print("=" * 65)
    print("           ZeroTrace Security Research Platform")
    print("=" * 65)
    print("  [*] Starting Backend API Server (port 8000)...")
    print("  [*] Starting Frontend Vite Server (port 5173)...")
    print("=" * 65)


def wait_for_service(url: str, timeout_seconds: int = 15, service_name: str = "Service") -> bool:
    """Polls an HTTP URL until it responds with 200 or times out."""
    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ZeroTrace-Launcher"})
            with urllib.request.urlopen(req, timeout=1.5) as response:
                if response.status in (200, 304):
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    print_banner()

    processes = []

    try:
        # 1. Start Backend FastAPI Server
        backend_cmd = [
            str(VENV_PYTHON),
            "-m",
            "uvicorn",
            "backend.app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ]
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        processes.append(("Backend", backend_proc))
        print("[+] Backend process spawned (PID: {})".format(backend_proc.pid))

        # 2. Start Frontend Vite Server
        frontend_cmd = [NPM_CMD, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"]
        frontend_proc = subprocess.Popen(
            frontend_cmd,
            cwd=str(FRONTEND_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        processes.append(("Frontend", frontend_proc))
        print("[+] Frontend process spawned (PID: {})".format(frontend_proc.pid))

        print("\n[*] Waiting for services to initialize...")

        # 3. Wait for Backend
        backend_ready = wait_for_service("http://127.0.0.1:8000/health", timeout_seconds=12, service_name="Backend")
        if backend_ready:
            print("  [OK] Backend Core API is live: http://127.0.0.1:8000")
            print("  [OK] API Docs: http://127.0.0.1:8000/docs")
        else:
            print("  [!] Backend took longer than expected to report healthy, continuing...")

        # 4. Wait for Frontend
        frontend_ready = wait_for_service("http://127.0.0.1:5173/", timeout_seconds=15, service_name="Frontend")
        if frontend_ready:
            print("  [OK] Frontend Dashboard is live: http://127.0.0.1:5173/")
        else:
            print("  [!] Frontend took longer than expected to respond, continuing...")

        target_url = "http://127.0.0.1:5173/"
        print(f"\n[+] Launching ZeroTrace web dashboard in browser: {target_url}")
        webbrowser.open(target_url)

        print("\n" + "=" * 65)
        print(" ZeroTrace is now RUNNING.")
        print(" Press Ctrl+C at any time to gracefully shut down all services.")
        print("=" * 65 + "\n")

        # Monitor processes
        while True:
            for name, proc in processes:
                ret = proc.poll()
                if ret is not None:
                    print(f"\n[!] {name} process exited unexpectedly with code {ret}.")
                    return
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n[*] Shutting down ZeroTrace services...")
    finally:
        for name, proc in processes:
            try:
                print(f"[*] Stopping {name} (PID {proc.pid})...")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
        print("[+] All services stopped cleanly.")


if __name__ == "__main__":
    main()
