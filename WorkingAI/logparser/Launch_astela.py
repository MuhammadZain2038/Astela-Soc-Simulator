"""
launch_astela.py - single entrypoint that binds the whole ASTELA stack
together:

  1. Make sure Docker is running (start Docker Desktop if it is
     installed but closed)
  2. Make sure OpenSearch (+ Dashboards) is up via its Docker Compose
     file, starting it if it isn't
  3. Make sure the OpenSearch "logs" index exists, creating it if not
  4. Make sure Redis is up (start it if it isn't)
  5. Make sure the ClamAV daemon is up (start it if it isn't)
  6. Open the Streamlit dashboard (frontend/app.py) in its own window
  7. Run dev checks/sync_threat_intel.py once immediately, so Redis is
     fresh before the pipeline starts scoring anything
  8. Schedule sync_threat_intel.py to re-run every 60 minutes in the
     background, for as long as this launcher stays open
  9. Run pipeline/astela_pipeline.py, then ask "run again? y/n" when it
     finishes
 10. On exit, cleanly stop anything this script itself started

All sub-process paths below are resolved relative to this file's own
location, not the current working directory, so this launcher works
regardless of where it's invoked from.

Redis and ClamAV run on Docker images that are not part of this repo, so
pulling them reaches the internet - those steps ask for confirmation
first. OpenSearch runs from a docker-compose.yml that ships with the
repo, so no confirmation is needed there; `docker compose up -d` starts
it whether the stack is fresh or already exists.
"""

import os
import sys
import time
import shutil
import ctypes
import threading
import subprocess

import redis
import requests
import pyclamd
from dotenv import load_dotenv

load_dotenv()

# This file lives in logparser/. sync_threat_intel.py, astela_pipeline.py
# and app.py live in its dev checks/, pipeline/, and frontend/ subfolders.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SYNC_SCRIPT = os.path.join(BASE_DIR, "dev checks", "sync_threat_intel.py")
PIPELINE_SCRIPT = os.path.join(BASE_DIR, "pipeline", "astela_pipeline.py")
DASHBOARD_SCRIPT = os.path.join(BASE_DIR, "frontend", "app.py")

DOCKER_INSTALL_URL = "https://www.docker.com/products/docker-desktop/"

# Manual override for a nonstandard Docker Desktop install location.
DOCKER_DESKTOP_EXE = os.getenv("DOCKER_DESKTOP_PATH")

# Common default install locations for Docker Desktop on Windows.
DOCKER_DESKTOP_PATHS = [
    os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                 "Docker", "Docker", "Docker Desktop.exe"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""),
                 "Programs", "Docker", "Docker", "Docker Desktop.exe"),
]


def _disable_quickedit_mode():
    """Windows' console QuickEdit Mode pauses ALL stdout writes from this
    process the instant you click inside the console window - including
    an accidental click just to bring the window into focus to press
    Ctrl+C. Output (and the script itself) only resumes once you press
    ANY key. This isn't Docker being slow; it's Windows console behavior.
    Disabling it here means a stray click can't freeze the launcher."""
    try:
        kernel32 = ctypes.windll.kernel32
        STD_INPUT_HANDLE = -10
        ENABLE_EXTENDED_FLAGS = 0x0080
        ENABLE_QUICK_EDIT_MODE = 0x0040

        handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return  # not attached to a real console (e.g. an IDE) - nothing to do

        new_mode = (mode.value & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS
        kernel32.SetConsoleMode(handle, new_mode)
    except Exception:
        pass  # not Windows, or any other issue - don't let this break the launcher


def _confirm_network_pull(what, detail=""):
    """Ask before anything that reaches the internet to download an image.
    Returns True only on an explicit 'y'."""
    print(f"\n[?] {what} needs to be pulled from the internet.")
    if detail:
        print(f"    {detail}")
    answer = input("    Continue? [y/n]: ").strip().lower()
    return answer == "y"


# ---------------------------------------------------------------------
# CONFIG - override any of these in your .env, none are required
# ---------------------------------------------------------------------
# OpenSearch (+ Dashboards): started via `docker compose -f <path> up -d`
# against the compose file shipped in this repo. Compose itself handles
# all three cases - pulls the images if missing, creates the containers
# if they don't exist yet, or just starts them if they're already there
# but stopped - so nothing here needs to know what's inside that file.
OPENSEARCH_COMPOSE_PATH = os.getenv("OPEN_SEARCH_PATH")  # e.g. E:\Astela_SOC_Simulator\project\SecurityAI\docker-compose.yml
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")

# Index the pipeline writes to and the dashboard reads from. This must
# match the index name used in astela_pipeline.py and app.py.
LOGS_INDEX = "logs"

# Redis: this launcher prefers Docker (pulls + runs a named container for
# you), and only falls back to a local redis-server.exe if Docker isn't
# available on this machine at all.
REDIS_CONTAINER_NAME = os.getenv("REDIS_CONTAINER_NAME", "astela-redis")
REDIS_DOCKER_IMAGE = os.getenv("REDIS_DOCKER_IMAGE", "redis:latest")
REDIS_DOCKER_PORT = os.getenv("REDIS_DOCKER_PORT", "6379")
REDIS_DOCKER_VOLUME = os.getenv("REDIS_DOCKER_VOLUME", "astela-redis-data")  # named volume, not a host path - portable across machines
REDIS_SERVER_EXE = os.getenv("REDIS_SERVER_EXE")          # only used if Docker isn't installed

# ClamAV: this launcher prefers Docker too (pulls + runs a named
# container with the official clamav/clamav image), and only falls back
# to a local clamd.exe if Docker isn't available on this machine.
# The virus database is persisted in a Docker volume so it doesn't
# re-download from scratch every time the container is recreated.
CLAMD_CONTAINER_NAME = os.getenv("CLAMD_CONTAINER_NAME", "astela-clamav")
CLAMD_DOCKER_IMAGE = os.getenv("CLAMD_DOCKER_IMAGE", "clamav/clamav:latest")
CLAMD_DOCKER_PORT = os.getenv("CLAMD_DOCKER_PORT", "3310")
CLAMD_DOCKER_VOLUME = os.getenv("CLAMD_DOCKER_VOLUME", "astela-clamav-db")
CLAMD_EXE_PATH = os.getenv("CLAMD_EXE_PATH")  # only used if Docker isn't installed - e.g. E:\Astela_SOC_Simulator\clamav-1.5.1.win.x64\clamav-1.5.1.win.x64\clamd.exe

SYNC_INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", 60 * 60))  # 60 minutes, matches MalwareBazaar's "last hour" selector

# Subprocesses this script itself starts, so it can clean them up on exit.
# Anything already running before this script started (e.g. Redis/ClamAV
# as existing Windows services) is left alone on exit.
_owned_processes = []

# Result of the Docker readiness check, cached so a failed check does not
# repeat the full startup wait once per service.
_docker_ready_cache = None


# ---------------------------------------------------------------------
# DOCKER
# ---------------------------------------------------------------------
def _docker_cli_installed():
    try:
        subprocess.run(["docker", "--version"], check=True, capture_output=True, text=True, timeout=10)
        return True
    except Exception:
        return False


def _docker_engine_ready():
    """True only if the Docker engine is actually answering, not just
    if the CLI is installed. `docker info` fails when Docker Desktop is
    installed but not running."""
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def _find_docker_desktop():
    """Locates Docker Desktop.exe. Checks, in order: the DOCKER_DESKTOP_PATH
    override from .env, a location derived from the docker CLI on PATH
    (works for any install drive), then the default install paths."""
    if DOCKER_DESKTOP_EXE and os.path.exists(DOCKER_DESKTOP_EXE):
        return DOCKER_DESKTOP_EXE

    # docker.exe lives at <install>\resources\bin\docker.exe, and
    # Docker Desktop.exe sits at <install>\Docker Desktop.exe.
    docker_cli = shutil.which("docker")
    if docker_cli:
        install_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(docker_cli))))
        candidate = os.path.join(install_dir, "Docker Desktop.exe")
        if os.path.exists(candidate):
            return candidate

    for path in DOCKER_DESKTOP_PATHS:
        if path and os.path.exists(path):
            return path
    return None


def _docker_available():
    """Makes sure Docker is usable, starting Docker Desktop if it is
    installed but not running. Returns True once the engine responds."""
    global _docker_ready_cache
    if _docker_ready_cache is not None:
        return _docker_ready_cache

    if not _docker_cli_installed():
        _docker_ready_cache = False
        return False

    if _docker_engine_ready():
        _docker_ready_cache = True
        return True

    desktop_exe = _find_docker_desktop()
    if not desktop_exe:
        print("[!] Docker is installed but its engine is not running, and Docker Desktop")
        print("    could not be located automatically.")
        print("    Fix option 1: start Docker Desktop manually and run this launcher again.")
        print("    Fix option 2: set DOCKER_DESKTOP_PATH in .env to the full path of")
        print("    'Docker Desktop.exe' so this launcher can start it for you.")
        _docker_ready_cache = False
        return False

    print("[*] Docker Desktop is not running. Starting it now...")
    # Deliberately not added to _owned_processes: Docker Desktop should
    # keep running after this launcher exits.
    subprocess.Popen([desktop_exe])

    for i in range(60):  # up to roughly 3 minutes
        time.sleep(3)
        if _docker_engine_ready():
            print("[+] Docker engine is ready.")
            _docker_ready_cache = True
            return True
        if i and i % 10 == 0:
            print(f"    ...still waiting for Docker ({i * 3}s elapsed)")

    print("[!] Docker Desktop did not become ready within about 3 minutes.")
    print("    Fix: open Docker Desktop, wait for it to finish starting, and run this launcher again.")
    _docker_ready_cache = False
    return False


def _docker_container_state(container_name):
    """Returns 'running', 'stopped', 'absent', or 'unknown' for the given
    container name. A failed Docker command returns 'unknown' rather than
    'absent', so an unresponsive engine is never mistaken for a missing
    container (which would trigger an unnecessary image pull)."""
    try:
        running = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{container_name}$", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=20,
        )
    except subprocess.TimeoutExpired:
        print("[!] `docker ps` timed out after 20s - Docker's engine may still be busy from another service starting up.")
        return "unknown"

    if running.returncode != 0:
        return "unknown"

    if container_name in running.stdout.split():
        return "running"

    try:
        existing = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^{container_name}$", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=20,
        )
    except subprocess.TimeoutExpired:
        print("[!] `docker ps -a` timed out after 20s.")
        return "unknown"

    if existing.returncode != 0:
        return "unknown"

    if container_name in existing.stdout.split():
        return "stopped"

    return "absent"


# ---------------------------------------------------------------------
# OPENSEARCH (+ DASHBOARDS)
# ---------------------------------------------------------------------
def _opensearch_alive():
    try:
        return requests.get(OPENSEARCH_URL, timeout=3).status_code == 200
    except Exception:
        return False


def ensure_opensearch():
    if _opensearch_alive():
        print("[+] OpenSearch already running.")
        return

    if not OPENSEARCH_COMPOSE_PATH:
        print("[!] OpenSearch is not running and OPEN_SEARCH_PATH is not set in .env.")
        print("    Fix: set OPEN_SEARCH_PATH in .env to the path of your docker-compose.yml")
        print("    (e.g. project\\SecurityAI\\docker-compose.yml), then run this launcher again.")
        print("    The pipeline and dashboard will not be able to push or read data until this is fixed.")
        return

    if not os.path.exists(OPENSEARCH_COMPOSE_PATH):
        print(f"[!] OPEN_SEARCH_PATH points to a file that does not exist: {OPENSEARCH_COMPOSE_PATH}")
        print("    Fix: correct the OPEN_SEARCH_PATH value in .env.")
        return

    if not _docker_available():
        print("[!] Docker is not available - OpenSearch cannot be started automatically.")
        print(f"    Fix: install Docker Desktop ({DOCKER_INSTALL_URL}) if needed, make sure it is running,")
        print("    and run this launcher again.")
        print(f"    Alternatively, start OpenSearch yourself and make sure it answers at {OPENSEARCH_URL}.")
        print("    The pipeline and dashboard will not be able to push or read data until this is fixed.")
        return

    print(f"[*] Starting OpenSearch stack via Compose ({OPENSEARCH_COMPOSE_PATH})...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", OPENSEARCH_COMPOSE_PATH, "up", "-d"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] `docker compose up` failed: {e}")
        return

    # OpenSearch is notably slower to become ready than Redis - it can
    # take a minute or more on a cold start (JVM boot + cluster init), so
    # this polls for longer before giving up.
    print("[*] Waiting for OpenSearch to become ready (can take a minute or more on a cold start)...")
    for i in range(90):
        time.sleep(2)
        if _opensearch_alive():
            print("[+] OpenSearch is up.")
            return
        if i and i % 15 == 0:
            print(f"    ...still waiting ({i * 2}s elapsed)")
    print(f"[!] OpenSearch still is not responding at {OPENSEARCH_URL} after roughly 3 minutes.")
    print(f"    Fix: check `docker compose -f {OPENSEARCH_COMPOSE_PATH} logs` for what is wrong.")


def ensure_logs_index():
    """Creates the logs index if it does not exist yet. OpenSearch would
    create it automatically on the first document the pipeline pushes,
    but the dashboard opens before that happens and would show a
    connection error on a fresh setup. Only the timestamp field is
    pinned (as a date, so the dashboard can sort on it); every other
    field is mapped automatically as before. An existing index is left
    untouched. Failures here only print a warning, since the pipeline
    can still create the index itself."""
    if not _opensearch_alive():
        return

    url = f"{OPENSEARCH_URL}/{LOGS_INDEX}"
    try:
        if requests.head(url, timeout=5).status_code == 200:
            print(f"[+] OpenSearch index '{LOGS_INDEX}' already exists.")
            return

        response = requests.put(
            url,
            json={"mappings": {"properties": {"timestamp": {"type": "date"}}}},
            timeout=10,
        )
        if response.status_code in (200, 201):
            print(f"[+] Created OpenSearch index '{LOGS_INDEX}'.")
        elif "resource_already_exists" in response.text:
            print(f"[+] OpenSearch index '{LOGS_INDEX}' already exists.")
        else:
            print(f"[!] Could not create index '{LOGS_INDEX}' ({response.status_code}): {response.text[:200]}")
            print("    The pipeline will create it on its first push, but the dashboard may")
            print("    show a connection error until then.")
    except Exception as e:
        print(f"[!] Could not check or create index '{LOGS_INDEX}': {e}")


# ---------------------------------------------------------------------
# REDIS
# ---------------------------------------------------------------------
def _redis_alive():
    try:
        redis.Redis(host="localhost", port=6379, db=0).ping()
        return True
    except Exception:
        return False


def _ensure_redis_via_docker():
    print("[*] Checking Redis container state...")
    state = _docker_container_state(REDIS_CONTAINER_NAME)

    if state == "unknown":
        print("[!] Could not determine container state (Docker not responding in time). Giving up on Docker for Redis this run.")
        return False

    if state == "running":
        print(f"[+] Redis container '{REDIS_CONTAINER_NAME}' already running.")
        return True

    if state == "stopped":
        print(f"[*] Starting existing Redis container '{REDIS_CONTAINER_NAME}'...")
        subprocess.run(["docker", "start", REDIS_CONTAINER_NAME], check=True, timeout=30)
        return True

    # absent - needs a fresh pull, which reaches the internet.
    if not _confirm_network_pull(f"Redis image '{REDIS_DOCKER_IMAGE}'"):
        print("[!] Skipped by user - Redis container was not created.")
        return False

    print(f"[*] Pulling {REDIS_DOCKER_IMAGE}...")
    subprocess.run(["docker", "pull", REDIS_DOCKER_IMAGE], check=True, timeout=180)

    print(f"[*] Creating Redis container '{REDIS_CONTAINER_NAME}' on port {REDIS_DOCKER_PORT} "
          f"(data persisted in Docker volume '{REDIS_DOCKER_VOLUME}')...")
    subprocess.run(
        [
            "docker", "run", "-d",
            "--name", REDIS_CONTAINER_NAME,
            "-p", f"{REDIS_DOCKER_PORT}:6379",
            "-v", f"{REDIS_DOCKER_VOLUME}:/data",
            REDIS_DOCKER_IMAGE,
        ],
        check=True, timeout=30,
    )
    return True


def ensure_redis():
    if _redis_alive():
        print("[+] Redis already running.")
        return

    if _docker_available():
        try:
            _ensure_redis_via_docker()
        except subprocess.TimeoutExpired as e:
            print(f"[!] A Docker command timed out: {e}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Docker command failed: {e}")
    elif REDIS_SERVER_EXE:
        print("[*] Docker not available - starting local redis-server.exe instead...")
        proc = subprocess.Popen([REDIS_SERVER_EXE], creationflags=subprocess.CREATE_NEW_CONSOLE)
        _owned_processes.append(proc)
    else:
        print("[!] Redis is not running, Docker is not available, and REDIS_SERVER_EXE is not set.")
        print(f"    Fix option 1: install Docker Desktop ({DOCKER_INSTALL_URL}) and run this launcher again.")
        print("    Fix option 2: install Redis locally and set REDIS_SERVER_EXE in .env to its executable path.")
        print("    Tier 1 hash lookups will fall back to the MalwareBazaar API only until this is fixed.")
        return

    for _ in range(15):
        time.sleep(1)
        if _redis_alive():
            print("[+] Redis is up.")
            return
    print("[!] Redis did not respond within 15s.")
    print(f"    Fix: check `docker logs {REDIS_CONTAINER_NAME}`, or the console window it opened in.")


# ---------------------------------------------------------------------
# CLAMAV
# ---------------------------------------------------------------------
def _clamd_alive():
    try:
        return bool(pyclamd.ClamdNetworkSocket(host="127.0.0.1", port=int(CLAMD_DOCKER_PORT)).ping())
    except Exception:
        return False


def _ensure_clamd_via_docker():
    print("[*] Checking ClamAV container state...")
    state = _docker_container_state(CLAMD_CONTAINER_NAME)

    if state == "unknown":
        print("[!] Could not determine container state (Docker not responding in time). Giving up on Docker for ClamAV this run.")
        return False

    if state == "running":
        print(f"[+] ClamAV container '{CLAMD_CONTAINER_NAME}' already running.")
        return True

    if state == "stopped":
        print(f"[*] Starting existing ClamAV container '{CLAMD_CONTAINER_NAME}'...")
        subprocess.run(["docker", "start", CLAMD_CONTAINER_NAME], check=True, timeout=30)
        return True

    # absent - this image bundles the virus database, so it is a large
    # pull (roughly 1-1.5 GB) the first time.
    if not _confirm_network_pull(
        f"ClamAV image '{CLAMD_DOCKER_IMAGE}'",
        "This is a large pull (roughly 1-1.5 GB) and includes the virus database - can take several minutes."
    ):
        print("[!] Skipped by user - ClamAV container was not created.")
        return False

    print(f"[*] Pulling {CLAMD_DOCKER_IMAGE} (bundles the virus database - large, can take a few minutes)...")
    subprocess.run(["docker", "pull", CLAMD_DOCKER_IMAGE], check=True, timeout=600)

    print(f"[*] Creating ClamAV container '{CLAMD_CONTAINER_NAME}' on port {CLAMD_DOCKER_PORT} "
          f"(signatures persisted in Docker volume '{CLAMD_DOCKER_VOLUME}')...")
    subprocess.run(
        [
            "docker", "run", "-d",
            "--name", CLAMD_CONTAINER_NAME,
            "-p", f"{CLAMD_DOCKER_PORT}:3310",
            "-v", f"{CLAMD_DOCKER_VOLUME}:/var/lib/clamav",
            CLAMD_DOCKER_IMAGE,
        ],
        check=True, timeout=30,
    )
    return True


def ensure_clamd():
    if _clamd_alive():
        print("[+] ClamAV daemon already running.")
        return

    if _docker_available():
        try:
            _ensure_clamd_via_docker()
        except subprocess.TimeoutExpired as e:
            print(f"[!] A Docker command timed out: {e}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Docker command failed: {e}")
    elif CLAMD_EXE_PATH:
        print("[*] Docker not available - starting local clamd.exe instead...")
        proc = subprocess.Popen([CLAMD_EXE_PATH], creationflags=subprocess.CREATE_NEW_CONSOLE)
        _owned_processes.append(proc)
    else:
        print("[!] ClamAV is not running, Docker is not available, and CLAMD_EXE_PATH is not set.")
        print(f"    Fix option 1: install Docker Desktop ({DOCKER_INSTALL_URL}) and run this launcher again.")
        print("    Fix option 2: install ClamAV locally and set CLAMD_EXE_PATH in .env to its executable path.")
        print("    Tier 1 will still run without ClamAV - YARA and Redis-based detection still work.")
        return

    # First-time container creation needs to pull the signature DB (or a
    # cold local clamd.exe needs to load it), which can genuinely take
    # a few minutes - this polls far longer than Redis needs.
    print("[*] Waiting for clamd to become ready (first-time database load can take a few minutes)...")
    for i in range(90):
        time.sleep(2)
        if _clamd_alive():
            print("[+] ClamAV daemon is up.")
            return
        if i and i % 15 == 0:
            print(f"    ...still waiting ({i * 2}s elapsed)")
    print(f"[!] clamd still is not responding on port {CLAMD_DOCKER_PORT} after roughly 3 minutes.")
    print(f"    Fix: check `docker logs {CLAMD_CONTAINER_NAME}`, or the console window it opened in.")


# ---------------------------------------------------------------------
# STREAMLIT DASHBOARD
# ---------------------------------------------------------------------
def launch_dashboard():
    print("[*] Opening Streamlit dashboard...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", DASHBOARD_SCRIPT],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    _owned_processes.append(proc)


# ---------------------------------------------------------------------
# THREAT INTEL SYNC (runs sync_threat_intel.py as its own process)
# ---------------------------------------------------------------------
def run_sync():
    print("[*] Running threat-intel sync...")
    subprocess.run([sys.executable, SYNC_SCRIPT])


def _sync_loop(stop_event):
    # wait() returns True if stop_event was set before the timeout -
    # that's our signal to exit the loop instead of syncing again.
    while not stop_event.wait(SYNC_INTERVAL_SECONDS):
        run_sync()


def start_background_sync():
    stop_event = threading.Event()
    thread = threading.Thread(target=_sync_loop, args=(stop_event,), daemon=True)
    thread.start()
    print(f"[+] Background sync scheduled every {SYNC_INTERVAL_SECONDS // 60} minutes.")
    return stop_event


# ---------------------------------------------------------------------
# PIPELINE
# ---------------------------------------------------------------------
def run_pipeline():
    print("[*] Running ASTELA pipeline...")
    subprocess.run([sys.executable, PIPELINE_SCRIPT])


# ---------------------------------------------------------------------
# STATUS SUMMARY
# ---------------------------------------------------------------------
def print_service_status():
    """Prints a short summary of which services actually came up, and
    what running without them means for detection quality. This runs
    right before the pipeline starts so the person launching this sees,
    in one place, exactly what is degraded and why - rather than finding
    out three steps later from a stack trace or an empty dashboard."""
    print("\n" + "=" * 60)
    print("   SERVICE STATUS")
    print("=" * 60)

    if _opensearch_alive():
        print("[+] OpenSearch: UP")
    else:
        print("[-] OpenSearch: DOWN - the dashboard will show no data and the")
        print("    pipeline will not be able to push detections anywhere.")

    if _redis_alive():
        print("[+] Redis: UP")
    else:
        print("[-] Redis: DOWN - Tier 1 hash lookups will fall back to the")
        print("    MalwareBazaar API for every hash, which is slower.")

    if _clamd_alive():
        print("[+] ClamAV: UP")
    else:
        print("[-] ClamAV: DOWN - Tier 1 will run on YARA and Redis intel only.")

    print("=" * 60 + "\n")


# ---------------------------------------------------------------------
# CLEANUP
# ---------------------------------------------------------------------
def cleanup():
    print("[*] Stopping processes this launcher started...")
    for proc in _owned_processes:
        try:
            proc.terminate()
        except Exception:
            pass


def main():
    _disable_quickedit_mode()

    print("=" * 60)
    print("   ASTELA SOC - Unified Launcher")
    print("=" * 60)

    try:
        ensure_opensearch()
        ensure_logs_index()
        ensure_redis()
        ensure_clamd()

        print_service_status()

        launch_dashboard()

        print("[*] Running initial threat-intel sync before the pipeline starts...")
        run_sync()

        stop_event = start_background_sync()

        while True:
            run_pipeline()
            again = input("\n[?] Pipeline run finished. Run it again? [y/n]: ").strip().lower()
            if again != "y":
                break
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    finally:
        try:
            stop_event.set()
        except NameError:
            pass  # interrupted before stop_event was even created
        cleanup()
        print("[*] Launcher exiting. The Streamlit dashboard window stays open - close it manually when you're done.")


if __name__ == "__main__":
    main()