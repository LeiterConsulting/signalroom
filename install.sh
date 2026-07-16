#!/usr/bin/env bash
# SignalRoom universal installer and lifecycle manager for Linux, macOS, and Git Bash.

set -euo pipefail

VERSION="0.1.0"
APP_NAME="SignalRoom Splunk Security Agent"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$INSTALL_DIR/.venv"
MANIFEST_FILE="$INSTALL_DIR/.install_manifest.json"
PID_FILE="$INSTALL_DIR/.signalroom.pid"
RUNTIME_FILE="$INSTALL_DIR/.signalroom.runtime.json"
LOG_FILE="$INSTALL_DIR/signalroom.log"
ERROR_LOG_FILE="$INSTALL_DIR/signalroom.err.log"
PYPI_URL="https://pypi.org/simple"
COMMAND=""
PUBLIC_ONLY="no"
FORCE_YES="no"
PURGE_DATA="no"
OPEN_BROWSER="no"
SETUP_MODELS="no"
INSTALL_OLLAMA="no"
PULL_MODELS="no"
PORT="8003"
BIND_ADDRESS="127.0.0.1"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;36m'; NC='\033[0m'
info() { printf "%b%s%b\n" "$BLUE" "$1" "$NC"; }
success() { printf "%b%s%b\n" "$GREEN" "$1" "$NC"; }
warn() { printf "%b%s%b\n" "$YELLOW" "$1" "$NC"; }
fail() { printf "%b%s%b\n" "$RED" "$1" "$NC" >&2; }

detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "macOS" ;;
        CYGWIN*|MINGW*|MSYS*) echo "Windows" ;;
        *) echo "Linux" ;;
    esac
}

show_help() {
    success "$APP_NAME v$VERSION"
    cat <<EOF

USAGE
    ./install.sh [OPTIONS]
    ./install.sh [start|stop|restart|status|uninstall]

OPTIONS
    (no arguments)    Install or update dependencies and start
    --start           Install if needed, then start
    --stop            Stop the managed service
    --restart         Restart the managed service
    --status          Show process, URL, health, and log locations
    --uninstall       Remove the virtual environment and runtime files
    --force-yes       Skip the uninstall confirmation
    --purge-data      With --uninstall, also remove local secrets and artifacts
    --public_only     Install only from public PyPI
    --port 8003       Preferred port; the app safely falls forward if busy
    --host ADDRESS    Bind address (default 127.0.0.1)
    --open-browser    Open the workspace after a successful start
    --setup-models    Check Ollama and Hugging Face model readiness
    --install-ollama  Explicitly install Ollama from ollama.com
    --pull-models     Download the configured Ollama model profiles
    --help            Show this help

EXAMPLES
    ./install.sh
    ./install.sh --start --public_only
    ./install.sh --setup-models --install-ollama --pull-models
    ./install.sh --restart
    ./install.sh --status
    ./install.sh --uninstall --force-yes

DEFAULT WORKSPACE
    http://localhost:8003
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            start|stop|restart|status|uninstall) COMMAND="$1" ;;
            --start|--stop|--restart|--status|--uninstall) COMMAND="${1#--}" ;;
            -h|--help) COMMAND="help" ;;
            --public_only|--public-only) PUBLIC_ONLY="yes" ;;
            --force-yes) FORCE_YES="yes" ;;
            --purge-data) PURGE_DATA="yes" ;;
            --open-browser) OPEN_BROWSER="yes" ;;
            --setup-models) SETUP_MODELS="yes" ;;
            --install-ollama) INSTALL_OLLAMA="yes" ;;
            --pull-models) PULL_MODELS="yes" ;;
            --port)
                shift; [[ $# -gt 0 ]] || { fail "--port requires a value"; exit 1; }; PORT="$1"
                ;;
            --port=*) PORT="${1#*=}" ;;
            --host)
                shift; [[ $# -gt 0 ]] || { fail "--host requires a value"; exit 1; }; BIND_ADDRESS="$1"
                ;;
            --host=*) BIND_ADDRESS="${1#*=}" ;;
            *) fail "Unknown option: $1"; show_help; exit 1 ;;
        esac
        shift
    done
    [[ "$PORT" =~ ^[0-9]+$ ]] || { fail "Port must be a number."; exit 1; }
}

find_python() {
    if command -v python3 >/dev/null 2>&1; then PYTHON_CMD="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then PYTHON_CMD="$(command -v python)"
    else fail "Python 3.11+ was not found."; exit 1
    fi
    if ! "$PYTHON_CMD" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
        fail "SignalRoom requires Python 3.11 or newer."
        exit 1
    fi
    if [[ "$(detect_os)" == "Windows" ]]; then VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
    else VENV_PYTHON="$VENV_DIR/bin/python"
    fi
}

run_pip() {
    local description="$1"; shift
    local common=(--disable-pip-version-check --retries 2 --timeout 20)
    if [[ "$PUBLIC_ONLY" == "yes" ]]; then
        info "Using public PyPI only."
        "$VENV_PYTHON" -m pip "$@" "${common[@]}" --index-url "$PYPI_URL" --no-cache-dir || {
            fail "$description failed while using public PyPI."; exit 1;
        }
        return
    fi
    if "$VENV_PYTHON" -m pip "$@" "${common[@]}"; then return; fi
    warn "$description failed with the configured package index. Retrying with public PyPI..."
    "$VENV_PYTHON" -m pip "$@" "${common[@]}" --index-url "$PYPI_URL" --no-cache-dir || {
        fail "$description failed. Check network access or retry with --public_only."; exit 1;
    }
}

installation_current() {
    find_python
    [[ -x "$VENV_PYTHON" && -f "$MANIFEST_FILE" ]] || return 1
    "$VENV_PYTHON" - "$MANIFEST_FILE" "$INSTALL_DIR/pyproject.toml" "$VERSION" <<'PY' >/dev/null 2>&1
import hashlib, json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
digest = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
raise SystemExit(0 if manifest.get("version") == sys.argv[3] and manifest.get("project_hash") == digest else 1)
PY
}

install_dependencies() {
    find_python
    local python_version
    python_version="$("$PYTHON_CMD" --version 2>&1 | awk '{print $2}')"
    success "Python $python_version found"
    if [[ ! -x "$VENV_PYTHON" ]]; then
        info "Creating isolated virtual environment..."
        "$PYTHON_CMD" -m venv "$VENV_DIR"
    fi
    if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
        warn "The existing virtual environment is incomplete; rebuilding it..."
        case "$VENV_DIR" in "$INSTALL_DIR"/*) ;; *) fail "Unsafe virtual environment path."; exit 1 ;; esac
        rm -rf -- "$VENV_DIR"
        "$PYTHON_CMD" -m venv "$VENV_DIR"
    fi
    info "Installing SignalRoom and dependencies..."
    run_pip "SignalRoom installation" install -e "$INSTALL_DIR" -q
    local pip_version project_hash
    pip_version="$("$VENV_PYTHON" -m pip --version | awk '{print $2}')"
    project_hash="$("$VENV_PYTHON" -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$INSTALL_DIR/pyproject.toml")"
    "$VENV_PYTHON" - "$MANIFEST_FILE" "$VERSION" "$project_hash" "$python_version" "$pip_version" "$VENV_DIR" "$PORT" "$(detect_os)" <<'PY'
import json, pathlib, sys
from datetime import datetime, timezone
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "version": sys.argv[2], "project_hash": sys.argv[3],
    "installed_at": datetime.now(timezone.utc).isoformat(), "os": sys.argv[8],
    "python": {"version": sys.argv[4], "executable": sys.argv[6]},
    "pip": {"version": sys.argv[5]}, "virtual_env": sys.argv[6],
    "preferred_port": int(sys.argv[7]),
}, indent=2), encoding="utf-8")
PY
    success "SignalRoom installation is up to date."
}

managed_pid() {
    if [[ -f "$RUNTIME_FILE" && -x "${VENV_PYTHON:-}" ]]; then
        local runtime_pid
        runtime_pid="$("$VENV_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["pid"])' "$RUNTIME_FILE" 2>/dev/null || true)"
        if [[ "$runtime_pid" =~ ^[0-9]+$ ]] && ps -p "$runtime_pid" >/dev/null 2>&1 && owned_process "$runtime_pid"; then
            printf "%s" "$runtime_pid"
            return 0
        fi
    fi
    [[ -f "$PID_FILE" ]] || return 1
    local pid; pid="$(tr -d '[:space:]' < "$PID_FILE")"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    printf "%s" "$pid"
}

owned_process() {
    local pid="$1" command_line
    command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    [[ "$command_line" == *"splunk_security_agent.main"* && "$command_line" == *".signalroom.runtime.json"* ]]
}

runtime_url() {
    [[ -f "$RUNTIME_FILE" ]] || return 1
    "$VENV_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["url"])' "$RUNTIME_FILE" 2>/dev/null
}

healthy() {
    local url="$1"
    "$VENV_PYTHON" -c 'import json,sys,urllib.request; print(json.load(urllib.request.urlopen(sys.argv[1] + "/api/health", timeout=2))["ok"])' "$url" 2>/dev/null | grep -q True
}

open_workspace() {
    local url="$1"
    case "$(detect_os)" in
        macOS) open "$url" >/dev/null 2>&1 & ;;
        Windows) cmd.exe /c start "" "$url" >/dev/null 2>&1 & ;;
        Linux) command -v xdg-open >/dev/null 2>&1 && xdg-open "$url" >/dev/null 2>&1 & ;;
    esac
}

start_signalroom() {
    if ! installation_current; then install_dependencies; fi
    local existing=""
    existing="$(managed_pid 2>/dev/null || true)"
    if [[ -n "$existing" ]] && ps -p "$existing" >/dev/null 2>&1; then
        if owned_process "$existing"; then
            local current_url; current_url="$(runtime_url 2>/dev/null || echo "http://localhost:$PORT")"
            warn "SignalRoom is already running (PID $existing)."
            info "Workspace: $current_url"
            return
        fi
        warn "Ignoring a stale PID file that points to an unrelated process."
    fi
    rm -f -- "$PID_FILE" "$RUNTIME_FILE"
    : > "$LOG_FILE"; : > "$ERROR_LOG_FILE"
    info "Starting SignalRoom..."
    nohup "$VENV_PYTHON" -m splunk_security_agent.main \
        --host "$BIND_ADDRESS" --port "$PORT" --runtime-file "$RUNTIME_FILE" \
        >"$LOG_FILE" 2>"$ERROR_LOG_FILE" &
    local pid=$!
    printf "%s\n" "$pid" > "$PID_FILE"
    local url="" is_healthy="no"
    for _ in $(seq 1 40); do
        sleep 0.25
        ps -p "$pid" >/dev/null 2>&1 || break
        url="$(runtime_url 2>/dev/null || true)"
        if [[ -n "$url" ]] && healthy "$url"; then is_healthy="yes"; break; fi
    done
    if [[ "$is_healthy" != "yes" ]]; then
        fail "SignalRoom did not become healthy."
        info "Error log: $ERROR_LOG_FILE"
        owned_process "$pid" && kill "$pid" 2>/dev/null || true
        rm -f -- "$PID_FILE" "$RUNTIME_FILE"
        tail -n 20 "$ERROR_LOG_FILE" 2>/dev/null || true
        exit 1
    fi
    pid="$("$VENV_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["pid"])' "$RUNTIME_FILE")"
    printf "%s\n" "$pid" > "$PID_FILE"
    success "SignalRoom started successfully (PID $pid)."
    info "Workspace: $url"
    info "Logs: tail -f \"$LOG_FILE\""
    info "Errors: tail -f \"$ERROR_LOG_FILE\""
    if [[ "$OPEN_BROWSER" == "yes" ]]; then open_workspace "$url"; fi
}

stop_signalroom() {
    local pid=""; pid="$(managed_pid 2>/dev/null || true)"
    if [[ -z "$pid" ]]; then warn "SignalRoom is not running."; rm -f -- "$RUNTIME_FILE"; return; fi
    if ! ps -p "$pid" >/dev/null 2>&1; then
        warn "SignalRoom is not running (stale PID file removed)."
        rm -f -- "$PID_FILE" "$RUNTIME_FILE"; return
    fi
    if ! owned_process "$pid"; then
        fail "PID $pid is not owned by this SignalRoom installation; it will not be stopped."
        rm -f -- "$PID_FILE" "$RUNTIME_FILE"; return
    fi
    info "Stopping SignalRoom (PID $pid)..."
    kill "$pid"
    for _ in $(seq 1 20); do
        ps -p "$pid" >/dev/null 2>&1 || break
        sleep 0.25
    done
    if ps -p "$pid" >/dev/null 2>&1; then warn "Forcing shutdown..."; kill -9 "$pid"; fi
    rm -f -- "$PID_FILE" "$RUNTIME_FILE"
    success "SignalRoom stopped."
}

show_status() {
    find_python
    local pid=""; pid="$(managed_pid 2>/dev/null || true)"
    if [[ -z "$pid" ]] || ! ps -p "$pid" >/dev/null 2>&1; then
        warn "SignalRoom is not running."; rm -f -- "$PID_FILE" "$RUNTIME_FILE"; return
    fi
    if ! owned_process "$pid"; then warn "SignalRoom PID file is stale or unrelated."; return; fi
    local url; url="$(runtime_url 2>/dev/null || echo "http://localhost:$PORT")"
    success "SignalRoom is running (PID $pid)."
    info "Workspace: $url"
    if healthy "$url"; then echo "Health: healthy"; else echo "Health: starting or unavailable"; fi
    echo "Logs: $LOG_FILE"
    echo "Errors: $ERROR_LOG_FILE"
}

clear_data() {
    local data_dir="$INSTALL_DIR/data"
    rm -f -- "$data_dir/config.json" "$data_dir/secrets.enc" "$data_dir/.vault.key" "$data_dir/evidence.db"
    for folder in "$data_dir/artifacts" "$data_dir/uploads"; do
        if [[ -d "$folder" ]]; then
            find "$folder" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf -- {} +
        fi
    done
}

uninstall_signalroom() {
    if [[ "$FORCE_YES" != "yes" ]]; then
        local scope="the environment (local data is preserved)"
        [[ "$PURGE_DATA" == "yes" ]] && scope="the environment and all local data"
        warn "This will remove $scope."
        read -r -p "Continue? (yes/no): " confirmation
        [[ "$confirmation" == "yes" ]] || { info "Uninstall cancelled."; return; }
    fi
    stop_signalroom || true
    case "$VENV_DIR" in "$INSTALL_DIR"/*) ;; *) fail "Unsafe virtual environment path."; exit 1 ;; esac
    if [[ -d "$VENV_DIR" ]]; then info "Removing virtual environment..."; rm -rf -- "$VENV_DIR"; fi
    rm -f -- "$MANIFEST_FILE" "$PID_FILE" "$RUNTIME_FILE" "$LOG_FILE" "$ERROR_LOG_FILE"
    if [[ "$PURGE_DATA" == "yes" ]]; then clear_data; warn "Local SignalRoom data was removed."; fi
    success "Uninstall complete. Source code remains in $INSTALL_DIR"
}

setup_models() {
    if [[ "$INSTALL_OLLAMA" == "yes" ]] && ! command -v ollama >/dev/null 2>&1; then
        case "$(detect_os)" in
            Linux)
                info "Installing Ollama from the official ollama.com installer..."
                local installer; installer="$(mktemp)"
                curl -fsSL https://ollama.com/install.sh -o "$installer"
                sh "$installer"
                rm -f -- "$installer"
                ;;
            macOS)
                warn "Ollama for macOS uses a signed app installer. Opening the official download page."
                open https://ollama.com/download/mac
                warn "Finish installing and starting Ollama, then rerun with --setup-models --pull-models."
                return 0
                ;;
            Windows)
                fail "Use install.ps1 -InstallOllama on Windows."
                return 1
                ;;
        esac
    fi
    info "Checking model readiness..."
    "$VENV_PYTHON" -m splunk_security_agent.model_setup status
    if [[ "$PULL_MODELS" == "yes" ]]; then
        warn "Downloading configured Ollama models. This can use several gigabytes of disk and bandwidth."
        "$VENV_PYTHON" -m splunk_security_agent.model_setup pull
    fi
}

main() {
    parse_args "$@"
    case "$COMMAND" in
        help) show_help ;;
        start)
            start_signalroom
            if [[ "$SETUP_MODELS" == "yes" || "$INSTALL_OLLAMA" == "yes" || "$PULL_MODELS" == "yes" ]]; then setup_models; fi
            ;;
        stop) stop_signalroom ;;
        restart) stop_signalroom; sleep 1; start_signalroom ;;
        status) show_status ;;
        uninstall) uninstall_signalroom ;;
        "")
            info "=================================================="
            success " $APP_NAME"
            success " Version $VERSION"
            info "=================================================="
            installation_current && success "Installation is up to date." || true
            start_signalroom
            if [[ "$SETUP_MODELS" == "yes" || "$INSTALL_OLLAMA" == "yes" || "$PULL_MODELS" == "yes" ]]; then setup_models; fi
            ;;
        *) fail "Unknown command: $COMMAND"; exit 1 ;;
    esac
}

main "$@"
