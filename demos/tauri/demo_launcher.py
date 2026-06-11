#!/usr/bin/env python3
"""Encrypted Spaces Demo Launcher — single-file TUI for building and running the Tauri demo."""

import os, sys, subprocess, asyncio, signal, shutil, time, re
from pathlib import Path

# Regex to strip ANSI escape sequences from subprocess output
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# --- Venv bootstrap: ensure we're running inside our local venv with textual ---
VENV_DIR = Path(__file__).resolve().parent / ".launcher-venv"

def _in_venv() -> bool:
    return sys.prefix != sys.base_prefix

def _bootstrap_venv():
    """Create a local venv, install textual, and re-exec this script inside it."""
    venv_python = VENV_DIR / "bin" / "python3"

    if VENV_DIR.exists() and venv_python.exists():
        # Venv exists but we're not in it — re-exec
        os.execv(str(venv_python), [str(venv_python), __file__] + sys.argv[1:])

    print("The 'textual' package is required but not installed.")
    print(f"A local venv will be created at: {VENV_DIR}\n")
    resp = input("Create venv and install textual? [Y/n] ").strip().lower()
    if resp == "n":
        print("\nYou can set it up manually:")
        print(f"  python3 -m venv {VENV_DIR}")
        print(f"  {venv_python} -m pip install textual")
        print(f"  Then re-run: {venv_python} {__file__}")
        sys.exit(1)

    print("\nCreating venv...")
    subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
    print("Installing textual...")
    subprocess.check_call([str(venv_python), "-m", "pip", "install", "-q", "textual"])
    print("Done! Launching...\n")
    os.execv(str(venv_python), [str(venv_python), __file__] + sys.argv[1:])

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical, Container
    from textual.binding import Binding
    from textual.widgets import (
        Header, Footer, Static, Button, RichLog, TabbedContent, TabPane,
        Switch, Label, Rule, LoadingIndicator, Select, Input,
    )
    from textual.css.query import NoMatches
    from textual import work
except ImportError:
    if _in_venv():
        print("Installing textual into existing venv...")
        try:
            subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "textual"])
        os.execv(sys.executable, [sys.executable, __file__] + sys.argv[1:])
    _bootstrap_venv()


# ---------------------------------------------------------------------------
# Paths — the script lives in demos/tauri/, workspace root is ../../
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parent.parent  # code/prototype

# Binary paths
SERVER_BIN = WORKSPACE_ROOT / "target" / "debug" / "encrypted-spaces-backend-server"
DEMO_BIN_DEBUG = WORKSPACE_ROOT / "target" / "debug" / "encrypted-spaces-demo"
DEMO_BIN_RELEASE = WORKSPACE_ROOT / "target" / "release" / "encrypted-spaces-demo"
SERVER_BIN_RELEASE = WORKSPACE_ROOT / "target" / "release" / "encrypted-spaces-backend-server"
LOGS_DIR = SCRIPT_DIR / "logs"


def _kill_stale_on_port(port: int, our_markers: list[str]):
    """Kill processes on a port if they belong to our project.

    Returns (killed, blocking) lists. Only kills processes whose cmdline
    contains one of the our_markers strings.
    """
    killed = []
    blocking = []
    try:
        out = subprocess.check_output(
            ["lsof", "-i", f":{port}", "-n", "-P"], stderr=subprocess.DEVNULL,
        ).decode()
        seen_pids = set()
        for line in out.strip().splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 2:
                continue
            proc_name, pid_str = parts[0], parts[1]
            try:
                pid = int(pid_str)
                if pid in seen_pids:
                    continue
                seen_pids.add(pid)
                try:
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
                except FileNotFoundError:
                    cmdline = ""
                if any(m in cmdline for m in our_markers) or any(m in proc_name.lower() for m in our_markers):
                    os.kill(pid, signal.SIGTERM)
                    killed.append(f"{proc_name} (pid {pid})")
                else:
                    blocking.append(f"{proc_name} (pid {pid})")
            except (ProcessLookupError, ValueError, PermissionError):
                pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return killed, blocking


def _kill_stale_dev_servers():
    """Kill leftover Next.js dev server processes from previous demo runs."""
    killed, blocking = _kill_stale_on_port(3000, ["demos/tauri", "next"])

    # Also kill any remaining next-server processes from our project
    # that might be on other ports
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "next-server|next dev"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        killed_pids = {int(k.split("pid ")[1].rstrip(")")) for k in killed if "pid " in k}
        for pid_str in out.split():
            try:
                pid = int(pid_str)
                if pid in killed_pids:
                    continue
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
                if "demos/tauri" in cmdline:
                    os.kill(pid, signal.SIGTERM)
                    killed.append(f"next-server (pid {pid})")
            except (ProcessLookupError, ValueError, FileNotFoundError, PermissionError):
                pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return killed, blocking


def _kill_stale_backend():
    """Kill leftover backend server processes from previous demo runs."""
    return _kill_stale_on_port(8080, ["encrypted-spaces-backend-server"])


def _port_in_use(port: int) -> bool:
    """Check if a TCP port is in use."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _detect_risc0() -> bool:
    """Check if the RISC Zero toolchain is available and supported on this platform."""
    import platform
    # RISC Zero doesn't support linux+arm64
    if sys.platform == "linux" and platform.machine() in ("aarch64", "arm64"):
        return False
    # Check for rzup (risc0 version manager) or cargo-risczero subcommand
    if shutil.which("rzup") or shutil.which("r0vm"):
        return True
    try:
        subprocess.run(
            ["cargo", "risczero", "--version"],
            capture_output=True, timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Check for ~/.risc0 with actual toolchain content (not just tmp)
    risc0_dir = Path.home() / ".risc0"
    if risc0_dir.exists():
        contents = [p.name for p in risc0_dir.iterdir() if p.name != "tmp"]
        if contents:
            return True
    return False


def _get_cpu_percent() -> str:
    """Get current CPU usage as a string. Works on Linux and macOS."""
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        idle = int(parts[4])
        total = sum(int(p) for p in parts[1:])
        # Store previous values in function attribute for delta calc
        prev_idle = getattr(_get_cpu_percent, "_prev_idle", idle)
        prev_total = getattr(_get_cpu_percent, "_prev_total", total)
        _get_cpu_percent._prev_idle = idle
        _get_cpu_percent._prev_total = total
        d_idle = idle - prev_idle
        d_total = total - prev_total
        if d_total == 0:
            return "CPU: ---%"
        pct = 100.0 * (1.0 - d_idle / d_total)
        return f"CPU: {pct:4.0f}%"
    except FileNotFoundError:
        # macOS fallback
        try:
            out = subprocess.check_output(
                ["sysctl", "-n", "kern.cp_time"],
                timeout=2, stderr=subprocess.DEVNULL,
            ).decode().strip()
            return f"CPU: {out}"
        except Exception:
            return "CPU: n/a"
    except Exception:
        return "CPU: n/a"


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------
APP_CSS = """
Screen {
    background: $surface;
}

#setup-screen {
    align: center middle;
    width: 100%;
    height: 100%;
}

#setup-box {
    width: 72;
    height: auto;
    border: thick $primary;
    padding: 1 2;
    background: $panel;
}

#setup-box Static {
    width: 100%;
}

.setup-title {
    text-style: bold;
    color: $text;
    text-align: center;
    padding: 1 0;
}

.setup-description {
    color: $text-muted;
    padding: 0 0 1 0;
}

.option-row {
    height: 3;
    padding: 0 1;
    align: left middle;
}

.option-row Label {
    padding: 0 1;
}

#build-button {
    width: 100%;
    margin: 1 0 0 0;
}

#main-screen {
    width: 100%;
    height: 100%;
}

#button-bar {
    height: 3;
    padding: 0 1;
    align: left middle;
    dock: top;
}

#button-bar Button {
    margin: 0 1 0 0;
}

.log-tab {
    height: 1fr;
}

RichLog {
    width: 1fr;
    min-width: 0;
}

#status-bar {
    height: 1;
    dock: bottom;
    background: $primary;
    color: $text;
    padding: 0 1;
    layout: horizontal;
}

#status-text {
    width: 1fr;
}

#cpu-display {
    width: auto;
    min-width: 12;
    text-align: right;
    dock: right;
}

.option-label-muted {
    color: $text-muted;
    padding: 0 1;
}

#log-level-select {
    width: 100%;
    margin: 0 1;
}

#server-input {
    dock: bottom;
    margin: 0 0;
}
"""


class ProcessManager:
    """Manages async subprocesses and streams their output."""

    def __init__(self, app: "DemoLauncher"):
        self.app = app
        self.processes: dict[str, asyncio.subprocess.Process] = {}

    async def start(self, name: str, cmd: list[str], env: dict | None = None,
                    cwd: Path | None = None, log_tab: str | None = None,
                    ready_marker: str | None = None, ready_timeout: float = 60,
                    stdin_pipe: bool = False,
                    ) -> asyncio.subprocess.Process:
        """Start a subprocess.

        If ready_marker is set, this coroutine blocks until a line containing
        that string appears in the output (or ready_timeout seconds elapse).
        """
        full_env = os.environ.copy()
        full_env["NO_COLOR"] = "1"  # disable ANSI colors in subprocesses
        if env:
            full_env.update(env)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_pipe else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(cwd) if cwd else None,
            env=full_env,
            start_new_session=True,  # own process group so we can kill the tree
        )
        self.processes[name] = proc

        if ready_marker and log_tab:
            ready_event = asyncio.Event()
            asyncio.create_task(self._stream(name, proc, log_tab, ready_event, ready_marker))
            try:
                await asyncio.wait_for(ready_event.wait(), timeout=ready_timeout)
            except asyncio.TimeoutError:
                self.app._log(log_tab, f"[bold yellow]⚠ Timed out waiting for ready signal[/]")
        elif log_tab:
            asyncio.create_task(self._stream(name, proc, log_tab))

        return proc

    async def _stream(self, name: str, proc: asyncio.subprocess.Process, log_tab: str,
                      ready_event: asyncio.Event | None = None, ready_marker: str | None = None):
        # Tee process output to a log file
        log_path = LOGS_DIR / f"{name}.log"
        log_fh = None
        try:
            LOGS_DIR.mkdir(exist_ok=True)
            log_fh = open(log_path, "w")
        except OSError:
            pass
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = _ANSI_RE.sub("", line.decode("utf-8", errors="replace").rstrip("\n"))
            self.app._log(log_tab, text)
            if log_fh:
                log_fh.write(text + "\n")
                log_fh.flush()
            if ready_event and ready_marker and ready_marker in text:
                ready_event.set()
        returncode = await proc.wait()
        self.app._log(log_tab, f"\n[Process exited with code {returncode}]")
        if log_fh:
            log_fh.write(f"\n[Process exited with code {returncode}]\n")
            log_fh.close()

    async def stop(self, name: str):
        proc = self.processes.pop(name, None)
        if proc and proc.returncode is None:
            # Kill the entire process group (catches child processes like next-server)
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.terminate()
                except ProcessLookupError:
                    return
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    pass

    async def stop_all(self):
        # Stop all processes in parallel
        names = list(self.processes.keys())
        await asyncio.gather(*(self.stop(name) for name in names))

    def is_running(self, name: str) -> bool:
        proc = self.processes.get(name)
        return proc is not None and proc.returncode is None


class DemoLauncher(App):
    """Encrypted Spaces Demo Launcher."""

    TITLE = "Encrypted Spaces Demo Launcher"
    CSS = APP_CSS
    ALLOW_SELECT = True

    BINDINGS = [
        Binding("q", "request_quit", "Quit"),
        Binding("n", "launch_instance", "New Instance"),
        Binding("question_mark", "noop", "Shift+drag to select, Ctrl+C to copy", key_display="💡"),
    ]

    def action_noop(self) -> None:
        pass

    def __init__(self):
        super().__init__()
        self.proc_mgr = ProcessManager(self)
        self.risc0_available = _detect_risc0()
        self.use_risc0 = self.risc0_available
        self.release_build = False
        self.gpu_proving = False
        self.cache_disabled = False
        self.log_level = "info"
        self.default_zoom = 100
        self.instance_counter = 0
        self.phase = "setup"  # setup | building | running
        self._cpu_timer = None

    # -- Setup screen -------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="setup-screen"):
            with Vertical(id="setup-box"):
                yield Static("⬡  Encrypted Spaces Demo Launcher", classes="setup-title")
                yield Rule()
                yield Static(
                    "This will build and launch the Tauri demo.\n"
                    "A backend server and one or more app instances will be started.",
                    classes="setup-description",
                )
                with Horizontal(classes="option-row"):
                    yield Switch(id="risc0-switch", value=self.risc0_available,
                                 disabled=not self.risc0_available)
                    if self.risc0_available:
                        yield Label("Build with RISC Zero proving (detected)")
                    elif sys.platform == "linux" and __import__("platform").machine() in ("aarch64", "arm64"):
                        yield Label("RISC Zero proving (not supported on linux/arm64)",
                                    classes="option-label-muted")
                    else:
                        yield Label("RISC Zero proving (not detected — install rzup to enable)",
                                    classes="option-label-muted")
                with Horizontal(classes="option-row"):
                    yield Switch(id="release-switch", value=False)
                    yield Label("Release build (slower build, faster runtime)")
                with Horizontal(classes="option-row"):
                    yield Switch(id="gpu-switch", value=False,
                                 disabled=not self.risc0_available)
                    if self.risc0_available:
                        yield Label("GPU Proving - CUDA")
                    else:
                        yield Label("GPU Proving - CUDA (requires RISC Zero)",
                                    classes="option-label-muted")
                with Horizontal(classes="option-row"):
                    yield Switch(id="cache-switch", value=False)
                    yield Label("Disable client-side cache")
                yield Label("  Log level", classes="option-label-muted")
                yield Select(
                    [("error", "error"), ("warn", "warn"), ("info", "info"),
                     ("debug", "debug"), ("trace", "trace")],
                    value="info",
                    id="log-level-select",
                    allow_blank=False,
                )
                yield Label("  Default zoom (%)", classes="option-label-muted")
                yield Select(
                    [("50%", 50), ("60%", 60), ("70%", 70), ("80%", 80), ("90%", 90),
                     ("100%", 100), ("110%", 110), ("120%", 120), ("130%", 130),
                     ("140%", 140), ("150%", 150), ("160%", 160), ("170%", 170),
                     ("180%", 180), ("190%", 190), ("200%", 200)],
                    value=100,
                    id="zoom-select",
                    allow_blank=False,
                )
                yield Rule()
                yield Button("Build & Launch", id="build-button", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        # Focus the build button so the user can just press Enter
        self.query_one("#build-button", Button).focus()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "risc0-switch":
            self.use_risc0 = event.value
            # GPU proving requires RISC Zero; clear it when RISC0 is turned off.
            if not event.value and self.gpu_proving:
                self.gpu_proving = False
                try:
                    self.query_one("#gpu-switch", Switch).value = False
                except NoMatches:
                    pass
        elif event.switch.id == "release-switch":
            self.release_build = event.value
        elif event.switch.id == "gpu-switch":
            self.gpu_proving = event.value
            # GPU proofs only work with RISC Zero; auto-enable it.
            if event.value and not self.use_risc0:
                self.use_risc0 = True
                try:
                    self.query_one("#risc0-switch", Switch).value = True
                except NoMatches:
                    pass
        elif event.switch.id == "cache-switch":
            self.cache_disabled = event.value

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "log-level-select":
            self.log_level = str(event.value)
        elif event.select.id == "zoom-select":
            self.default_zoom = int(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "server-input":
            cmd_text = event.value.strip()
            if cmd_text and self.proc_mgr.is_running("server"):
                proc = self.proc_mgr.processes["server"]
                if proc.stdin:
                    proc.stdin.write((cmd_text + "\n").encode())
                    self._log("server", f"[bold green]> {cmd_text}[/]")
            event.input.value = ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "build-button":
            self._start_build()
        elif event.button.id == "launch-btn":
            self.action_launch_instance()
        elif event.button.id == "stop-all-btn":
            self._stop_all()

    # -- Build phase --------------------------------------------------------

    def _start_build(self):
        self.phase = "building"
        setup = self.query_one("#setup-screen")
        setup.remove()
        self._mount_main_screen()
        self._run_build()

    def _mount_main_screen(self):
        main = Vertical(id="main-screen")
        self.mount(main, before=self.query_one(Footer))

        bar = Horizontal(id="button-bar")
        main.mount(bar)
        bar.mount(Button("Launch Instance", id="launch-btn", variant="success", disabled=True))
        bar.mount(Button("Stop All & Quit", id="stop-all-btn", variant="error"))

        tabs = TabbedContent(id="tabs")
        main.mount(tabs)

        status_bar = Horizontal(id="status-bar")
        main.mount(status_bar)
        status_bar.mount(Static("⏳ Building...", id="status-text"))
        status_bar.mount(Static("CPU: ---%", id="cpu-display"))

        # Add the build log tab
        build_pane = TabPane("Build", id="tab-build")
        tabs.add_pane(build_pane)
        build_log = RichLog(id="log-build", highlight=True, markup=True, wrap=True, min_width=0)
        build_pane.mount(build_log)

        # Start CPU monitor
        self._start_cpu_monitor()

    def _log(self, tab_id: str, text: str):
        """Write a line to a log tab. Safe to call from callbacks."""
        try:
            log_widget = self.query_one(f"#log-{tab_id}", RichLog)
            log_widget.write(text)
        except NoMatches:
            pass

    @work(thread=True)
    def _run_build(self):
        """Run the build steps sequentially in a worker thread."""
        import subprocess as sp

        env_extra = {} if self.use_risc0 else {"RISC0_SKIP_BUILD": "1"}
        full_env = {**os.environ, "NO_COLOR": "1", **env_extra}

        server_bin = SERVER_BIN_RELEASE if self.release_build else SERVER_BIN
        demo_bin = DEMO_BIN_RELEASE if self.release_build else DEMO_BIN_DEBUG
        cargo_profile_args = ["--release"] if self.release_build else []

        steps = []

        # npm install — check if node_modules exists and package.json hasn't changed
        node_modules = SCRIPT_DIR / "node_modules"
        pkg_json = SCRIPT_DIR / "package.json"
        pkg_lock = SCRIPT_DIR / "package-lock.json"
        npm_stamp = node_modules / ".install-stamp" if node_modules.exists() else None
        npm_stale = not node_modules.exists() or (
            npm_stamp is not None and (
                not npm_stamp.exists()
                or (pkg_json.exists() and pkg_json.stat().st_mtime > npm_stamp.stat().st_mtime)
                or (pkg_lock.exists() and pkg_lock.stat().st_mtime > npm_stamp.stat().st_mtime)
            )
        )
        if npm_stale:
            steps.append(
                ("Installing frontend dependencies...",
                 ["npm", "--prefix", "demos/tauri", "install"],
                 WORKSPACE_ROOT),
            )
        else:
            self.call_from_thread(self._log, "build",
                                  "[dim]✓ Frontend dependencies already installed[/]")

        # Always run cargo build — Cargo's own fingerprinting handles
        # staleness detection and is a fast no-op when nothing changed.
        # When GPU proving is on, the server needs --features cuda,real-proofs,
        # which can't share an invocation with the demo binary (features only
        # apply to packages that declare them). Otherwise build both at once
        # to avoid paying Cargo's startup overhead twice.
        if self.gpu_proving and self.use_risc0:
            steps.append(
                ("Building server (--features cuda,real-proofs)...",
                 ["cargo", "build", "-p", "encrypted-spaces-backend-server",
                  "--features", "cuda,real-proofs"] + cargo_profile_args,
                 WORKSPACE_ROOT),
            )
            steps.append(
                ("Building demo binary...",
                 ["cargo", "build", "-p", "encrypted-spaces-demo"] + cargo_profile_args,
                 WORKSPACE_ROOT),
            )
        else:
            steps.append(
                ("Building Rust binaries...",
                 ["cargo", "build",
                  "-p", "encrypted-spaces-backend-server",
                  "-p", "encrypted-spaces-demo"] + cargo_profile_args,
                 WORKSPACE_ROOT),
            )

        npm_cmd = ["npm", "--prefix", "demos/tauri", "install"]

        for description, cmd, cwd in steps:
            self.call_from_thread(self._log, "build", f"\n[bold cyan]▶ {description}[/]")
            try:
                proc = sp.Popen(
                    cmd, stdout=sp.PIPE, stderr=sp.STDOUT,
                    cwd=str(cwd), env=full_env,
                )
                for line in iter(proc.stdout.readline, b""):
                    text = _ANSI_RE.sub("", line.decode("utf-8", errors="replace").rstrip("\n"))
                    self.call_from_thread(self._log, "build", text)
                proc.wait()
                if proc.returncode != 0:
                    self.call_from_thread(self._log, "build",
                                          f"\n[bold red]✗ Step failed (exit {proc.returncode})[/]")
                    self.call_from_thread(self._update_status, "❌ Build failed")
                    return
                # After successful npm install, write a stamp so we can detect
                # when package.json changes relative to the last install.
                if cmd == npm_cmd:
                    try:
                        (SCRIPT_DIR / "node_modules" / ".install-stamp").touch()
                    except OSError:
                        pass
                self.call_from_thread(self._log, "build",
                                      f"[bold green]✓ Done[/]")
            except FileNotFoundError as e:
                self.call_from_thread(self._log, "build",
                                      f"\n[bold red]✗ Command not found: {e}[/]")
                self.call_from_thread(self._update_status, "❌ Build failed")
                return

        self.call_from_thread(self._log, "build",
                              "\n[bold green]✓ Build complete![/]")
        self.call_from_thread(self._on_build_complete)

    def _on_build_complete(self):
        self.phase = "running"
        self._update_status("✅ Build complete — launching server...")
        try:
            self.query_one("#launch-btn", Button).disabled = False
        except NoMatches:
            pass
        self._launch_server()

    def _update_status(self, text: str):
        try:
            self.query_one("#status-text", Static).update(text)
        except NoMatches:
            pass

    def _start_cpu_monitor(self):
        """Start a timer that updates CPU usage every second."""
        _get_cpu_percent()  # prime the delta calculation
        self._cpu_timer = self.set_interval(1.0, self._update_cpu)

    def _update_cpu(self):
        try:
            self.query_one("#cpu-display", Static).update(_get_cpu_percent())
        except NoMatches:
            pass

    # -- Server & instance management ----------------------------------------

    @work()
    async def _launch_server(self):
        env = {} if self.use_risc0 else {"RISC0_SKIP_BUILD": "1"}
        env["RUST_LOG"] = self.log_level
        if self.cache_disabled:
            env["CACHE_DISABLED"] = "1"

        # Clean up stale processes from previous runs
        # Backend server on port 8080
        stale_be, blocking_be = _kill_stale_backend()
        if stale_be:
            for s in stale_be:
                self._log("build", f"[dim]Killed stale backend: {s}[/]")
            for _ in range(10):
                await asyncio.sleep(0.5)
                if not _port_in_use(8080):
                    break
        if blocking_be:
            self._log("build", "[bold red]✗ Port 8080 is in use by an unrelated process:[/]")
            for b in blocking_be:
                self._log("build", f"[bold red]  {b}[/]")
            self._log("build", "[bold red]Please free port 8080 and try again.[/]")
            self._update_status("❌ Port 8080 is blocked by another process")
            return

        # Next.js dev server on port 3000
        stale, blocking = _kill_stale_dev_servers()
        if stale:
            for s in stale:
                self._log("build", f"[dim]Killed stale process: {s}[/]")
            for _ in range(10):
                await asyncio.sleep(0.5)
                if not _port_in_use(3000):
                    break
        if blocking:
            self._log("build", "[bold red]✗ Port 3000 is in use by an unrelated process:[/]")
            for b in blocking:
                self._log("build", f"[bold red]  {b}[/]")
            self._log("build", "[bold red]Please free port 3000 and try again.[/]")
            self._update_status("❌ Port 3000 is blocked by another process")
            return

        # Use the binary directly to avoid cargo rebuild overhead
        server_bin = SERVER_BIN_RELEASE if self.release_build else SERVER_BIN
        if server_bin.exists():
            cmd = [
                str(server_bin),
                "--schema", str(WORKSPACE_ROOT / "demos" / "tauri" / "app_schema.kdl"),
            ]
        else:
            cmd = [
                "cargo", "run", "-p", "encrypted-spaces-backend-server",
                "--", "--schema", "./demos/tauri/app_schema.kdl",
            ]

        # Add server tab
        tabs = self.query_one("#tabs", TabbedContent)
        server_pane = TabPane("Server", id="tab-server")
        await tabs.add_pane(server_pane)
        server_log = RichLog(id="log-server", highlight=True, markup=True, wrap=True, min_width=0)
        server_input = Input(id="server-input", placeholder="Type a server command (e.g. p, c) and press Enter...")
        await server_pane.mount(server_log, server_input)

        self._log("server", "[bold cyan]▶ Starting backend server...[/]")
        self._log("server", f"  cmd: {' '.join(cmd)}")
        self._log("server", f"  cwd: {WORKSPACE_ROOT}\n")

        await self.proc_mgr.start(
            "server", cmd, env=env, cwd=WORKSPACE_ROOT,
            log_tab="server",
            stdin_pipe=True,
        )

        # Start the Next.js dev server separately so it persists even if
        # individual app instances are closed.
        devserver_pane = TabPane("Next.js Server", id="tab-devserver")
        await tabs.add_pane(devserver_pane)
        devserver_log = RichLog(id="log-devserver", highlight=True, markup=True, wrap=True, min_width=0)
        await devserver_pane.mount(devserver_log)

        self._log("devserver", "[bold cyan]▶ Starting Next.js dev server (localhost:3000)...[/]")
        dev_cmd = ["npm", "--prefix", "demos/tauri", "run", "dev"]
        self._log("devserver", f"  cmd: {' '.join(dev_cmd)}")
        self._log("devserver", f"  cwd: {WORKSPACE_ROOT}\n")

        await self.proc_mgr.start(
            "devserver", dev_cmd, env=env, cwd=WORKSPACE_ROOT,
            log_tab="devserver",
            ready_marker="Ready",
            ready_timeout=30,
        )

        self._log("devserver", "[bold green]✓ Dev server ready[/]")
        self._update_status("✅ Servers running — launching first app instance...")

        # Auto-launch first instance
        self.instance_counter += 1
        await self._do_launch_instance_async(self.instance_counter)

    def action_launch_instance(self):
        if self.phase != "running":
            return
        self.instance_counter += 1
        self._do_launch_instance(self.instance_counter)

    @work()
    async def _do_launch_instance(self, instance_id: int):
        await self._do_launch_instance_async(instance_id)

    async def _do_launch_instance_async(self, instance_id: int):
        name = f"app-{instance_id}"
        tab_label = f"App {instance_id}"

        # Add tab
        tabs = self.query_one("#tabs", TabbedContent)
        pane = TabPane(tab_label, id=f"tab-{name}")
        await tabs.add_pane(pane)
        log_widget = RichLog(id=f"log-{name}", highlight=True, markup=True, wrap=True, min_width=0)
        await pane.mount(log_widget)

        # Switch to the new tab
        tabs.active = f"tab-{name}"

        env = {} if self.use_risc0 else {"RISC0_SKIP_BUILD": "1"}
        env["RUST_LOG"] = self.log_level
        if self.cache_disabled:
            env["CACHE_DISABLED"] = "1"

        # All instances use the binary directly. The Next.js dev server
        # runs as a separate long-lived process so closing any app instance
        # doesn't affect the others.
        demo_bin = DEMO_BIN_RELEASE if self.release_build else DEMO_BIN_DEBUG
        if demo_bin.exists():
            cmd = [str(demo_bin)]
        else:
            cmd = ["cargo", "run", "-p", "encrypted-spaces-demo", "--"]
        if self.default_zoom != 100:
            cmd.append(f"--default-zoom={self.default_zoom}")
        LOGS_DIR.mkdir(exist_ok=True)
        cmd.append(f"--logfile={LOGS_DIR / f'{name}.log'}")

        self._log(name, f"[bold cyan]▶ Launching {tab_label}...[/]")
        self._log(name, f"  cmd: {' '.join(cmd)}")
        self._log(name, f"  cwd: {WORKSPACE_ROOT}\n")

        await self.proc_mgr.start(
            name, cmd, env=env, cwd=WORKSPACE_ROOT,
            log_tab=name,
        )

        running = sum(1 for k in self.proc_mgr.processes if k.startswith("app-")
                      and self.proc_mgr.is_running(k))
        self._update_status(f"✅ Server + {running} instance(s) running — press N for more")

    # -- Shutdown ------------------------------------------------------------

    @work()
    async def _stop_all(self):
        self._update_status("⏳ Stopping all processes...")
        await self.proc_mgr.stop_all()
        # Also clean up any stale next-server processes just in case
        _kill_stale_dev_servers()
        self._update_status("All processes stopped.")
        await asyncio.sleep(0.3)
        self.exit()

    async def action_request_quit(self):
        if self.proc_mgr.processes:
            self._stop_all()
        else:
            self.exit()

    def action_copy_selection(self) -> None:
        """Copy selected text to clipboard."""
        selection = self.get_selection()
        if selection:
            self.copy_to_clipboard(selection)
            self.notify("Copied to clipboard", timeout=1)


if __name__ == "__main__":
    app = DemoLauncher()
    app.run()
