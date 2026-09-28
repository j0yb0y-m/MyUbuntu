#!/usr/bin/env python3

import argparse
import atexit
import contextlib
import glob
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import pwd
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path


# paths

HOME_DIR = Path.home()
WORKING_DIR = HOME_DIR / "tools"
WORDLISTS_DIR = WORKING_DIR / "wordlists"
EXPLOITS_DIR = WORKING_DIR / "exploits"
GO_DIR = HOME_DIR / "go"
LOG_FILE = WORKING_DIR / "myubuntu.log"
STATE_FILE = WORKING_DIR / ".myubuntu-state.json"

# Where the official Exploit-DB git checkout lives. This exact path matters:
# searchsploit's bundled .searchsploit_rc already defaults to it, so no
# per-user config is needed.
EXPLOITDB_DIR = Path("/opt/exploitdb")


# logging

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"
    BRED = "\033[1;31m"
    BGREEN = "\033[1;32m"


_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text, color):
    return f"{color}{text}{C.RESET}" if _COLOR else text


log = logging.getLogger("myubuntu")


class _ConsoleFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: C.GREY,
        logging.INFO: C.GREEN,
        logging.WARNING: C.YELLOW,
        logging.ERROR: C.RED,
        logging.CRITICAL: C.BRED,
    }

    def format(self, record):
        stamp = self.formatTime(record, "%H:%M:%S")
        color = self.LEVEL_COLORS.get(record.levelno, "")
        head = f"{_c(stamp, C.GREY)} " if _COLOR else f"{stamp} "
        tail = f" [{record.levelname}]"
        body = f"{color}{record.getMessage()}{tail}{C.RESET}" if _COLOR \
            else f"{record.getMessage()}{tail}"
        if record.exc_info:
            body += "\n" + self.formatException(record.exc_info)
        return head + body


class _TailHandler(logging.Handler):
    """Feeds the last few records to the live display's tail pane.

    It reads the LogRecord rather than formatted output, so the colour codes
    _ConsoleFormatter injects never have to be parsed back out again. maxlen
    on the deque does the trimming.
    """

    def __init__(self, sink):
        super().__init__(logging.DEBUG)
        self.sink = sink

    def emit(self, record):
        try:
            self.sink.append((record.levelno, record.getMessage()))
        except Exception:
            pass


# Last few log records, for the live tail pane. Also the heartbeat's source.
TAIL = deque(maxlen=6)

# The stdout handler, which the live display mutes while it owns the terminal
# (anything written to stdout mid-bar tears the bar apart).
_console_handler = None


def setup_logging(level, quiet=False):
    global _console_handler

    log.setLevel(logging.DEBUG)
    log.propagate = False
    for h in list(log.handlers):
        log.removeHandler(h)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.CRITICAL if quiet else level)
    console.setFormatter(_ConsoleFormatter())
    log.addHandler(console)
    _console_handler = console
    log.addHandler(_TailHandler(TAIL))

    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Rotated, not append-forever: _exec streams every line of every
        # command at DEBUG, and `go install -v` across seventeen toolchains is
        # enough on its own to fill a disk over a long run.
        disk = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=5 << 20, backupCount=3, encoding="utf-8",
        )
        disk.setLevel(logging.DEBUG)
        disk.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(message)s", "%Y-%m-%d %H:%M:%S")
        )
        log.addHandler(disk)
    except OSError as e:
        console.setLevel(level)
        sys.stderr.write(f"[!] could not open {LOG_FILE}: {e}\n")


# state

class State:
    """Records what finished so a re-run resumes instead of restarting."""

    def __init__(self, path):
        self.path = path
        self.data = {}
        self.dirty = False
        try:
            self.data = json.loads(path.read_text())
            if not isinstance(self.data, dict):
                self.data = {}
        except (OSError, json.JSONDecodeError):
            self.data = {}

    def done(self, key):
        entry = self.data.get(key)
        return isinstance(entry, dict) and entry.get("status") == "ok"

    def mark(self, key, status="ok", **extra):
        # A dry run must never poison the resume state, or the next real run
        # would skip work that never actually happened.
        if DRY_RUN:
            return
        entry = {"status": status, "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
        entry.update(extra)
        self.data[key] = entry
        self.dirty = True
        self.save()

    def save(self):
        if not self.dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n")
            tmp.replace(self.path)
            self.dirty = False
        except OSError as e:
            log.debug("could not persist state: %s", e)


state = State(STATE_FILE)


# ui: live progress display
# Three tiers, chosen automatically, with no flag to remember:
#
#   live       stdout is a tty and rich imported  -> Live progress + tail pane
#   heartbeat  no tty (nohup, piped into tee)     -> one line per minute
#   plain      rich missing, --quiet, --dry-run   -> exactly today's behaviour
#
# The fallback matters more than the bar. A progress display is the one part of
# this script that is allowed to fail without taking the run down with it, so
# every rich call below is guarded and every entry point is a no-op until
# enable() decides the terminal can be taken over.

_RICH = {}


def _load_rich():
    """Import rich on demand rather than at module scope.

    On a fresh box rich only exists after the progress-ui step installs it, so
    an import-time attempt would pin the script to the plain logger for the
    whole run no matter what apt did later. The submodules are stashed rather
    than their individual names so callers reach them as _RICH["text"].Text and
    friends -- importing bare names into a function scope would make them
    invisible to everything else in this module.
    """
    if _RICH:
        return True
    try:
        from rich import console, live, panel, progress, table, text
    except Exception:
        return False
    _RICH.update(console=console, live=live, panel=panel,
                 progress=progress, table=table, text=text)
    return True


def _fmt_bytes(n):
    if n is None:
        return "?"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def _fmt_span(seconds):
    if seconds is None or seconds != seconds or seconds < 0:
        return ""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


_TAIL_STYLE = {
    logging.DEBUG: "dim",
    logging.INFO: "green",
    logging.WARNING: "yellow",
    logging.ERROR: "red",
    logging.CRITICAL: "bold red",
}
_TAIL_NAME = {
    logging.DEBUG: "dbg",
    logging.INFO: "info",
    logging.WARNING: "warn",
    logging.ERROR: "err",
    logging.CRITICAL: "fatal",
}


class _Tail:
    """Renders TAIL, read live on every repaint.

    This has to be an object with __rich_console__ rather than a table built
    once at startup: rich re-renders this each frame, so new log lines appear
    without rebuilding the layout. A table snapshotted up front renders an
    empty panel for the entire run.
    """

    def __rich_console__(self, console, options):
        Text = _RICH["text"].Text
        table = _RICH["table"].Table.grid(padding=(0, 1))
        # overflow="ignore" keeps the level column intact; only the message
        # column is allowed to crop, otherwise "warn" renders as "w...".
        table.add_column(width=4, no_wrap=True, overflow="ignore")
        table.add_column(overflow="ellipsis", no_wrap=True)
        if not TAIL:
            table.add_row(Text("info", style="dim"),
                          Text("(no output yet)", style="dim"))
        for level, message in TAIL:
            style = _TAIL_STYLE.get(level, "white")
            table.add_row(Text(_TAIL_NAME.get(level, "info"), style=style),
                          Text(message, style=style))
        yield table


class _Row:
    """Handle for one live row. Every method is a no-op once it is closed."""

    def __init__(self, owner, task_id, label):
        self.owner = owner
        self.id = task_id
        self.label = label
        self.closed = False

    def note(self, text):
        if not self.closed and self.id is not None:
            self.owner._set(self.id, note=text)

    def advance(self, n=1):
        if not self.closed and self.id is not None:
            self.owner._advance(self.id, n)

    def set_bytes(self, count, total=None, speed=None):
        if self.closed or self.id is None:
            return
        # completed has to be updated too, or the bar and the percentage stay
        # at zero while the note text races ahead of them.
        if total:
            self.owner._set(self.id, completed=min(count, total))
            parts = [f"{_fmt_bytes(count)}/{_fmt_bytes(total)}"]
            if speed:
                parts.append(f"{_fmt_bytes(speed)}/s")
                parts.append(f"{_fmt_span((total - count) / speed)} left")
            self.note(" · ".join(parts))
        else:
            self.owner._set(self.id, completed=count)
            self.note(_fmt_bytes(count))

    def end(self):
        if self.closed:
            return
        self.closed = True
        if self.id is not None:
            self.owner._close(self.id)


class UI:
    """Live progress facade. Inert until enable() succeeds."""

    def __init__(self):
        self.mode = "plain"
        self.live = None
        self.progress = None
        self.console = None
        self._overall = None
        self._step_row = None
        self._step_name = ""
        self._index = 0
        self._total = 0
        self._done = 0
        self._console_level = None
        self._halt = threading.Event()
        self._beater = None

    # activation

    def enable(self, total_steps=0, quiet=False):
        if self.mode == "live":
            return self.mode
        self._total = total_steps
        if (not quiet
                and not DRY_RUN
                and sys.stdout.isatty()
                and os.environ.get("NO_COLOR") is None
                and os.environ.get("TERM") != "dumb"
                and _load_rich()):
            try:
                self._start_live()
                self.mode = "live"
                return self.mode
            except Exception as e:
                # Any rich failure at all lands here and the run carries on.
                log.debug("live display unavailable (%s: %s); using plain output",
                          type(e).__name__, e)
                self._restore_console()
                self.live = None
        if not quiet and not DRY_RUN and not sys.stdout.isatty():
            self._start_heartbeat()
            self.mode = "heartbeat"
        return self.mode

    def _start_live(self):
        self.console = _RICH["console"].Console(soft_wrap=False)
        progress_mod = _RICH["progress"]
        self.progress = progress_mod.Progress(
            progress_mod.SpinnerColumn(),
            progress_mod.TextColumn("[bold]{task.description}"),
            progress_mod.TextColumn("[dim]{task.fields[note]}"),
            progress_mod.BarColumn(bar_width=20),
            progress_mod.TaskProgressColumn(),
            progress_mod.TimeElapsedColumn(),
            console=self.console,
            expand=True,
        )
        self._overall = self.progress.add_task("MyUbuntu", total=max(self._total, 1), note="")
        # total=None gives a pulse bar: honest about a step having no
        # measurable progress, where a 0% bar would just look broken.
        self._step_row = self.progress.add_task("starting", total=None, note="")
        # Progress is used here as a renderable, never start()ed -- starting it
        # would spawn a second Live and the two displays would fight.
        self.live = _RICH["live"].Live(
            _RICH["console"].Group(
                self.progress,
                _RICH["panel"].Panel(_Tail(), title="recent output",
                                     border_style="grey37", padding=(0, 1)),
            ),
            console=self.console,
            refresh_per_second=6,
            transient=False,
        )
        self.live.start()
        # The display owns the terminal now; any other stdout write tears the
        # bar apart, so mute the console handler and leave the file handler.
        if _console_handler is not None:
            self._console_level = _console_handler.level
            _console_handler.setLevel(logging.CRITICAL + 10)

    def _restore_console(self):
        if _console_handler is not None and self._console_level is not None:
            try:
                _console_handler.setLevel(self._console_level)
            except Exception:
                pass
        self._console_level = None

    def _start_heartbeat(self):
        if self._beater is not None:
            return

        def beat():
            while not self._halt.wait(60):
                if not TAIL:
                    continue
                level, message = TAIL[-1]
                log.info("heartbeat: step %s/%s %s | %s: %s",
                         self._index or "-", self._total or "-", self._step_name,
                         _TAIL_NAME.get(level, "info"), message[:160])

        self._beater = threading.Thread(target=beat, daemon=True)
        self._beater.start()

    # progress mutation

    def _set(self, task_id, **kw):
        if self.progress is None or task_id is None:
            return
        try:
            self.progress.update(task_id, **kw)
        except Exception:
            pass

    def _advance(self, task_id, n=1):
        if self.progress is None or task_id is None:
            return
        try:
            self.progress.advance(task_id, n)
        except Exception:
            pass

    def _close(self, task_id):
        if self.progress is None:
            return
        try:
            self.progress.update(task_id, total=1, completed=1)
            self.progress.remove_task(task_id)
        except Exception:
            pass

    def _overall_label(self):
        if self._total:
            self._set(self._overall, total=self._total,
                      description=f"MyUbuntu  {self._done}/{self._total}")

    def step_start(self, name, index=0, total=0):
        self._step_name = name
        self._index = index
        if total:
            self._total = total
        if self.mode != "live":
            return
        self._overall_label()
        self._set(self._step_row, description=name, total=None, completed=0, note="")

    def step_end(self, ok, seconds=0):
        if self.mode != "live":
            return
        self._done += 1
        self._advance(self._overall, 1)
        self._overall_label()
        self._set(self._step_row, description=f"{self._step_name}  "
                                              f"{'ok' if ok else 'FAILED'}  "
                                              f"({int(seconds)}s)")

    def subtask(self, label, total=None):
        """A counted row. total=None renders a pulse instead of a bar."""
        if self.mode != "live" or self.progress is None:
            return _Row(self, None, label)
        try:
            task_id = self.progress.add_task(label, total=total, note="")
        except Exception:
            return _Row(self, None, label)
        return _Row(self, task_id, label)

    def download(self, label, total=None):
        row = self.subtask(label, total=total or None)
        if total is None:
            row.note("size unknown")
        return row

    @contextlib.contextmanager
    def task(self, label, total=None, note=""):
        """A live row for a span of work, closed even if the body raises."""
        row = self.subtask(label, total=total)
        if note:
            row.note(note)
        try:
            yield row
        finally:
            row.end()

    # teardown

    def stop(self):
        self._halt.set()
        if self.live is not None:
            try:
                self.live.stop()
            except Exception:
                pass
            self.live = None
        self._restore_console()


ui = UI()


# run: the single choke point for every external command

DRY_RUN = False

# Set only by --update. The install steps are shared between the two modes, so
# this is what turns their "already present, skipping" checks off -- otherwise
# --update would conclude there was nothing to do on a fully installed box.
UPDATE = False


def _fmt_cmd(cmd):
    if isinstance(cmd, str):
        return cmd
    out = []
    for part in cmd:
        if not out or not re.match(r"^[A-Za-z0-9_@%+=:,./-]+$", part):
            out.append(f"'{part}'")
        else:
            out.append(part)
    return " ".join(out)


def _terminate_group(proc, grace=10):
    """Kill proc's entire process group, escalating SIGTERM -> SIGKILL.

    A single proc.kill() only signals the direct child. When that child is
    `sudo` (or a shell wrapper script like msfinstall), the process actually
    doing the work -- apt-get, dpkg, a maintainer script -- is a grandchild
    that a single-PID kill never touches, so it just keeps running, still
    holding the dpkg lock, after we've given up on it. Since _exec() starts
    every command in its own session (start_new_session=True), the child's
    PID is also its process group ID, so killpg reaches the whole tree.

    Note dpkg deliberately ignores SIGTERM/SIGINT mid-transaction to avoid
    corrupting the package database, which is why this escalates to SIGKILL
    after a grace period instead of waiting forever -- but it does mean a
    forced interrupt during a package install can leave dpkg's state
    half-configured; `sudo dpkg --configure -a` cleans that up.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    if pgid == os.getpgid(0):
        # This child was run with new_session=False (currently: only the
        # interactive `sudo -v` prompt, which needs our controlling
        # terminal), so it shares our own process group instead of having
        # its own. killpg here would signal ourselves too -- fall back to a
        # plain single-PID kill instead.
        try:
            proc.kill()
            proc.wait(timeout=grace)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            grace = 3  # short fuse before escalating to SIGKILL


def _exec(cmd, timeout=None, cwd=None, env=None, input_bytes=None, new_session=True):
    """Run a command once, streaming its output into the log file at DEBUG.

    Returns (returncode, combined_output, error_message).

    new_session=False is a narrow escape hatch for the one call that must
    keep our controlling terminal: an interactive `sudo -v`. sudo opens
    /dev/tty directly to prompt for a password, independent of stdin/stdout,
    but /dev/tty resolves to "this session's controlling terminal" -- with
    no controlling terminal at all (new_session=True's whole point), that
    open fails and sudo aborts instantly instead of prompting. Every other
    caller should leave this at the default.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            # Its own session, not ours: a bare Ctrl+C at the terminal would
            # otherwise race this child for the SIGINT (and dpkg/apt-get are
            # known to just ignore it mid-transaction), and a debconf/dialog
            # frontend falling back to /dev/tty can no longer reach our real
            # terminal from a session with no controlling tty of its own.
            start_new_session=new_session,
        )
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0] if not isinstance(cmd, str) else cmd}"
    except PermissionError as e:
        return 126, "", str(e)
    except OSError as e:
        return 126, "", str(e)

    chunks = []

    def _drain():
        try:
            for raw in iter(proc.stdout.readline, b""):
                text = raw.decode("utf-8", "replace")
                chunks.append(text)
                log.debug("%s", text.rstrip("\n"))
        except (OSError, ValueError):
            pass
        finally:
            try:
                proc.stdout.close()
            except OSError:
                pass

    if input_bytes is not None:
        try:
            proc.stdin.write(input_bytes)
            proc.stdin.close()
        except OSError:
            pass

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_group(proc)
    except BaseException:
        # Covers KeyboardInterrupt (and anything else unexpected): without
        # this, Ctrl+C unwinds out of Python cleanly while the real work --
        # apt-get, dpkg, msfinstall -- keeps running in the background,
        # which is exactly what "can't quit with Ctrl+C" looks like from the
        # terminal (the prompt comes back, but the box is still busy, still
        # holding the dpkg lock, for however long that command had left).
        _terminate_group(proc)
        reader.join(timeout=5)
        raise
    reader.join(timeout=15)

    out = "".join(chunks)
    if timed_out:
        return 124, out, f"timed out after {timeout}s"
    return proc.returncode, out, None


def _attempt(cmd, timeout, cwd, env, input_bytes, new_session=True):
    if DRY_RUN:
        return 0, "", None
    return _exec(cmd, timeout=timeout, cwd=cwd, env=env, input_bytes=input_bytes, new_session=new_session)


def run(cmd, timeout=None, retries=0, cwd=None, env=None, input_bytes=None,
        show=True, fatal=False, new_session=True):
    """Run a command with retries and a timeout. Returns True/False.

    Retries apply to timeouts and to non-zero exits -- for the install
    commands below, a non-zero exit on a flaky link is almost always a
    network blip rather than a deterministic failure. Keep retries=0 for
    anything non-idempotent.
    """
    if show:
        log.info("%s", _fmt_cmd(cmd))

    delay = 3.0
    rc, out, err = 0, "", None
    for attempt in range(retries + 1):
        rc, out, err = _attempt(cmd, timeout, cwd, env, input_bytes, new_session=new_session)
        if rc == 0:
            return True
        if rc == 127:
            log.error("Command not found: %s", _fmt_cmd(cmd))
            break
        if attempt < retries:
            log.warning(
                "Failed (rc=%s), retry %d/%d in %.0fs: %s",
                rc, attempt + 1, retries, delay, _fmt_cmd(cmd),
            )
            time.sleep(delay)
            delay = min(delay * 2, 60) * (0.75 + 0.5 * random.random())
        else:
            break

    log.error("Failed (rc=%s)%s: %s", rc, f" -- {err}" if err else "", _fmt_cmd(cmd))
    if out.strip():
        for line in out.strip().splitlines()[-12:]:
            log.error("  | %s", line)
    if fatal:
        sys.exit(1)
    return False


def run_out(cmd, timeout=None, retries=0, cwd=None, env=None):
    """Like run(), but returns the combined output on success, else None."""
    delay = 3.0
    rc, out = 0, ""
    for attempt in range(retries + 1):
        rc, out, _ = _attempt(cmd, timeout, cwd, env, None)
        if rc == 0:
            return out
        if rc == 127:
            log.error("Command not found: %s", _fmt_cmd(cmd))
            return None
        if attempt < retries:
            time.sleep(delay)
            delay = min(delay * 2, 60) * (0.75 + 0.5 * random.random())
    return None


_SUDO_NEEDS_TTY = False  # set True if the temp NOPASSWD rule couldn't be installed


def run_sudo(cmd, **kw):
    """run() with the non-interactive apt/dpkg environment actually reaching
    the child process.

    Passing env=apt_env() to a `sudo ...` Popen call looks right but does
    nothing: sudo's default `env_reset` policy (standard on Ubuntu) throws
    away almost the entire environment before it execs the target, so
    DEBIAN_FRONTEND, NEEDRESTART_MODE etc. were silently never reaching
    apt-get/dpkg/debconf no matter what this function set them to. That is
    almost certainly what let a debconf or needrestart prompt appear on the
    real /dev/tty (invisible in the captured log) and stall a run for hours.

    `sudo env VAR=val ... realcmd` sets those variables on the far side of
    sudo's reset, unconditionally, regardless of sudoers policy -- unlike
    env=, this actually works.

    On new_session: normally left at the default (True) here, since once
    the temp NOPASSWD rule from install_temp_sudoers() is active, sudo
    doesn't need a cached ticket -- or a tty -- for anything. But if that
    rule never got installed, sudo falls back to its normal ticket cache,
    which most Ubuntu installs scope *per controlling terminal*
    (`Defaults tty_tickets`/timestamp_type=tty); a session-isolated call has
    no controlling terminal at all, so it can neither reuse that ticket nor
    prompt, and fails immediately with "a terminal is required to
    authenticate". _SUDO_NEEDS_TTY (set by install_temp_sudoers on failure)
    makes every run_sudo() call fall back to new_session=False so sudo
    keeps working -- at the cost of losing this run's Ctrl+C/debconf
    isolation for the rest of the script, which is a straight trade against
    "every remaining sudo call fails outright".
    """
    if cmd and cmd[0] == "sudo":
        cmd = cmd[1:]
    kw.pop("env", None)  # would be reset by sudo before reaching cmd anyway
    if _SUDO_NEEDS_TTY:
        kw.setdefault("new_session", False)
    prefixed = ["sudo", "env"] + [f"{k}={v}" for k, v in APT_ENV_BASE.items()] + list(cmd)
    return run(prefixed, **kw)


# downloads: resumable, so a dropped link does not restart a 400MB fetch

CURL_RETRY = [
    "--retry", "10",
    "--retry-delay", "3",
    "--retry-max-time", "900",
    "--retry-all-errors",
    "--connect-timeout", "30",
    "--speed-limit", "1000",
    "--speed-time", "120",
]


def _probe_size(url, timeout=15):
    """Total size of url via HEAD, or None if the server won't say."""
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "myubuntu.py"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            length = resp.headers.get("Content-Length")
        return int(length) if length and length.isdigit() else None
    except Exception:
        return None


def _watch_size(row, dest, stop, total, seed):
    """Feed the destination's growth into a live row while curl writes.

    curl's progress meter only prints a percentage when stderr is a tty, and
    wrapping it in a pty purely to scrape that is fragile. curl writes straight
    to the destination, so the file's size *is* the number of bytes received --
    simpler, and immune to any change in curl's output format.
    """
    started = time.monotonic()
    interval = 0.2
    while not stop.wait(interval):
        try:
            current = os.path.getsize(dest)
        except OSError:
            continue
        elapsed = time.monotonic() - started
        # Average throughput rather than last-interval: a single slow poll
        # would otherwise make the ETA lurch.
        speed = (current - seed) / elapsed if elapsed > 0.5 else 0
        row.set_bytes(current, total=total, speed=speed)
        interval = min(interval * 1.3, 1.0)


@contextlib.contextmanager
def _watching(dest, url):
    """Yield a live row for a download, or None when there's no display.

    Probing Content-Length costs a round trip, so it only happens when there
    is actually a bar to feed -- a piped run pays nothing.
    """
    if ui.mode != "live":
        yield None
        return

    try:
        seed = dest.stat().st_size if dest.exists() else 0
    except OSError:
        seed = 0
    total = _probe_size(url)
    row = ui.download(f"fetch {dest.name}", total=total)
    row.set_bytes(seed, total=total)

    stop = threading.Event()
    watcher = threading.Thread(target=_watch_size,
                               args=(row, dest, stop, total, seed), daemon=True)
    watcher.start()
    try:
        yield row
    finally:
        stop.set()
        watcher.join(timeout=2)
        # One final read: the last bytes land after the process has exited, and
        # without this the bar stalls a few hundred KB short of the total.
        try:
            final = dest.stat().st_size
            row.set_bytes(min(final, total) if total else final, total=total)
        except OSError:
            pass
        row.end()


def download(url, dest, timeout=3600, quiet=True):
    """Download url to dest with resume and retries.

    Falls back to wget, and falls back to a fresh (non-resumed) fetch if the
    server refuses the range request that `-C -` needs.
    """
    dest = Path(dest)
    if DRY_RUN:
        log.info("[dry-run] download %s -> %s", url, dest)
        return True

    dest.parent.mkdir(parents=True, exist_ok=True)

    def _curl(resume):
        cmd = ["curl", "-fL", "-sS", "-o", str(dest)]
        if resume:
            cmd += ["-C", "-"]
        cmd += CURL_RETRY + [url]
        return cmd

    if shutil.which("curl"):
        attempts = [(True, _curl(True)), (False, _curl(False))]
    elif shutil.which("wget"):
        def _wget(resume):
            cmd = ["wget", "-q", "-O", str(dest)]
            if resume:
                cmd.insert(1, "-c")
            cmd += ["--tries=20", "--waitretry=5", "--timeout=120",
                    "--connect-timeout=30", "--read-timeout=120", url]
            return cmd
        attempts = [(True, _wget(True)), (False, _wget(False))]
    else:
        log.error("Neither curl nor wget is available; cannot download %s", url)
        return False

    with _watching(dest, url):
        last_error = ""
        for resume, cmd in attempts:
            ok = run(cmd, timeout=timeout, show=not resume, retries=0)
            if ok and dest.exists() and dest.stat().st_size > 0:
                return True
            if ok and dest.exists():
                # curl -fL can exit 0 on an empty 416 reply; treat that as usable
                # only if something actually landed on disk.
                return False
            last_error = "resume" if resume else "fresh"
            if resume:
                log.debug("Resumable fetch of %s failed; retrying from scratch.", url)
        log.debug("download failed (%s) for %s", last_error, url)
        return False


def fetch_json(url, timeout=20):
    """GET a URL and parse JSON, or return None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "myubuntu.py"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, ValueError, OSError) as e:
        log.warning("Could not fetch %s: %s", url, e)
        return None


def sha256_of(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


# sudo / files

def sudo_ok():
    """Refresh the sudo timestamp once so later calls never block on a prompt.

    With a tty this prompts once and lets sudo cache the credential. Without
    one, `sudo -v` cannot prompt at all, so probe with -n and fail fast rather
    than hanging for the full timeout.
    """
    if os.geteuid() == 0:
        return True
    if shutil.which("sudo") is None:
        log.error("sudo is not installed.")
        return False
    if DRY_RUN:
        return True

    if sys.stdin.isatty():
        rc, _, _ = _exec(["sudo", "-v"], timeout=120, new_session=False)
    else:
        rc, out, _ = _exec(["sudo", "-n", "true"], timeout=30)
        if rc != 0:
            log.error("No usable sudo credentials and no terminal to prompt on.")
            log.error("Re-run from an interactive shell, or as root.")
            return False
    if rc != 0:
        log.error("Could not obtain sudo. Re-run with sudo rights, or as root.")
        return False
    install_temp_sudoers()
    return True


TEMP_SUDOERS_PATH = Path("/etc/sudoers.d/090-pentest-setup-temp")
_TEMP_SUDOERS_INSTALLED = False


def _current_user():
    return pwd.getpwuid(os.geteuid()).pw_name


def install_temp_sudoers():
    """Trade the one interactive sudo prompt above for a scoped, temporary
    NOPASSWD rule, so a run that takes hours never stalls on a re-prompt
    once sudo's normal ~15-minute timestamp cache lapses mid-install.

    Removed automatically when the run ends -- on success, on failure, and
    on Ctrl+C (see remove_temp_sudoers and the atexit/signal wiring at the
    bottom of this file). The one thing this can't survive is the process
    being killed outright (SIGKILL, a crashed terminal, power loss); the log
    line below says exactly how to remove it by hand if that happens.
    """
    global _TEMP_SUDOERS_INSTALLED, _SUDO_NEEDS_TTY

    if os.geteuid() == 0:
        return True
    if _TEMP_SUDOERS_INSTALLED or _SUDO_NEEDS_TTY:
        return True  # already handled by an earlier call in this run

    # Deliberately no "is sudo already passwordless?" shortcut here: right
    # after sudo_ok()'s sudo -v, a plain `sudo -n true` succeeds regardless
    # of whether that's from a real permanent NOPASSWD rule or just the
    # ticket -v itself cached moments ago, and there's no reliable way to
    # tell those apart from the command line. Installing our own rule
    # unconditionally costs a few harmless syscalls if one already existed,
    # and cleanup only ever touches the one file we created -- versus
    # silently skipping installation and letting the *real* problem this
    # whole mechanism exists for (the cached ticket expiring ~15 minutes
    # into a multi-hour run) happen anyway.
    user = _current_user()
    line = f"{user} ALL=(ALL) NOPASSWD: ALL\n"

    if DRY_RUN:
        log.info("[dry-run] would install a temporary passwordless sudo rule for %s.", user)
        return True

    tmp_path = Path(f"/tmp/setup-sudoers-{os.getpid()}")
    try:
        tmp_path.write_text(line)
        tmp_path.chmod(0o440)
    except OSError as e:
        log.warning("Could not stage a temporary sudoers file (%s); falling back to "
                    "keeping every sudo call tied to this terminal instead.", e)
        _SUDO_NEEDS_TTY = True
        return True  # not fatal -- the run still works, just without this convenience

    # Sudoers syntax errors can lock sudo out entirely, so this is validated
    # with visudo -c *before* it ever lands in /etc/sudoers.d.
    valid = run_sudo(["sudo", "visudo", "-c", "-f", str(tmp_path)], show=False, retries=0, new_session=False)
    if not valid:
        log.warning("Generated sudoers rule failed validation; falling back to keeping "
                    "every sudo call tied to this terminal instead.")
        tmp_path.unlink(missing_ok=True)
        _SUDO_NEEDS_TTY = True
        return True

    installed = run_sudo(
        ["sudo", "install", "-o", "root", "-g", "root", "-m", "0440",
         str(tmp_path), str(TEMP_SUDOERS_PATH)],
        show=False, retries=0, new_session=False,
    )
    tmp_path.unlink(missing_ok=True)
    if not installed:
        log.warning("Could not install the temporary sudoers rule; falling back to "
                    "keeping every sudo call tied to this terminal instead.")
        _SUDO_NEEDS_TTY = True
        return True

    _TEMP_SUDOERS_INSTALLED = True
    log.info("Installed a temporary passwordless sudo rule for '%s' (%s).", user, TEMP_SUDOERS_PATH)
    log.info("Removed automatically when this run ends. If it's ever killed outright "
             "instead of exiting normally, remove it by hand: sudo rm %s", TEMP_SUDOERS_PATH)
    return True


def remove_temp_sudoers():
    """Best-effort cleanup, kept deliberately simple: this also runs from the
    force-quit signal path, where the fancier logging/threading machinery
    elsewhere in this file may not be in a good state to rely on."""
    global _TEMP_SUDOERS_INSTALLED
    if not _TEMP_SUDOERS_INSTALLED:
        return
    _TEMP_SUDOERS_INSTALLED = False
    try:
        result = subprocess.run(["sudo", "-n", "rm", "-f", str(TEMP_SUDOERS_PATH)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if result.returncode == 0:
            sys.stderr.write(f"[*] Removed the temporary sudo rule ({TEMP_SUDOERS_PATH}).\n")
            return
    except Exception:
        pass
    # subprocess.run() without check=True never raises on a non-zero exit, so
    # the return code has to be checked explicitly -- otherwise this would
    # silently claim success on a failed removal, leaving passwordless sudo
    # in place with nothing telling the user to clean it up.
    sys.stderr.write(f"[!] Could not confirm removal of {TEMP_SUDOERS_PATH}; "
                      f"remove it by hand with: sudo rm {TEMP_SUDOERS_PATH}\n")


atexit.register(remove_temp_sudoers)


def write_with_sudo_tee(text, dest_path, check=False):
    """Write text to a root-owned file via `sudo tee`."""
    if DRY_RUN:
        log.info("[dry-run] would write %d bytes to %s", len(text), dest_path)
        return True
    data = text.encode() if isinstance(text, str) else text
    cmd = ["sudo", "tee", dest_path]
    rc, out, _ = _exec(cmd, input_bytes=data, timeout=300)
    if rc != 0:
        log.error("Failed writing %s (rc=%s)", dest_path, rc)
        for line in out.strip().splitlines()[-5:]:
            log.error("  | %s", line)
        if check:
            return False
    return True


def run_piped_to_sudo_tee(source_cmd, dest_path, check=False):
    """Run source_cmd and pipe its stdout into `sudo tee dest_path`."""
    if DRY_RUN:
        log.info("[dry-run] would pipe %s -> %s", _fmt_cmd(source_cmd), dest_path)
        return True
    src = subprocess.Popen(source_cmd, stdout=subprocess.PIPE, start_new_session=True)
    tee_proc = subprocess.Popen(["sudo", "tee", dest_path], stdin=src.stdout,
                                stdout=subprocess.DEVNULL, start_new_session=True)
    src.stdout.close()
    try:
        src_rc = src.wait()
        tee_rc = tee_proc.wait()
    except BaseException:
        _terminate_group(src)
        _terminate_group(tee_proc)
        raise
    if tee_rc != 0 or src_rc != 0:
        log.error("Failed writing %s (source rc=%s, tee rc=%s)", dest_path, src_rc, tee_rc)
        if check:
            return False
    return True


def write_managed_block(path: Path, body: str, begin: str, end: str):
    """Replace a managed block in a shell rc file, or append it once.

    Unlike a plain append-if-absent, this rewrites the block in place on every
    run, so re-running the setup never accumulates duplicate stanzas.
    """
    if DRY_RUN:
        log.info("[dry-run] would write managed block to %s", path)
        return True

    path.parent.mkdir(parents=True, exist_ok=True)
    block = f"{begin}\n{body.rstrip()}\n{end}\n"
    try:
        existing = path.read_text(errors="replace")
    except OSError:
        existing = ""

    if begin in existing and end in existing:
        head, _, rest = existing.partition(begin)
        _, _, tail = rest.partition(end)
        updated = head + block + tail.lstrip("\n")
    elif block.strip() in existing:
        return True
    else:
        sep = "" if not existing or existing.endswith("\n\n") else "\n"
        updated = existing + sep + block

    if updated == existing:
        return True

    try:
        if path.exists():
            backup = path.with_name(path.name + ".myubuntubak")
            if not backup.exists():
                shutil.copy2(path, backup)
        path.write_text(updated)
        log.info("Wrote %s (previous version backed up if it existed)", path)
    except OSError as e:
        log.error("Could not write %s: %s", path, e)
        return False
    return True


# The slow-link block used to be tagged with the script's own name, so the
# rename retired these markers while the live blocks in ~/.bashrc and ~/.zshrc
# still carry them.
LEGACY_SLOW_BEGIN = "# >>> slow-link tuning (tools/setup.py) >>>"
LEGACY_SLOW_END = "# <<< slow-link tuning (tools/setup.py) <<<"


def migrate_legacy_markers():
    """Retag the pre-rename slow-link block in the shell rc files.

    write_managed_block locates a block by matching its own begin/end markers.
    Rename the markers and the existing block stops matching, so the next run
    would append a second copy beside the live one instead of replacing it.

    Retagging in place rather than deleting the block keeps those exports
    active in the meantime: the next run then finds the block under its new
    markers and replaces it as it always did. Only the two marker lines change.

    Idempotent, and it touches nothing outside them.
    """
    pending = []
    for rc in (HOME_DIR / ".bashrc", HOME_DIR / ".zshrc"):
        try:
            text = rc.read_text(errors="replace")
        except OSError:
            continue
        if LEGACY_SLOW_BEGIN in text or LEGACY_SLOW_END in text:
            pending.append((rc, text))
    if not pending:
        return True

    if DRY_RUN:
        log.info("[dry-run] would retag the slow-link block in %s",
                 ", ".join(str(rc) for rc, _t in pending))
        return True

    ok = True
    for rc, text in pending:
        updated = text.replace(LEGACY_SLOW_BEGIN, SLOW_ENV_BEGIN)
        updated = updated.replace(LEGACY_SLOW_END, SLOW_ENV_END)
        if updated == text:
            continue
        try:
            backup = rc.with_name(rc.name + ".myubuntubak")
            if not backup.exists():
                shutil.copy2(rc, backup)
            rc.write_text(updated)
            log.info("Retagged the slow-link block in %s", rc)
        except OSError as e:
            log.error("Could not retag %s: %s", rc, e)
            ok = False
    return ok


def add_to_path_everywhere(bin_dir: Path):
    """Extend PATH for this run, plus persist it for bash/zsh/fish."""
    bin_dir = Path(bin_dir)
    current = os.environ.get("PATH", "")
    if str(bin_dir) not in current.split(":"):
        os.environ["PATH"] = f"{current}:{bin_dir}"

    body = f'export PATH="$PATH:{bin_dir}"'
    for rc in (HOME_DIR / ".bashrc", HOME_DIR / ".zshrc"):
        write_managed_block(rc, body, "# >>> tools PATH >>>", "# <<< tools PATH <<<")

    fish = HOME_DIR / ".config" / "fish" / "config.fish"
    if DRY_RUN:
        log.info("[dry-run] would add %s to fish PATH", bin_dir)
    else:
        fish.parent.mkdir(parents=True, exist_ok=True)
        try:
            text = fish.read_text(errors="replace") if fish.exists() else ""
            line = f"fish_add_path {bin_dir}\n"
            if line not in text:
                if text and not text.endswith("\n"):
                    text += "\n"
                fish.write_text(text + line)
        except OSError as e:
            log.debug("could not update %s: %s", fish, e)


# slow-link tuning

APT_SLOW_CONF = """\
// Written by ~/tools/myubuntu.py -- tuned for slow / high-latency / flaky links.
Acquire::Retries "5";
Acquire::http::Timeout "300";
Acquire::https::Timeout "300";

// Dropping the non-Packages index targets saves ~65MB and six round trips on
// every single `apt-get update`. Preferred compression is deliberately NOT
// overridden: Acquire::CompressionTypes::Order only reorders, it cannot
// remove xz/lzma/zst, and those still win when they compress best.
//
// Deliberately left alone, with reasons:
//   Acquire::http::Pipeline-Depth  -- 0 would DISABLE pipelining; the default
//                                      of 10 is what helps on high latency.
//   Acquire::http::Dl-Limit        -- implicitly disables multi-server fetches.
//   APT::Periodic::Update-Package-Lists -- disabling it silently drops security
//                                      updates on a pentest box.
Acquire::IndexTargets::deb::Translations::DefaultEnabled "false";
Acquire::IndexTargets::deb::DEP-11::DefaultEnabled "false";
Acquire::IndexTargets::deb::DEP-11-icons::DefaultEnabled "false";
Acquire::IndexTargets::deb::DEP-11-icons-small::DefaultEnabled "false";
Acquire::IndexTargets::deb::DEP-11-icons-hidpi::DefaultEnabled "false";
Acquire::IndexTargets::deb::CNF::DefaultEnabled "false";
"""

# Applied to this process and persisted for future shells.
SLOW_ENV_VARS = [
    ("PIP_DEFAULT_TIMEOUT", "120"),
    ("PIP_RETRIES", "10"),
    ("PIP_NO_INPUT", "1"),
    ("UV_HTTP_TIMEOUT", "300"),
    ("UV_HTTP_RETRIES", "10"),
    ("UV_CONCURRENT_DOWNLOADS", "8"),
    ("CARGO_NET_RETRY", "10"),
    ("CARGO_HTTP_TIMEOUT", "120"),
    ("CARGO_CACHE_AUTO_CLEAN_FREQUENCY", "never"),
    ("GOPROXY", "https://proxy.golang.org|direct"),
    ("GOTOOLCHAIN", "local"),
    ("GIT_HTTP_LOW_SPEED_LIMIT", "1000"),
    ("GIT_HTTP_LOW_SPEED_TIME", "60"),
    ("NEEDRESTART_MODE", "a"),
]

SLOW_ENV_BEGIN = "# >>> slow-link tuning (tools/myubuntu.py) >>>"
SLOW_ENV_END = "# <<< slow-link tuning (tools/myubuntu.py) <<<"


def tune_slow_links():
    """Write the apt config and persist the network env vars for future shells."""
    apply_slow_env()

    dest = Path("/etc/apt/apt.conf.d/99-slow-links")
    if dest.exists():
        try:
            if dest.read_text(errors="replace") == APT_SLOW_CONF:
                log.info("/etc/apt/apt.conf.d/99-slow-links already tuned.")
                return True
        except OSError:
            pass
    if write_with_sudo_tee(APT_SLOW_CONF, str(dest), check=True):
        if not DRY_RUN:
            log.info("Wrote /etc/apt/apt.conf.d/99-slow-links (retries, timeouts, trimmed indices).")
        return True
    return False


def apply_slow_env():
    for key, value in SLOW_ENV_VARS:
        os.environ[key] = value

    if DRY_RUN:
        return

    posix = "\n".join(f'export {k}="{v}"' for k, v in SLOW_ENV_VARS)
    for rc in (HOME_DIR / ".bashrc", HOME_DIR / ".zshrc"):
        write_managed_block(rc, posix, SLOW_ENV_BEGIN, SLOW_ENV_END)

    fish = HOME_DIR / ".config" / "fish" / "config.fish"
    try:
        fish.parent.mkdir(parents=True, exist_ok=True)
        text = fish.read_text(errors="replace") if fish.exists() else ""
        block = "# >>> slow-link tuning >>>\n"
        block += "".join(f'set -gx {k} "{v}"\n' for k, v in SLOW_ENV_VARS)
        block += "# <<< slow-link tuning <<<\n"
        if block not in text:
            if text and not text.endswith("\n"):
                text += "\n"
            fish.write_text(text + "\n" + block)
    except OSError as e:
        log.debug("could not update %s: %s", fish, e)

    # systemd --user sessions and login sessions read environment.d.
    envd = HOME_DIR / ".config" / "environment.d"
    try:
        envd.mkdir(parents=True, exist_ok=True)
        (envd / "99-slow-links.conf").write_text(
            "\n".join(f"{k}={v}" for k, v in SLOW_ENV_VARS) + "\n"
        )
    except OSError as e:
        log.debug("could not write %s: %s", envd, e)

    cargo_cfg = HOME_DIR / ".cargo" / "config.toml"
    try:
        if not cargo_cfg.exists():
            cargo_cfg.parent.mkdir(parents=True, exist_ok=True)
            cargo_cfg.write_text(
                "# Written by ~/tools/myubuntu.py -- slow-link friendly cargo defaults.\n"
                "# http.multiplexing stays on: it is HTTP/2 and is the parallelism.\n"
                "[http]\n"
                "timeout = 120\n"
                "low-speed-limit = 100\n"
                "multiplexing = true\n"
                "\n[net]\n"
                "retry = 10\n"
                "\n[cache]\n"
                'auto-clean-frequency = "never"\n'
            )
    except OSError as e:
        log.debug("could not write %s: %s", cargo_cfg, e)


# apt

APT_ENV_BASE = {
    "DEBIAN_FRONTEND": "noninteractive",
    "NEEDRESTART_MODE": "a",
    "APT_LISTCHANGES_FRONTEND": "none",
    "LC_ALL": "C",
}

DPKG_FORCE = ["-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef"]

_APT_UPDATED = False


def apt_env(extra=None):
    env = os.environ.copy()
    env.update(APT_ENV_BASE)
    if extra:
        env.update(extra)
    return env


def dpkg_lock_wait(timeout=900):
    """Block until nobody else holds the dpkg frontend lock.

    unattended-upgrades runs on its own schedule shortly after a fresh Ubuntu
    install and holds this lock, which is the single most common cause of a
    first-run `apt-get` failing outright.
    """
    if os.geteuid() == 0:
        return True
    if DRY_RUN or shutil.which("flock") is None:
        return True

    deadline = time.monotonic() + timeout
    announced = False
    sudo_checked = False
    row = None
    try:
        while True:
            rc, out, _ = _exec(["sudo", "flock", "-n", "/var/lib/dpkg/lock-frontend", "-c", "true"])
            if rc == 0:
                if announced:
                    log.info("Acquired the dpkg lock.")
                return True
            # Distinguish "the lock is genuinely held" from "sudo is not working".
            # Without this, a broken-sudo box spins for the full timeout.
            if not sudo_checked and "sudo:" in out and \
                    "terminal is required" in out.lower():
                log.error("Cannot use sudo non-interactively; not waiting on the dpkg lock.")
                return False
            sudo_checked = True
            if not announced:
                log.info("Waiting for the dpkg/apt lock (is unattended-upgrades running?)...")
                announced = True
                # This wait is the single most common silent stall on a first
                # run, so it gets a row of its own rather than looking like a
                # frozen display.
                row = ui.subtask("waiting for apt/dpkg lock", note="unattended-upgrades?")
            if time.monotonic() > deadline:
                log.error("Timed out after %ss waiting for the dpkg lock.", timeout)
                return False
            time.sleep(5)
    finally:
        if row is not None:
            row.end()


def apt_update(force=False):
    global _APT_UPDATED
    if _APT_UPDATED and not force:
        return True
    with ui.task("apt update"):
        if not dpkg_lock_wait():
            return False
        ok = run_sudo(["sudo", "apt-get", "update"], timeout=900, retries=2)
    _APT_UPDATED = ok
    return ok


def _apt_lists_populated():
    """True when apt has actually downloaded package indices.

    Without this, a dry run on a fresh box (where nothing has ever run
    `apt-get update`) would report every single package as unavailable, which
    is both wrong and alarming.

    Matched on apt's own naming rather than a compression suffix: recent apt
    keeps the indices as bare `..._Packages` files, so testing for .lz4/.gz
    would call a perfectly healthy cache empty.
    """
    d = Path("/var/lib/apt/lists")
    try:
        return any(p.is_file() and ("_Packages" in p.name or p.name.endswith("InRelease"))
                   for p in d.iterdir())
    except OSError:
        return False


def apt_install(packages, label=None, retries=1):
    """Install a list of packages, dropping names this release does not carry.

    A preflight `apt-get install -s` resolves the whole set in one pass and
    reports the unknown names, so one bad entry can no longer abort the other
    eighty-nine. That was the original script's single most destructive bug.
    """
    packages = [p for p in dict.fromkeys(packages) if p]
    if not packages:
        return True

    label = label or f"{len(packages)} package(s)"
    log.info("Installing %s via apt...", label)

    if not apt_update():
        log.error("Skipping %s: apt-get update failed.", label)
        return False
    if not dpkg_lock_wait():
        log.error("Skipping %s: dpkg lock unavailable.", label)
        return False

    # The resolve is a read-only simulate and needs no root, so it runs in a
    # dry run too. That is the single most useful thing a dry run can tell
    # you: which of these hand-picked package names this release does not
    # carry, before a three-hour run quietly drops them.
    unknown = set()
    if DRY_RUN and not _apt_lists_populated():
        log.warning("[dry-run] apt package lists are empty, so availability cannot be "
                    "checked. Run `sudo apt-get update` first, then re-run this dry run.")
    else:
        # No sudo here: `apt-get install -s` only reads, it never installs.
        rc, out, _ = _exec(
            ["apt-get", "install", "-s", "-y"] + packages,
            timeout=900, env=apt_env(),
        )
        unknown = set(re.findall(r"Unable to locate package (\S+)", out))
        if rc != 0 and not unknown:
            log.debug("preflight resolve returned rc=%s", rc)
        if unknown:
            if DRY_RUN:
                log.warning("[dry-run] %d of %d not available on this release: %s",
                            len(unknown), len(packages), ", ".join(sorted(unknown)))
            else:
                log.warning("Not available on this release, skipping: %s",
                            ", ".join(sorted(unknown)))
        elif DRY_RUN:
            log.info("[dry-run] apt: %d/%d packages resolve on this release",
                     len(packages), len(packages))

    wanted = [p for p in packages if p not in unknown]
    if not wanted:
        if DRY_RUN:
            # Not a failure: a dry run never writes the repos this script adds
            # itself (cloudflared, for one), so their packages are legitimately
            # absent from apt's view here and would fail a real install no
            # earlier than it already does. The real run stays authoritative.
            log.info("[dry-run] %s: %d package(s) unresolvable, but apt state is "
                     "not fully materialised in a dry run. Deferring to the real run.",
                     label, len(unknown))
            wanted = list(packages)
        else:
            log.error("None of %s are available on this release.", label)
            return False

    # apt-get is one opaque command, so the bar pulses rather than pretending
    # to know a percentage it cannot honestly report. The package count is
    # real information even without a determinate bar.
    with ui.task(label, note=f"{len(wanted)} packages"):
        ok = run_sudo(
            ["sudo", "apt-get", "install", "-y"] + DPKG_FORCE + wanted,
            timeout=7200, retries=retries,
        )
    if not ok:
        log.error("apt install of %s did not complete cleanly; continuing.", label)
    return ok


def debconf_set(pkg, question, kind, value):
    if DRY_RUN:
        return
    run_sudo(["sudo", "debconf-set-selections"],
             input_bytes=f"{pkg} {question} {kind} {value}\n".encode(), show=False)


def _sources_text():
    parts = []
    candidates = [Path("/etc/apt/sources.list")]
    d = Path("/etc/apt/sources.list.d")
    if d.is_dir():
        candidates += sorted(p for p in d.iterdir() if p.is_file())
    for p in candidates:
        try:
            parts.append(p.read_text(errors="replace"))
        except OSError:
            pass
    return "\n".join(parts)


def ensure_repositories():
    """Make sure universe and multiverse are on.

    Roughly thirty of the security packages below live in universe, so a
    minimal server or a freshly imaged VM without it fails on almost
    everything.
    """
    text = _sources_text()
    if not text.strip():
        log.warning("No apt sources found; skipping component check.")
        return True
    missing = [c for c in ("universe", "multiverse") if not re.search(rf"\b{c}\b", text)]
    if not missing:
        log.info("universe and multiverse are already enabled.")
        return True

    log.info("Enabling apt component(s): %s", ", ".join(missing))
    for component in missing:
        run_sudo(["sudo", "add-apt-repository", "-y", component], timeout=600, retries=1)
    apt_update(force=True)
    return True


# tool manifests

basic_workflow_tools = [
    "git", "python3", "python3-pip", "python3-dev", "python3-venv",
    "wget", "curl", "zsh", "fish", "tmux", "vim", "pipx",
    "build-essential", "ripgrep", "fd-find", "gcc", "g++", "make",
    "clangd", "cmake", "python3-setuptools", "gdb", "nodejs", "npm",
    "gufw", "7zip", "adb", "mcrypt", "ncat", "socat", "ruby-dev",
    "ipython3", "cherrytree",
    "ca-certificates", "gnupg", "unzip", "zip", "xz-utils", "bzip2",
    "file", "lsb-release", "software-properties-common",
]

# NOTE: there is no apt package named "httpx" in any Ubuntu suite, and
# "python3-httpx" is encode/httpx -- the Python HTTP *client library*, which
# ships no CLI and is useless for pentesting. The real httpx is a Go binary
# and is installed via `go install` below. Do not "fix" this back.
#
# openvas-scanner / GVM is intentionally absent: it is a multi-GB download
# with a feed-sync step, and it dominated setup time on slow links.
apt_security_tools = [
    "wireshark", "tshark", "tcpdump", "nmap", "hashcat", "wifite",
    "netdiscover", "smbmap", "nikto", "dirb", "hydra", "macchanger",
    "bully", "reaver", "aircrack-ng", "hashid", "libimage-exiftool-perl",
    "hcxtools", "hcxdumptool", "stegcracker", "wfuzz", "ettercap-graphical",
    "proxychains4", "mitmproxy", "masscan", "recon-ng", "medusa", "ncrack",
    "binwalk", "chkrootkit", "sublist3r", "apktool", "radare2", "whatweb",
]

apt_cli_tools = [
    "fzf", "bat", "eza", "zoxide", "jq", "gh", "tree", "htop", "btop",
    "ncdu", "shellcheck", "shfmt", "git-lfs", "git-delta", "rclone",
    "restic", "default-jre",
]

apt_net_tools = [
    "bettercap", "p0f", "arp-scan", "hostapd", "nftables", "ethtool", "iw",
    "pciutils", "dnsutils", "whois", "sslscan",
]

apt_re_tools = [
    "yara", "python3-pefile", "python3-pyelftools", "patchelf", "ltrace",
    "gdb-multiarch", "upx-ucl",
]

apt_firmware_tools = [
    "flashrom", "openocd", "qemu-system-arm", "qemu-system-misc", "ovmf",
    "squashfs-tools",
]

apt_ad_tools = [
    "ldap-utils", "smbclient", "samba-common-bin", "krb5-user", "libkrb5-dev",
]

# spec, expected command (or glob) in the tool bin dir
uv_tools = [
    ("pwntools", "checksec"),
    ("sqlmap", "sqlmap"),
    ("git+https://github.com/Pennyw0rth/NetExec", "nxc"),
    # The PyPI project "bloodhound" is dirkjanm's collector for BloodHound
    # *Legacy* (<= 4.3). The Community Edition collector is a separate
    # project: bloodhound-ce -> bloodhound-ce-python.
    ("bloodhound-ce", "bloodhound-ce-python"),
    ("certipy-ad", "certipy"),
    ("frida-tools", "frida"),
    # The PyPI project is "ROPGadget" but the console script it declares is
    # "ROPgadget". Checking for the wrong casing meant the post-install probe
    # reported a failure for a tool that had in fact installed cleanly.
    ("ROPGadget", "ROPgadget"),
    ("bandit", "bandit"),
    ("impacket", "secretsdump*"),
    # The PyPI name "responder" is an unrelated HTTP framework by Kenneth
    # Reitz, so lgandx's poisoner has to come straight from git.
    ("git+https://github.com/lgandx/Responder", "responder"),
    ("bloodyAD", "bloodyAD"),
    ("ldapdomaindump", "ldapdomaindump"),
    # "pwndbg" on PyPI is a reserved name holding zero files; the git form
    # is the only install. The [gdb] extra pulls its own patched GDB.
    ("git+https://github.com/pwndbg/pwndbg[gdb]", "pwndbg"),
    ("pwncat", "pwncat"),
    ("esptool", "esptool"),
]

# module path, expected binary in GOBIN, rename to (ligolo installs as bare
# "proxy"/"agent", which is a namespace collision waiting to happen)
go_tools = [
    ("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei", None),
    ("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder", None),
    ("github.com/projectdiscovery/httpx/cmd/httpx@latest", "httpx", None),
    ("github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "naabu", None),
    ("github.com/ffuf/ffuf/v2@latest", "ffuf", None),
    ("github.com/OJ/gobuster/v3@latest", "gobuster", None),
    ("github.com/owasp-amass/amass/v5/cmd/amass@latest", "amass", None),
    # OAST client that pairs with nuclei. Not on PyPI -- it is a Go binary.
    ("github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", "interactsh-client", None),
    ("github.com/projectdiscovery/katana/cmd/katana@latest", "katana", None),
    ("github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "dnsx", None),
    ("github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "tlsx", None),
    ("github.com/jpillora/chisel@latest", "chisel", None),
    ("github.com/nicocha30/ligolo-ng/cmd/proxy@latest", "proxy", "ligolo-proxy"),
    ("github.com/nicocha30/ligolo-ng/cmd/agent@latest", "agent", "ligolo-agent"),
    ("github.com/sensepost/gowitness@latest", "gowitness", None),
    ("github.com/edoardottt/scilla/cmd/scilla@latest", "scilla", None),
    ("github.com/jaeles-project/jaeles@latest", "jaeles", None),
]

cargo_tools = [
    "feroxbuster",
    "rustscan",
]

john_build_deps = [
    "build-essential", "libssl-dev", "zlib1g-dev", "yasm", "libgmp-dev",
    "libpcap-dev", "libnss3-dev", "libkrb5-dev", "pkg-config", "libbz2-dev",
]

firefox_extensions = [
    "foxyproxy-standard",
    "wappalyzer",
    "cookie-editor",
    "user-agent-string-switcher",
]

git_wordlists = [
    "https://github.com/danielmiessler/SecLists.git",
    "https://github.com/fuzzdb-project/fuzzdb.git",
    "https://github.com/trickest/wordlists.git",
]

# PEASS-ng ships its built scripts as CI release artifacts, not as tracked
# files, so the raw.githubusercontent URL that every tutorial uses is a 404.
# The .ps1 for winPEAS is the exception -- that one is tracked in git.
PEASS_RELEASE = "https://github.com/peass-ng/PEASS-ng/releases/latest/download"
PEASS_RAW = "https://raw.githubusercontent.com/peass-ng/PEASS-ng/master"

linpeas_assets = [
    "linpeas.sh",
    "linpeas_small.sh",
]
linpeas_binaries = {
    "x86_64": "linpeas_linux_amd64",
    "aarch64": "linpeas_linux_arm64",
    "armv7l": "linpeas_linux_arm",
    "i686": "linpeas_linux_386",
}

winpeas_assets = [
    ("winPEAS.ps1", f"{PEASS_RAW}/winPEAS/winPEASps1/winPEAS.ps1"),
    ("winPEASx64.exe", f"{PEASS_RELEASE}/winPEASx64.exe"),
    ("winPEASany_ofs.exe", f"{PEASS_RELEASE}/winPEASany_ofs.exe"),
    ("winPEAS.bat", f"{PEASS_RELEASE}/winPEAS.bat"),
]

TMUX_CONFIG = """\
# Set prefix to Ctrl+a (easier than Ctrl+b)
unbind C-b
set-option -g prefix C-a
bind-key C-a send-prefix

# Mouse support
set -g mouse on

# 256 colors
set -g default-terminal "tmux-256color"
set -ga terminal-overrides ",xterm-256color:Tc"

# Start windows and panes at 1
set -g base-index 1
setw -g pane-base-index 1

# Split panes with | and -
bind | split-window -h -c "#{pane_current_path}"
bind - split-window -v -c "#{pane_current_path}"

# Increase scrollback
set -g history-limit 10000
"""


# toolchain installers

GO_ARCH_MAP = {
    "x86_64": "amd64", "amd64": "amd64",
    "aarch64": "arm64", "arm64": "arm64",
    "armv7l": "armv6", "armv6l": "armv6",
    "i686": "386", "i386": "386",
}


def machine_arch():
    return GO_ARCH_MAP.get(platform.machine().lower(), platform.machine().lower())


def install_go():
    if shutil.which("go") and not UPDATE:
        log.info("Go already installed, skipping toolchain download.")
        return True

    log.info("Fetching latest Go release info...")
    releases = fetch_json("https://go.dev/dl/?mode=json")
    if not releases:
        log.error("Could not determine the latest Go version; skipping Go install.")
        return False

    arch = machine_arch()
    release = releases[0]
    version = release.get("version", "")
    if not version:
        log.error("Unexpected Go release payload; skipping.")
        return False

    # Prefer the file list so the right architecture is picked automatically;
    # fall back to the conventional tarball name if the API shape changes.
    filename, want_sha = None, None
    for entry in release.get("files") or []:
        if entry.get("os") == "linux" and entry.get("arch") == arch \
                and entry.get("kind") == "archive":
            filename = entry.get("filename")
            want_sha = entry.get("sha256")
            break
    if not filename:
        filename = f"{version}.linux-{arch}.tar.gz"
    if not want_sha:
        want_sha = release.get("sha256")

    dest = Path("/tmp") / filename
    if not download(f"https://dl.google.com/go/{filename}", dest, quiet=False):
        return False

    if want_sha and not DRY_RUN:
        got = sha256_of(dest)
        if got != want_sha:
            log.error("Go tarball checksum mismatch (expected %s, got %s).", want_sha, got)
            dest.unlink(missing_ok=True)
            return False
        log.info("Go tarball checksum verified.")

    if not run_sudo(["sudo", "rm", "-rf", "/usr/local/go"], show=False, retries=0):
        pass
    if not run_sudo(["sudo", "tar", "-C", "/usr/local", "-xzf", str(dest)], timeout=1800):
        return False
    dest.unlink(missing_ok=True)

    add_to_path_everywhere(Path("/usr/local/go/bin"))
    add_to_path_everywhere(GO_DIR / "bin")
    os.environ.setdefault("PATH", "")
    if "/usr/local/go/bin" not in os.environ["PATH"]:
        os.environ["PATH"] += ":/usr/local/go/bin"
    log.info("Go %s installed.", version)
    return True


def install_rust():
    cargo_bin = HOME_DIR / ".cargo" / "bin"
    if shutil.which("cargo") or (cargo_bin / "cargo").exists():
        log.info("Rust/cargo already installed, skipping.")
        add_to_path_everywhere(cargo_bin)
        return True

    log.info("Installing Rust via rustup (minimal profile, non-interactive)...")
    installer = Path("/tmp/rustup-init.sh")
    if not download("https://sh.rustup.rs", installer):
        log.error("Could not download rustup; Rust tools will be skipped.")
        return False

    # The default profile pulls rust-docs, which is a large download for
    # nothing on a pentest box. Keep rustfmt/clippy, drop the docs.
    ok = run(
        ["sh", str(installer), "-y", "--profile", "minimal",
         "--default-toolchain", "stable", "-c", "rustfmt", "-c", "clippy"],
        timeout=3600, retries=2,
    )
    installer.unlink(missing_ok=True)
    if not ok:
        log.error("rustup failed; Rust tools will be skipped.")
        return False

    if not (cargo_bin / "cargo").exists():
        log.error("rustup reported success but %s/cargo is missing.", cargo_bin)
        return False

    add_to_path_everywhere(cargo_bin)
    if str(cargo_bin) not in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = os.environ.get("PATH", "") + f":{cargo_bin}"
    log.info("Rust installed at %s.", cargo_bin)
    return True


def go_bin_dir():
    gobin = run_out(["go", "env", "GOBIN"], timeout=60)
    if gobin and gobin.strip():
        return Path(gobin.strip())
    gopath = run_out(["go", "env", "GOPATH"], timeout=60)
    base = Path(gopath.strip()) if gopath and gopath.strip() else GO_DIR
    return base / "bin"


def install_go_tools():
    if not shutil.which("go"):
        log.warning("`go` is not on PATH -- skipping Go tools.")
        return False

    bindir = go_bin_dir()
    add_to_path_everywhere(bindir)

    failures = []
    with ui.task("go tools", total=len(go_tools)) as row:
        for spec, binary, rename in go_tools:
            # finally, so skipped and failed items still advance: a bar that
            # stalls at 14/17 while eight tools get installed looks broken.
            try:
                row.note(binary)
                key = f"go:{spec}"
                if not UPDATE and state.done(key) and (bindir / (rename or binary)).exists():
                    log.debug("skipping %s (already recorded)", binary)
                    continue
                if not UPDATE and (bindir / (rename or binary)).exists():
                    log.info("%s already present, skipping.", binary)
                    state.mark(key)
                    continue

                log.info("go install %s", spec)
                if not run(["go", "install", "-v", spec], timeout=3600, retries=1, show=False):
                    log.error("Failed: %s", spec)
                    failures.append(binary)
                    continue

                built = bindir / binary
                if not DRY_RUN and not built.exists():
                    log.error("go install reported success but %s is missing.", built)
                    failures.append(binary)
                    continue
                if rename and not DRY_RUN:
                    target = bindir / rename
                    target.unlink(missing_ok=True)
                    if run(["mv", "-f", str(built), str(target)], show=False):
                        log.info("Renamed %s -> %s", binary, rename)
                    else:
                        failures.append(rename)
                        continue
                state.mark(key)
                log.info("Installed %s.", rename or binary)
            finally:
                row.advance()

    if failures:
        log.warning("Go tools that failed: %s", ", ".join(failures))
        return False
    return True


def uv_bin_dir():
    override = os.environ.get("XDG_BIN_HOME")
    if override:
        return Path(override)
    return HOME_DIR / ".local" / "bin"


def ensure_progress_ui():
    """Make the live progress display available, cheaply if possible.

    python3-rich lives in the Ubuntu archive, so this needs no network and no
    pip resolution; on a box that already has it this is a single import.
    Failure is deliberately never fatal -- the plain line logger is a perfectly
    good outcome, and a cosmetic feature must not be able to fail a run.
    """
    if _load_rich():
        return True
    if DRY_RUN:
        return True
    log.info("Installing python3-rich for the live progress display...")
    apt_install(["python3-rich"], "python3-rich (progress display)")
    if not _load_rich():
        log.warning("python3-rich still unavailable; continuing with plain output.")
    return True


def ensure_uv():
    if shutil.which("uv"):
        return True
    if not shutil.which("pipx"):
        log.error("Neither uv nor pipx is available; cannot install Python tools.")
        return False
    log.info("Bootstrapping uv via pipx (one slow pip install; everything after is fast)...")
    if not run(["pipx", "install", "uv"], timeout=1800, retries=2):
        log.error("Could not install uv.")
        return False
    bindir = HOME_DIR / ".local" / "bin"
    add_to_path_everywhere(bindir)
    if not shutil.which("uv"):
        log.error("uv is still not on PATH after install.")
        return False
    return True


def install_uv_tools():
    if not ensure_uv():
        return False

    bindir = uv_bin_dir()
    add_to_path_everywhere(bindir)

    failures = []
    with ui.task("python tools (uv)", total=len(uv_tools)) as row:
        for spec, expected in uv_tools:
            try:
                row.note(spec)
                key = f"uv:{spec}"
                if state.done(key) and any(bindir.glob(expected)):
                    log.debug("skipping %s (already recorded)", spec)
                    continue
                if any(bindir.glob(expected)):
                    log.info("%s already present, skipping.", spec)
                    state.mark(key)
                    continue

                log.info("uv tool install %s", spec)
                if not run(["uv", "tool", "install", spec], timeout=1800, retries=2, show=False):
                    log.error("Failed: %s", spec)
                    failures.append(spec)
                    continue
                if not DRY_RUN and not any(bindir.glob(expected)):
                    log.warning("Installed %s but %s is not in %s.", spec, expected, bindir)
                    failures.append(spec)
                    continue
                state.mark(key)
                log.info("Installed %s.", spec)
            finally:
                row.advance()

    if failures:
        log.warning("Python tools that failed: %s", ", ".join(failures))
        return False
    return True


def install_cargo_tools():
    if not shutil.which("cargo") and not (HOME_DIR / ".cargo" / "bin" / "cargo").exists():
        log.warning("`cargo` is not on PATH -- skipping Rust tools.")
        return False
    with ui.task("rust tools (cargo)", total=len(cargo_tools), note="compiling from source"):
        cmd = ["cargo", "install", "--locked"]
        if UPDATE:
            # cargo refuses to replace an already-installed binary without
            # --force, which is exactly what "update" is asking for here.
            cmd.append("--force")
        cmd += cargo_tools
        return run(cmd, timeout=5400, retries=1)


# from-source / scripted installers

def _clone_or_pull(url, dest):
    dest = Path(dest)
    if not dest.exists():
        return run(["git", "clone", "--depth", "1", url, str(dest)], timeout=3600, retries=2)
    # A dirty tree makes `git pull` fail permanently, so check the exit code
    # rather than the (empty, and therefore falsy) porcelain output.
    rc, out, _ = _exec(["git", "-C", str(dest), "status", "--porcelain"], timeout=300)
    if rc != 0:
        log.warning("Could not check %s for local changes; leaving it alone.", dest.name)
        return True
    if out.strip():
        log.info("%s has local changes; leaving it alone.", dest.name)
        return True
    return run(["git", "-C", str(dest), "pull", "--ff-only"], timeout=1800, retries=2)


def install_theharvester():
    if not UPDATE and (shutil.which("theHarvester") or shutil.which("theharvester")):
        log.info("theHarvester already installed, skipping.")
        return True
    # Its published PyPI package has no working console scripts, so installing
    # by package name fails; the git checkout is the supported route.
    WORKING_DIR.mkdir(parents=True, exist_ok=True)
    if not _clone_or_pull("https://github.com/laramies/theHarvester", WORKING_DIR / "theHarvester"):
        return False

    repo = str(WORKING_DIR / "theHarvester")
    # This tool is built from the checkout above, so "update" has to rebuild it
    # from the freshly pulled tree. uv will not do that by itself: the source
    # is a local path, not an index, so `uv tool upgrade` has nothing to resolve
    # and the installed copy would keep pointing at the old build.
    reinstall = ["--reinstall"] if UPDATE else []
    if shutil.which("uv"):
        return run(["uv", "tool", "install", *reinstall, repo], timeout=1800, retries=2)
    return run(["pipx", "install", repo], timeout=1800, retries=2)


def install_john():
    john_dir = WORKING_DIR / "john"
    john_bin = john_dir / "run" / "john"
    if john_bin.exists() and not UPDATE:
        log.info("John the Ripper already built, skipping.")
        add_to_path_everywhere(john_dir / "run")
        return True

    log.info("Building John the Ripper (jumbo) from source...")
    apt_install(john_build_deps, "John the Ripper build dependencies")
    WORKING_DIR.mkdir(parents=True, exist_ok=True)
    if not _clone_or_pull("https://github.com/openwall/john.git", john_dir):
        return False

    src_dir = john_dir / "src"
    run(["make", "-s", "clean"], cwd=str(src_dir), show=False)
    if not run(["./configure"], cwd=str(src_dir), timeout=1800):
        return False
    nproc = os.cpu_count() or 1
    if not run(["make", f"-sj{nproc}"], cwd=str(src_dir), timeout=7200, retries=1):
        return False

    add_to_path_everywhere(john_dir / "run")
    log.info("John the Ripper built at %s.", john_dir / "run")
    return True


def install_metasploit():
    if shutil.which("msfconsole"):
        log.info("Metasploit already installed, skipping.")
        return True

    log.info("Installing Metasploit Framework (Rapid7 omnibus installer)...")
    installer = Path("/tmp/msfinstall")
    url = ("https://raw.githubusercontent.com/rapid7/metasploit-omnibus/"
           "master/config/templates/metasploit-framework-wrappers/msfupdate.erb")
    if not download(url, installer):
        log.error("Could not fetch the Metasploit installer.")
        return False

    if not DRY_RUN:
        installer.chmod(0o755)
    if not run_sudo(["sudo", str(installer)], timeout=7200, retries=1):
        installer.unlink(missing_ok=True)
        return False
    installer.unlink(missing_ok=True)

    # msfconsole's database is dead without a running Postgres behind it.
    apt_install(["postgresql", "postgresql-contrib"], "PostgreSQL (Metasploit database)")
    if not run_sudo(["sudo", "systemctl", "enable", "--now", "postgresql"], timeout=600, retries=2):
        log.warning("Could not start PostgreSQL; `msfdb` will not work until it is up.")
    if not run_sudo(["sudo", "msfdb", "init"], timeout=1800, retries=1):
        log.warning("msfdb init failed. Run `sudo msfdb init` manually before using the database.")

    log.info("Metasploit installed. Launch with `msfconsole`.")
    return True


def install_caido():
    if shutil.which("caido") and not UPDATE:
        log.info("Caido already installed, skipping.")
        return True

    log.info("Installing Caido...")
    release = fetch_json("https://caido.download/releases/latest")
    if not release:
        log.error("Could not fetch Caido release info; skipping.")
        return False

    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64"}.get(
        platform.machine().lower(), "x86_64")
    deb_link = next(
        (item.get("link") for item in release.get("links", [])
         if item.get("os") == "linux" and item.get("arch") == arch
         and item.get("kind") == "desktop" and item.get("format") == "deb"),
        None,
    )
    if not deb_link:
        log.error("No matching Linux/%s .deb found for Caido; skipping.", arch)
        return False

    dest = Path("/tmp/caido-desktop.deb")
    if not download(deb_link, dest, quiet=False):
        return False
    if not run_sudo(["sudo", "dpkg", "-i", str(dest)], timeout=1800):
        run_sudo(["sudo", "apt-get", "install", "-f", "-y"], timeout=3600, retries=1)
        if not run_sudo(["sudo", "dpkg", "-i", str(dest)], timeout=1800):
            return False
    dest.unlink(missing_ok=True)
    log.info("Caido %s installed. Launch with `caido`.", release.get("version", ""))
    return True


def install_zap():
    if shutil.which("zaproxy"):
        log.info("OWASP ZAP already installed, skipping.")
        return True
    log.info("Installing OWASP ZAP (snap, per zaproxy.org's own instructions)...")
    return run_sudo(["sudo", "snap", "install", "zaproxy", "--classic"], timeout=5400, retries=2)


def install_cloudflared():
    if shutil.which("cloudflared"):
        log.info("cloudflared already installed, skipping.")
        return True
    # The "any" suite sidesteps codename mismatches, which matters as new
    # Ubuntu releases land. Note the old cloudflare-public-key.gpg was retired
    # in 2026-04; the current key is cloudflare-main.gpg.
    log.info("Installing cloudflared from Cloudflare's apt repo...")
    run_sudo(["sudo", "install", "-d", "-m", "0755", "/usr/share/keyrings"])
    ok = run_piped_to_sudo_tee(
        ["curl", "-fsSL", "https://pkg.cloudflare.com/cloudflare-main.gpg"],
        "/usr/share/keyrings/cloudflare-main.gpg",
    )
    if not ok:
        log.error("Could not install the Cloudflare signing key; skipping.")
        return False
    write_with_sudo_tee(
        "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] "
        "https://pkg.cloudflare.com/cloudflared any main\n",
        "/etc/apt/sources.list.d/cloudflared.list",
    )
    apt_update(force=True)
    if not apt_install(["cloudflared"], "cloudflared"):
        return False
    return True


def install_virtualization():
    packages = ["libvirt-daemon-system", "libvirt-clients",
                "bridge-utils", "virtinst", "virt-manager", "ovmf"]
    if not apt_install(packages, "QEMU/KVM + libvirt"):
        return False
    run_sudo(["sudo", "systemctl", "enable", "--now", "libvirtd"], timeout=600, retries=2)
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or HOME_DIR.name
    run_sudo(["sudo", "usermod", "-aG", "libvirt,kvm", user])
    log.info("Added %s to the libvirt/kvm groups (log out and back in to apply).", user)
    return True


def install_podman():
    return apt_install(["podman", "uidmap", "slirp4netns"], "Podman")


def install_vscode():
    if shutil.which("code"):
        log.info("VS Code already installed, skipping.")
        return True

    log.info("Installing VS Code (official Microsoft apt repo)...")
    apt_install(["wget", "gpg"], "VS Code prerequisites")
    run_sudo(["sudo", "install", "-d", "-m", "0755", "/etc/apt/keyrings"])

    keyring = "/etc/apt/keyrings/packages.microsoft.gpg"
    if not run_piped_to_sudo_tee(
        ["curl", "-fsSL", "https://packages.microsoft.com/keys/microsoft.asc"], keyring
    ):
        log.error("Could not install the Microsoft signing key; skipping VS Code.")
        return False
    write_with_sudo_tee(
        "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] "
        "https://packages.microsoft.com/repos/code stable main\n",
        "/etc/apt/sources.list.d/vscode.list",
    )
    apt_update(force=True)
    return apt_install(["apt-transport-https", "code"], "VS Code")


def install_opencode():
    if shutil.which("opencode") and not UPDATE:
        log.info("OpenCode already installed, skipping.")
        return True

    log.info("Installing OpenCode (official install script)...")
    script = Path("/tmp/opencode-install.sh")
    if not download("https://opencode.ai/install", script):
        return False
    ok = run(["sh", str(script)], timeout=1800, retries=2)
    script.unlink(missing_ok=True)
    if not ok:
        log.error("The OpenCode installer failed.")
        return False

    # The installer picks $OPENCODE_INSTALL_DIR, $XDG_BIN_DIR, $HOME/bin, or
    # $HOME/.opencode/bin, in that order -- make sure whichever it used is on
    # PATH for the rest of this run and for future shells.
    for candidate in (HOME_DIR / "bin", HOME_DIR / ".opencode" / "bin",
                      HOME_DIR / ".local" / "bin"):
        if candidate.exists():
            add_to_path_everywhere(candidate)
    return bool(shutil.which("opencode"))


def install_brave():
    if shutil.which("brave-browser") and not UPDATE:
        log.info("Brave already installed, skipping.")
        return True
    log.info("Installing Brave Browser (official installer)...")
    script = Path("/tmp/brave-install.sh")
    if not download("https://dl.brave.com/install.sh", script):
        return False
    ok = run(["sh", str(script)], timeout=1800, retries=2)
    script.unlink(missing_ok=True)
    return ok


def install_firefox():
    log.info("Installing Firefox from Mozilla's official apt repo (not the Ubuntu snap)...")
    run_sudo(["sudo", "snap", "remove", "firefox"], show=False, retries=0)
    run_sudo(["sudo", "install", "-d", "-m", "0755", "/etc/apt/keyrings"])

    if not run_piped_to_sudo_tee(
        ["curl", "-fsSL", "https://packages.mozilla.org/apt/repo-signing-key.gpg"],
        "/etc/apt/keyrings/packages.mozilla.org.asc",
    ):
        log.error("Could not install the Mozilla signing key; skipping Firefox.")
        return False
    write_with_sudo_tee(
        "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] "
        "https://packages.mozilla.org/apt mozilla main\n",
        "/etc/apt/sources.list.d/mozilla.list",
    )
    write_with_sudo_tee(
        "Package: *\n"
        "Pin: origin packages.mozilla.org\n"
        "Pin-Priority: 1000\n\n"
        "Package: firefox*\n"
        "Pin: release o=Ubuntu\n"
        "Pin-Priority: -1\n",
        "/etc/apt/preferences.d/mozilla",
    )
    apt_update(force=True)
    # Drop Ubuntu's snap-installing transition package so apt's firefox
    # resolves to the Mozilla build.
    run_sudo(["sudo", "apt-get", "remove", "-y"] + DPKG_FORCE + ["firefox"],
             timeout=600, retries=1, show=False)
    return apt_install(["firefox"], "Firefox (Mozilla apt repo)")


def fetch_amo_extension(slug):
    """Resolve an AMO extension's real ID and current .xpi URL at install time.

    A hardcoded extension ID fails silently when it is wrong, and looking it
    up live is no less reliable -- and it self-updates.
    """
    data = fetch_json(f"https://addons.mozilla.org/api/v5/addons/addon/{slug}/")
    if not data:
        log.warning("Could not look up AMO extension '%s'.", slug)
        return None, None
    guid = data.get("guid")
    file_info = ((data.get("current_version") or {}).get("file")) or {}
    xpi_url = file_info.get("url") or \
        f"https://addons.mozilla.org/firefox/downloads/latest/{slug}/latest.xpi"
    if not guid:
        return None, None
    return guid, xpi_url


def configure_firefox():
    log.info("Writing a pentest-oriented Firefox policy (hardening + force-installed extensions)...")
    extension_settings = {}
    for slug in firefox_extensions:
        guid, xpi_url = fetch_amo_extension(slug)
        if guid:
            extension_settings[guid] = {
                "installation_mode": "force_installed",
                "install_url": xpi_url,
            }
        else:
            log.warning("Skipping Firefox extension '%s' (could not resolve its ID).", slug)

    policies = {"policies": {
        "DisableTelemetry": True,
        "DisableFirefoxStudies": True,
        "DisablePocket": True,
        "DontCheckDefaultBrowser": True,
        "OfferToSaveLogins": False,
        "NetworkPrediction": False,
        "SearchSuggestEnabled": False,
        "ExtensionSettings": extension_settings,
    }}
    body = json.dumps(policies, indent=2) + "\n"

    # The distribution path differs slightly across builds; write to both so
    # one of them takes effect regardless of how the .deb laid itself out.
    for dist_dir in ("/usr/lib/firefox/distribution", "/etc/firefox/policies"):
        run_sudo(["sudo", "mkdir", "-p", dist_dir], show=False, retries=0)
        write_with_sudo_tee(body, f"{dist_dir}/policies.json")

    log.info("Firefox policy written -- extensions force-install on first launch.")
    log.info("If you intercept HTTPS with Caido/mitmproxy/ZAP, import its CA cert manually.")
    return True


# searchsploit / linPEAS / winPEAS

def install_exploitdb():
    """searchsploit: git clone of the official Exploit-DB repo.

    There is no `exploitdb` or `searchsploit` package in any Ubuntu or Debian
    suite (the Kali-only `exploitdb` package does not exist outside Kali, and
    Ubuntu's `go-exploitdb` is an unrelated Go HTTP server), and there is no
    PyPI project either. The repo also moved from GitHub to GitLab, so the
    offensive-security/exploitdb GitHub path is dead.
    """
    if shutil.which("searchsploit") and EXPLOITDB_DIR.exists():
        log.info("searchsploit already installed, skipping.")
        return True

    # xmllint backs searchsploit's --nmap flag.
    apt_install(["libxml2-utils"], "libxml2-utils (for searchsploit --nmap)")

    log.info("Cloning Exploit-DB into %s (this is a few hundred MB)...", EXPLOITDB_DIR)
    if not EXPLOITDB_DIR.exists():
        if not run_sudo(
            ["sudo", "git", "clone", "--depth", "1",
             "https://gitlab.com/exploit-database/exploitdb.git", str(EXPLOITDB_DIR)],
            timeout=7200, retries=2,
        ):
            return False
    else:
        run_sudo(["sudo", "git", "-C", str(EXPLOITDB_DIR), "pull", "--ff-only"],
                 timeout=3600, retries=1, show=False)

    run_sudo(["sudo", "chmod", "+x", str(EXPLOITDB_DIR / "searchsploit")], show=False, retries=0)
    if not run_sudo(["sudo", "ln", "-sf", str(EXPLOITDB_DIR / "searchsploit"),
                     "/usr/local/bin/searchsploit"], show=False, retries=0):
        return False

    # Persist any rc the tool wrote, so `searchsploit -u` keeps working.
    rc_local = EXPLOITDB_DIR / ".searchsploit_rc"
    if rc_local.exists():
        run(["cp", "-n", str(rc_local), str(HOME_DIR / ".searchsploit_rc")], show=False, retries=0)

    log.info("searchsploit installed. Update the database with `searchsploit -u`.")
    return True


def install_linpeas():
    dest = EXPLOITS_DIR / "linpeas"
    dest.mkdir(parents=True, exist_ok=True)
    arch = platform.machine().lower()
    wanted = list(linpeas_assets)
    if arch in linpeas_binaries:
        wanted.append(linpeas_binaries[arch])

    failures = []
    for name in wanted:
        target = dest / name
        if target.exists() and target.stat().st_size > 0 and not UPDATE:
            log.info("%s already present, skipping.", name)
            continue
        if not download(f"{PEASS_RELEASE}/{name}", target):
            failures.append(name)
            continue
        if not DRY_RUN:
            target.chmod(0o755)
        log.info("Fetched %s", name)

    if failures:
        log.error("linPEAS: could not fetch %s", ", ".join(failures))
        return False
    log.info("linPEAS staged in %s -- run ./linpeas.sh on a target.", dest)
    return True


def install_winpeas():
    dest = EXPLOITS_DIR / "winpeas"
    dest.mkdir(parents=True, exist_ok=True)
    failures = []
    for name, url in winpeas_assets:
        target = dest / name
        if target.exists() and target.stat().st_size > 0 and not UPDATE:
            log.info("%s already present, skipping.", name)
            continue
        if not download(url, target):
            failures.append(name)
            continue
        log.info("Fetched %s", name)
    if failures:
        log.error("winPEAS: could not fetch %s", ", ".join(failures))
        return False
    log.info("winPEAS staged in %s -- copy to the Windows target; the .exe needs .NET 4.5.2+.",
             dest)
    return True

# wordlists

def setup_wordlists():
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    log.info("Setting up wordlists in %s (SecLists alone is multi-GB)...", WORDLISTS_DIR)

    for url in git_wordlists:
        repo_name = url.split("/")[-1].replace(".git", "")
        target = WORDLISTS_DIR / repo_name
        if target.exists() and not UPDATE:
            log.info("%s already exists, skipping.", repo_name)
            continue
        # --depth 1 only. Do not add --filter=blob:none: for wordlists every
        # blob is the payload, so a partial clone re-fetches them lazily one
        # at a time and ends up slower than a single shallow clone.
        run(["git", "clone", "--depth", "1", url, str(target)], timeout=10800, retries=2)

    leaked = WORDLISTS_DIR / "SecLists" / "Passwords" / "Leaked-Databases"
    rockyou_txt = leaked / "rockyou.txt"
    if not rockyou_txt.exists():
        candidates = sorted(leaked.glob("rockyou*")) if leaked.is_dir() else []
        for archive in candidates:
            if archive.suffix == ".gz":
                log.info("Extracting %s...", archive.name)
                if run(["tar", "-xzf", str(archive), "-C", str(leaked)], timeout=3600):
                    break
            elif archive.name == "rockyou.txt":
                break

    log.info("Wordlist setup complete.")
    return True


# system tweaks

def disable_localsearch():
    log.info("Disabling GNOME localsearch (Tracker) services...")
    run_sudo([
        "sudo", "systemctl", "--global", "mask",
        "localsearch-3.service", "localsearch-control-3.service",
        "localsearch-writeback-3.service",
    ], retries=0)
    return True


def setup_tmux():
    log.info("Writing ~/.tmux.conf...")
    conf = HOME_DIR / ".tmux.conf"
    if DRY_RUN:
        log.info("[dry-run] would write %s", conf)
        return True
    try:
        if conf.exists() and conf.read_text(errors="replace") != TMUX_CONFIG:
            backup = HOME_DIR / ".tmux.conf.bak"
            shutil.copy2(conf, backup)
            log.info("Existing ~/.tmux.conf backed up to %s", backup)
        conf.write_text(TMUX_CONFIG)
    except OSError as e:
        log.error("Could not write %s: %s", conf, e)
        return False
    return True


def tune_snap():
    if not shutil.which("snap"):
        return True
    log.info("Scheduling snap refreshes and pausing them on metered links...")
    run_sudo(["sudo", "snap", "set", "system", "refresh.metered=hold"], timeout=300, retries=0)
    # refresh.timer rather than refresh.hold: the latter would block
    # unattended security patches indefinitely.
    run_sudo(["sudo", "snap", "set", "system", "refresh.timer=02:00-06:00"],
             timeout=300, retries=0)
    return True


def install_gpu_support():
    if shutil.which("nvidia-smi") is None:
        log.info("No NVIDIA GPU detected; skipping hashcat GPU backend.")
        return True
    log.info("NVIDIA GPU detected; installing the OpenCL runtime for hashcat.")
    return apt_install(["ocl-icd-libopencl1", "hashcat-nvidia"], "hashcat GPU backend")


def cleanup():
    log.info("Cleaning up package and build caches...")
    if run_sudo(["sudo", "apt-get", "clean"], timeout=900, retries=1, show=False):
        log.info("apt cache cleaned.")
    run_sudo(["sudo", "apt-get", "autoremove", "-y"] + DPKG_FORCE,
             timeout=1800, retries=1, show=False)

    # The go build cache is pure derived data -- deleting it only costs a
    # recompile next time. So reclaim it when it is genuinely large, or when
    # disk is tight enough that a few GB matters more than a faster re-run.
    # A fixed size threshold alone let 6.8GB sit there indefinitely on a box
    # that had just been through a fresh install.
    if shutil.which("go"):
        cache = Path(os.environ.get("XDG_CACHE_HOME") or (HOME_DIR / ".cache")) / "go-build"
        if cache.is_dir():
            size = dir_size(cache)
            free = free_bytes()
            tight = free is not None and free < LOW_SPACE
            if size > 8 * (1 << 30):
                log.info("Go build cache is %s; clearing it.", human_size(size))
                run(["go", "clean", "-cache"], timeout=1800, show=False)
            elif tight and size > (1 << 30):
                log.info(
                    "Only %s free; clearing the %s go build cache to reclaim it "
                    "(a later `go install` will just recompile).",
                    human_size(free), human_size(size),
                )
                run(["go", "clean", "-cache"], timeout=1800, show=False)
    return True


def _classify(pattern, bindirs):
    """ok / missing / broken for one expected tool.

    PATH is searched as well as the tool directories: most of the load-bearing
    binaries (go, nmap, pipx, msfconsole) come from apt and live in /usr/bin,
    so checking only the user directories would report the whole base install
    as broken.

    'broken' is separated from 'missing' because it is the more confusing
    case: the file is there, but it cannot actually be run.
    """
    search_path = os.pathsep.join(
        [str(d) for d in bindirs]
        + [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    )
    try:
        if not any(ch in pattern for ch in "*?["):
            if shutil.which(pattern, path=search_path):
                return "ok", ""
            return "missing", ""
        hits = []
        for d in search_path.split(os.pathsep):
            if d:
                hits.extend(Path(m) for m in glob.glob(os.path.join(d, pattern)))
    except OSError:
        return "missing", ""
    if not hits:
        return "missing", ""
    if not any(os.access(h, os.X_OK) for h in hits):
        return "broken", f"{hits[0]} is not executable"
    return "ok", ""


# Tools that everything else leans on. Each is only demanded once the step that
# installs it has succeeded, so a partial run does not report a wall of
# unrelated failures.
LOAD_BEARING = [
    ("step:go-toolchain", "go"),
    ("step:rust-toolchain", "rustc"),
    ("step:rust-toolchain", "cargo"),
    ("step:uv-tools", "uv"),
    ("step:core-packages", "pipx"),
    ("step:searchsploit", "searchsploit"),
    ("step:metasploit", "msfconsole"),
    ("step:cli-utilities", "nmap"),
]


def verify_installation():
    """Confirm the tools are actually runnable, not just that installers exited 0.

    Everything is gated on the resume state, so this checks what the script
    *claims* to have installed. That makes it correct for a partial run as well
    as a full one, and it turns "installed" from an assumption into a fact.
    """
    bindirs = [go_bin_dir(), uv_bin_dir(), HOME_DIR / ".cargo" / "bin"]
    bindirs = [d for d in bindirs if d.is_dir()]

    for d in bindirs:
        entries = os.environ.get("PATH", "").split(os.pathsep)
        if str(d) not in entries:
            log.warning(
                "%s holds installed tools but is not on PATH in this shell. "
                "New terminals will pick it up; this one needs a fresh login.",
                d,
            )

    checks = []
    for spec, binary, rename in go_tools:
        if state.done(f"go:{spec}"):
            checks.append((f"go:{spec}", rename or binary))
    for spec, expected in uv_tools:
        if state.done(f"uv:{spec}"):
            checks.append((f"uv:{spec}", expected))
    for name in cargo_tools:
        if state.done(f"cargo:{name}"):
            checks.append((f"cargo:{name}", name))
    for key, binary in LOAD_BEARING:
        if state.done(key):
            checks.append((key, binary))

    if not checks:
        log.info("Nothing recorded as installed yet; nothing to verify.")
        return True

    log.info("Verifying %d installed tool(s)...", len(checks))
    problems = []
    with ui.task("verify tools", total=len(checks)) as row:
        for key, want in checks:
            status, detail = _classify(want, bindirs)
            if status != "ok":
                log.error("%-46s %s%s", want, status, f" -- {detail}" if detail else "")
                problems.append((key, want, status, detail))
            row.advance()

    if problems:
        log.error("%d of %d installed tool(s) are not runnable.", len(problems), len(checks))
        return False
    log.info("All %d installed tool(s) are present and runnable.", len(checks))
    return True


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}TB"


def dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda e: None):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


# Below this much free space the go build cache stops being a speedup and
# starts being a liability. A full run pulls roughly 16GB (wordlists, ExploitDB,
# Metasploit, the Go module and build caches, cargo), so a 24GB VM really can
# run out part-way through a three-hour install.
LOW_SPACE = 20 * (1 << 30)


def free_bytes(path="/"):
    try:
        st = os.statvfs(path)
    except (OSError, ValueError):
        return None
    return st.f_bavail * st.f_frsize


def check_disk(required, label):
    """Warn when there isn't room for what a step is about to pull.

    Warn, never abort. Running short of space is worth shouting about, but
    refusing to try would be worse than a download that dies at 90% -- and this
    script's whole design is to keep going past individual failures.
    """
    if DRY_RUN or required <= 0:
        return True
    # Measure the filesystem that will actually hold the install, not "/",
    # since /home is a separate mount often enough to matter.
    free = free_bytes(WORKING_DIR if WORKING_DIR.exists() else "/")
    if free is None:
        log.debug("could not read free space; skipping the disk check for %s", label)
        return True
    if free < required:
        log.warning(
            "%s wants about %s but only %s is free (%s).",
            label, human_size(required), human_size(free),
            "see --step cleanup to reclaim caches",
        )
        return False
    log.debug("%s: %s free, %s needed", label, human_size(free), human_size(required))
    return True


# step registry

STEPS = []


def step(name, *profiles):
    def wrap(func):
        STEPS.append((name, set(profiles), func))
        return func
    return wrap


def all_profiles():
    """Computed on demand -- STEPS is still growing while decorators run."""
    return sorted({p for _n, profs, _f in STEPS for p in profs})


def _core_tools():
    return apt_install(basic_workflow_tools, "core workflow tools")


def _security_tools():
    # wireshark otherwise raises a debconf dialog and hangs a headless run.
    debconf_set("wireshark-common", "wireshark-common/install-setuid", "boolean", "true")
    debconf_set("wireshark-common", "wireshark-common/common.install-setuid", "boolean", "true")
    return apt_install(apt_security_tools, "security tools")


@step("preflight", "base")
def _s_preflight():
    if os.geteuid() == 0:
        log.error(
            "Refusing to run as root: pipx/uv/Go/Rust and every user-scoped tool would "
            "install into root's home instead of yours. Re-run as your normal user; "
            "the script will sudo where it needs to."
        )
        return False
    if not sudo_ok():
        return False
    ensure_repositories()
    return True

@step("progress-ui", "base")
def _s_progress_ui():
    return ensure_progress_ui()


@step("slow-link-tuning", "base")
def _s_slow():
    return tune_slow_links()


@step("core-packages", "base")
def _s_core():
    return _core_tools()


@step("go-toolchain", "languages")
def _s_go():
    return install_go()


@step("rust-toolchain", "languages")
def _s_rust():
    return install_rust()


@step("cli-utilities", "base")
def _s_cli():
    return apt_install(apt_cli_tools, "CLI utilities")


@step("security-packages", "sec-tools")
def _s_sec():
    return _security_tools()


@step("network-packages", "net-tools")
def _s_net():
    return apt_install(apt_net_tools, "network utilities")


@step("re-packages", "re")
def _s_re():
    return apt_install(apt_re_tools, "reverse engineering / triage")


@step("firmware-packages", "firmware")
def _s_firmware():
    return apt_install(apt_firmware_tools, "firmware / IoT")


@step("ad-packages", "ad")
def _s_ad():
    return apt_install(apt_ad_tools, "Active Directory / SMB")


@step("gpu-support", "base")
def _s_gpu():
    return install_gpu_support()


@step("uv-tools", "recon", "ad", "re", "c2")
def _s_uv():
    return install_uv_tools()


@step("go-tools", "recon")
def _s_gotools():
    # The module cache is kept permanently, the build cache is not; together
    # with 17 toolchains this is the single largest consumer on the box.
    check_disk(9 * (1 << 30), "go-tools")
    return install_go_tools()


@step("cargo-tools", "recon")
def _s_cargo():
    check_disk(2 * (1 << 30), "cargo-tools")
    return install_cargo_tools()


@step("theharvester", "recon")
def _s_harvester():
    return install_theharvester()


@step("john", "re")
def _s_john():
    return install_john()


@step("searchsploit", "exploits")
def _s_exploitdb():
    check_disk(1 * (1 << 30), "searchsploit (Exploit-DB)")
    return install_exploitdb()


@step("linpeas", "exploits")
def _s_linpeas():
    return install_linpeas()


@step("winpeas", "exploits")
def _s_winpeas():
    return install_winpeas()


@step("metasploit", "metasploit")
def _s_msf():
    check_disk(2 * (1 << 30), "metasploit")
    return install_metasploit()


@step("caido", "traffic")
def _s_caido():
    return install_caido()


@step("zap", "traffic")
def _s_zap():
    return install_zap()


@step("cloudflared", "c2")
def _s_cf():
    return install_cloudflared()


@step("podman", "base")
def _s_podman():
    return install_podman()


@step("virtualization", "base")
def _s_virt():
    return install_virtualization()


@step("vscode", "desktop")
def _s_vscode():
    return install_vscode()


@step("opencode", "desktop")
def _s_opencode():
    return install_opencode()


@step("brave", "browsers")
def _s_brave():
    return install_brave()


@step("firefox", "browsers")
def _s_firefox():
    return install_firefox()


@step("firefox-policy", "browsers")
def _s_ffpolicy():
    return configure_firefox()


@step("wordlists", "wordlists")
def _s_wordlists():
    check_disk(3 * (1 << 30), "wordlists")
    return setup_wordlists()


@step("system-tweaks", "base")
def _s_tweaks():
    ok = True
    disable_localsearch()
    setup_tmux()
    tune_snap()
    return ok


@step("cleanup", "base")
def _s_cleanup():
    return cleanup()


# Last, so it sees the state the run actually ended in rather than what the
# plan promised. Re-runnable on its own with `--step verify`, which is the point
# of registering it as a step instead of bolting it onto main().
@step("verify", "base")
def _s_verify():
    return verify_installation()


# --update
#
# Not a step: it belongs to no profile and never appears in --list. It reuses the
# install functions above with UPDATE set, and that flag is the whole mechanism
# -- it is what turns their "already present, skipping" checks off. Without it,
# updating a fully installed box would correctly conclude there is nothing to
# do, which is the one thing --update must never do.


def _u_preflight():
    return _s_preflight()


def _u_apt():
    log.info("Refreshing apt package lists...")
    if not run_sudo(["sudo", "apt-get", "update"], timeout=1800, retries=2):
        return False
    # upgrade, never dist-upgrade, and never autoremove. Both of those can
    # remove packages, and an update is not the thing that should decide to
    # uninstall something the user put there deliberately.
    return run_sudo(["sudo", "apt-get", "upgrade", "-y"], timeout=7200, retries=1)


def _u_snaps():
    if not shutil.which("snap"):
        log.info("snap is not installed; nothing to refresh.")
        return True
    run_sudo(["sudo", "snap", "refresh"], timeout=3600, retries=1)
    # tune_snap() sets refresh.metered=hold, so snaps still listed after the
    # refresh were deliberately deferred rather than missed. Reading that list
    # needs root, and a root capture would mean bypassing the temp-sudoers
    # bootstrap, so it streams to the log instead of being summarised inline.
    run_sudo(["sudo", "snap", "refresh", "--list"], show=True, timeout=300, retries=0)
    return True


def _u_go():
    # install_go() replaces /usr/local/go wholesale, so it needs the same free
    # space the first-time install asked for.
    if not check_disk(2 * (1 << 30), "Go toolchain"):
        return False
    if not install_go():
        return False
    return install_go_tools()


def _u_rust():
    if shutil.which("rustup"):
        if not run(["rustup", "update"], timeout=3600, retries=1):
            return False
    else:
        log.warning("rustup is not on PATH; leaving the Rust toolchain alone.")
    return install_cargo_tools()


def _u_clones():
    ok = True
    # Each of these pulls its checkout when the tree is clean and rebuilds from
    # it, so they double as their own update paths.
    for name, func in (("theHarvester", install_theharvester),
                       ("john", install_john),
                       ("Exploit-DB", install_exploitdb),
                       ("wordlists", setup_wordlists)):
        log.info("Updating %s...", name)
        if not func():
            log.warning("%s did not update cleanly.", name)
            ok = False
    return ok


def _u_metasploit():
    # msfupdate, deliberately not a second run of the omnibus installer: that
    # would re-run the postgresql setup against a database that already exists.
    if not shutil.which("msfupdate"):
        log.warning("msfupdate is not on PATH; leaving Metasploit alone.")
        return False
    return run(["msfupdate"], timeout=7200, retries=1)


def _u_uv():
    if not ensure_uv():
        return False
    # --all covers the index and the three git+ specs. theHarvester is the one
    # tool built from a local path, and it is reinstalled by install_theharvester
    # in the clones group above, because `upgrade` has no source to resolve for
    # a path and would leave the previously built copy in place.
    return run(["uv", "tool", "upgrade", "--all"], timeout=3600, retries=2)


def _u_peass():
    # PEASS_RELEASE points at releases/latest/download, so simply re-fetching
    # is the update: the same URLs yield a newer build.
    ok = bool(install_linpeas())
    return bool(install_winpeas()) and ok


def _u_desktop():
    # Each of these re-runs its own official installer, which is how they
    # update: Caido ships a .deb, Brave and OpenCode ship self-updating scripts.
    ok = True
    for name, func in (("Caido", install_caido),
                       ("Brave", install_brave),
                       ("OpenCode", install_opencode)):
        if not func():
            log.warning("%s did not update cleanly.", name)
            ok = False
    return ok


UPDATE_PLAN = [
    ("preflight", "sudo access and package repositories", _u_preflight),
    ("apt", "system packages", _u_apt),
    ("snaps", "snap packages", _u_snaps),
    ("go", "Go toolchain and tools", _u_go),
    ("rust", "Rust toolchain and cargo tools", _u_rust),
    ("clones", "theHarvester, john, Exploit-DB, wordlists", _u_clones),
    ("metasploit", "Metasploit Framework", _u_metasploit),
    ("uv", "python tools", _u_uv),
    ("peass", "PEASS payloads", _u_peass),
    ("desktop", "Caido, Brave, OpenCode", _u_desktop),
    ("verify", "load-bearing tools", verify_installation),
]


def print_update_plan():
    print(_c("Planned updates:", C.BOLD))
    for name, detail, _f in UPDATE_PLAN:
        print(f"  {name:<22} {_c(detail, C.GREY)}")
    print()


def run_update(quiet=False):
    """Refresh the system and everything this script installed.

    Deliberately reuses the install functions rather than reimplementing them:
    a tool whose install method changes is then updated by the same code that
    installs it, instead of by a second implementation that quietly rots.
    """
    if os.geteuid() == 0:
        log.error(
            "Refusing to run as root: the user-scoped tools would update in "
            "root's home instead of yours. Re-run as your normal user."
        )
        return 1
    if not check_disk(1 * (1 << 30), "system update"):
        return 1

    if DRY_RUN:
        log.warning("DRY RUN -- nothing will be updated or written.")
    print_update_plan()

    log.info("Starting update: %d group(s).", len(UPDATE_PLAN))
    log.info("Log file: %s", LOG_FILE)

    started = time.time()
    ui_on = False
    total = len(UPDATE_PLAN)
    for index, (name, _detail, func) in enumerate(UPDATE_PLAN, 1):
        # Same reason as the step loop: preflight may need a password prompt,
        # which a live bar would hide.
        if not ui_on and name != "preflight":
            ui.enable(total, quiet=quiet)
            ui_on = True
        log.info("%s", _c(f"--- [{index}/{total}] {name} ---", C.BOLD))
        step_started = time.time()
        ui.step_start(name, index, total)
        try:
            ok = func()
        except KeyboardInterrupt:
            ui.stop()
            log.warning("Interrupted during the %s group.", name)
            state.save()
            RESULTS.append((name, "failed", "interrupted"))
            raise
        except Exception as e:
            # One uncooperative updater must not abandon the rest.
            log.error("'%s' raised %s: %s", name, type(e).__name__, e, exc_info=DRY_RUN)
            RESULTS.append((name, "failed", type(e).__name__))
            state.mark(f"update:{name}", "failed", error=f"{type(e).__name__}: {e}")
            ui.step_end(False, int(time.time() - step_started))
            continue

        elapsed = int(time.time() - step_started)
        ui.step_end(ok is not False, elapsed)
        state.mark(f"update:{name}", "ok" if ok is not False else "failed")
        RESULTS.append((name, "ok" if ok is not False else "failed", f"{elapsed}s"))

    total_s = int(time.time() - started)
    # Hand the terminal back before the summary is written, so the two don't
    # fight over the same rows.
    ui.stop()
    log.info("Update finished in %dm%02ds.", total_s // 60, total_s % 60)
    state.mark("meta:last-update", "ok")
    print_results()

    return 1 if any(r[1] == "failed" for r in RESULTS) else 0


# orchestration

RESULTS = []
# Steps whose failure makes every remaining step pointless. Continuing past
# one of these is how a setup script turns into a multi-hour no-op.
CRITICAL_STEPS = {"preflight"}


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="MyUbuntu -- idempotent, resumable setup for a Linux pentest workstation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="profiles: " + ", ".join(all_profiles()),
    )
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan without changing anything")
    p.add_argument("--list", action="store_true",
                   help="list profiles and steps, then exit")
    p.add_argument("--update", action="store_true",
                   help="update the system and the already-installed tools, "
                        "then exit (not a profile or step)")
    p.add_argument("--only", nargs="+", metavar="PROFILE",
                   help="only run steps belonging to these profiles")
    p.add_argument("--skip", nargs="+", metavar="PROFILE", default=[],
                   help="skip steps belonging to these profiles")
    p.add_argument("--step", nargs="+", metavar="NAME",
                   help="run only these named steps")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--quiet", action="store_true",
                   help="console shows only errors; the log file keeps everything")
    return p.parse_args(argv)

def print_plan(selected_steps):
    print(_c("Planned steps:", C.BOLD))
    for name, profs, _f in selected_steps:
        print(f"  {name:<22} {_c('[' + ','.join(sorted(profs)) + ']', C.GREY)}")
    print()


def print_results():
    if not RESULTS:
        return
    failed = [r for r in RESULTS if r[1] == "failed"]
    skipped = [r for r in RESULTS if r[1] == "skipped"]
    ok = [r for r in RESULTS if r[1] == "ok"]

    print()
    print(_c("=" * 62, C.GREY))
    print(_c(f"  Summary: {len(ok)} ok, {len(failed)} failed, {len(skipped)} skipped", C.BOLD))
    print(_c("=" * 62, C.GREY))
    for name, status, detail in RESULTS:
        if status == "ok":
            mark, colour = "+", C.GREEN
        elif status == "skipped":
            mark, colour = "~", C.GREY
        else:
            mark, colour = "!", C.RED
        line = f"  {mark} {name}"
        if detail:
            line += f"  ({detail})"
        print(_c(line, colour))
    print(_c("=" * 62, C.GREY))
    print(f"  Full log: {LOG_FILE}")
    print(f"  State:    {STATE_FILE}")
    if failed:
        print(_c(f"  Re-run after fixing the {len(failed)} failure(s) above; completed "
                 "steps are skipped.", C.YELLOW))
    print()


def main(argv=None):
    global DRY_RUN, UPDATE

    args = parse_args(argv)
    setup_logging(getattr(logging, args.log_level), quiet=args.quiet)

    WORKING_DIR.mkdir(parents=True, exist_ok=True)
    DRY_RUN = args.dry_run

    if args.list:
        print(_c("Profiles:", C.BOLD) + " " + ", ".join(all_profiles()))
        print()
        for name, profs, _f in STEPS:
            print(f"  {name:<22} {_c('[' + ','.join(sorted(profs)) + ']', C.GREY)}")
        return 0

    # After the --list early return, so listing stays free of side effects.
    # Runs on every other invocation, not just --update: the slow-link step
    # writes through write_managed_block, which matches blocks by marker, so
    # without this a normal run would append a second copy beside the renamed
    # one instead of replacing it in place.
    if args.update:
        # --update refreshes what a full run would have installed, so selecting
        # a subset of steps has no meaning here. Refuse rather than silently
        # ignoring the filter and updating more than the user asked for -- and
        # do it before touching anything on disk.
        if args.only or args.skip or args.step:
            log.error("--update cannot be combined with --only, --skip or --step.")
            log.error("It is a mode of its own, not a step; run those separately.")
            return 2
        migrate_legacy_markers()
        UPDATE = True
        return run_update(quiet=args.quiet)

    migrate_legacy_markers()

    selected = set(all_profiles())
    if args.only:
        unknown = [p for p in args.only if p not in selected]
        if unknown:
            log.error("Unknown profile(s): %s", ", ".join(unknown))
            log.error("Available: %s", ", ".join(all_profiles()))
            return 2
        selected = set(args.only)
    selected -= set(args.skip)

    steps = [(n, p, f) for n, p, f in STEPS if (p & selected)]
    if args.step:
        wanted = set(args.step)
        unknown = wanted - {n for n, _p, _f in STEPS}
        if unknown:
            log.error("Unknown step(s): %s", ", ".join(sorted(unknown)))
            return 2
        steps = [s for s in steps if s[0] in wanted]
    if not steps:
        log.error("No steps selected.")
        return 2

    if DRY_RUN:
        log.warning("DRY RUN -- nothing will be installed or written.")
        print_plan(steps)

    log.info("Starting setup: %d step(s) selected.", len(steps))
    log.info("Log file: %s", LOG_FILE)

    started = time.time()
    ui_on = False
    for index, (name, profs, func) in enumerate(steps, 1):
        # The display is switched on only once the interactive steps are out
        # of the way: preflight runs `sudo -v`, and a live bar would hide that
        # password prompt behind a spinner.
        if not ui_on and name not in ("preflight", "progress-ui"):
            ui.enable(len(steps), quiet=args.quiet)
            ui_on = True
        prefix = f"[{index}/{len(steps)}] {name}"
        log.info("%s", _c(f"--- {prefix} ---", C.BOLD))
        step_started = time.time()
        ui.step_start(name, index, len(steps))
        try:
            ok = func()
        except KeyboardInterrupt:
            ui.stop()
            log.warning("Interrupted during '%s'. Completed steps are recorded.", name)
            state.save()
            RESULTS.append((name, "failed", "interrupted"))
            raise
        except Exception as e:
            # One broken installer must never take down the rest of the run.
            log.error("'%s' raised %s: %s", name, type(e).__name__, e, exc_info=DRY_RUN)
            RESULTS.append((name, "failed", type(e).__name__))
            state.mark(f"step:{name}", "failed", error=f"{type(e).__name__}: {e}")
            ui.step_end(False, time.time() - step_started)
            continue

        elapsed = int(time.time() - step_started)
        ui.step_end(ok is not False, elapsed)
        if ok is False:
            RESULTS.append((name, "failed", f"{elapsed}s"))
            state.mark(f"step:{name}", "failed")
            if name in CRITICAL_STEPS:
                log.error(
                    "'%s' is a prerequisite for every remaining step -- aborting instead "
                    "of failing the same way %d more time(s).",
                    name, len(steps) - index,
                )
                RESULTS.append(("<remaining steps>", "skipped", "aborted"))
                break
        else:
            RESULTS.append((name, "ok", f"{elapsed}s"))
            state.mark(f"step:{name}", "ok")

    total = int(time.time() - started)
    # Hand the terminal back before the summary is written, so the two don't
    # fight over the same rows.
    ui.stop()
    log.info("Run finished in %dm%02ds.", total // 60, total % 60)
    print_results()

    return 1 if any(r[1] == "failed" for r in RESULTS) else 0


_INTERRUPTS = 0


def _sigint_handler(_signum, _frame):
    global _INTERRUPTS
    _INTERRUPTS += 1
    if _INTERRUPTS >= 2:
        # First Ctrl+C tries to clean up (kill the running command's whole
        # process group, save resume state). If that doesn't finish fast
        # enough -- or dpkg is mid-transaction and is deliberately ignoring
        # the signal -- a second Ctrl+C exits immediately, no cleanup, no
        # question. That's the actual fix for "can't quit": there's now
        # always a keypress that works no matter what the child is doing.
        #
        # os._exit() skips atexit, so the temporary sudo rule is removed
        # explicitly here rather than relying on remove_temp_sudoers()'s
        # atexit registration to fire.
        sys.stderr.write("\n[!] Second interrupt -- force quitting now.\n")
        remove_temp_sudoers()
        os._exit(130)
    raise KeyboardInterrupt()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _sigint_handler)
    # SIGTERM gets the same graceful-first path as a single Ctrl+C (kill the
    # running command's process group, save resume state, exit through
    # normal atexit cleanup) rather than Python's default of dying silently
    # and leaving both a child process and the temporary sudo rule behind.
    signal.signal(signal.SIGTERM, _sigint_handler)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
