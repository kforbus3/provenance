"""Background job manager: runs a command, captures output, streams it live.

Jobs and their logs are persisted under <output>/jobs so history survives a
web UI restart (logs of finished jobs are read back from disk on demand).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
from dataclasses import dataclass, field
from typing import Literal

JobStatus = Literal["running", "success", "failed", "canceled"]

# The builder scripts colourise their output for a terminal; in the browser's log
# pane those escapes are just literal "[0;32m" noise, so drop them on the way in
# — that keeps both the live stream and the persisted log clean.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# build-image.sh emits "[progress] 7/14 Installing kernel..." alongside its
# normal log line. These are control data for the progress bar, not log content
# — the human-readable "[build] ..." line covers the log — so they are recorded
# and then dropped rather than shown twice.
_PROGRESS_RE = re.compile(r"^\[progress\] (\d+)/(\d+) (.*)$")

# Orchestrator command templates carry this token where the job id belongs; it
# is substituted in start(), which is the first place the id is known.
JOB_TOKEN = "%JOB%"


def container_name(job_id: str) -> str:
    """Name of the container a job runs its work in, so cancel can remove it."""
    return f"dab-{job_id}"


class _ProgressEvent:
    """Marks a queue item as a progress update rather than a log line."""

    __slots__ = ("data",)

    def __init__(self, data: dict) -> None:
        self.data = data


@dataclass
class Job:
    id: str
    type: str
    label: str
    cmd: list[str]
    status: JobStatus = "running"
    returncode: int | None = None
    lines: list[str] = field(default_factory=list)
    started: str = ""
    finished: str = ""
    env: dict[str, str] | None = None
    progress: dict | None = None
    _proc: asyncio.subprocess.Process | None = None
    _subscribers: list[asyncio.Queue] = field(default_factory=list)
    _logfh: object | None = None

    def public(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "status": self.status,
            "returncode": self.returncode,
            "started": self.started,
            "finished": self.finished,
            "lines": len(self.lines),
            "progress": self.progress,
        }


class JobManager:
    def __init__(self, state_dir: str | None = None) -> None:
        self._jobs: dict[str, Job] = {}
        self._counter = 0
        self._state_dir = state_dir
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
            self._load_index()

    # ------------------------- persistence -------------------------
    def _index_path(self) -> str:
        return os.path.join(self._state_dir, "jobs.json")

    def _log_path(self, job_id: str) -> str:
        return os.path.join(self._state_dir, f"{job_id}.log")

    def _load_index(self) -> None:
        try:
            with open(self._index_path()) as f:
                for j in json.load(f):
                    job = Job(
                        id=j["id"], type=j["type"], label=j["label"], cmd=[],
                        status=j["status"], returncode=j.get("returncode"),
                        started=j.get("started", ""), finished=j.get("finished", ""),
                    )
                    # A job that was "running" when the UI died is dead now.
                    if job.status == "running":
                        job.status = "failed"
                    self._jobs[job.id] = job
                    n = int(job.id.rsplit("-", 1)[-1]) if job.id.rsplit("-", 1)[-1].isdigit() else 0
                    self._counter = max(self._counter, n)
        except (FileNotFoundError, ValueError, KeyError):
            pass

    def _save_index(self) -> None:
        if not self._state_dir:
            return
        tmp = self._index_path() + ".tmp"
        with open(tmp, "w") as f:
            json.dump([j.public() for j in self._jobs.values()], f)
        os.replace(tmp, self._index_path())

    def log_text(self, job: Job) -> str:
        """Full log, preferring the on-disk copy.

        The in-memory buffer is capped (see _emit), so a long build's head is
        gone from it — the file on disk is the complete record. Fall back to
        memory only when there is no state dir or the file is unreadable.
        """
        if self._state_dir:
            try:
                with open(self._log_path(job.id)) as f:
                    return f.read().rstrip("\n")
            except OSError:
                pass
        return "\n".join(job.lines)

    # --------------------------- lifecycle ---------------------------
    def list(self) -> list[dict]:
        return [j.public() for j in sorted(self._jobs.values(), key=lambda j: j.started, reverse=True)]

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def running(self, type: str | None = None) -> Job | None:
        """First running job (optionally of a given type)."""
        for j in self._jobs.values():
            if j.status == "running" and (type is None or j.type == type):
                return j
        return None

    async def start(self, *, type: str, label: str, cmd: list[str], now: str,
                    env: dict[str, str] | None = None) -> Job:
        self._counter += 1
        job_id = f"{type}-{self._counter}"
        # The orchestrator names the container it launches after the job so that
        # cancel can reach it; the id only exists here, hence the placeholder.
        cmd = [c.replace(JOB_TOKEN, job_id) for c in cmd]
        job = Job(id=job_id, type=type, label=label, cmd=cmd, started=now, env=env)
        self._jobs[job.id] = job
        self._save_index()
        asyncio.create_task(self._run(job))
        return job

    async def _run(self, job: Job) -> None:
        if self._state_dir:
            job._logfh = open(self._log_path(job.id), "w")
        try:
            # Secrets travel in the process environment, never on the command
            # line, so they don't show up in `ps` or the job's persisted cmd.
            proc = await asyncio.create_subprocess_exec(
                *job.cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, **(job.env or {})},
                # Own process group, so cancel can signal the shell *and* the
                # docker CLI it is waiting on, not just the shell.
                start_new_session=True,
            )
        except Exception as exc:  # noqa: BLE001
            await self._emit(job, f"Failed to launch: {exc}")
            job.status = "failed"
            job.returncode = -1
            await self._close(job)
            return

        job._proc = proc
        assert proc.stdout
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            await self._emit(job, raw.decode(errors="replace").rstrip("\n"))
        rc = await proc.wait()
        job.returncode = rc
        if job.status != "canceled":
            job.status = "success" if rc == 0 else "failed"
        await self._close(job)

    async def _emit(self, job: Job, line: str) -> None:
        line = _ANSI_RE.sub("", line)
        m = _PROGRESS_RE.match(line)
        if m:
            job.progress = {"step": int(m.group(1)), "total": int(m.group(2)),
                            "label": m.group(3)}
            for q in list(job._subscribers):
                await q.put(_ProgressEvent(job.progress))
            return
        job.lines.append(line)
        if len(job.lines) > 5000:
            job.lines = job.lines[-5000:]
        if job._logfh:
            # Flush per line: the on-disk log is what /jobs/{id} serves, and a
            # running build's log must be readable as it happens.
            job._logfh.write(line + "\n")
            job._logfh.flush()
        for q in list(job._subscribers):
            await q.put(line)

    async def _close(self, job: Job) -> None:
        from orchestrator import now as _now
        job.finished = _now()
        if job._logfh:
            job._logfh.close()
            job._logfh = None
        self._save_index()
        for q in list(job._subscribers):
            await q.put(None)

    async def cancel(self, job: Job) -> None:
        """Actually stop the build, not just relabel it.

        The real work happens inside the container the job launched, and a
        non-interactive bash defers signals until its foreground command
        returns — so signalling the shell alone leaves the builder running while
        the UI claims the job is canceled. Remove the container first (that ends
        `docker run`), then signal the whole process group to catch the case
        where we are still in `docker build`.
        """
        if not job._proc or job.status != "running":
            return
        job.status = "canceled"
        try:
            rm = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_name(job.id),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await rm.wait()
        except OSError:
            pass
        try:
            os.killpg(os.getpgid(job._proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                job._proc.terminate()
            except ProcessLookupError:
                pass

    async def subscribe(self, job: Job):
        """Yield existing lines, then live output until the job ends.

        Yields `str` for log lines and `_ProgressEvent` for progress updates;
        the router turns each into the matching SSE event type. Progress is
        replayed first so a reattaching browser shows the right bar immediately
        instead of waiting for the next step boundary — which can be minutes.
        """
        q: asyncio.Queue = asyncio.Queue()
        if job.progress:
            yield _ProgressEvent(job.progress)
        for line in list(job.lines):
            yield line
        if job.status != "running":
            return
        job._subscribers.append(q)
        try:
            while True:
                item = await q.get()
                if item is None:
                    break
                yield item
        finally:
            if q in job._subscribers:
                job._subscribers.remove(q)


def _state_dir() -> str | None:
    try:
        from config import settings
        return os.path.join(settings.output_dir, "jobs")
    except Exception:  # noqa: BLE001
        return None


jobs = JobManager(_state_dir())
