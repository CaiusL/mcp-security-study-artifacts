"""Shared records for calls, tool results, and task expectations."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Call:
    server: str
    tool: str
    args: dict


@dataclass
class ToolResult:
    ok: bool
    text: str = ""
    error: str = ""


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str


@dataclass(frozen=True)
class Step:
    tool: str
    rel: str = ""
    dest: str = ""
    content: str = ""
    pattern: str = ""
    url: str = ""
    max_length: int = 2000


@dataclass(frozen=True)
class Expect:
    """Automatic success check. Every listed condition must hold."""

    texts: tuple[str, ...] = ()
    files: tuple[tuple[str, str], ...] = ()
    absent: tuple[str, ...] = ()
    list_items: tuple[str, ...] = ()
    info: bool = False


@dataclass
class Task:
    id: str
    server: str
    split: str
    steps: tuple[Step, ...]
    expect: Expect


@dataclass(frozen=True)
class Probe:
    id: str
    server: str
    role: str
    kind: str
    effect: str
    needle: str
    call: Call
    file_rel: str = ""


@dataclass
class Layout:
    root: Path
    proj: Path
    has_symlink: bool


@dataclass
class Profile:
    """Generalizations of benign training calls. Derived only from traces."""

    read_dirs: set[str] = field(default_factory=set)
    write_dirs: set[str] = field(default_factory=set)
    write_exts: set[str] = field(default_factory=set)
    fs_paths: set[str] = field(default_factory=set)
    ancestor: str = ""
    hosts: set[str] = field(default_factory=set)
    segments: set[tuple[str, str]] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    fetch_raw: set[bool] = field(default_factory=set)
    timezones: set[str] = field(default_factory=set)
    memory_names: set[str] = field(default_factory=set)
    memory_queries: set[str] = field(default_factory=set)
    git_revisions: set[str] = field(default_factory=set)
    exact: set[tuple[str, str]] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Scope:
    """Deployment configuration. This is Declared intent, not a trace."""

    declared_root: str
