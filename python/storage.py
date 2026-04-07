"""Pluggable storage backends for SecID registry data.

All backends implement the same interface: get(key) and set(key, value).
Registry data is read-only at runtime — load once, serve from cache.
"""

from abc import ABC, abstractmethod
from typing import Optional


class Store(ABC):
    """Abstract key-value store interface."""

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Get a value by key. Returns None if not found."""
        ...

    @abstractmethod
    def set(self, key: str, value: str) -> None:
        """Set a key-value pair."""
        ...

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete a key."""
        ...

    @abstractmethod
    def keys(self) -> list[str]:
        """List all keys."""
        ...


class MemoryStore(Store):
    """In-memory dict. Default backend. No external dependencies."""

    def __init__(self):
        self._data: dict[str, str] = {}

    def get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def keys(self) -> list[str]:
        return list(self._data.keys())


class RedisStore(Store):
    """Redis/Valkey backend. Requires: pip install redis"""

    def __init__(self, url: str = "redis://localhost:6379", prefix: str = "secid:"):
        import redis
        self._client = redis.from_url(url)
        self._prefix = prefix

    def get(self, key: str) -> Optional[str]:
        val = self._client.get(self._prefix + key)
        return val.decode() if val else None

    def set(self, key: str, value: str) -> None:
        self._client.set(self._prefix + key, value)

    def delete(self, key: str) -> None:
        self._client.delete(self._prefix + key)

    def keys(self) -> list[str]:
        prefix_len = len(self._prefix)
        return [k.decode()[prefix_len:] for k in self._client.keys(self._prefix + "*")]


class MemcachedStore(Store):
    """Memcached backend. Requires: pip install pymemcache"""

    def __init__(self, url: str = "localhost:11211", prefix: str = "secid:"):
        from pymemcache.client.base import Client
        host, port = url.split(":")
        self._client = Client((host, int(port)))
        self._prefix = prefix
        self._known_keys: set[str] = set()

    def get(self, key: str) -> Optional[str]:
        val = self._client.get(self._prefix + key)
        return val.decode() if val else None

    def set(self, key: str, value: str) -> None:
        self._client.set(self._prefix + key, value.encode())
        self._known_keys.add(key)

    def delete(self, key: str) -> None:
        self._client.delete(self._prefix + key)
        self._known_keys.discard(key)

    def keys(self) -> list[str]:
        return list(self._known_keys)


class SQLiteStore(Store):
    """SQLite backend. No external dependencies (stdlib)."""

    def __init__(self, path: str = ":memory:"):
        import sqlite3
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)")
        self._conn.commit()

    def get(self, key: str) -> Optional[str]:
        row = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set(self, key: str, value: str) -> None:
        self._conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, value))
        self._conn.commit()

    def delete(self, key: str) -> None:
        self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
        self._conn.commit()

    def keys(self) -> list[str]:
        return [row[0] for row in self._conn.execute("SELECT key FROM kv").fetchall()]


def create_store(backend: str = "memory", **kwargs) -> Store:
    """Factory for storage backends.

    Args:
        backend: "memory", "redis", "memcached", or "sqlite"
        **kwargs: Backend-specific options (url, path, prefix)
    """
    if backend == "memory":
        return MemoryStore()
    elif backend == "redis":
        return RedisStore(url=kwargs.get("url", "redis://localhost:6379"))
    elif backend == "memcached":
        return MemcachedStore(url=kwargs.get("url", "localhost:11211"))
    elif backend == "sqlite":
        return SQLiteStore(path=kwargs.get("path", ":memory:"))
    else:
        raise ValueError(f"Unknown storage backend: {backend}. Use: memory, redis, memcached, sqlite")
