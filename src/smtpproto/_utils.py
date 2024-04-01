from __future__ import annotations

from collections.abc import Generator
from contextlib import (
    AbstractAsyncContextManager,
    AbstractContextManager,
    contextmanager,
)
from dataclasses import dataclass, field
from threading import Lock
from types import TracebackType
from typing import Any, TypeVar

from anyio.abc import BlockingPortal
from anyio.from_thread import start_blocking_portal

T = TypeVar("T")


@dataclass
class BlockingPortalProvider:
    async_backend: str
    async_backend_options: dict[str, Any] | None
    _lock: Lock = field(init=False, default_factory=Lock)
    _leases: int = field(init=False, default=0)
    _portal: BlockingPortal = field(init=False)
    _portal_cm: AbstractContextManager[BlockingPortal] | None = field(
        init=False, default=None
    )

    def __enter__(self) -> BlockingPortal:
        with self._lock:
            if self._portal_cm is None:
                self._portal_cm = start_blocking_portal(
                    self.async_backend, self.async_backend_options
                )
                self._portal = self._portal_cm.__enter__()

            self._leases += 1
            return self._portal

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        portal_cm: AbstractContextManager[BlockingPortal] | None = None
        with self._lock:
            assert self._portal_cm
            assert self._leases > 0
            self._leases -= 1
            if not self._leases:
                portal_cm = self._portal_cm
                self._portal_cm = None
                del self._portal

        if portal_cm:
            portal_cm.__exit__(None, None, None)


@contextmanager
def wrap_async_context_manager(
    async_cm: AbstractAsyncContextManager[T], portal: BlockingPortal
) -> Generator[T, Any, bool | None]:
    retval = portal.call(async_cm.__aenter__)
    try:
        yield retval
    except BaseException as exc:
        return portal.call(async_cm.__aexit__, type(exc), exc, exc.__traceback__)
    else:
        return portal.call(async_cm.__aexit__, None, None, None)
