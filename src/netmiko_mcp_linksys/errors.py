"""Exceptions for switch transport and CLI failures."""

from __future__ import annotations

from netmiko_mcp_linksys.validation import redact_secrets


class SwitchConnectionError(RuntimeError):
    """Switch connection or CLI execution failed. Message is already redacted.

    Netmiko, socket, and other transport or CLI exceptions are wrapped
    with a redacted message. The original exception is not chained, so
    secrets in its text cannot leak via ``__cause__``.
    """


def wrap_transport_error(
    exc: BaseException,
    message: str | None = None,
) -> SwitchConnectionError:
    """Return a redacted ``SwitchConnectionError`` for a transport/CLI failure.

    An already-redacted ``SwitchConnectionError`` is returned as-is when no
    override message is given. Callers should raise the result ``from None``.
    """
    if isinstance(exc, SwitchConnectionError) and message is None:
        return exc
    text = message if message is not None else redact_secrets(str(exc))
    return SwitchConnectionError(text)
