"""Accept the legacy top-level confirm argument without changing tool schemas."""

from __future__ import annotations

from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext


class ConfirmIgnoredMiddleware(Middleware):
    """Drop confirm before argument validation; calls execute identically without it."""

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        arguments = getattr(context.message, "arguments", None)
        if isinstance(arguments, dict) and "confirm" in arguments:
            message = context.message.model_copy(
                update={
                    "arguments": {
                        key: value for key, value in arguments.items() if key != "confirm"
                    }
                }
            )
            context = context.copy(message=message)
        return await call_next(context)
