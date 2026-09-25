from typing import Any

from fastapi import Request


def signed_in_username(request: Request) -> str | None:
    """Return the authenticated server identity without trusting client fields."""
    analyst = getattr(request.state, "analyst", None)
    if not analyst:
        return None
    return str(analyst.get("username") or "").strip() or None


def bind_signed_in_actor(request: Request, model: Any, *fields: str) -> Any:
    """Replace audit fields only when optional authentication is active."""
    username = signed_in_username(request)
    if username is None:
        return model
    return model.model_copy(update={field: username for field in fields})
