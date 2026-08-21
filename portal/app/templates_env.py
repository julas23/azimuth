"""
Shared Jinja2Templates instance used by all routers.
Sets PT as the global fallback for `t` and `lang` so admin pages
(which don't pass language context) always render correctly.
"""
from datetime import datetime, timezone

from fastapi import Request
from fastapi.templating import Jinja2Templates

from i18n import PT, TRANSLATIONS, get_lang

templates = Jinja2Templates(directory="templates")

# ── Filters ───────────────────────────────────────────────────────────────────

def _fmt_bytes(b: int) -> str:
    if b >= 1024 ** 3:
        return f"{b / 1024**3:.1f} GB"
    if b >= 1024 ** 2:
        return f"{b / 1024**2:.0f} MB"
    return f"{b / 1024:.0f} KB"


def _fmt_date(dt) -> str:
    if dt is None:
        return "—"
    if isinstance(dt, str):
        return dt[:10]
    return dt.strftime("%d/%m/%Y")


def _fmt_timestamp(ts) -> str:
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%m/%Y")
    except (ValueError, OSError):
        return "—"


templates.env.filters["fmt_bytes"] = _fmt_bytes
templates.env.filters["fmt_date"] = _fmt_date
templates.env.filters["fmt_timestamp"] = _fmt_timestamp

# PT as global fallback (admin pages inherit this without passing `t`)
templates.env.globals["t"] = PT
templates.env.globals["lang"] = "pt"


# ── Per-request render helper ─────────────────────────────────────────────────

def render(request: Request, template: str, ctx: dict, **kwargs):
    """Render a template, injecting `lang` and `t` from the lang cookie."""
    lang = get_lang(request)
    ctx["lang"] = lang
    ctx["t"] = TRANSLATIONS[lang]
    return templates.TemplateResponse(template, ctx, **kwargs)
