"""A interface web. Roda sem privilegio nenhum.

Este processo nunca escreve em /etc nem executa nada como root. Quando o
usuario muda alguma coisa, o resultado e' gravado em config.pending.yaml e o
trabalho de verdade fica com o fwctl, chamado via sudo com uma lista fechada
de subcomandos.

Consequencia pratica: um bug aqui — ou alguem que consiga falar com este
processo — nao consegue escrever uma regra de firewall arbitraria. So consegue
propor uma config, que ainda passa pelo modelo e pelo nft -c antes de valer.
"""

from __future__ import annotations

import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Callable
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from fwadmin import db, paths, status
from fwadmin.models import (
    Config,
    Failover,
    Host,
    PortForward,
    Reservation,
    Rule,
    Service,
)
from fwadmin.render import dump, load

TEMPLATES = Path(__file__).parent / "templates"
STATIC = Path(__file__).parent / "static"
HTMX = Path("/usr/share/javascript/htmx")

SESSION_COOKIE = "fwadmin_session"

MAX_BODY = 256 * 1024
"""Nenhum formulario daqui chega perto disso; o limite corta abuso."""


class FormData(dict):
    """Campos de um formulario, com leitura tolerante.

    Formulario que nao veio (checkbox desmarcado, campo ausente) devolve o
    default em vez de estourar — a validacao de verdade e' do modelo Pydantic,
    nao daqui.
    """

    def text(self, key: str, default: str = "") -> str:
        return self.get(key, default).strip()

    def number(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, "").strip())
        except ValueError:
            return default

    def flag(self, key: str) -> bool:
        return bool(self.get(key, "").strip())

    def csv(self, key: str) -> list[str]:
        return [part.strip() for part in self.get(key, "").split(",") if part.strip()]


async def form(request: Request) -> FormData:
    """Le o corpo do POST como urlencoded.

    Nao usamos o Form() do FastAPI de proposito: ele exige o python-multipart,
    e o pacote de mesmo nome no Debian e' de outro projeto, sem a API que o
    FastAPI espera. Como nenhum formulario daqui envia arquivo, urlencoded
    resolve — e o firewall fica sem depender de um pacote descasado.
    """
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail="formulário grande demais")
    parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    return FormData({key: values[-1] for key, values in parsed.items()})


Fields = Annotated[FormData, Depends(form)]

FWCTL = "/usr/local/sbin/fwctl"
ALLOWED_FWCTL = {"check", "apply", "confirm", "rollback", "status", "diff"}

app = FastAPI(title="fwadmin", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=str(TEMPLATES))
templates.env.filters["timestamp"] = lambda value: datetime.fromtimestamp(value).strftime(
    "%d/%m %H:%M"
)


# ---------------------------------------------------------------------------
# chamada ao fwctl — a unica ponte para o privilegio
# ---------------------------------------------------------------------------


def fwctl(*args: str, timeout: int = 180) -> tuple[bool, str]:
    """Executa um subcomando do fwctl via sudo.

    A lista de subcomandos e' fechada aqui e tambem no sudoers: mesmo que este
    processo seja comprometido, ele nao consegue rodar outra coisa como root.
    """
    if not args or args[0] not in ALLOWED_FWCTL:
        return False, f"subcomando nao permitido: {args[0] if args else '(vazio)'}"
    try:
        proc = subprocess.run(
            ["sudo", "-n", FWCTL, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"nao consegui chamar o fwctl: {exc}"
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


# ---------------------------------------------------------------------------
# configuracao em edicao
# ---------------------------------------------------------------------------


def current() -> Config:
    """A config que a UI mostra: a pendente, se houver, senao a viva."""
    source = paths.PENDING if paths.PENDING.exists() else paths.CONFIG
    return load(source)


def save_pending(cfg: Config) -> None:
    """Grava a proposta. Nada e' aplicado ate alguem pedir."""
    paths.PENDING.parent.mkdir(parents=True, exist_ok=True)
    paths.PENDING.write_text(
        dump(cfg, header="# Proposta pela interface web, ainda NAO aplicada.\n")
    )


def has_pending() -> bool:
    return paths.PENDING.exists()


def edit(request: Request, mutate: Callable[[Config], Any], action: str) -> str | None:
    """Aplica uma mudanca no modelo, valida e grava como pendente.

    Devolve None em caso de sucesso, ou a mensagem de erro. Como a validacao
    roda antes de gravar, uma edicao invalida nao chega nem a virar proposta.
    """
    cfg = current()
    try:
        mutate(cfg)
        validated = Config.model_validate(cfg.model_dump())
    except ValidationError as exc:
        return format_validation_error(exc)
    except (ValueError, KeyError) as exc:
        return str(exc)

    save_pending(validated)
    db.log(action, username=user_of(request), address=client_ip(request))
    return None


def format_validation_error(exc: ValidationError) -> str:
    """Transforma o erro do Pydantic em algo legivel num formulario."""
    parts = []
    for error in exc.errors():
        location = ".".join(str(p) for p in error["loc"] if p != "__root__")
        message = error["msg"].removeprefix("Value error, ")
        parts.append(f"{location}: {message}" if location else message)
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# autenticacao
# ---------------------------------------------------------------------------


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def user_of(request: Request) -> str:
    session = db.get_session(request.cookies.get(SESSION_COOKIE, ""))
    return session.username if session else ""


async def require_login(request: Request) -> str:
    session = db.get_session(request.cookies.get(SESSION_COOKIE, ""))
    if session is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return session.username


User = Annotated[str, Depends(require_login)]


@app.exception_handler(HTTPException)
async def redirect_unauthenticated(request: Request, exc: HTTPException) -> Response:
    if exc.status_code == 303 and "Location" in (exc.headers or {}):
        return RedirectResponse(exc.headers["Location"], status_code=303)
    return HTMLResponse(f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>", status_code=exc.status_code)


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


def page(request: Request, template: str, **ctx: Any) -> HTMLResponse:
    base = {
        "request": request,
        "user": user_of(request),
        "pending": has_pending(),
        "nav": NAV,
        "path": request.url.path,
    }
    return templates.TemplateResponse(request, template, base | ctx)


NAV = [
    ("/", "Painel", "▦"),
    ("/interfaces", "Interfaces", "⇄"),
    ("/routing", "Roteamento", "⇱"),
    ("/dns", "DNS e DHCP", "◎"),
    ("/firewall", "Firewall", "⛨"),
    ("/services", "Serviços", "▤"),
    ("/diag", "Diagnóstico", "◈"),
    ("/system", "Sistema", "⚙"),
]


def back(path: str, error: str | None = None) -> RedirectResponse:
    target = f"{path}?erro={error}" if error else f"{path}?ok=1"
    return RedirectResponse(target, status_code=303)


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request) -> Response:
    if db.user_count() == 0:
        return page(request, "setup.html")
    return page(request, "login.html")


@app.post("/login")
async def login(request: Request, fields: Fields) -> Response:
    username = fields.text("username")
    password = fields.get("password", "")

    if db.user_count() == 0:
        if len(password) < 10:
            return page(request, "setup.html", error="a senha precisa de ao menos 10 caracteres")
        db.create_user(username, password)
        db.log("setup", username=username, address=client_ip(request))

    user_id = db.verify(username, password)
    if user_id is None:
        db.log("login-negado", username=username, address=client_ip(request))
        time.sleep(1)  # desacelera tentativa em massa; o fail2ban cuida do resto
        return page(request, "login.html", error="usuário ou senha inválidos")

    token = db.open_session(user_id, client_ip(request))
    db.log("login", username=username, address=client_ip(request))
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        max_age=db.SESSION_TTL,
        path="/",
    )
    return response


@app.post("/logout")
async def logout(request: Request) -> Response:
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        db.close_session(token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
# painel
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: User) -> Response:
    cfg = current()
    return page(
        request,
        "dashboard.html",
        cfg=cfg,
        wans=status.wans(cfg),
        system=status.system(),
        services=status.services(),
        leases=status.leases(cfg),
        failover=status.failover_state(),
        route_dev=status.default_route()[0],
    )


@app.get("/fragment/wans", response_class=HTMLResponse)
async def fragment_wans(request: Request, user: User) -> Response:
    """Atualizado sozinho pelo htmx a cada 10s."""
    cfg = current()
    return page(
        request,
        "_wans.html",
        cfg=cfg,
        wans=status.wans(cfg),
        failover=status.failover_state(),
    )


# ---------------------------------------------------------------------------
# interfaces
# ---------------------------------------------------------------------------


@app.get("/interfaces", response_class=HTMLResponse)
async def interfaces(request: Request, user: User) -> Response:
    return page(request, "interfaces.html", cfg=current(), links=status.links())


@app.post("/interfaces/{name}")
async def save_interface(request: Request, user: User, name: str, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        iface = cfg.iface(name)
        iface.description = fields.text("description")
        iface.ipv4.mode = fields.text("mode") or iface.ipv4.mode
        iface.ipv4.address = fields.text("address") or None
        iface.ipv4.gateway = fields.text("gateway") or None
        if iface.pppoe:
            iface.pppoe.username = fields.text("pppoe_username") or iface.pppoe.username
            mtu = fields.number("pppoe_mtu", iface.pppoe.mtu)
            iface.pppoe.mtu = mtu
            iface.pppoe.mru = mtu

    return back("/interfaces", edit(request, mutate, f"interface:{name}"))


# ---------------------------------------------------------------------------
# roteamento
# ---------------------------------------------------------------------------


@app.get("/routing", response_class=HTMLResponse)
async def routing(request: Request, user: User) -> Response:
    cfg = current()
    return page(
        request,
        "routing.html",
        cfg=cfg,
        wans=status.wans(cfg),
        failover=status.failover_state(),
        routes=status.routes(),
    )


@app.post("/routing")
async def save_routing(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.routing.primary = fields.text("primary")
        cfg.routing.backup = fields.text("backup") or None
        cfg.routing.failover = Failover(
            enabled=fields.flag("enabled"),
            interval_seconds=fields.number("interval_seconds", 60),
            threshold=fields.number("threshold", 3),
            ping_targets=fields.csv("ping_targets") or ["8.8.8.8"],
        )

    return back("/routing", edit(request, mutate, "routing"))


# ---------------------------------------------------------------------------
# DNS e DHCP
# ---------------------------------------------------------------------------


@app.get("/dns", response_class=HTMLResponse)
async def dns(request: Request, user: User) -> Response:
    cfg = current()
    return page(request, "dns.html", cfg=cfg, leases=status.leases(cfg))


@app.post("/dns/settings")
async def save_dns(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.dns.domain = fields.text("domain", cfg.dns.domain)
        cfg.dns.upstream = fields.csv("upstream")
        cfg.dns.bind_interfaces = fields.flag("bind_interfaces")
        cfg.dhcp.enabled = fields.flag("dhcp_enabled")
        cfg.dhcp.range.start = fields.text("range_start", cfg.dhcp.range.start)
        cfg.dhcp.range.end = fields.text("range_end", cfg.dhcp.range.end)
        cfg.dhcp.range.lease = fields.text("lease", cfg.dhcp.range.lease)

    return back("/dns", edit(request, mutate, "dns"))


@app.post("/dns/reservation")
async def add_reservation(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.dhcp.reservations.append(
            Reservation(
                mac=fields.text("mac"),
                ip=fields.text("ip"),
                name=fields.text("name"),
                description=fields.text("description"),
            )
        )

    return back("/dns", edit(request, mutate, f"reserva+:{fields.text('name')}"))


@app.post("/dns/reservation/{mac}/delete")
async def del_reservation(request: Request, user: User, mac: str) -> Response:
    def mutate(cfg: Config) -> None:
        remaining = [r for r in cfg.dhcp.reservations if r.mac != mac]
        if len(remaining) == len(cfg.dhcp.reservations):
            raise ValueError(f"reserva inexistente: {mac}")
        cfg.dhcp.reservations = remaining

    return back("/dns", edit(request, mutate, f"reserva-:{mac}"))


@app.post("/dns/host")
async def add_host(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.hosts.append(
            Host(
                name=fields.text("name"),
                ip=fields.text("ip"),
                group=fields.text("group") or None,
                description=fields.text("description"),
            )
        )

    return back("/dns", edit(request, mutate, f"host+:{fields.text('name')}"))


@app.post("/dns/host/{name}/delete")
async def del_host(request: Request, user: User, name: str) -> Response:
    def mutate(cfg: Config) -> None:
        remaining = [h for h in cfg.hosts if h.name != name]
        if len(remaining) == len(cfg.hosts):
            raise ValueError(f"host inexistente: {name}")
        cfg.hosts = remaining

    return back("/dns", edit(request, mutate, f"host-:{name}"))


# ---------------------------------------------------------------------------
# firewall
# ---------------------------------------------------------------------------


@app.get("/firewall", response_class=HTMLResponse)
async def firewall(request: Request, user: User) -> Response:
    return page(request, "firewall.html", cfg=current())


@app.post("/firewall/policy")
async def save_policy(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.firewall.input_policy = fields.text("input_policy")
        cfg.firewall.forward_policy = fields.text("forward_policy")

    return back("/firewall", edit(request, mutate, "firewall:policy"))


def _chain_of(cfg: Config, chain: str) -> list[Rule]:
    if chain not in ("input", "forward"):
        raise ValueError(f"cadeia desconhecida: {chain}")
    return getattr(cfg.firewall, f"{chain}_rules")


@app.post("/firewall/rule/{chain}")
async def add_rule(request: Request, user: User, chain: str, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        _chain_of(cfg, chain).append(
            Rule(
                action=fields.text("action"),
                source=fields.text("source", "any"),
                destination=fields.text("destination", "any"),
                proto=fields.text("proto", "any"),
                dest_ports=fields.text("dest_ports"),
                description=fields.text("description"),
                log=fields.flag("log"),
            )
        )

    return back("/firewall", edit(request, mutate, f"regra+:{chain}"))


@app.post("/firewall/rule/{chain}/{index}/delete")
async def del_rule(request: Request, user: User, chain: str, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        rules = _chain_of(cfg, chain)
        if not 0 <= index < len(rules):
            raise ValueError("regra inexistente")
        rules.pop(index)

    return back("/firewall", edit(request, mutate, f"regra-:{chain}:{index}"))


@app.post("/firewall/rule/{chain}/{index}/move")
async def move_rule(
    request: Request, user: User, chain: str, index: int, fields: Fields
) -> Response:
    def mutate(cfg: Config) -> None:
        rules = _chain_of(cfg, chain)
        target = index - 1 if fields.text("direction") == "up" else index + 1
        if not (0 <= index < len(rules) and 0 <= target < len(rules)):
            raise ValueError("movimento fora da lista")
        rules[index], rules[target] = rules[target], rules[index]

    return back("/firewall", edit(request, mutate, f"regra~:{chain}:{index}"))


@app.post("/firewall/forward")
async def add_forward(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.firewall.port_forwards.append(
            PortForward(
                interface=fields.text("interface"),
                wan_port=fields.number("wan_port"),
                to_ip=fields.text("to_ip"),
                to_port=fields.number("to_port"),
                proto=fields.text("proto", "tcp"),
                description=fields.text("description"),
                source_filter=fields.text("source_filter"),
            )
        )

    return back("/firewall", edit(request, mutate, f"dnat+:{fields.text('wan_port')}"))


@app.post("/firewall/forward/{index}/delete")
async def del_forward(request: Request, user: User, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        if not 0 <= index < len(cfg.firewall.port_forwards):
            raise ValueError("port-forward inexistente")
        cfg.firewall.port_forwards.pop(index)

    return back("/firewall", edit(request, mutate, f"dnat-:{index}"))


# ---------------------------------------------------------------------------
# servicos — o portal, agora vindo do mesmo modelo do DNS
# ---------------------------------------------------------------------------


@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request, user: User) -> Response:
    cfg = current()
    grouped = {}
    for group in sorted(cfg.portal.groups, key=lambda g: g.order):
        members = [h for h in cfg.hosts if h.group == group.id and h.services]
        if members:
            grouped[group.id] = (group, members)
    loose = [h for h in cfg.hosts if h.services and (not h.group or h.group not in grouped)]
    return page(request, "services.html", cfg=cfg, grouped=grouped, loose=loose)


@app.post("/services/add")
async def add_service(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        host = fields.text("host")
        target = next((h for h in cfg.hosts if h.name == host), None)
        if target is None:
            raise ValueError(f"host desconhecido: {host}")
        target.services.append(
            Service(
                name=fields.text("name"),
                url=fields.text("url"),
                description=fields.text("description"),
                icon=fields.text("icon"),
                tag=fields.text("tag"),
                tag_style=fields.text("tag_style"),
            )
        )

    return back("/services", edit(request, mutate, f"servico+:{fields.text('name')}"))


@app.post("/services/{host}/{index}/delete")
async def del_service(request: Request, user: User, host: str, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        target = next((h for h in cfg.hosts if h.name == host), None)
        if target is None or not 0 <= index < len(target.services):
            raise ValueError("serviço inexistente")
        target.services.pop(index)

    return back("/services", edit(request, mutate, f"servico-:{host}:{index}"))


# ---------------------------------------------------------------------------
# diagnostico
# ---------------------------------------------------------------------------


@app.get("/diag", response_class=HTMLResponse)
async def diag(request: Request, user: User) -> Response:
    return page(request, "diag.html", cfg=current(), result=None)


@app.post("/diag", response_class=HTMLResponse)
async def run_diag(
    request: Request,
    user: User,
    fields: Fields,
) -> Response:
    tool = fields.text("tool")
    target = fields.text("target")
    iface = fields.text("iface")

    probes = {
        "ping": lambda: status.ping(target, iface),
        "traceroute": lambda: status.traceroute(target),
        "dns": lambda: status.dns_lookup(target),
    }
    if tool in probes:
        result = probes[tool]()
    elif tool == "nft":
        result = status.Probe(True, status.nft_ruleset(), "nft list ruleset")
    elif tool == "routes":
        result = status.Probe(True, status.routes(), "ip route show")
    elif tool == "journal":
        result = status.Probe(True, status.journal(target), f"journalctl -u {target or 'todos'}")
    else:
        result = status.Probe(False, f"ferramenta desconhecida: {tool}")

    db.log(f"diag:{tool}", username=user, address=client_ip(request))
    return page(request, "diag.html", cfg=current(), result=result, tool=tool, target=target)


# ---------------------------------------------------------------------------
# sistema — aplicar, confirmar, reverter
# ---------------------------------------------------------------------------


@app.get("/system", response_class=HTMLResponse)
async def system_page(request: Request, user: User) -> Response:
    ok, state = fwctl("status", timeout=20)
    _, diff = fwctl("diff", timeout=60) if has_pending() else (True, "")
    return page(
        request,
        "system.html",
        cfg=current(),
        state=state,
        diff=diff,
        history=git_history(),
        audit=db.recent(30),
        system=status.system(),
    )


@app.post("/system/apply")
async def do_apply(request: Request, user: User, fields: Fields) -> Response:
    # A mensagem do commit vai por arquivo, nao por argumento: assim o sudoers
    # lista comandos exatos, sem curinga.
    note = fields.text("note") or f"alteração pela web · {user}"
    paths.NOTE.parent.mkdir(parents=True, exist_ok=True)
    paths.NOTE.write_text(note[:200])

    args = ["apply", "--yes"] if fields.flag("yes") else ["apply"]
    ok, output = fwctl(*args)
    db.log("apply", username=user, address=client_ip(request), ok=ok)
    return page(request, "result.html", title="Aplicar", ok=ok, output=output, cfg=current())


@app.post("/system/confirm")
async def do_confirm(request: Request, user: User) -> Response:
    ok, output = fwctl("confirm")
    db.log("confirm", username=user, address=client_ip(request), ok=ok)
    return page(request, "result.html", title="Confirmar", ok=ok, output=output, cfg=current())


@app.post("/system/rollback")
async def do_rollback(request: Request, user: User) -> Response:
    ok, output = fwctl("rollback")
    db.log("rollback", username=user, address=client_ip(request), ok=ok)
    return page(request, "result.html", title="Reverter", ok=ok, output=output, cfg=current())


@app.post("/system/discard")
async def discard_pending(request: Request, user: User) -> Response:
    paths.PENDING.unlink(missing_ok=True)
    db.log("descartar-pendente", username=user, address=client_ip(request))
    return back("/system")


@app.get("/system/state", response_class=PlainTextResponse)
async def system_state(request: Request, user: User) -> str:
    """Consultado pelo htmx para o contador de confirmacao."""
    _, output = fwctl("status", timeout=20)
    return output


@app.get("/system/config", response_class=PlainTextResponse)
async def download_config(request: Request, user: User) -> Response:
    source = paths.PENDING if has_pending() else paths.CONFIG
    return PlainTextResponse(
        source.read_text(),
        headers={"Content-Disposition": 'attachment; filename="fwadmin-config.yaml"'},
    )


def git_history(limit: int = 20) -> list[dict[str, str]]:
    """Historico de commits da config — o rollback de longo prazo."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(paths.ETC), "log", f"-{limit}", "--format=%h%x1f%ar%x1f%s"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    entries = []
    for line in proc.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 3:
            entries.append({"hash": parts[0], "when": parts[1], "subject": parts[2]})
    return entries


# ---------------------------------------------------------------------------
# arquivos estaticos e inicializacao
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
if HTMX.is_dir():
    app.mount("/vendor", StaticFiles(directory=str(HTMX)), name="vendor")


@app.on_event("startup")
async def startup() -> None:
    db.init()
