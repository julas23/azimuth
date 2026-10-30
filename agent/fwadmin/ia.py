"""A camada de IA do painel: a IA propoe, o humano assina.

O painel manda a pergunta, a config (que nao tem segredo nenhum: senhas e
chaves moram em arquivos a parte) e o estado do momento. A resposta volta como
JSON: uma explicacao e, se for o caso, uma proposta em operacoes de JSON Patch
sobre o modelo. A proposta nao toca em nada: e' validada pelo modelo, mostrada
como diff, e so vira proposta pendente quando alguem clica. Dali em diante e' o
caminho de sempre, com Aplicar, prova e rollback.

HTTP direto, com a biblioteca padrao: a ISO evita pacote que nao vem do
Debian, e cada provedor e' uma requisicao so. Dois formatos: a Messages API da
Anthropic e o chat/completions compativel com OpenAI, que cobre Ollama, vLLM,
DeepSeek, Kimi e Gemini.

A configuracao (provedor, endereco, modelo e a chave) mora em
/var/lib/fwadmin/ia.json, 0600: e' do painel, nao do firewall, entao nao passa
pelo config.yaml nem pelo git. A chave nunca volta para a tela.
"""

from __future__ import annotations

import copy
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from fwadmin import paths

FILE = paths.VAR / "ia.json"

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2026-10-21"
ANTHROPIC_DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
"""Modelos que aceitam fallbacks: "default" (recusa por seguranca e' refeita
noutro modelo dentro da mesma chamada). Nos outros o campo daria 400."""

TIMEOUT = 300
MAX_TOKENS = 16000

PROVIDERS = {
    "anthropic": "Anthropic (Claude)",
    "openai": "Compatível com OpenAI (Ollama, vLLM, DeepSeek, Kimi, Gemini…)",
}


# ---------------------------------------------------------------------------
# configuracao
# ---------------------------------------------------------------------------


@dataclass
class Settings:
    provider: str = "anthropic"
    base_url: str = ""
    """So no formato OpenAI: 'http://10.0.0.50:11434/v1' para um Ollama da LAN."""

    model: str = ANTHROPIC_DEFAULT_MODEL
    key: str = ""

    @property
    def ready(self) -> bool:
        if self.provider == "anthropic":
            return bool(self.key and self.model)
        return bool(self.base_url and self.model)  # Ollama local nao pede chave

    @property
    def local(self) -> bool:
        """O endereco e' da LAN ou da propria caixa: nada sai de casa."""
        m = re.match(r"https?://([^/:]+)", self.base_url)
        host = m.group(1) if m else ""
        return self.provider == "openai" and bool(
            re.match(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost$)", host)
        )


def load() -> Settings:
    try:
        data = json.loads(FILE.read_text())
    except (OSError, ValueError):
        return Settings()
    known = {k: str(v) for k, v in data.items() if k in Settings.__dataclass_fields__}
    return Settings(**known)


def save(settings: Settings) -> None:
    FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_name(f".{FILE.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(settings.__dict__, indent=1))
    tmp.replace(FILE)


# ---------------------------------------------------------------------------
# o que vai e o que volta
# ---------------------------------------------------------------------------

SYSTEM = """Você ajuda o dono de um firewall doméstico (Azimuth) a entender e ajustar a rede de casa.
Responda em português do Brasil, direto e em poucas frases, sem jargão desnecessário.

Você recebe a configuração declarativa do firewall (o modelo, em JSON) e o estado do momento.
O modelo é a fonte da verdade: o motor gera os arquivos do sistema a partir dele.

Se a pergunta pede uma mudança, ou a resposta é uma mudança, devolva-a em "proposal": operações
JSON Patch (RFC 6902) sobre o modelo, com "op" (add, remove ou replace), "path" (JSON Pointer, por
exemplo "/dhcp/reservations/-" para acrescentar) e "value_json" (o valor, codificado como texto
JSON; use "null" no remove). Mude só o necessário e explique em "summary", numa frase, o que muda.
Sem mudança a propor, "proposal" é null.

Nunca proponha abrir a entrada do firewall, trocar a política para accept, nem redirecionar porta
da internet sem que a pergunta peça explicitamente: a VPN é a porta de entrada da casa. Uma
proposta nunca é aplicada por você: o dono revisa o diff e decide."""

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "proposal": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string"},
                        "ops": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "op": {"type": "string", "enum": ["add", "remove", "replace"]},
                                    "path": {"type": "string"},
                                    "value_json": {"type": "string"},
                                },
                                "required": ["op", "path", "value_json"],
                                "additionalProperties": False,
                            },
                        },
                    },
                    "required": ["summary", "ops"],
                    "additionalProperties": False,
                },
            ]
        },
    },
    "required": ["answer", "proposal"],
    "additionalProperties": False,
}


@dataclass
class Reply:
    ok: bool
    answer: str = ""
    summary: str = ""
    ops: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    usage: str = ""
    model: str = ""


def _post(url: str, headers: dict[str, str], body: dict) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=headers | {"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 — URL do dono
        return json.loads(response.read())


def _http_error(exc: urllib.error.HTTPError) -> str:
    try:
        detail = json.loads(exc.read()).get("error", {})
        message = detail.get("message", "") if isinstance(detail, dict) else str(detail)
    except (ValueError, AttributeError, OSError):
        message = ""
    return f"o provedor respondeu {exc.code}" + (f": {message}" if message else "")


def _parse(text: str) -> dict:
    """O JSON da resposta. No formato OpenAI o modelo pode cercar com ```json."""
    text = text.strip()
    m = re.search(r"\{.*\}", text, re.S)
    return json.loads(m.group(0) if m else text)


def _reply(data: dict, usage: str, model: str) -> Reply:
    proposal = data.get("proposal") or {}
    ops = []
    for op in proposal.get("ops") or []:
        try:
            value = json.loads(op.get("value_json") or "null")
        except ValueError:
            return Reply(False, error=f"a proposta trouxe um valor que não é JSON: {op.get('value_json')!r}")
        ops.append({"op": op.get("op"), "path": op.get("path"), "value": value})
    return Reply(True, answer=str(data.get("answer", "")), summary=str(proposal.get("summary", "")), ops=ops, usage=usage, model=model)


def ask(settings: Settings, question: str, context: dict[str, Any]) -> Reply:
    prompt = (
        "Configuração do firewall (modelo):\n```json\n"
        + json.dumps(context["config"], ensure_ascii=False, indent=1)
        + "\n```\n\nEstado agora:\n```json\n"
        + json.dumps(context["state"], ensure_ascii=False, indent=1)
        + f"\n```\n\nPergunta do dono: {question}"
    )
    try:
        if settings.provider == "anthropic":
            return _ask_anthropic(settings, prompt)
        return _ask_openai(settings, prompt)
    except urllib.error.HTTPError as exc:
        return Reply(False, error=_http_error(exc))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return Reply(False, error=f"não consegui falar com o provedor: {getattr(exc, 'reason', exc)}")
    except (ValueError, KeyError, TypeError) as exc:
        return Reply(False, error=f"a resposta do provedor não veio no formato esperado ({exc})")


def _ask_anthropic(settings: Settings, prompt: str) -> Reply:
    headers = {"x-api-key": settings.key, "anthropic-version": ANTHROPIC_VERSION}
    body: dict[str, Any] = {
        "model": settings.model,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM,
        "messages": [{"role": "user", "content": prompt}],
        "output_config": {"effort": "high", "format": {"type": "json_schema", "schema": SCHEMA}},
    }
    if settings.model in FALLBACK_MODELS:
        headers["anthropic-beta"] = FALLBACK_BETA
        body["fallbacks"] = "default"
    data = _post(ANTHROPIC_URL, headers, body)

    stop = data.get("stop_reason")
    if stop == "refusal":
        why = (data.get("stop_details") or {}).get("explanation") or "sem explicação"
        return Reply(False, error=f"o modelo recusou a pergunta ({why})")
    if stop == "max_tokens":
        return Reply(False, error="a resposta passou do limite de tamanho e veio cortada; tente uma pergunta mais estreita")
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    u = data.get("usage") or {}
    usage = f"{u.get('input_tokens', 0)} tokens de entrada, {u.get('output_tokens', 0)} de saída"
    return _reply(json.loads(text), usage, data.get("model", settings.model))


def _ask_openai(settings: Settings, prompt: str) -> Reply:
    url = settings.base_url.rstrip("/") + "/chat/completions"
    headers = {"authorization": f"Bearer {settings.key}"} if settings.key else {}
    body: dict[str, Any] = {
        "model": settings.model,
        "messages": [
            {"role": "system", "content": SYSTEM + "\n\nResponda só com um objeto JSON com as chaves \"answer\" e \"proposal\"."},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    try:
        data = _post(url, headers, body)
    except urllib.error.HTTPError as exc:
        if exc.code != 400:
            raise
        # nem todo servidor compativel conhece response_format: tenta sem
        del body["response_format"]
        data = _post(url, headers, body)
    choice = data["choices"][0]
    if choice.get("finish_reason") == "length":
        return Reply(False, error="a resposta passou do limite de tamanho e veio cortada")
    u = data.get("usage") or {}
    usage = f"{u.get('prompt_tokens', 0)} tokens de entrada, {u.get('completion_tokens', 0)} de saída" if u else ""
    return _reply(_parse(choice["message"]["content"]), usage, data.get("model", settings.model))


# ---------------------------------------------------------------------------
# JSON Patch sobre o modelo
# ---------------------------------------------------------------------------


def _pointer(path: str) -> list[str]:
    if not path.startswith("/"):
        raise ValueError(f"caminho invalido: {path!r}")
    return [p.replace("~1", "/").replace("~0", "~") for p in path[1:].split("/")]


def apply_patch(doc: dict, ops: list[dict[str, Any]]) -> dict:
    """add, remove e replace (RFC 6902) numa copia. ValueError com o motivo."""
    out = copy.deepcopy(doc)
    for op in ops:
        parts = _pointer(str(op.get("path", "")))
        parent: Any = out
        for key in parts[:-1]:
            parent = parent[int(key)] if isinstance(parent, list) else parent[key]
        last = parts[-1]
        kind = op.get("op")
        if isinstance(parent, list):
            if kind == "add":
                index = len(parent) if last == "-" else int(last)
                if not 0 <= index <= len(parent):
                    raise ValueError(f"indice fora da lista: {op['path']}")
                parent.insert(index, op.get("value"))
            elif kind in ("remove", "replace"):
                index = int(last)
                if not 0 <= index < len(parent):
                    raise ValueError(f"indice fora da lista: {op['path']}")
                if kind == "remove":
                    parent.pop(index)
                else:
                    parent[index] = op.get("value")
            else:
                raise ValueError(f"operacao desconhecida: {kind!r}")
        elif isinstance(parent, dict):
            if kind in ("add", "replace"):
                if kind == "replace" and last not in parent:
                    raise ValueError(f"nao existe para substituir: {op['path']}")
                parent[last] = op.get("value")
            elif kind == "remove":
                if last not in parent:
                    raise ValueError(f"nao existe para remover: {op['path']}")
                del parent[last]
            else:
                raise ValueError(f"operacao desconhecida: {kind!r}")
        else:
            raise ValueError(f"caminho nao leva a lista nem objeto: {op['path']}")
    return out
