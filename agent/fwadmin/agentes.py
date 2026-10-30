"""Agentes no navegador: catalogo, niveis de acesso e os arquivos de cada um.

O desenho esta no AGENTES.md. Quanto poder o agente tem e' escolha do
usuario: este modulo so traduz o nivel escolhido em arquivos de sistema. Quem
os escreve, como root, e' o 'fwctl agente'; o painel so le o estado.

Cada agente tem um usuario Linux proprio (az-<nome>). Com um usuario so para
todos, um agente de leitura poderia escrever um .bashrc que um agente com root
executaria, e o nivel de um vazaria para o outro.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass

from fwadmin import paths

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,15}$")

HOME = "/var/lib/azimuth-agente"
LOGS = "/var/log/azimuth-agente"
ETC = "/etc/azimuth-agente"
RUN = "/run/azimuth-agente"
UNIT = "azimuth-agente@{}.service"
DROPIN = "/etc/systemd/system/azimuth-agente@{}.service.d/nivel.conf"
SUDOERS = "/etc/sudoers.d/azimuth-agente-{}"

STATE = paths.VAR / "agentes.json"
"""{nome: {kind, nivel, criado}}. Escrito pelo fwctl, lido pelo painel."""

REQUEST = paths.VAR / "agente-pedido.json"
"""O pedido do painel ao 'fwctl agente', por arquivo, como o do fail2ban."""

PANEL_USER = "netadm"


@dataclass(frozen=True)
class Kind:
    title: str
    packages: tuple[str, ...]
    """Pacotes do Debian que o agente precisa (instalados pelo fwctl, como root)."""

    install: str
    """Como instalar o CLI no diretorio do usuario, se faltar. Roda na propria
    sessao, para o usuario ver o progresso no navegador."""

    command: str
    """O que a sessao abre. Vazio = so o shell."""

    note: str


CATALOG: dict[str, Kind] = {
    "claude-code": Kind(
        title="Claude Code",
        packages=("nodejs", "npm"),
        install="npm install -g @anthropic-ai/claude-code",
        command="claude",
        note="o agente da Anthropic; o login (conta Claude ou chave da API) acontece no próprio terminal",
    ),
    "shell": Kind(
        title="Shell livre",
        packages=(),
        install="",
        command="",
        note="um terminal no ambiente do agente, para instalar e rodar o agente que você quiser",
    ),
}

LEVELS: dict[str, str] = {
    "isolado": "só o próprio ambiente; não enxerga nada do firewall",
    "leitura": "lê os logs do sistema (journal) e o que é legível na máquina; não enxerga senhas nem chaves",
    "motor": "muda a configuração e os serviços pelo motor, com validação, prova e rollback",
    "root": "tudo, na máquina inteira (sudo sem senha)",
}
DEFAULT_LEVEL = "leitura"
UNAVAILABLE: dict[str, str] = {}
"""Niveis que ainda nao funcionam, com o motivo que a tela mostra."""

RANK = {"isolado": 0, "leitura": 1, "motor": 2, "root": 3}
"""O que cada nivel alcanca no comando azimuth: leitura le, motor (e root) muda."""

CERT = f"{ETC}/painel.crt"
"""O certificado do painel, copiado para onde o agente le: o comando azimuth
confia nele e em nenhum outro."""

PANEL_PORT = 8443


def user_of(nome: str) -> str:
    return f"az-{nome}"


def home_of(nome: str) -> str:
    return f"{HOME}/{nome}"


def socket_of(nome: str) -> str:
    return f"{RUN}/{nome}/tmux.sock"


def load_state() -> dict[str, dict]:
    try:
        data = json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def env_file(nome: str, kind: str) -> str:
    """O que a sessao precisa saber do agente. Valores so do catalogo."""
    k = CATALOG[kind]
    return (
        f"# gerado pelo fwctl agente — agente '{nome}' ({k.title})\n"
        f"AGENTE_NOME={nome}\n"
        f"AGENTE_KIND={kind}\n"
        f"AGENTE_CMD='{k.command}'\n"
        f"AGENTE_INSTALA='{k.install}'\n"
        f"AGENTE_PAINEL={PANEL_USER}\n"
    )


def dropin(nome: str, level: str) -> str:
    """O nivel em forma de unidade do systemd.

    Abaixo de root, o agente roda com o sistema so para leitura, sem ganhar
    privilegio (NoNewPrivileges desliga o sudo) e sem enxergar onde moram as
    senhas e chaves do firewall. Root tira tudo isso: e' o que o usuario pediu.
    """
    head = f"# gerado pelo fwctl agente — nivel '{level}' do agente '{nome}'\n[Service]\n"
    if level == "root":
        return head + "# root: sem restricao, por escolha do usuario\n"
    lines = [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "PrivateTmp=yes",
        f"ReadWritePaths={home_of(nome)} {LOGS}/{nome}",
        "InaccessiblePaths=-/etc/fwadmin -/var/lib/fwadmin -/etc/wireguard -/etc/ppp -/root -/run/fwadmin",
    ]
    if level in ("leitura", "motor"):
        lines.append("SupplementaryGroups=systemd-journal")
    return head + "\n".join(lines) + "\n"


def sudoers(nome: str) -> str:
    return (
        f"# gerado pelo fwctl agente — nivel root do agente '{nome}', escolhido pelo usuario\n"
        f"{user_of(nome)} ALL=(ALL) NOPASSWD: ALL\n"
    )


# ---------------------------------------------------------------------------
# o comando azimuth: token por agente, do nivel escolhido
# ---------------------------------------------------------------------------


def new_token() -> tuple[str, str]:
    """(token, sha256). O painel guarda so o hash, no agentes.json."""
    token = secrets.token_urlsafe(32)
    return token, token_digest(token)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_config(url: str, token: str) -> str:
    return json.dumps({"url": url, "token": token, "cert": CERT}, indent=1) + "\n"


GUIDE = {
    "isolado": "Neste nível você **não tem acesso ao firewall**: o comando `azimuth` recusa, e as pastas do "
    "firewall ficam fora do seu alcance. Peça ao dono para subir o nível na página Agentes, se precisar.",
    "leitura": "Neste nível você **lê**: estado, configuração, leases, alertas, logs, o diff pendente e "
    "diagnósticos. Não muda nada. Para propor ou aplicar uma mudança, o dono precisa subir o nível para "
    "**motor** na página Agentes.",
    "motor": "Neste nível você **lê e muda pelo motor**: propõe uma mudança (JSON Patch sobre o modelo, "
    "validada antes de virar proposta), aplica (com prova de função e rollback automático) e age sobre os "
    "serviços da stack. **O confirmar do apply é do dono, no painel**: depois de `azimuth aplicar`, avise que "
    "ele precisa conferir a rede e clicar em Confirmar em Sistema, senão tudo volta sozinho em 90 segundos.",
    "root": "Neste nível você tem **a máquina inteira** (`sudo` sem senha). Mesmo assim, **mude a rede pelo "
    "comando `azimuth`**: o que passa pelo motor é validado, provado e reversível. Edição feita à mão em "
    "/etc é detectada pelo motor como \"edição à mão\" e trava o próximo apply até alguém decidir.",
}


def guide(nome: str, level: str) -> str:
    """O AZIMUTH.md do agente: o que e' esta caixa, o nivel e o comando."""
    return f"""# Você está num firewall Azimuth

Você é o agente `{nome}`, rodando dentro de um firewall doméstico (Azimuth), usado pelo dono no
navegador. Ajude a diagnosticar, configurar, instalar e ajustar a rede de casa. Responda em
português do Brasil.

## Seu nível: {level}

{GUIDE[level]}

## Como o firewall funciona

- A configuração inteira é **um modelo declarativo** (YAML). O motor gera os arquivos do sistema
  (nftables, dnsmasq, unbound, WireGuard, interfaces, PPPoE) a partir dele. Mudar a rede é mudar o
  modelo, nunca os arquivos em /etc.
- Toda mudança passa por: **proposta** (validada contra o schema) → **aplicar** (instala, recarrega,
  prova que o serviço voltou e reverte sozinho se não voltou) → **confirmar** (o dono, no painel,
  depois de conferir que ainda alcança a caixa).
- A entrada vinda da internet é fechada: da WAN só passa a porta do WireGuard. A VPN é a porta da casa.

## O comando `azimuth`

```
azimuth quem                         # quem você é e o que seu nível alcança
azimuth estado                       # WANs, alertas, serviços, apply/proposta pendentes
azimuth config                       # o modelo inteiro (YAML, sem senhas nem chaves)
azimuth leases                       # quem pegou IP por DHCP
azimuth alertas
azimuth logs [unidade] [-n linhas]   # journal (ex.: azimuth logs dnsmasq -n 50)
azimuth diff                         # o que a proposta pendente muda nos arquivos
azimuth diag ping|dns|traceroute|rotas|nft [alvo]
azimuth propor [arquivo.json] -m "resumo"   # JSON Patch sobre o modelo (lê da entrada sem arquivo)
azimuth aplicar                      # o Aplicar de sempre; o confirmar é do dono
azimuth descartar                    # joga fora a proposta pendente
azimuth servico iniciar|parar|reiniciar|recarregar|instalar <nome>
```

Uma proposta é uma lista de operações JSON Patch (RFC 6902) sobre o modelo que `azimuth config`
mostra, por exemplo:

```json
[{{"op": "add", "path": "/dhcp/reservations/-",
  "value": {{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.60", "name": "impressora"}}}}]
```

Antes de propor, leia a configuração; depois de aplicar, confira com `azimuth estado` e os
diagnósticos, e diga ao dono o que confirmar.
"""
