"""O catalogo de aplicativos: o que e' fixo em cada um.

O usuario liga e desliga; o resto e' decisao do projeto e mora aqui — a
imagem (por digest, porque tag que anda nao e' rollback), as montagens (as do
STORAGE.md), a porta em loopback, o usuario do processo e a prova de funcao.

Os caminhos sao os do STORAGE.md: os dados do usuario em /srv/aionas/<Pasta>,
o estado de cada aplicativo em /var/lib/aionas/<app>. Sem o modulo de storage
eles ficam no disco do sistema; quando ele chegar, monta o volume nos mesmos
caminhos, e nada aqui muda.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MEDIA = "/srv/aionas"
STATE = "/var/lib/aionas"


@dataclass(frozen=True)
class Mount:
    host: str
    container: str
    readonly: bool = False


@dataclass(frozen=True)
class AppSpec:
    key: str
    name: str
    role: str
    image: str
    """repositorio:tag@sha256:digest — o digest e' o que vale; a tag e' leitura."""

    port: int
    """Porta do container, publicada em 127.0.0.1 com o mesmo numero."""

    uid: int
    """Usuario do processo dentro do container, dono do diretorio de estado."""

    mounts: tuple[Mount, ...]
    env: dict[str, str] = field(default_factory=dict)
    health: str = "/"
    """Caminho HTTP que responde 200 quando o aplicativo esta de pe."""

    upload_limit: str = "16m"

    @property
    def state_dir(self) -> str:
        return f"{STATE}/{self.key}"

    @property
    def media_dirs(self) -> list[str]:
        return [m.host for m in self.mounts if m.host.startswith(MEDIA + "/")]


CATALOG: dict[str, AppSpec] = {
    "navidrome": AppSpec(
        key="navidrome",
        name="Navidrome",
        role="Música: biblioteca e streaming, com apps Subsonic no celular",
        image=(
            "deluan/navidrome:0.64.2"
            "@sha256:38dc2727bfcfd5ede290f8ada114fc90368146f265ae4701ddddbcbe2a44ee52"
        ),
        port=4533,
        uid=2001,
        mounts=(
            Mount(f"{MEDIA}/Music", "/music", readonly=True),
            Mount(f"{STATE}/navidrome", "/data"),
        ),
        env={
            "ND_MUSICFOLDER": "/music",
            "ND_DATAFOLDER": "/data",
            "ND_LOGLEVEL": "info",
        },
        health="/ping",
    ),
}
