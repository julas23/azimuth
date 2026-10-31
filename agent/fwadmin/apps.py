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

    health_body: str | None = None
    """Corpo exato que conta como de pe, quando 200 nao basta: o Jellyfin
    responde 200 'Degraded' enquanto ainda esta subindo."""

    upload_limit: str = "16m"
    gpu: bool = False
    """Aceita aceleracao de hardware pelo /dev/dri (Intel e AMD: VA-API, QSV).
    NVIDIA exige o nvidia-container-toolkit e fica de fora por enquanto."""

    @property
    def state_dir(self) -> str:
        return f"{STATE}/{self.key}"

    @property
    def media_dirs(self) -> list[str]:
        return [m.host for m in self.mounts if m.host.startswith(MEDIA + "/")]

    @property
    def state_dirs(self) -> list[str]:
        """Diretorios de estado montados, criados com o dono do processo."""
        return [m.host for m in self.mounts if m.host.startswith(self.state_dir + "/")]


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
    "jellyfin": AppSpec(
        key="jellyfin",
        name="Jellyfin",
        role="Filmes, séries e música, com apps na TV e no celular",
        image=(
            "jellyfin/jellyfin:12.4"
            "@sha256:fea863d0cd9ec445985d9c75fc6ed64e38a1d2766cf0c250a33d553f4fc1b771"
        ),
        port=8096,
        uid=2002,
        mounts=(
            Mount(f"{MEDIA}/Videos", "/media/videos", readonly=True),
            Mount(f"{MEDIA}/Music", "/media/music", readonly=True),
            Mount(f"{STATE}/jellyfin/config", "/config"),
            Mount(f"{STATE}/jellyfin/cache", "/cache"),
        ),
        health="/health",
        health_body="Healthy",
        upload_limit="64m",
        gpu=True,
    ),
}
