"""O catalogo de aplicativos: o que e' fixo em cada um.

O usuario liga e desliga; o resto e' decisao do projeto e mora aqui — a
imagem (por digest, porque tag que anda nao e' rollback), as montagens (as do
STORAGE.md), a porta em loopback, o usuario do processo e a prova de funcao.

Os caminhos sao os do STORAGE.md: os dados do usuario em /srv/aionas/<Pasta>,
o estado de cada aplicativo em /var/lib/aionas/<app>. Sem o modulo de storage
eles ficam no disco do sistema; quando ele chegar, monta o volume nos mesmos
caminhos, e nada aqui muda.

Aplicativo com mais de um container (banco, cache) declara os outros como
'sidecars': entram no mesmo compose, na rede interna dele, sem porta nenhuma
publicada. So o principal e' alcancavel, e so em loopback.
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
class Sidecar:
    """Um container de apoio: banco, cache, inferencia."""

    name: str
    """Nome do servico no compose — e' o hostname pelo qual o principal o acha."""

    image: str
    mounts: tuple[Mount, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    command: tuple[str, ...] = ()
    shm_size: str | None = None
    secret: bool = False
    """Recebe o arquivo de segredo do aplicativo (env_file)."""

    optional: str | None = None
    """Campo do App que liga este container (ex.: 'ml'). None = sempre sobe."""


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
    """Usuario dos processos dentro dos containers, dono do estado."""

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

    sidecars: tuple[Sidecar, ...] = ()
    secret_vars: tuple[str, ...] = ()
    """Variaveis que recebem a senha gerada do aplicativo (a do banco). A senha
    nasce no primeiro apply, mora em secrets.yaml e chega aos containers por
    um env_file 0600 — nunca no compose, que o painel mostra."""

    secret: bool = False
    """O container principal tambem recebe o arquivo de segredo."""

    off_env: dict[str, dict[str, str]] = field(default_factory=dict)
    """Variaveis do principal quando um sidecar opcional esta desligado:
    {'ml': {'IMMICH_MACHINE_LEARNING_ENABLED': 'false'}}."""

    @property
    def state_dir(self) -> str:
        return f"{STATE}/{self.key}"

    @property
    def all_mounts(self) -> tuple[Mount, ...]:
        out = list(self.mounts)
        for s in self.sidecars:
            out.extend(s.mounts)
        return tuple(out)

    @property
    def media_dirs(self) -> list[str]:
        """Pastas do usuario, so leitura: criadas do root, 0755."""
        return sorted({m.host for m in self.all_mounts if m.host.startswith(MEDIA + "/") and m.readonly})

    @property
    def media_dirs_rw(self) -> list[str]:
        """Pastas do usuario onde o aplicativo escreve: criadas com o dono dele.

        Provisorio ate o modulo de storage, que vai dar a cada pasta um grupo
        comum aos aplicativos e ao SMB. Hoje so o Immich escreve em Pictures.
        """
        ro = set(self.media_dirs)
        return sorted(
            {m.host for m in self.all_mounts if m.host.startswith(MEDIA + "/") and not m.readonly} - ro
        )

    @property
    def state_dirs(self) -> list[str]:
        """Diretorios de estado montados, criados com o dono do processo."""
        return sorted({m.host for m in self.all_mounts if m.host.startswith(self.state_dir + "/")})

    def options(self) -> set[str]:
        return {s.optional for s in self.sidecars if s.optional}

    def images(self, enabled: set[str] | frozenset[str] = frozenset()) -> list[str]:
        """Todas as imagens que sobem com estas opcoes ligadas."""
        out = [self.image]
        out += [s.image for s in self.sidecars if s.optional is None or s.optional in enabled]
        return out


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
    # A biblioteca e' o proprio Pictures (STORAGE.md): o storage template grava
    # em Pictures/<usuario>/<ano>/... O que e' do Immich e nao do usuario —
    # upload em andamento, miniaturas, video transcodificado, backup do banco —
    # fica em /var/lib/aionas/immich, montado por cima das subpastas de /data.
    "immich": AppSpec(
        key="immich",
        name="Immich",
        role="Fotos e vídeos: backup do celular, álbuns e busca",
        image=(
            "ghcr.io/immich-app/immich-server:v3.3.5"
            "@sha256:485d546a2e31d6a8b4db8423fcba5c109de8c218d93410af115fd1ccfc4352a6"
        ),
        port=2283,
        uid=2003,
        mounts=(
            Mount(f"{MEDIA}/Pictures", "/data/library"),
            Mount(f"{STATE}/immich/upload", "/data/upload"),
            Mount(f"{STATE}/immich/thumbs", "/data/thumbs"),
            Mount(f"{STATE}/immich/encoded-video", "/data/encoded-video"),
            Mount(f"{STATE}/immich/profile", "/data/profile"),
            Mount(f"{STATE}/immich/backups", "/data/backups"),
        ),
        env={
            "DB_HOSTNAME": "database",
            "DB_USERNAME": "immich",
            "DB_DATABASE_NAME": "immich",
            "REDIS_HOSTNAME": "redis",
            "IMMICH_MACHINE_LEARNING_URL": "http://machine-learning:3003",
        },
        health="/api/server/ping",
        health_body='{"res":"pong"}',
        upload_limit="50000m",
        gpu=True,
        secret=True,
        secret_vars=("DB_PASSWORD", "POSTGRES_PASSWORD"),
        off_env={"ml": {"IMMICH_MACHINE_LEARNING_ENABLED": "false"}},
        sidecars=(
            Sidecar(
                name="database",
                image=(
                    "ghcr.io/immich-app/postgres:14-vectorchord0.4.3-pgvectors0.2.0"
                    "@sha256:bcf63357191b76a916ae5eb93464d65c07511da41e3bf7a8416db519b40b1c23"
                ),
                mounts=(Mount(f"{STATE}/immich/postgres", "/var/lib/postgresql/data"),),
                env={
                    "POSTGRES_USER": "immich",
                    "POSTGRES_DB": "immich",
                    "POSTGRES_INITDB_ARGS": "--data-checksums",
                },
                shm_size="128mb",
                secret=True,
            ),
            Sidecar(
                name="redis",
                image=(
                    "docker.io/valkey/valkey:9"
                    "@sha256:c123e3715db63d06d4ad6964884037aa0d5d4d703939b9929954112889708e1d"
                ),
                # Fila e cache: nada a persistir, e sem volume nao ha onde.
                command=("valkey-server", "--save", "", "--appendonly", "no"),
            ),
            Sidecar(
                name="machine-learning",
                image=(
                    "ghcr.io/immich-app/immich-machine-learning:v3.3.5"
                    "@sha256:5b28c9352c8374b8a1ed96fbdd8d6755fea6e43510ec43fdf6538aa02ea40f56"
                ),
                mounts=(Mount(f"{STATE}/immich/model-cache", "/cache"),),
                optional="ml",
            ),
        ),
    ),
}
