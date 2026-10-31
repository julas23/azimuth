# O que o Azimuth usa

Inventário de tudo que o produto empacota, roda ou depende — com papel, licença e estado.

Este arquivo tem três empregos. É o crédito: quase nada aqui é desenvolvimento
próprio, e a lista mostra de quem é o trabalho. É o que a ISO precisa
declarar, porque distribuir software GPL de terceiros obriga a dizer o que vai dentro e
onde estão os fontes. E é o inventário de dependência, que é por onde se descobre que
uma biblioteca parou de ser mantida antes de ela virar incidente.

**Legenda:** ✅ em uso e sob o motor · 🟡 em uso, ainda fora do motor · ⬜ decidido, não integrado · 🔍 candidato, ainda não decidido

---

## Base do sistema

| Componente | Papel | Licença | Estado |
|---|---|---|---|
| **Debian 13 (trixie)** | Sistema base da ISO | mista, majoritariamente GPL | ⬜ |
| **systemd** | Unidades, timers, sandbox dos serviços | LGPL-2.1+ | ✅ |
| **nginx** | TLS e filtro de origem na frente do painel | BSD-2-Clause | ✅ |
| **Python 3** | Linguagem do agente e do control plane | PSF | ✅ |
| **OpenSSH** | Acesso de manutenção | BSD-like | 🟡 |

O endurecimento do painel é feito por systemd, não por código: `ProtectSystem=full`,
usuário sem privilégio e `NoNewPrivileges=no` deliberado, porque o `sudo` para o `fwctl`
é a única ponte controlada que existe.

---

## Camada 1 — Conectividade e segurança

| Componente | Papel | Licença | Estado |
|---|---|---|---|
| **nftables** | Firewall, NAT, isolamento entre zonas | GPL-2.0 | ✅ |
| **dnsmasq** | DNS local, DHCP, reservas por MAC | GPL-2.0 ou GPL-3.0 | ✅ |
| **ifupdown** | Interfaces estáticas e DHCP | GPL-2.0 | ✅ |
| **ppp / pppd** | PPPoE na WAN quando o modem está em bridge | mista, estilo BSD | ✅ |
| **iproute2** | Rotas, links, estado — base do `status.py` | GPL-2.0 | ✅ |
| **wireguard-tools** | Túnel de acesso remoto; a única porta exposta | GPL-2.0 | 🟡 |
| **fail2ban** | Bloqueio ativo contra força bruta | GPL-2.0+ | 🟡 |
| **inadyn** | DDNS na conta do próprio usuário (DuckDNS, Cloudflare, No-IP…) | GPL-2.0 | ✅ |
| **iputils / traceroute** | Prova de função e diagnóstico | GPL-2.0 / BSD | ✅ |
| **bind9-dnsutils** (`dig`) | Consulta ao resolvedor local, na prova de função do DNS | MPL-2.0 | ✅ |

WireGuard e fail2ban estão marcados 🟡 pelo mesmo motivo: rodam em produção, mas fora do
motor transacional. Enquanto for assim, mudança neles não tem validação, nem manifesto,
nem rollback.

**O projeto não fornece DDNS.** O nome é do usuário, no provedor que ele escolher, e o
inadyn só o mantém apontando para o IP público. O token fica em arquivo próprio, 0600,
puxado por `include()`, pelo mesmo motivo da senha do PPPoE: o arquivo principal aparece
no diff e no backup. A unidade é do motor (`azimuth-ddns.service`), porque o pacote do
Debian traz só um script SysV, desligado.

O que protege o banimento ativo do fail2ban num reload de nftables é o gerador **não**
usar `flush ruleset`: ele recria só as tabelas próprias, pelo idioma `table X; delete
table X`. O campo `preserve_tables` do schema ainda não participa disso — hoje ele só
rende linhas de comentário no arquivo gerado. Transformá-lo em verificação de verdade,
conferindo depois do reload que cada tabela listada continua no ruleset, é o que fecha o
teste que o PLAN tem em aberto.

---

## Camada 2 — Orquestração

### Agente (`agent/`)

| Componente | Papel | Licença |
|---|---|---|
| **Pydantic 2** | Schema, validação e fonte de verdade do configurável | MIT |
| **Jinja2** | Geração dos arquivos de `/etc` e das telas do painel | BSD-3-Clause |
| **FastAPI** | Painel local | MIT |
| **uvicorn** | Servidor ASGI, escutando só no loopback | BSD-3-Clause |
| **PyYAML** | Leitura e escrita do `config.yaml` | MIT |
| **sqlite3** | Auditoria e sessões, da biblioteca padrão | domínio público |

**Essa lista é curta de propósito, e vale mantê-la assim.** O agente roda como root por
procuração, na borda da rede de uma casa, e cada dependência nova é código de terceiro
com esse alcance. Hoje são quatro pacotes fora da biblioteca padrão. Qualquer quinto
precisa se justificar.

### Control plane (`portal/`) — v2

| Componente | Papel | Licença |
|---|---|---|
| **FastAPI + uvicorn** | Aplicação web | MIT / BSD-3 |
| **PostgreSQL 16** | Banco | PostgreSQL License |
| **SQLAlchemy 2 + asyncpg** | ORM e driver assíncrono | MIT / Apache-2.0 |
| **Alembic** | Migrations versionadas | MIT |
| **passlib + bcrypt** | Hash de senha | BSD / Apache-2.0 |
| **python-jose** | JWT de acesso e refresh | MIT |
| **slowapi** | Rate limit | MIT |
| **httpx** | Cliente HTTP | BSD-3-Clause |
| **qrcode + Pillow** | QR do peer e do primeiro acesso | BSD / HPND |
| **aiosmtplib** | Verificação de e-mail e senha temporária | MIT |
| **APScheduler** | Tarefas periódicas | MIT |
| **Stripe** | Cobrança — código herdado do `vpn-web`, fora do produto | **serviço comercial** |
| **Docker + Compose** | Substrato de implantação do ACP | Apache-2.0 |

### Distribuição

| Componente | Papel | Licença | Estado |
|---|---|---|---|
| **debian-installer (preseed)** | ISO com uma pergunta só | GPL-2.0 | ⬜ |
| **GnuPG** | Assinatura do repositório APT | GPL-3.0 | ⬜ |
| **aptly** | Repositório APT assinado, com snapshot por canal | MIT |  ⬜ |
| **Distribution** (`registry:2`) | Registry de imagens do projeto, amd64 e arm64 | Apache-2.0 | ⬜ |
| **skopeo** / **regclient** | Cópia curada de digest para o registry do projeto | Apache-2.0 | ⬜ |
| **Avahi (mDNS)** | Achar o appliance sem monitor | LGPL-2.1 | ⬜ |

---

## Camada 3 — IA

Nada aqui aplica mudança, e nada aqui é obrigatório: tudo degrada sem quebrar o resto.

| Componente | Papel | Licença | Estado |
|---|---|---|---|
| **Ollama** | Motor local de modelo | MIT | ⬜ |
| **vLLM** | Motor local para quem tem GPU | Apache-2.0 | ⬜ |
| **Open WebUI** | Interface de conversa na LAN | BSD-3 **com cláusula de marca** | 🔍 |
| **Whisper** (`whisper.cpp` / `faster-whisper`) | Voz para texto | MIT | ⬜ |
| **Piper** | Texto para voz, roda em hardware modesto | MIT | ⬜ |
| **Claude, Gemini, DeepSeek, Kimi** | BYOK — chave do usuário, chamada pelo cliente | **serviços comerciais** | ⬜ |

Provedor externo nunca é dependência do produto: é opção do usuário, com a chave dele.
Isso não é só privacidade — é o que deixa o projeto sem custo de inferência, porque
nenhuma chamada de modelo sai da conta dele.

---

## Camada 4 — Storage e mídia

| Componente | Papel | Licença | Estado |
|---|---|---|---|
| **nfs-kernel-server** | Compartilhamento para Linux | GPL-2.0 | ⬜ |
| **Samba** | Compartilhamento para Windows e celular | GPL-3.0 | ⬜ |
| **Nextcloud** | Arquivos, calendário, contatos | AGPL-3.0 | ⬜ |
| **Immich** | Fotos, com ML condicionado a nó de computação | AGPL-3.0 | ⬜ |
| **Jellyfin** | Vídeo, com foco em Direct Play | GPL-2.0 | ⬜ |
| **Navidrome** | Música | GPL-3.0 | ⬜ |
| **PostgreSQL** | Banco das aplicações, instância separada por app | PostgreSQL License | ⬜ |
| **Valkey** | Cache e lock, instância separada por app | BSD-3-Clause | ⬜ |
| **Docker Engine + Compose** | Substrato único das aplicações desta camada | Apache-2.0 | ⬜ |

---

## Achados que essa lista produziu

**Valkey no lugar de Redis.** O Redis trocou de licença em 2024 para RSALv2/SSPLv1, que
não é software livre pelos critérios da OSI, e o Debian passou a empacotar o Valkey — um
fork BSD-3 do último Redis livre. Como o produto se define por empacotar software livre,
Redis não entra. Isso não muda em nada o alerta que o PLAN já traz: instância separada
por aplicação, porque o Nextcloud usa esse cache para travar arquivo, e despejo por
pressão de memória descarta esses locks.

**`python-jose` 3.3.0 precisa subir.** A versão fixada no `requirements.txt` tem CVE
conhecida de confusão de algoritmo em ECDSA, corrigida na 3.4.0. O código já faz a coisa
certa fixando o algoritmo na decodificação, o que reduz muito a exposição, mas o pin
está numa versão vulnerável e a biblioteca anda pouco mantida. Subir para 3.4.0 é o
mínimo; trocar por `PyJWT` ou `joserfc` é a saída melhor.

**`passlib` está parado desde 2020.** O pin de `bcrypt==3.2.2` existe porque
`passlib` 1.7.4 quebra com `bcrypt` 4.x. É dívida silenciosa: hash de senha preso a duas
versões antigas por incompatibilidade, não por escolha.

**O Docker não escreve no firewall.** O `forward` do motor tem policy drop, e entre
cadeias-base do mesmo gancho um drop é final: o ACCEPT que o Docker põe na chain dele não
salva o pacote. Por isso o motor gera o `/etc/docker/daemon.json` com `"iptables": false`
e um pool de redes fixo (`containers.pool`, 172.30.0.0/16 por padrão), e o próprio
nftables do motor deixa os containers saírem pela WAN, com NAT. Da LAN, os containers só
são alcançados pelo nginx do firewall, porque escutam em loopback. A prova de função
confere que nenhuma chain `DOCKER` apareceu no ruleset e que o `docker0` está no endereço
declarado. LXC ficou fora do v1: as aplicações desta camada são imagem OCI, e dois
substratos dobrariam gerador, validador e prova de função.

**Open WebUI não é mais BSD puro.** Ganhou cláusula de marca, que restringe remover ou
alterar o branding em redistribuição. Usar na LAN do usuário é tranquilo; **empacotar
dentro da ISO exige ler a cláusula antes**. É o único item da Camada 3 marcado 🔍 por
motivo jurídico e não técnico.

**Nextcloud e Immich são AGPL.** Rodam como processos separados, então não contaminam o
código do Azimuth — mas a ISO que os distribui precisa oferecer os fontes correspondentes.

**Stripe não é dependência do produto.** O código de cobrança veio com o portal herdado
e fica no repositório como referência (ver [SALVAGE.md](SALVAGE.md)); o Azimuth é
inteiro livre e não cobra por nada.

---

## O compromisso que essa lista cria

A ISO precisa carregar, junto da imagem, a declaração do que vai dentro e o apontamento
para os fontes de cada componente sob GPL ou AGPL. Não é burocracia evitável: é
exatamente a mesma honestidade que sustenta o projeto. **Empacotar o trabalho dos outros
só é honesto enquanto o crédito e os fontes forem dados por escrito.**
