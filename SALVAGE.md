# O que aproveitar

Inventário das duas bases que agora convivem neste repositório, com veredito por peça.

**Legenda:** ♻️ aproveitar quase como está · 🔧 aproveitar adaptando · 🗑️ não aproveitar

---

## A descoberta que reorganiza o projeto

As duas bases não competem — **são metades complementares do Azimuth**, e cada uma tem exatamente o que falta na outra.

| | `portal/` (ex-vpn-web) | `agent/` (ex-fwadmin) |
|---|---|---|
| Tem | Conta, cobrança, UI, provisionamento, QR | Schema, geradores, aplicação transacional, rollback |
| Não tem | Qualquer noção de estado desejado ou reversão | Qualquer control plane remoto |
| É hoje | Serviço de VPN centralizado | Appliance local sem nuvem |
| Vira | **ACP** | **ARA** |

O trabalho não é escrever um portal nem escrever um motor. É **ligar os dois**: o portal deixa de provisionar peers no próprio servidor e passa a publicar perfis de estado desejado que agentes buscam.

---

## O padrão que já está provado nos dois lados

O `vpn-bridge` e o `fwctl` são **a mesma ideia, implementada duas vezes de forma independente**: uma aplicação web sem privilégio conversando com um executor privilegiado por um canal estreito e controlado.

| | `fwctl` | `vpn-bridge` |
|---|---|---|
| Canal | sudo com lista fechada de comandos | socket Unix com JSON por linha |
| Privilégio | root via sudoers sem curinga | daemon root, socket com grupo dedicado |
| Validação | schema Pydantic antes de gerar | `_valid_key`, `_valid_ip`, `_valid_domain` |
| Estado | **declarativo e transacional** | **mutação direta** |

A linha de baixo é a diferença que importa. O canal do bridge é melhor — socket é mais estreito e mais fácil de auditar que sudo. O modelo de estado do `fwctl` é melhor — muta com validação, manifesto e volta atrás.

**A síntese: canal do bridge, modelo do fwctl.**

---

## `portal/` — peça a peça

> **Decisão de 21/08:** o Azimuth **não** comercializa VPN. Aquela plataforma foi
> construída para isso. O que se herda dela é a **administração de acessos** e a
> **lógica do QR** — não o negócio.

### Administração de acessos ♻️ — a peça principal
`routers/auth.py` · `models/user.py` · `deps.py` · `services/mailer.py` · `services/temp_password.py`

Registro, login, verificação de e-mail, token de acesso e de refresh, senha temporária,
e o `Depends` que resolve o usuário corrente. **Em produção e bem feito:**

- bcrypt via `passlib.CryptContext`, não hash caseiro
- algoritmo do JWT **fixado** na decodificação — fecha a confusão de `alg`
- o refresh valida `kind != "refresh"` — token de acesso não serve como refresh
- e-mail verificado é exigido também na renovação

É a base de conta do ACP, pronta. Só falta o vínculo com *site*, que hoje é com *peer*.

**Um ajuste ao migrar:** no `login`, `if user is None or not _verify(...)` pula o bcrypt
quando o e-mail não existe. A diferença de tempo de resposta permite enumerar quem tem
conta. Correção é uma linha — verificar contra um hash descartável mesmo quando o usuário
não existe, para o custo ser sempre o mesmo.

### Lógica do QR ♻️ — a outra peça eleita
`services/wg_config.py` · `routers/peers.py`

`build_conf()` monta o `.conf` e `build_qr_png()` gera o PNG. O fluxo de peers cobre criar,
listar, baixar e revogar. No Azimuth serve duas vezes: o QR do peer de VPN **e** o QR de
inscrição do appliance no portal, que é o passo 5 da instalação.

### Cobrança 🔧 — guardada, não descartada
`routers/checkout.py` · `routers/webhooks.py` · `models/plan.py` · `models/subscription.py` · `services/provisioner.py`

Stripe com webhooks tratando checkout, fatura paga, falha e cancelamento. Não entra agora,
mas **a mecânica é idêntica à de que o Azimuth vai precisar** para os planos Standard e
Full: pagamento confirmado dispara provisionamento. Muda só o objeto — de peer num
concentrador para site com perfil. Fica no repositório como referência, não como dívida.

### `services/wg_config.py` ♻️
`build_conf()` e `build_qr_png()` — exatamente as duas funções que o PLAN listava como a fazer no WireGuard. Precisa apenas parametrizar `AllowedIPs`, que hoje é fixo em full tunnel.

### `services/ip_allocator.py` 🔧
Alocação de IP com persistência em banco. A lógica serve; o que muda é o escopo — hoje aloca numa rede do concentrador, no Azimuth aloca na rede de túnel de cada site.

### `services/vpn_bridge.py` ♻️
O cliente async do socket. Protocolo simples, tratamento de erro limpo, nomes de campo documentados. É o transporte do ARA quase pronto.

### `bridge/bridge.py` 🔧
562 linhas. **Os validadores e o servidor de socket são ouro**; a manipulação de estado precisa dar lugar ao motor transacional. Hoje ele chama `nft` e `wg set` direto — mesma classe de arquitetura que descartamos no aionas antigo.

### Templates e estático 🔧
1.594 linhas de Jinja em `account/`, `admin/`, `auth/`, `dashboard/`. Mesmo motor de template do agente, então o padrão de layout e os fluxos de formulário se aproveitam. O conteúdo muda.

### Migrations, `docker-compose.yml`, `nginx/` ♻️
Alembic configurado, Postgres 16, TLS na frente. É o padrão de implantação do ACP resolvido.

### `models/bandwidth.py` 🗑️
Contabilidade de tráfego por peer, para fatiar plano de VPN. Sem concentrador para medir,
não há o que contabilizar. A telemetria que o Azimuth precisa é outra: saúde de serviço e
versão aplicada, e vem do agente.

### Lógica de VPN comercial 🗑️
`services/brazil_cidrs.py` · chain `plan-policy` do nftables · limitação de banda por `tc` · quota por plano · split tunnel por CIDR

Isso é produto de **VPN comercial**: diferenciar cliente por plano num concentrador compartilhado. O Azimuth é o oposto — cada usuário tem a própria caixa, e não há concentrador para fatiar. Não jogar fora do git, mas não carregar para o produto novo.

---

## `agent/` — peça a peça

Tudo aproveitado. É a base.

| Peça | Estado |
|---|---|
| `fwadmin/models.py` — schema Pydantic | ♻️ a fonte de verdade do configurável |
| `fwadmin/render.py` + `etc_templates/` | ♻️ geradores validados por diff semântico |
| `fwadmin/apply.py` | ♻️ atômico, manifesto antes da troca, rollback |
| `sbin/fwctl` | 🔧 vira o executor chamado pelo laço, não pelo humano |
| `fwadmin/web.py` + templates | 🔧 painel local sobrevive; o remoto passa a ser o ACP |
| `tools/test_apply.sh` + `test_partial_apply.py` | ♻️ 22 testes verdes, e um deles nasceu de incidente real |
| `deploy/` | ♻️ unit, sudoers, nginx, instalador |

---

## O que fazer com isso

1. **Extrair o servidor de socket do `bridge.py`** e descartar a mutação direta. O executor passa a ser o motor do agente.
2. **Trocar o objeto da assinatura** no portal: de peer num concentrador para site com perfil.
3. **Introduzir estado desejado** — a tabela que hoje guarda `VpnPeer` ganha irmã guardando versão de perfil com hash.
4. **Endpoints de reconciliação**: o agente busca o desejado, devolve o real e a saúde.
5. **Migrar `wg_config` para o schema do agente**, para que WireGuard seja gerado como qualquer outro arquivo de `/etc` — com validador, recarga e prova de função.

O passo 5 é o que fecha o círculo: hoje o WireGuard é gerado pelo portal e aplicado por um daemon que muta estado. Depois, é gerado pelo agente e aplicado pelo mesmo caminho transacional do `nftables` e do `dnsmasq` — com rollback.

---

## Riscos herdados, para não passarem em branco

**O `vpn-web` não estava em git.** Quatro mil e quinhentas linhas com cobrança integrada existiam em cópia única num VPS. Agora estão aqui. O `.env` ficou de fora de propósito — ele tem chave do Stripe e senha do Postgres, e o `.env.example` serve de modelo.

**Webmin escuta em `0.0.0.0:10000` na VPS**, com `iptables` do host em `-P INPUT ACCEPT`. Não responde da internet hoje, mas quem segura é a *security list* do Oracle, não a máquina — está a uma mudança de console da exposição. O firewall de casa derruba Webmin vindo da WAN explicitamente; aqui a mesma proteção está terceirizada.

**Um peer com handshake de quatro dias.** Pode ser cliente inativo, pode ser peer órfão. Vale conferir antes de virar dado migrado.

---

## O que continua em cópia única

O código está salvo. **O estado que não se regenera, não.**

| Item | Onde | Se perder |
|---|---|---|
| `portal/.env` | só no VPS | Chave do Stripe, segredo JWT e senha do Postgres. Reconfigurável, mas com downtime e ida ao painel do Stripe |
| Chave privada do WireGuard | `/etc/wireguard/private.key` | **Todos os peers param.** Cada cliente precisa de config nova |
| Banco Postgres | container no VPS | 4 usuários, 4 assinaturas, 4 peers. Vínculo com o Stripe se perde |
| Certificado TLS | Let's Encrypt | Renovável sozinho, sem risco |

**Não há backup de nada disso.** A única tarefa agendada no VPS é o `dpkg-db-backup` do próprio Debian. Um `pg_dump` diário e uma cópia da chave do WireGuard fora da máquina resolvem, e são minutos de trabalho.

Com quatro assinantes o prejuízo é pequeno; a hora barata de criar o hábito é agora, e não quando forem quatrocentos.
