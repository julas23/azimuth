# Agentes no navegador — desenho

Status: **em código** (30/10/2026): terminal no navegador, Claude Code e shell livre, os quatro níveis e o comando `azimuth`. Falta: OpenClaw e Hermes no catálogo, e o mesmo conjunto como servidor MCP.

O cliente escolhe um agente (Claude Code, OpenClaw, Hermes…) e o usa **dentro do painel, no
navegador**, com a mesma tela que teria no terminal do computador dele. O agente é um assistente
de troubleshooting e de configuração: ajuda a diagnosticar, configurar, instalar e ajustar.

**Quanto poder o agente tem é decisão do usuário, não nossa.** O painel oferece os meios e níveis
de acesso; o cliente escolhe o nível de cada agente, do só leitura até root na máquina, e muda
quando quiser. O papel do produto é deixar a escolha explícita, visível e reversível, e manter as
proteções do motor funcionando em qualquer nível.

---

## Princípios

1. **O agente é do cliente.** O painel instala e roda o CLI que ele escolheu; a conta, o login e a
   assinatura do provedor são dele. O login acontece no próprio terminal, como no computador.
2. **O nível de acesso é escolha do usuário**, por agente, mostrado o tempo todo na página e
   trocável a qualquer momento. O painel explica o que cada nível permite; não decide por ele.
3. **As proteções do motor valem em qualquer nível.** Um agente com root que edite o `/etc` por
   fora do motor é detectado como edição à mão (o selo), e o motor não passa por cima sem
   decisão. Mudança feita pelo motor tem validação, backup, prova e rollback, venha de quem vier.
4. **A sessão sobrevive ao navegador.** Fechar a aba não para o agente; reabrir, de qualquer
   lugar da LAN ou da VPN, mostra a mesma tela no mesmo ponto.
5. **Só na LAN e na VPN**, como o resto do painel. O terminal no navegador é um shell; ele nunca
   é publicado na WAN.

---

## Níveis de acesso

| Nível | O que o agente pode | Como |
|---|---|---|
| **Isolado** | conversar e usar o próprio ambiente; não enxerga nada do firewall | usuário `agente` sem grupo nenhum, `/etc/fwadmin` e `/var/lib/fwadmin` fora de alcance |
| **Leitura** | ler configuração, estado, leases, alertas, logs do journal e diff pendente; rodar diagnósticos (ping, DNS, rota, porta, estado de serviço) | o CLI `azimuth` com token de leitura (abaixo) e o grupo `systemd-journal` |
| **Motor** | tudo da leitura, e mudar a configuração e os serviços **pelo motor**: propor, aplicar, instalar e reiniciar serviço do catálogo | o CLI `azimuth` com token de motor |
| **Root** | tudo, na máquina inteira | `sudo` sem senha para o usuário `agente`, numa regra própria do sudoers que só existe neste nível |

- **O confirmar do apply** é o único ponto que fica fora do agente em todos os níveis abaixo de
  root: quem prova que o dono ainda alcança a caixa é o confirm, porque ele volta pelo mesmo
  caminho que a mudança poderia ter quebrado. No nível root, o agente consegue tudo, inclusive
  isso — e a página diz.
- O CLI pergunta antes de agir? **Isso também é do usuário**: o próprio agente (o Claude Code,
  por exemplo) tem modos de permissão, configurados no terminal. O painel não sobrepõe.
- Trocar de nível vale na hora (o token troca, a regra do sudoers entra ou sai) e fica no
  histórico do painel.

---

## O CLI `azimuth`: as mãos do agente no firewall

Todo agente sabe rodar comando de shell; nem todo fala MCP. Por isso a interface do agente com o
firewall é um CLI, instalado no `PATH` do usuário `agente`, que fala com o painel por HTTP local
com um token do nível escolhido:

```
azimuth estado | config | leases | alertas | logs [unidade] | diff
azimuth diag ping|dns|rota|porta <alvo>
azimuth propor < patch.json        # JSON Patch sobre o modelo, validado; vira proposta pendente
azimuth aplicar                    # o Aplicar de sempre; o confirm fica no painel
azimuth servico instalar|iniciar|reiniciar|parar <nome do catálogo>
```

Mais tarde, o mesmo conjunto como servidor MCP, para os agentes que preferem.

---

## Terminal no navegador

- **xterm.js** (a biblioteca do terminal do VS Code), servido pelo próprio painel: a caixa abre
  sem internet, então nada de CDN.
- **WebSocket** pelo uvicorn que já roda o painel, com o `wsproto` do Debian.
- **tmux** guarda a sessão: um servidor tmux por agente, rodando como o usuário `agente`, numa
  unidade do systemd. O painel entra nele pelo `server-access` do tmux 3.5, sem `sudo`. Fechar
  a aba solta o cliente; o agente continua.
- O login do painel e o filtro de origem valem para o WebSocket como para qualquer página.

---

## Catálogo de agentes

O painel instala o CLI escolhido no diretório do usuário `agente`, fora da ISO (é escolha do
cliente, e atualiza no ritmo do agente, não do produto):

| Agente | Como |
|---|---|
| Claude Code | npm (Node.js do Debian) |
| OpenClaw | npm |
| Hermes Agent | pip, num ambiente próprio |
| Outro | um shell no ambiente do agente, para o cliente instalar o que quiser |

Instalar o Node.js do Debian e o agente são ações de root: passam pelo `fwctl`, com o pedido por
arquivo, como o banir do fail2ban (o sudoers não tem curinga).

---

## O README

A frase "A IA propõe, o humano assina. Nenhum agente automático aplica mudança" deixa de
descrever o produto. Redação proposta:

> **A IA trabalha no nível que você der.** Um agente pode só ler, mudar a rede pelo motor ou ter a
> máquina inteira — a escolha é sua, por agente, e muda quando você quiser. Em qualquer nível, o
> que passa pelo motor é validado, provado e reversível, e o que passa por fora é detectado.

---

## Decisões (fechadas em 30/10/2026, pela recomendação)

1. **Nível padrão: Leitura.** O cliente sobe quando quiser.
2. **A página de IA** (pergunta e resposta por API) fica, como agente embutido para quem não
   tem agente próprio.
3. **As sessões ficam gravadas por 30 dias** (`tmux pipe-pane`, limpas pelo tmpfiles).

## Feito na primeira entrega

- Um usuário Linux por agente (`az-<nome>`): com um usuário só, um agente de leitura poderia
  escrever o `.bashrc` que um agente com root executaria.
- Abaixo de root, a unidade roda com `NoNewPrivileges` (o sudo não eleva), `ProtectSystem=strict`
  e sem enxergar `/etc/fwadmin`, `/var/lib/fwadmin`, `/etc/wireguard` e `/etc/ppp`. Root tira
  tudo isso e põe uma regra própria no sudoers, validada com `visudo`.
- O WebSocket não passa pelos middlewares HTTP: ele repete os portões (rede permitida, sessão,
  `Origin` igual ao host, painel fora do somente leitura). Testado: outro `Origin` ou nenhum
  dá 403.
- Testado de ponta a ponta fora do fw: o xterm.js no Chrome mostra a sessão tmux, o teclado
  chega, o redimensionamento vale, e fechar solta o cliente sem matar a sessão.

## Feito na segunda entrega: o comando `azimuth`

- `/usr/local/bin/azimuth`, Python só com a biblioteca padrão, fala com o painel por HTTPS local
  (`/api/agente/*`). Confia exatamente no certificado do painel, copiado para
  `/etc/azimuth-agente/painel.crt` (o SAN traz o IP da LAN, então o nome também é conferido); um
  certificado de terceiros derruba a conexão.
- Um token por agente, gerado pelo `fwctl agente` a cada troca de nível, num arquivo do próprio
  agente (0600); o painel guarda só o sha256. Isolado não tem token.
- Leitura: `quem`, `estado`, `config`, `leases`, `alertas`, `logs`, `diff`, `diag`. Motor (e
  root): também `propor` (JSON Patch validado pelo modelo, vira proposta pendente com o agente
  como autor no histórico), `aplicar` (o confirmar continua do dono), `descartar` e `servico`.
- `fwctl servico` (iniciar, parar, reiniciar, recarregar, instalar), restrito à stack
  (`fwadmin/stack.py`), com o pedido por arquivo; a tela de Serviços passou a usá-lo também.
- O agente recebe `~/AZIMUTH.md` (o que é a caixa, o nível, o comando), regerado a cada troca de
  nível, e um `~/CLAUDE.md` que só o importa e é do usuário depois de criado.
