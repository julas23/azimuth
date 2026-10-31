# AIONAS - All In One Network Attach Storage

**Uma central doméstica que qualquer pessoa consegue instalar, e que se conserta sozinha quando dá errado.**

Firewall, DNS, DHCP, VPN, compartilhamento de arquivos, mídia e IA sob um governo só — administrados pelo navegador, sem expor nada à internet.

---

## O que isso é, em uma frase

Não é mais um painel de administração. É um **motor de estado declarativo transacional com rollback automático**, e rede foi apenas o primeiro domínio.

Você declara como a rede deve ser. O servidor converge para esse estado. Se a mudança quebrar a conectividade, ele volta sozinho ao último estado bom em 90 segundos — sem ninguém precisar ir até a máquina.

## O problema que resolve

Administrar firewall à distância é aterrorizante por um motivo só: **a mudança que você aplica é a mesma coisa que carrega a sua resposta de volta**. Errou uma regra de NAT e não perdeu um serviço — perdeu o caminho até ele.

Todos os painéis desse mercado escrevem o arquivo, recarregam o serviço e torcem. O Azimuth valida antes, aplica de forma atômica, prova que o serviço voltou de fato e reverte quando não voltou.

---

## Princípios

**A nuvem não tem autoridade.** O servidor do usuário é a fonte da verdade. Na instalação local não há nuvem nenhuma. Quando existe control plane, ele guarda o estado desejado e mostra o estado real — mas quem decide e escreve é sempre o agente, na casa da pessoa.

**Só sai, nunca entra.** O agente pergunta ao ACP se há instrução para ele. A plataforma nunca alcança a casa do usuário — sem porta aberta, sem encaminhamento, sem IP fixo. Esse canal funciona até atrás de CGNAT; o que o CGNAT impede é a VPN, e por isso ela é verificada antes de ser prometida.

**Fechado por padrão, e a VPN é a porta.** Na internet, a caixa não responde a nada além do WireGuard — que, por sua vez, ignora em silêncio quem não tem chave. Não há redirecionamento de porta, e nenhuma aplicação é publicada: quem precisa alcançar a casa de fora entra pelo túnel. Encaminhar porta é publicar um serviço doméstico na internet, e é assim que a maioria das casas é invadida.

**Lista de bloqueio é dado assinado, não autoridade.** As listas descem verificadas e valem para nomes e endereços — mas exceção do dono vence lista sempre, e nenhuma lista alcança a LAN, o túnel ou a porta da VPN. Uma lista que pudesse trancar você do lado de fora da própria casa seria pior que o problema que resolve.

**Nada muda sem ser reversível.** Toda alteração passa por validação de sintaxe, aplicação atômica com manifesto, verificação de função e janela de rollback. Operações irreversíveis saem desse fluxo e exigem confirmação explícita.

**O motor sabe o que é dele, e não apaga o que não é.** Cada arquivo gerenciado é selado quando vira estado oficial. Se alguém editou `/etc` à mão depois disso — o dono numa madrugada, ou um atendimento de suporte —, a mudança é detectada e o servidor se recusa a passar por cima dela sem uma decisão. Descartar é possível, guarda cópia antes e fica escrito no histórico. Um sistema declarativo que apaga ajustes em silêncio ensina a ninguém confiar nele.

**Verificação prova função, não código de retorno.** Serviço recarregado precisa demonstrar que voltou. `systemctl` dizer "ok" não é evidência.

**A IA trabalha no nível que você der.** Um agente pode só ler, mudar a rede pelo motor ou ter a máquina inteira — a escolha é sua, por agente, e muda quando você quiser. Em qualquer nível, o que passa pelo motor é validado, provado e reversível, e o que passa por fora é detectado.

---

## As camadas

### 1 — Conectividade e segurança
| Serviço | Papel |
|---|---|
| **nftables** | Firewall, NAT, isolamento entre zonas |
| **dnsmasq** | DNS local, DHCP, reservas por MAC, bloqueio por lista |
| **WireGuard** | Acesso remoto; a única porta exposta à internet |
| **inadyn** | DDNS: um nome estável para a VPN, na conta do próprio usuário |
| **fail2ban** | Bloqueio ativo contra força bruta |
| **NFS** e **Samba** | Compartilhamento de arquivos na LAN, sob a mesma política de rede |

### 2 — Orquestração
| Componente | Onde roda | Papel |
|---|---|---|
| **ACP** — Azimuth Control Plane | VPS | Guarda perfis e templates. Não decide, não aplica |
| **ARA** — Azimuth Remote Agent | Appliance | Converge o estado real no desejado. É quem escreve |
| **ADO** — Azimuth Data Orchestrator | Nó de storage | Volumes, snapshots e integridade dos dados |

### 3 — IA (chaves do usuário, sempre)
BYOK para provedores externos, BYOA para o agente que você escolher, usado no navegador com a tela do terminal e no nível de acesso que você der, motor local via Ollama ou vLLM, e OpenWebUI com Whisper (voz para texto) e Piper (texto para voz) — tudo na LAN, sem dado saindo de casa.

### 4 — Storage e mídia
Nextcloud, Immich, Jellyfin e Navidrome sobre volumes gerenciados. **Nada disso é publicado na internet:** respondem na LAN e pela VPN.

---

## Topologias

O Azimuth atende dois desenhos, escolhidos no painel durante o setup:

**Borda** — entre o modem e a casa. **É o modo recomendado.** Firewall completo, dual-WAN com failover automático, todo pacote passa pelo filtro. Exige duas placas de rede, o roteador da operadora em modo bridge e o roteador Wi-Fi que já existe rebaixado a ponto de acesso.

**Atrás do roteador** — uma porta livre no roteador que já existe. Instalação sem cirurgia nenhuma, uma placa só. Filtro de DNS, DHCP, compartilhamento e VPN funcionam integralmente; perde-se dual-WAN e a garantia de que todo pacote atravessa o filtro. É a saída para quem tem uma placa só, ou uma operadora que não libera bridge.

> O medo de ficar sem Wi-Fi é o que sempre matou a topologia de borda, e a resposta é que o Wi-Fi não morre — muda de dono. O roteador da casa vira ponto de acesso: DHCP desligado, IP fixo dentro da rede nova, cabo de porta LAN em porta LAN, nunca na WAN. A rede sem fio continua com o mesmo nome e a mesma senha.

Com o modem em bridge, o PPPoE muda de dono junto: sai do roteador da operadora e passa a subir no próprio appliance. Usuário e senha do provedor precisam estar em mãos antes de começar.

---

## Como se instala

1. Baixar a ISO — **a mesma para todo mundo**
2. Dar boot; uma única pergunta, qual disco apagar
3. A instalação corre sozinha e termina mostrando o endereço do painel, um **QR code** e um **código curto**
4. Abrir o endereço no navegador — ou ler o QR com o celular, que traz junto a impressão digital do certificado
5. Digitar o código, criar o administrador, responder o perfil e aplicar

A partir do passo 3, toda pergunta restante acontece no navegador, com teclado e tela de verdade — nunca no console. Não há conta para criar antes, nem nuvem no caminho: a instalação inteira acontece dentro de casa.

O código existe porque uma caixa recém-ligada na rede, sem ele, pertence a quem chegar primeiro. Quem está configurando precisa estar vendo a tela.

**A virada para o modo de borda é reversível.** Configurada a caixa, ainda falta a parte física: modem em bridge, roteador virando ponto de acesso, cabos mudando de lugar. Se depois disso a internet não voltar, a caixa retorna sozinha ao estado em que estava sendo configurada e mostra o endereço na tela outra vez — com tudo o que você já respondeu intacto.

---

## Aberto, por inteiro

Quase nada aqui é desenvolvimento próprio. nftables, dnsmasq, WireGuard, Nextcloud, Jellyfin, Immich e o resto são trabalho de outras pessoas, entregue sob licenças livres. A lista inteira, com papel, licença e crédito de cada peça, está em [STACK.md](STACK.md).

O que o projeto acrescenta — motor, agente, painel, control plane, ISO e repositório de atualização — é livre do mesmo jeito, sob a [AGPLv3](LICENSE). Não existe plano pago, módulo fechado nem recurso reservado. O control plane é auto-hospedável por princípio de projeto: quem quiser rodar o próprio desde o primeiro dia, roda.

### Quem prefere receber pronto

Instalar, migrar a rede que já existe e manter tudo funcionando dá trabalho, e esse trabalho é contratável:

- **Implementação** — o Azimuth instalado e configurado em casa, no homelab ou no pequeno escritório, com a migração da rede atual
- **Gestão** — atualização, monitoramento, VPN e backup acompanhados mês a mês
- **Projeto sob medida** — firewall, VPN, IA local ou self-hosting para quem não quer o Azimuth inteiro

Contato pelo perfil [julas23](https://github.com/julas23) no GitHub.

---

## Requisitos

- Debian 13, instalado pela ISO do projeto
- x86-64; ARM e Raspberry Pi ficam para a v2
- Duas placas de rede no modo borda (recomendado), uma no modo atrás do roteador
- **IP público na WAN** para a VPN direta — CGNAT não funciona no v1
- Disco que não seja cartão SD

---

## Estado do projeto

🟡 **Em construção.** O motor de aplicação transacional está pronto e validado em produção real desde agosto de 2026, incluindo um incidente em que o rollback foi exercitado de verdade.

**O v1 é a instalação local inteira, sem nuvem nenhuma:** motor, painel, ISO e os domínios novos. O control plane hospedado e o laço de reconciliação ficam para a v2 — com um requisito que vale desde já, o de que um appliance instalado no v1 possa ser inscrito depois **sem reinstalação**.

Veja [STACK.md](STACK.md) para o que o produto empacota e sob que licença, e [SALVAGE.md](SALVAGE.md) para o veredito de aproveitamento das duas bases.

## Estrutura

```
agent/                    ARA — roda no appliance do usuário
  fwadmin/models.py       schema Pydantic — fonte de verdade do configurável
  fwadmin/render.py       geração dos arquivos de /etc a partir do modelo
  fwadmin/apply.py        validação, aplicação atômica, manifesto, rollback
  fwadmin/ownership.py    posse: o que é do motor, e quem editou /etc à mão
  fwadmin/etc_templates/  templates Jinja de cada arquivo gerado
  sbin/fwctl              executor privilegiado: check, diff, apply, rollback
  deploy/                 unit systemd, sudoers, nginx, instalador
  tools/                  testes e importador do estado vivo
  legacy/live/            o /etc original do firewall, base do diff semântico

portal/                   ACP — roda na nuvem
  app/routers/            auth, checkout, webhooks, peers, admin
  app/models/             user, plan, subscription, peer, bandwidth
  app/services/           provisionamento, alocação de IP, config e QR
  app/templates/          Jinja: conta, painel, admin
  bridge/                 daemon privilegiado por socket Unix
  nginx/                  TLS e proxy reverso
```

Ver [SALVAGE.md](SALVAGE.md) para o veredito de aproveitamento peça a peça.

## Sobre a configuração de exemplo

`agent/config/config.yaml` e `agent/legacy/live/` trazem uma rede **fictícia**: MACs na
faixa localmente administrada (`02:00:00:00:00:xx`) e nomes genéricos. Servem de exemplo
e de base para os testes. A configuração real de cada instalação nasce do portal e vive
em `/etc/fwadmin/config.yaml`, no appliance — nunca no repositório.

## Licença

[GNU Affero General Public License v3.0](LICENSE).

Na prática: usar, estudar, modificar e instalar para terceiros é livre, sem obrigação nenhuma. Quem distribuir uma versão modificada, ou oferecê-la como serviço pela rede — um control plane hospedado, por exemplo —, entrega os fontes dessa versão sob a mesma licença. É o que impede alguém de fechar o projeto e concorrer com ele.

Os componentes de terceiros mantêm as próprias licenças; ver [STACK.md](STACK.md).
