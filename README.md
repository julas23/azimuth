# Azimuth

**Uma central doméstica que qualquer pessoa consegue instalar, e que se conserta sozinha quando dá errado.**

Firewall, DNS, DHCP, VPN, compartilhamento de arquivos, mídia e IA sob um governo só — administrados de qualquer lugar por um portal, sem expor nada à internet.

---

## O que isso é, em uma frase

Não é mais um painel de administração. É um **motor de estado declarativo transacional com rollback automático**, e rede foi apenas o primeiro domínio.

Você declara como a rede deve ser. O servidor converge para esse estado. Se a mudança quebrar a conectividade, ele volta sozinho ao último estado bom em 90 segundos — sem ninguém precisar ir até a máquina.

## O problema que resolve

Administrar firewall à distância é aterrorizante por um motivo só: **a mudança que você aplica é a mesma coisa que carrega a sua resposta de volta**. Errou uma regra de NAT e não perdeu um serviço — perdeu o caminho até ele.

Todos os painéis desse mercado escrevem o arquivo, recarregam o serviço e torcem. O Azimuth valida antes, aplica de forma atômica, prova que o serviço voltou de fato e reverte quando não voltou.

---

## Princípios

**A nuvem não tem autoridade.** O servidor do usuário é a fonte da verdade. O portal guarda o estado desejado e mostra o estado real; quem decide e escreve é sempre o agente, na casa da pessoa.

**Só sai, nunca entra.** O agente pergunta ao portal se há instrução para ele. A plataforma nunca alcança a casa do usuário — sem porta aberta, sem encaminhamento, sem IP fixo. Funciona atrás de CGNAT.

**Nada muda sem ser reversível.** Toda alteração passa por validação de sintaxe, aplicação atômica com manifesto, verificação de função e janela de rollback. Operações irreversíveis saem desse fluxo e exigem confirmação explícita.

**Verificação prova função, não código de retorno.** Serviço recarregado precisa demonstrar que voltou. `systemctl` dizer "ok" não é evidência.

**A IA propõe, o humano assina.** Nenhum agente automático aplica mudança. Diagnóstico é leitura; alteração é proposta que vira diff para revisão.

---

## As camadas

### 1 — Conectividade e segurança
| Serviço | Papel |
|---|---|
| **nftables** | Firewall, NAT, isolamento entre zonas |
| **dnsmasq** | DNS local, DHCP, reservas por MAC, bloqueio por lista |
| **WireGuard** | Acesso remoto; a única porta exposta à internet |
| **fail2ban** | Bloqueio ativo contra força bruta |

### 2 — Orquestração
| Componente | Onde roda | Papel |
|---|---|---|
| **ACP** — Azimuth Control Plane | VPS | Guarda perfis e templates. Não decide, não aplica |
| **ARA** — Azimuth Remote Agent | Appliance | Converge o estado real no desejado. É quem escreve |
| **ADO** — Azimuth Data Orchestrator | Nó de storage | Volumes, snapshots, compartilhamentos |

### 3 — IA (chaves do usuário, sempre)
BYOK para provedores externos, BYOA para agentes autônomos em modo leitura e proposta, motor local via Ollama ou vLLM, e OpenWebUI com Whisper (voz para texto) e Piper (texto para voz) — tudo na LAN, sem dado saindo de casa.

### 4 — Storage e mídia
Nextcloud, Immich, Jellyfin e Navidrome sobre volumes gerenciados, com NFS e Samba integrados à mesma política de rede.

---

## Topologias

O Azimuth atende dois desenhos, escolhidos no portal:

**Borda** — entre o modem e a casa. Firewall completo, dual-WAN com failover automático, todo pacote passa pelo filtro. Exige duas placas de rede e colocar o roteador da operadora em modo bridge.

**Atrás do roteador** — uma porta livre no roteador que já existe. Instalação sem cirurgia nenhuma, Wi-Fi da casa intacto, uma placa só. Filtro de DNS, DHCP, compartilhamento e VPN funcionam integralmente; perde-se dual-WAN e a garantia de que todo pacote atravessa o filtro.

> A topologia atrás do roteador existe porque a maior barreira de adoção nunca foi o software: é pedir a uma pessoa comum que ponha o modem em bridge e fique sem Wi-Fi.

---

## Como se instala

1. Criar conta no portal e preencher o perfil
2. Baixar a ISO — **a mesma para todo mundo**
3. Dar boot; uma única pergunta, qual disco apagar
4. A instalação corre sozinha e exibe um **QR code**
5. Ler o QR com o celular, autenticar e conferir a impressão digital da chave
6. Aprovar. O perfil é liberado e o agente aplica

A partir do passo 4, toda pergunta restante acontece no navegador, com teclado e tela de verdade — nunca no console.

---

## Planos

| | Free | Standard | Full |
|---|---|---|---|
| Firewall, DNS, DHCP, VPN, compartilhamento | ✅ | ✅ | ✅ |
| Mídia e IA local | ✅ | ✅ | ✅ |
| Portal hospedado e perfil sincronizado | — | ✅ | ✅ |
| Multi-site, histórico longo, RBL assinada | — | ✅ | ✅ |
| Análise agendada, templates, suporte | — | — | ✅ |

**Funcionalidade local nunca é cobrada.** O que se vende é a infraestrutura hospedada e a conveniência. Quem quiser rodar o próprio control plane, roda.

Suporte é sob demanda e avulso, não plano — por isso a assinatura é barata.

---

## Requisitos

- Debian 13, instalado pela ISO do projeto
- x86-64; ARM e Raspberry Pi ficam para a v2
- Duas placas de rede no modo borda, uma no modo atrás do roteador
- **IP público na WAN** para a VPN direta — CGNAT não funciona no v1
- Disco que não seja cartão SD

---

## Estado do projeto

🟡 **Em construção.** O motor de aplicação transacional está pronto e validado em produção real desde agosto de 2026, incluindo um incidente em que o rollback foi exercitado de verdade. O que falta é transporte, portal e os domínios novos.

Veja [PLAN.md](PLAN.md) para o mapa de integração serviço a serviço.

## Estrutura

```
agent/                    ARA — roda no appliance do usuário
  fwadmin/models.py       schema Pydantic — fonte de verdade do configurável
  fwadmin/render.py       geração dos arquivos de /etc a partir do modelo
  fwadmin/apply.py        validação, aplicação atômica, manifesto, rollback
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

A definir.
