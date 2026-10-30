# Módulo do Unbound — desenho

Status: **implementado** (30/10/2026), com as quatro recomendações aceitas. Os três pontos "a
verificar" foram verificados no fw, numa instância de teste do unbound, antes do código. O que a
verificação mudou no desenho está marcado *(verificado)*.

O módulo tira o unbound da lista de "unidades sem dono" do `fwctl inventory`: o resolvedor
recursivo passa a ser declarado no `config.yaml`, gerado, validado, recarregado e provado como o
dnsmasq já é. Com isso a página de DNS deixa de ser só leitura e ganha o que hoje não tem como
fazer pelo painel: **encaminhar um domínio para outro servidor** e **bloquear um domínio**.

---

## Como o DNS da casa funciona hoje

```
aparelho da LAN ──▶ dnsmasq 10.0.0.1:53 ──▶ unbound 127.0.0.1:5335 ──▶ servidores raiz
                    nomes de casa, DHCP      recursivo, DNSSEC, cache
                    (do motor)               (de ninguém)
```

O dnsmasq já é do motor e pergunta ao unbound pelo `server=127.0.0.1#5335` que está no
`dns.upstream` do modelo, como texto solto. O unbound é configurado à mão, em três arquivos de
`/etc/unbound/unbound.conf.d/`:

| Arquivo | Origem | Conteúdo |
|---|---|---|
| `homelab.conf` | à mão, 16/09 | toda a config: escuta, acesso, DNSSEC, cache, privacidade |
| `remote-control.conf` | à mão, 23/07 | `unbound-control` por socket unix, `/run/unbound.ctl` |
| `root-auto-trust-anchor-file.conf` | pacote Debian | o trust anchor do DNSSEC |

E quatro ajustes feitos à mão em volta dele, todos funcionando:

| Unidade | O que faz |
|---|---|
| `dns-healthcheck.timer` (5 min) | testa nome local, externo, unbound direto, DNSSEC válido e *bogus*; se falhar, **reinicia o unbound** uma vez |
| `dns-cache-dump.timer` (15 min) | grava o cache do unbound em `/var/lib/unbound/cache.db` |
| `unbound.service.d/cache-load.conf` | ao subir, recarrega o cache gravado (`dns-cache-load.sh`) |
| `dnsmasq-vps.service` | um segundo dnsmasq, para o túnel da VPS, que pergunta ao dnsmasq principal |

---

## Princípios

1. **O motor escreve um arquivo só, e é dele:** `/etc/unbound/unbound.conf.d/azimuth.conf`. É o
   mesmo trato do nftables, em que o motor escreve só a tabela `inet azimuth`. O `unbound.conf` do
   Debian (que só faz o `include`) e o arquivo do trust anchor continuam do pacote.
2. **O unbound escuta só no loopback.** A porta da LAN é o dnsmasq. O schema recusa outro
   endereço em `listen`: um resolvedor recursivo aberto na LAN é um amplificador de DDoS
   esperando acontecer, e na WAN, pior.
3. **Mudança de config não joga o cache fora.** A recarga normal é `unbound-control
   reload_keep_cache`. Restart só para o que o unbound não relê (escuta, threads, socket de
   controle).
4. **Provar que está rodando *esta* config, e não só que responde.** Ver *Prova de função*.
5. **Internet fora não reverte mudança de DNS.** A prova fatal não depende da WAN. O que
   depende dela é prova inconclusiva, que não reverte nada (a mesma regra do `base.Prova`).
6. **O que o modelo não sabe dizer não é absorvido pela metade.** Ver *Adoção*.

---

## Modelo no `config.yaml`

```yaml
resolver:
  enabled: true
  listen: 127.0.0.1@5335          # so loopback; o schema recusa o resto
  mode: recursive                 # recursive | forward
  forwarders: []                  # so em mode: forward
  #  - address: 1.1.1.1
  #    tls_name: cloudflare-dns.com   # com tls_name, vai por DNS sobre TLS (853)
  dnssec: true
  ipv6: false                     # do-ip6 / prefer-ip6
  privacy:
    qname_minimisation: true
    hide_identity: true           # hide-identity + hide-version
  cache:
    min_ttl: 60
    max_ttl: 86400
    msg_size: 64m
    rrset_size: 128m
    prefetch: true                # prefetch + prefetch-key
  threads: 2
  edns_buffer_size: 1232

  # as duas listas que o painel edita, com Editar / Desativar / Remover
  forward_zones:
    - domain: corp.exemplo
      servers: [10.8.0.1]
      description: VPN do trabalho
      enabled: true
  blocked:
    - domain: telemetria.exemplo
      description: ''
      enabled: true
```

O que **não** vira campo, porque não há escolha a fazer: `do-ip4/udp/tcp: yes`,
`harden-glue`, `harden-referral-path`, `harden-dnssec-stripped` (segue `dnssec`),
`aggressive-nsec` (segue `dnssec`), `root-hints`, `so-reuseport`, `access-control` (segue
`listen`: loopback permitido, todo o resto `refuse`) e o bloco `remote-control` com o socket
unix. O render escreve todos eles sempre. O importador confere que a caixa adotada tem o mesmo
valor, e o que divergir vira mudança da adoção.

### O que o render faz com as duas listas

- **Domínio encaminhado** vira `forward-zone` com `forward-addr`. Com `dnssec: true`, ganha também
  `domain-insecure`: sem isso, um domínio interno que a raiz diz que não existe (com assinatura)
  é tratado como *bogus* e não resolve nunca. Esse é o erro que todo mundo comete na primeira vez,
  então o motor não deixa cometer.
- **Domínio bloqueado** vira `local-zone: "<domínio>" always_nxdomain`, que bloqueia o domínio e
  tudo abaixo dele. NXDOMAIN, e não `0.0.0.0`: o aparelho desiste na hora, em vez de tentar
  conectar e esperar o timeout.
- O schema recusa domínio repetido entre as duas listas, e recusa encaminhar ou bloquear o
  domínio da casa (`dns.domain`), que é do dnsmasq.

### Ligação com o dnsmasq

Com `resolver.enabled`, o `server=` do dnsmasq passa a sair de `resolver.listen` (com `#` no
lugar de `@`), e não mais do texto em `dns.upstream`, que fica para quem não usa o unbound. Dois
pontos onde o mesmo endereço precisava ser digitado igual viram um só. O `proxy_dnssec` do
dnsmasq só faz sentido com `resolver.dnssec`, e o schema avisa quando os dois discordam.

---

## O que o módulo gera

| Arquivo | Conteúdo |
|---|---|
| `/etc/unbound/unbound.conf.d/azimuth.conf` | `server:` com tudo acima, as `forward-zone`, as `local-zone` e o `remote-control:` |

Um arquivo, um `ServiceModule`, na ordem logo **antes** do dnsmasq (que depende dele):

| Campo | Valor |
|---|---|
| `targets` | `{"unbound.conf": "/etc/unbound/unbound.conf.d/azimuth.conf"}` |
| `units` | `unbound.service` |
| `validator` | `unbound-checkconf` (ver abaixo) |
| `reloads` | `reload_keep_cache`; `restart` se mudou `listen`, `threads` ou `edns_buffer_size` |
| `probe` | a versão em TXT, e o DNSSEC como inconclusivo (ver abaixo) |

### Validação: o arquivo e a árvore

O `unbound-checkconf` no arquivo sozinho não pega o erro mais provável, que é **duplicata com
outro arquivo do `conf.d`**: duas linhas `interface:` iguais fazem o unbound não subir. Então a
validação roda duas vezes no staging:

1. no `azimuth.conf` sozinho;
2. num `unbound.conf` de staging que inclui o `azimuth.conf` novo **mais os outros arquivos que
   continuam no `conf.d`**, que é exatamente a árvore que vai subir.

### Prova de função

O render escreve sempre um registro sintético:

```
local-data: 'versao.azimuth. TXT "<12 caracteres>"'
```

A versão é o hash da seção `resolver` do modelo junto com o texto do template, e não do arquivo
gerado: o arquivo contém o próprio TXT, e o hash dele seria circular. Muda o modelo ou o
template, muda a versão.

- **Fatal:** `dig @127.0.0.1 -p 5335 versao.azimuth TXT` devolve o hash do arquivo que acabou de
  ser aplicado. Isso prova que o unbound está no ar, na porta certa, e que **carregou esta
  config**, e não a anterior (um `reload` que falha deixa o unbound respondendo com a config
  velha, e um teste de "responde?" passaria). Não depende da internet.
- **Inconclusiva** (não reverte nada): um nome externo resolve com a flag `ad`, e
  `dnssec-failed.org` dá `SERVFAIL`. São os testes do `dns-healthcheck`, que dependem da WAN.
- Com domínio bloqueado novo, ele precisa responder NXDOMAIN. Isso também não depende da
  internet, então é fatal.
- A consulta é UDP crua, como a do dnsmasq (sem `dig`), agora com EDNS e o bit DO: sem EDNS a
  resposta para em 512 bytes, e sem DO quem está no meio não repassa a flag `ad`.
- *(verificado)* O dnsmasq repassaria `versao.azimuth` para o unbound, e a LAN veria o TXT. O
  dnsmasq gerado ganha `local=/azimuth/`, que responde sozinho e não repassa.

---

## Adoção

O importador lê a árvore do unbound (o `live.parse_unbound` já faz isso para a página de DNS) e
separa os arquivos em três grupos:

| Grupo | Exemplo | Destino |
|---|---|---|
| do pacote | `unbound.conf`, `root-auto-trust-anchor-file.conf` | ficam como estão, sempre |
| **absorvível**: toda linha tem tradução no modelo | `homelab.conf`, `remote-control.conf` | viram modelo; o primeiro apply os **aposenta** |
| **com sobra**: alguma linha não tem tradução | uma opção que o modelo não conhece | ver abaixo |

**Aposentar** quer dizer que o primeiro apply move o arquivo para o backup daquele apply (o
mesmo backup do rollback), e não que o apaga. Isso é uma mudança da adoção como as outras: aparece
em "O que o motor mudaria ao assumir" e trava o apply até alguém marcar como intencional. O
rollback devolve o arquivo.

**Arquivo com sobra não é absorvido pela metade.** Se o motor traduzisse as linhas que entende e
deixasse o arquivo no lugar por causa das outras, as linhas traduzidas ficariam em dobro, e
`interface:` em dobro faz o unbound não subir. A regra é: com sobra, o arquivo fica inteiro, o
módulo fica `enabled: false`, e a mudança da adoção lista as linhas sem tradução. A página de DNS
continua só leitura até a sobra ser resolvida: ou o modelo aprende a opção, ou alguém tira a
linha do arquivo.

**Opção ausente vale o padrão do unbound, não o do modelo.** Sem `prefetch` no arquivo, o unbound
roda sem prefetch, e o modelo (cujo padrão é ligado) precisa trazer "desligado"; senão a adoção
mudaria a caixa sem ninguém pedir. O importador tem a tabela de padrões do unbound para isso.

**Máquina já adotada** (como esta) não passa de novo pelo importador. A página de DNS, com o
unbound fora do modelo, mostra o que o tradutor faria e um botão "Trazer para o modelo", que grava
o resultado como proposta. O diff do Sistema mostra os arquivos absorvidos virando aviso, e o
Aplicar prova.

Nesta caixa, `homelab.conf` e `remote-control.conf` são 100% absorvíveis. Conferi linha por
linha: as 24 opções do `homelab.conf` (25 linhas, porque `access-control` aparece duas vezes)
estão todas no modelo acima, como campo ou como valor fixo. E a árvore nova é equivalente à de
hoje: comparando com `unbound-checkconf -o` as 28 opções que o render escreve, a árvore atual e a
nova (com `azimuth.conf` e os dois arquivos virando aviso) dão o mesmo valor em todas.

### Os ajustes à mão em volta do unbound

| Unidade | Decisão |
|---|---|
| `dns-cache-dump.timer` + `cache-load.conf` | **ficam de fora na v1**, como decisão escrita. Continuam funcionando, porque o módulo mantém o mesmo socket de controle. Com o `reload_keep_cache`, o restart, que é o caso que eles cobrem, fica raro. |
| `dns-healthcheck.timer` | **fica, com uma ressalva**: o auto-heal dele reinicia o unbound, e se isso cair dentro da janela de prova de um apply, a prova vê o unbound subindo. O módulo declara o timer em `quiet`, e o fwctl o para antes das recargas e o religa no confirm ou no rollback (só se estava ativo). Aposentar fica para uma versão depois (decisão 4). |
| `dnsmasq-vps.service` | fora deste módulo. Pergunta ao dnsmasq principal e não sabe que o unbound existe. |

---

## Painel

A página de DNS deixa de ser só leitura:

- **Resolvedor** (cartão com o Salvar da barra de baixo): modo recursivo ou encaminhado, os
  servidores do modo encaminhado, DNSSEC, IPv6, privacidade, cache. O caminho de uma consulta e os
  contadores continuam no topo.
- **Domínios encaminhados** e **Domínios bloqueados**: caixa de inclusão, tabela compacta e
  Editar / Desativar / Remover por linha, como as outras listas.
- Com sobra na adoção, a página fica só leitura e explica o motivo, com as linhas sem tradução.

---

## Decisões (fechadas em 30/10/2026, todas pela recomendação)

1. **Encaminhar domínio no unbound**, e não no dnsmasq: mantém cada um no seu papel, e o
   `domain-insecure` do DNSSEC só existe ali.
2. **Bloqueio na v1: só o manual.** Listas são o "dado assinado" do README e pedem desenho
   próprio; o `local-zone` deixa espaço para elas.
3. **Modo encaminhado com DNS sobre TLS entra na v1**, como opção. O padrão continua sendo
   resolver pelas raízes. Ou todos os servidores têm nome TLS, ou nenhum: o
   `forward-tls-upstream` vale para a zona inteira.
4. **O `dns-healthcheck` fica por enquanto**, pausado durante a janela de prova.

---

## Verificado antes do código

Numa segunda instância do unbound no fw (loopback, porta de teste, diretório próprio), sem tocar
no de produção:

1. **`reload_keep_cache` mantém o cache** ao mudar `forward-zone`, `local-zone` e `local-data`, e
   a versão no TXT troca na hora. Mudar o tamanho do cache faz ele descartar o cache, mas aplica
   sem restart. Por isso restart só para escuta, threads e EDNS.
2. **O `unbound-checkconf` aceita** um staging fora de `/etc/unbound` incluindo a árvore real. O
   validador não é confinado; o daemon é (próximo item).
3. **O unbound roda confinado pelo AppArmor**: não lê `/tmp` nem abre socket fora dos caminhos
   do perfil. Não afeta o módulo, que escreve em `/etc/unbound/unbound.conf.d` e usa
   `/run/unbound.ctl`, mas qualquer teste com instância própria precisa morar em
   `/var/lib/unbound`.
4. **A validação da árvore pega o que o arquivo sozinho não pega**: com o `homelab.conf` no lugar
   ao lado do `azimuth.conf`, o arquivo passa e a árvore falha com `interface: 127.0.0.1@5335
   present twice`.
5. **O `#` do nome TLS não é comentário**: `forward-addr: 1.1.1.1@853#cloudflare-dns.com`. O leitor
   do painel e o importador cortavam tudo depois do `#`; agora só no começo ou depois de espaço.
