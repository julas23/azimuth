# Módulo de Storage — desenho

Status: **desenho aprovado** (decisões fechadas em 28/10/2026). Falta a verificação em VM; nada disto tem código ainda.

O módulo transforma os discos de dados da caixa num volume único, opcionalmente espelhado,
com quatro diretórios fixos, servidos por SMB e NFS na LAN e na VPN, e montados pelos apps
(Jellyfin, Immich, Navidrome, Nextcloud).

---

## Princípios

1. **O volume tem sempre quatro diretórios, e só eles:** `Pictures`, `Videos`, `Music`,
   `Documents`. São criados pelo motor, não pelo usuário, e não se apagam pelo painel. O que vai
   dentro deles é do usuário.
2. **Dados do usuário e estado dos apps não se misturam.** Bancos, caches e configs dos
   containers vivem num segundo volume lógico (`apps`), no mesmo grupo e com a mesma proteção,
   mas que nunca é exportado por SMB ou NFS.
3. **Mexer em disco não é apply.** Particionar, formatar e espelhar são operações destrutivas e
   sem volta: não entram no ciclo aplicar → provar → reverter. Têm fluxo próprio, com plano
   mostrado antes e confirmação explícita (ver *Operações*).
4. **O roteador sobe sem o storage.** Volume ausente, degradado ou corrompido nunca impede o boot
   nem derruba a rede: os pontos de montagem são `nofail`, e quem depende do volume espera por ele.
5. **Nunca servir o diretório vazio.** Se o volume não montou, SMB, NFS e containers não sobem.
   Sem isso, o primeiro upload depois de uma falha cai no disco do sistema e some quando o volume
   volta.
6. **Disco se identifica por `/dev/disk/by-id`** (modelo + número de série), nunca por `/dev/sdX`,
   que muda de um boot para outro.

---

## Layout em disco

```
disco(s) de dados ── GPT, 1 partição "Linux LVM" (alinhada em 1 MiB, disco inteiro)
                     └── PV
VG  aionas
 ├── LV  dados   ext4   /srv/aionas        Pictures/ Videos/ Music/ Documents/
 └── LV  apps    ext4   /var/lib/aionas    estado dos containers (não exportado)
     + espaço livre reservado no VG (crescer o 'apps', reparo)
```

| Discos de dados | Tipo dos LVs | Capacidade útil | Perde um disco |
|---|---|---|---|
| 1 | linear | o disco | perde os dados |
| 2 | `raid1` (`-m1`): matriz + cópia | o menor dos dois | continua, degradado |
| 3+ | `raid1` (`-m1`) em dois discos; os demais são **reserva** | o menor dos dois do espelho | a reserva entra sozinha e o espelho se refaz |

- **Matriz e cópia.** O espelho é ao vivo (toda escrita vai para os dois discos), mas não é
  simétrico: a cópia é marcada `--writemostly`, e as leituras saem da matriz. O painel mostra os
  papéis. Se a matriz morre, a cópia assume sem perder nada e sem parar o serviço.
- **Espelho não é backup.** Arquivo apagado ou cifrado some dos dois discos na mesma hora. A
  proteção contra isso é outro assunto (snapshot e backup), fora deste módulo.
- **Reserva:** com 3 discos ou mais, os que sobram entram no VG sem LV nenhum, e
  `raid_fault_policy = allocate` reconstrói a perna perdida neles automaticamente.
- **LVM mesmo com um disco só.** Com o disco já em PV, a segunda unidade entra depois sem
  reformatar nada: `vgextend` + `lvconvert --type raid1 -m1`, com o volume montado e em uso.
- **ext4 e não XFS:** cresce com o volume montado (`lvextend -r`) e tem `fsck` que qualquer
  técnico conhece. Montado com `noatime`. Com integridade ligada, o LV não encolhe (limite do
  LVM). Isso não pesa aqui, porque o volume só cresce.
- **Discos de tamanhos diferentes:** o espelho usa o tamanho do menor; a sobra fica livre no VG e
  o painel mostra isso.
- **`apps`:** tamanho inicial de 64 GiB (miniaturas do Immich e o banco do Nextcloud crescem com
  o acervo). Cresce online pelo painel.

### Proteção contra corrupção silenciosa

O `raid1` do LVM não tem checksum. Se as duas cópias divergirem, ele detecta, mas não sabe dizer
qual está certa. Duas camadas cuidam disso:

- **`--raidintegrity y`, ligado por padrão** (dm-integrity por baixo de cada perna). Cada bloco
  ganha checksum, e uma leitura que falha no checksum é corrigida a partir da outra perna. Custa
  desempenho de escrita. Dá para desligar ao preparar os discos, mas não depois.
- **Scrub mensal** por timer, com o resultado (`integritymismatches` ou `raid_mismatch_count`) no
  painel e em alerta. Com integridade, o LVM não aceita `--syncaction`, então o scrub é uma
  leitura completa do LV, que dispara as correções. Sem integridade, é o
  `lvchange --syncaction check`.

### Disco que falha

- `lvmlocal.conf` com `activation_mode = "degraded"`: o espelho monta mesmo sem uma das pernas.
- `raid_fault_policy`: `warn` com 2 discos; `allocate` quando há disco reserva.
- `dmeventd` monitora os LVs e o `smartd` monitora os discos. Os dois alimentam o painel e os
  alertas.

---

## Identidade e permissões

Um dono só para tudo o que está no volume, para que SMB, NFS e containers enxerguem e gravem os
mesmos arquivos sem briga de permissão:

- Usuário e grupo de sistema `aionas-data`, **uid/gid 2000** (fixo, igual em toda caixa).
- Os quatro diretórios são `aionas-data:aionas-data`, modo `2775` (setgid: o que nasce dentro
  herda o grupo). Máscara de criação `0664`/`2775` em todos os caminhos de escrita.
- **SMB:** usuários autenticados de verdade (Samba `tdbsam`, contas Unix sem shell). A escrita sai
  como `aionas-data` (`force user`/`force group`).
- **NFS:** `all_squash,anonuid=2000,anongid=2000`. Toda escrita vira `aionas-data`.
- **Containers:** rodam com `--user 2000:2000` (rootless, `keep-id`). Gravam como o mesmo dono.

Permissão por usuário e por diretório (ACL) fica fora da v1. Na v1, cada usuário SMB tem
acesso `rw` ou `ro` a tudo.

---

## Serviços de rede

Os dois são servidos **só nas zonas `lan` e `vpn`**. O schema recusa `wan`, e não há como
liberar isso pelo painel.

### SMB (Samba, só o `smbd`)

- Um compartilhamento `aionas` com os quatro diretórios. Cliente Windows, macOS, Linux, TV e
  Kodi enxergam a mesma árvore.
- `server min protocol = SMB2_10`, sem SMB1, sem NetBIOS (`disable netbios = yes`, `nmbd`
  desligado), sem convidado.
- `bind interfaces only = yes` nas interfaces das zonas escolhidas.
- Atributos do macOS (`vfs objects = fruit streams_xattr`) ligados: sem eles o Finder fica lento e
  deixa arquivos `._*` espalhados.
- Senhas no `secrets.yaml` e aplicadas com `smbpasswd -s` **pela entrada padrão**, nunca na linha
  de comando.

### NFS (só v4)

- Uma exportação, `/srv/aionas`, para as faixas das zonas escolhidas. `rw`, `sync`,
  `no_subtree_check` e o squash acima.
- `nfs.conf`: `vers3=n`. Com NFSv4 só, não precisa de `rpcbind` nem de `mountd` exposto. Fica uma
  porta, `2049/tcp`.
- `sec=sys` confia no uid que o cliente declara. É por isso que existe o `all_squash`, e é por
  isso que o NFS nunca sai da LAN e da VPN.

---

## Acesso dos apps

Montagens fixas, definidas no catálogo do módulo de Services e não pelo usuário:

| App | Monta | Modo | Estado do app |
|---|---|---|---|
| Jellyfin | `Videos`, `Music` | `ro` | `/var/lib/aionas/jellyfin` |
| Navidrome | `Music` | `ro` | `/var/lib/aionas/navidrome` |
| Immich | `Pictures` | `rw` | `/var/lib/aionas/immich` (banco, miniaturas, vídeo transcodificado) |
| Nextcloud | os quatro, via *External storage → Local* | `rw` | `/var/lib/aionas/nextcloud` |

- **Immich só em `Pictures`.** A biblioteca de originais do Immich é o próprio `Pictures`, e o
  storage template grava em `Pictures/<usuário>/<ano>/...`. O que entra por SMB ou NFS fora
  dessas pastas é indexado como *external library* do mesmo caminho, excluindo as pastas dos
  usuários do Immich, para não aparecer duplicado. Fica tudo em `Pictures`, sem pasta de app.
- **Nextcloud pelo External storage, e não pelo diretório de dados:** assim ele enxerga o que
  entra por SMB e NFS (com "verificar mudanças em acesso direto"), em vez de manter uma árvore
  própria que só ele entende.
- Todo container sobe com `RequiresMountsFor=/srv/aionas /var/lib/aionas` (princípio 5).

---

## O que o módulo gera (parte declarativa)

Esta parte entra no ciclo normal aplicar → provar → reverter, como qualquer outro serviço:

| Arquivo | Conteúdo |
|---|---|
| `/etc/systemd/system/srv-aionas.mount` | LV `dados` por UUID, `nofail`, timeout curto |
| `/etc/systemd/system/var-lib-aionas.mount` | LV `apps`, idem |
| `/etc/lvm/lvmlocal.conf` | modo degradado e política de falha |
| `/etc/samba/smb.conf` | o compartilhamento e o endurecimento acima |
| `/etc/exports.d/aionas.exports` | a exportação NFS |
| `/etc/nfs.conf.d/aionas.conf` | NFSv4 só |
| `/etc/systemd/system/{smbd,nfs-server}.service.d/aionas.conf` | `RequiresMountsFor=` |
| `aionas-storage-scrub.{service,timer}` | scrub mensal |

O ponto de montagem vazio recebe `chattr +i`: com o volume fora, nada consegue gravar ali.

**Prova de função:**
- o volume está montado e a origem é o LV certo (`findmnt`);
- os quatro diretórios existem, com dono e modo certos;
- o `smbd` responde na 445 do IP da LAN;
- `exportfs -s` lista a exportação e o `nfsd` responde na 2049.

**Espelho degradado não reprova o apply:** é alerta, não regressão de configuração. Reverter uma
mudança no `smb.conf` porque um disco morreu não ajuda ninguém.

### Modelo no `config.yaml`

```yaml
storage:
  enabled: true
  disks:                          # escolhidos por id; o motor recusa o disco do sistema
    - id: ata-MODELO_SERIE1
    - id: ata-MODELO_SERIE2
  layout: mirror                  # single | mirror  (o schema confere com a qtd de discos)
  primary: ata-MODELO_SERIE1      # a matriz; a outra perna do espelho e' --writemostly
  spares: []                      # 3+ discos: os que nao estao no espelho
  integrity: true                 # so se escolhe ao preparar os discos
  apps_size_gib: 64
  scrub: monthly                  # monthly | weekly | off
  smb:
    enabled: true
    zones: [lan, vpn]             # 'wan' nao passa no schema
    users:
      - name: maria
        access: rw                # rw | ro; senha no secrets.yaml
  nfs:
    enabled: true
    zones: [lan]
```

`disks` e `layout` descrevem o estado **esperado**. Se o real divergir (disco novo, disco
faltando), o painel mostra a divergência e oferece a operação correspondente. O apply nunca
particiona nada por conta própria.

---

## Operações (parte destrutiva)

Cada operação gera um **plano**, a lista exata de comandos, mostrado antes de qualquer execução.
A confirmação é por digitação dos 4 últimos caracteres do número de série de cada disco afetado.
Tudo fica na auditoria.

| Operação | O que faz |
|---|---|
| Preparar discos | GPT + PV + VG + LVs + mkfs + quatro diretórios |
| Adicionar disco | `vgextend`; converte de linear para espelho, ou entra como reserva |
| Trocar disco | `lvconvert --repair` (disco morto) ou `--replace` (disco vivo, preventivo) |
| Crescer `apps` | `lvextend -r` |
| Scrub agora | `lvchange --syncaction check` |
| Adotar volume existente | após reinstalar o sistema, reconhece o VG `aionas` e monta **sem formatar** |

Travas que não dependem do usuário acertar:
- recusa o disco do sistema e qualquer disco com partição montada;
- mostra as assinaturas que serão apagadas (`wipefs -n`) antes de confirmar;
- **reinstalar o sistema nunca toca nos discos de dados.** O instalador detecta um VG `aionas` e
  vai para "adotar".

---

## Sistema no espelho

Sem disco dedicado ao sistema, e com dois discos ou mais, **o próprio sistema vai para o
espelho**. Num roteador, disco de boot que morre deixa a casa sem internet.

```
cada disco do espelho ── GPT
                         ├── ESP (512 MiB, FAT32)    uma em cada disco, mantidas iguais
                         └── Linux LVM               PV do VG aionas
VG aionas  +  LV sistema (raid1, ext4, /)  antes de 'apps' e 'dados'
```

- O GRUB vai instalado nos dois discos, e cada ESP vira uma entrada de boot no firmware.
  Qualquer um dos dois discos dá boot sozinho.
- Um hook do `kernel`/`grub` copia a ESP principal para a outra a cada atualização.

---

## Perfil: a mesma ISO, a stack definida pelo YAML

A ISO é a mesma para todo mundo. O que muda de uma caixa para outra é o **perfil**, um YAML que
diz quais módulos sobem e como. O formulário do site gera o perfil, e a instalação o lê. O
formulário nunca recebe senha nem dado pessoal: a senha do PPPoE e as dos usuários são pedidas
no navegador, na própria caixa.

O perfil diz **o que se espera**. O instalador **detecta** o hardware de verdade e, se houver
divergência (o perfil fala em dois discos e a caixa tem um), mostra a diferença e pergunta, em vez
de seguir.

Efeito no storage:

| Discos detectados | Layout |
|---|---|
| 1 | sistema e dados no mesmo disco, linear, aviso de "sem redundância" |
| 1 de sistema + 1 de dados | linear no disco de dados; o painel sugere o segundo disco |
| 1 de sistema + 2 de dados | espelho matriz + cópia nos dados |
| 2, sem disco de sistema separado | sistema e dados no espelho |
| 3 ou mais | espelho em dois, os demais como reserva |

---

## A verificar em VM antes do código

São limites do LVM que mudam o desenho se não se confirmarem. Cada item vira um teste, numa VM
com discos virtuais, antes da primeira linha do módulo:

1. `--raidintegrity y` e `--writemostly` funcionam juntos no mesmo LV (Debian 13).
2. Com integridade ligada, `lvconvert --repair` e a reserva automática (`allocate`) refazem a
   perna perdida. Integridade restringe operações de RAID, e o desenho depende dessas duas.
3. O GRUB lê `/boot` dentro de um LV `raid1` com integridade. Se não ler, `/boot` sai para uma
   partição própria em cada disco, sincronizada como a ESP.
4. A caixa dá boot com um dos dois discos arrancado, nos dois sentidos (matriz morta, cópia
   morta).
