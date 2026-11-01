# ISO do Azimuth

Debian 13.7 com tudo o que a caixa usa já instalado, a partir da própria ISO, sem internet. Só as
imagens dos containers dos aplicativos ficam para depois: baixam pelo painel, quando o aplicativo
é ligado.

No primeiro boot o painel se instala sozinho e atende em `https://<endereço>:8443`, com o usuário
e a senha criados na instalação. Numa caixa nova ele abre direto em **Configurar a rede**: lista as
placas, e o dono diz qual é a WAN (DHCP, PPPoE ou IP fixo) e qual é a LAN (endereço da caixa,
faixa de DHCP, domínio). Salvar gera o primeiro `config.yaml` e abre o resto do painel; a rede só
muda no primeiro apply, em Sistema, com o rollback automático de sempre. Depois disso, cada
componente se liga pelo painel.

## Gerar

```
iso/build.sh [--teste] debian-13.7.0-amd64-netinst.iso azimuth-13.7.iso
```

Não precisa de root. Baixa os pacotes com um apt isolado (não toca no apt da máquina) e reempacota
a netinst oficial com `xorriso`, repetindo os registros de boot dela. A netinst deve ser
verificada antes, pelo `SHA256SUMS` e pela assinatura `SHA256SUMS.sign` do cdimage.debian.org
(chave `DF9B 9C49 EAA9 2984 3258 9D76 DA87 E80D 6294 BE9B`).

`--teste` responde também o usuário (`operador`), a senha (`azimuth-teste`) e o disco (`/dev/sda`), põe o instalador no
console serial (em inglês, porque ali o d-i só oferece idiomas em ASCII) e desliga no fim: é a
que se usa para instalar numa VM sem ninguém olhando.

## O que a instalação faz

- **Três perguntas:** o nome do usuário (sugestão `administrador`), a senha dele e qual disco
  apagar. Root fica sem senha. O usuário entra no grupo `sudo`, com sudo sem senha
  (`/etc/sudoers.d/azimuth-admin`). Idioma pt_BR, teclado ABNT2, fuso de São Paulo, hostname
  `azimuth`.
- **Painel no primeiro boot:** a `azimuth-primeiro-boot.service` roda o
  `deploy/install-readonly.sh` do agente uma vez, na placa da rota padrão, marca a caixa como nova
  (`/var/lib/fwadmin/caixa-nova`) e se desliga. Salvar "Configurar a rede" chama o
  `fwctl inicial`, que roda o `deploy/adopt.sh --config` com o config do formulário. O login é o do sistema, conferido pelo PAM
  (`/etc/pam.d/azimuth`): entra quem está no grupo `sudo`, e root nunca. O painel roda sem
  privilégio (usuário `netadm`) e faz tudo pelo `sudo fwctl`, numa lista fechada de comandos.
- **Disco:** até 32 GiB de sistema e 4 GiB de swap. O resto fica livre para uma partição de dados,
  porque o LVM é só dos dados (STORAGE.md, princípio 7). Partição de BIOS e ESP criadas, então o
  mesmo disco dá boot em BIOS legado e em UEFI.
- **Pacotes** (`pacotes.txt`): rede (nftables, dnsmasq, unbound, WireGuard, fail2ban, PPPoE,
  inadyn), painel (Python, FastAPI, nginx), Docker e compose, storage (LVM, Samba, NFS,
  smartmontools), firmware e microcódigo.
- **Desligado até o motor configurar:** dnsmasq (seria resolvedor aberto), unbound (porta 53),
  Samba, NFS, Docker, nginx, inadyn. O `rpcbind` fica mascarado: o NFS daqui é só v4.
- **Firewall ligado desde o primeiro boot:** entrada fechada, com SSH, painel e DHCP cliente.
- **Docker fora do firewall** desde já (`/etc/docker/daemon.json` com `iptables: false`), para o
  caso de subir antes do motor.
- **Chave SSH** autorizada para o usuário criado (por padrão, `~/.ssh/id_rsa.pub` de quem gerou a
  ISO). Para uma ISO que vai para outra pessoa, gere com `CHAVES=/dev/null`.
- **apt** apontando para deb.debian.org, para as atualizações de depois. O repositório da ISO fica
  em `/var/lib/azimuth-iso` para reinstalar pacote sem internet.
- Log em `/var/log/azimuth-instalacao.log`; a saída do apt está no
  `/var/log/installer/syslog`.

## Verificado em 01/11/2026

No Proxmox, numa VM com CPU `kvm64` (x86-64-v1, o mesmo conjunto de instruções do Turion II do
MicroServer):

- instala sozinha em BIOS legado e em UEFI, em uns 10 minutos, e dá boot pelo disco nos dois;
- os 71 pacotes da lista instalados, nenhuma unidade com falha, só a 22 e o DHCP cliente
  escutando;
- `systemctl` funciona sem root (é por ele que o painel lê o estado dos serviços);
- o Docker sobe sem escrever regra no firewall;
- **Immich sem o ML roda em x86-64-v1:** o Postgres com VectorChord responde consulta por índice
  `vchordrq`, o servidor sobe e gera miniatura. Dois núcleos saturam na primeira subida.

Problemas que os testes acharam e que o build já trata: o busybox do instalador não tem `tee`; o
apt do sistema novo reprova as entradas `cdrom:` do instalador; no Debian 13 o cliente `docker`
virou pacote à parte (`docker-cli`); sem `dbus` o `systemctl` de usuário não fala com o systemd; o
menu do Debian inicia a instalação falada se ninguém escolhe nada.
