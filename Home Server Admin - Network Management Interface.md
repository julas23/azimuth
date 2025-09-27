# Home Server Admin - Network Management Interface

Uma interface web completa para administrar e gerenciar NFTables, WireGuard e Fail2Ban em servidores domésticos.

## 🏗️ Arquitetura

Este projeto implementa uma solução completa de gerenciamento de home server com arquitetura em **5 camadas**:

### 1. **Network Layer** (Implementada)
- **NFTables**: Gerenciamento de firewall e regras de rede
- **WireGuard**: VPN com gestão de usuários e QR codes
- **Fail2Ban**: Proteção contra ataques de força bruta

### 2. **Storage Layer** (Planejada)
- **NFS**: Network File System
- **Samba**: Compartilhamento de arquivos Windows
- **Persistent Volumes**: Volumes persistentes

### 3. **Virtualization Layer** (Planejada)
- **KVM**: Kernel-based Virtual Machine
- **QEMU**: Machine Emulator

### 4. **Applications Layer** (Planejada)
- **K3S**: Kubernetes lightweight
- **Docker/Containerd**: Container runtime
- **Immich**: Gerenciamento de fotos
- **Jellyfin**: Media server
- **Nextcloud**: Cloud pessoal
- **Obsidian**: Notas e conhecimento

### 5. **AI Services Layer** (Planejada)
- **Ollama**: Modelos de IA locais
- **GPU Support**: Aceleração por hardware

## 🚀 Tecnologias

### Backend
- **Python 3.11** com Flask
- **python3-nftables**: Integração nativa com NFTables
- **WireGuard Tools**: Gerenciamento de VPN
- **Fail2Ban**: Sistema de proteção
- **QRCode**: Geração de códigos QR para configuração móvel

### Frontend
- **React 18** com Vite
- **Tailwind CSS**: Framework de estilos
- **shadcn/ui**: Componentes de interface
- **Lucide Icons**: Ícones modernos
- **Recharts**: Gráficos e visualizações

## 📁 Estrutura do Projeto

```
home_server_admin/
├── backend/                    # API Flask
│   ├── app.py                 # Aplicação principal
│   ├── api_routes.py          # Endpoints da API
│   ├── wireguard_manager.py   # Gerenciador WireGuard
│   ├── fail2ban_manager.py    # Gerenciador Fail2Ban
│   └── requirements.txt       # Dependências Python
├── frontend/                   # Interface React
│   └── home-server-admin-frontend/
│       ├── src/
│       │   ├── App.jsx        # Componente principal
│       │   └── components/
│       │       ├── NetworkLayer.jsx  # Camada de rede
│       │       └── VPNManager.jsx    # Gestão VPN
│       └── package.json       # Dependências Node.js
└── README.md                  # Esta documentação
```

## 🛠️ Instalação e Configuração

### Pré-requisitos

```bash
# Instalar dependências do sistema
sudo apt update
sudo apt install -y python3 python3-pip nodejs npm
sudo apt install -y wireguard-tools fail2ban qrencode
sudo apt install -y python3-nftables nftables
```

### Backend (Flask API)

```bash
cd backend/

# Instalar dependências Python
pip install -r requirements.txt

# Iniciar servidor de desenvolvimento
python3 app.py
```

O backend estará disponível em `http://localhost:5001`

### Frontend (React)

```bash
cd frontend/home-server-admin-frontend/

# Instalar dependências
pnpm install

# Iniciar servidor de desenvolvimento
pnpm run dev --host
```

O frontend estará disponível em `http://localhost:5173`

## 🔧 Configuração dos Serviços

### NFTables
```bash
# Habilitar NFTables
sudo systemctl enable nftables
sudo systemctl start nftables
```

### WireGuard
```bash
# Habilitar WireGuard
sudo systemctl enable wg-quick@wg0
```

### Fail2Ban
```bash
# Habilitar Fail2Ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## 📡 API Endpoints

### Gerenciamento de Serviços
- `GET /api/v1/services/{service_name}` - Status do serviço
- `POST /api/v1/services/{service_name}/action` - Ações (start/stop/reload)

### Interfaces de Rede
- `GET /api/v1/network/interfaces` - Listar interfaces
- `PUT /api/v1/network/interfaces/{interface_name}` - Configurar papel (LAN/WAN)

### NFTables
- `GET /api/v1/nftables/ruleset` - Obter regras atuais
- `POST /api/v1/nftables/rules` - Adicionar nova regra
- `POST /api/v1/nftables/apply-defaults` - Aplicar regras padrão

### WireGuard VPN
- `GET /api/v1/wireguard/status` - Status do serviço
- `GET /api/v1/wireguard/users` - Listar usuários VPN
- `POST /api/v1/wireguard/users` - Criar novo usuário
- `GET /api/v1/wireguard/users/{user_name}/config` - Obter configuração e QR code
- `DELETE /api/v1/wireguard/users/{user_name}` - Excluir usuário

### Fail2Ban
- `GET /api/v1/fail2ban/status` - Status e jails ativas
- `GET /api/v1/fail2ban/banned-ips` - IPs banidos
- `POST /api/v1/fail2ban/ban-ip` - Banir IP manualmente
- `POST /api/v1/fail2ban/unban-ip` - Desbanir IP

## 🎯 Funcionalidades Implementadas

### ✅ Gestão de Serviços
- Controle de start/stop/reload para nftables, wireguard e fail2ban
- Monitoramento de status em tempo real
- Interface visual com indicadores de status

### ✅ Gestão VPN (WireGuard)
- Criação automática de usuários VPN
- Geração de chaves públicas/privadas
- QR codes para configuração móvel
- Download de arquivos de configuração
- Atribuição automática de IPs na rede VPN

### ✅ Interface Moderna
- Design responsivo com Tailwind CSS
- Navegação por abas intuitiva
- Cards informativos com métricas
- Modais para ações complexas
- Feedback visual para ações do usuário

## 🔒 Segurança

### Regras Padrão do Firewall
- **Bloqueia** todo tráfego WAN por padrão
- **Permite** tráfego na rede local (LAN)
- **Permite** acesso VPN (porta 51820)
- **Permite** SSH apenas via VPN
- **Permite** conexões estabelecidas e relacionadas

### Fail2Ban
- Proteção contra ataques de força bruta
- Banimento automático de IPs suspeitos
- Monitoramento de logs do sistema
- Configuração de jails customizáveis

## 🚧 Desenvolvimento Futuro

### Próximas Funcionalidades
1. **Interface de Firewall**: Editor visual de regras NFTables
2. **Monitoramento**: Gráficos de tráfego e uso de recursos
3. **Logs**: Visualização centralizada de logs do sistema
4. **Backup**: Sistema de backup automático de configurações
5. **Notificações**: Alertas por email/webhook

### Camadas Adicionais
- Implementação completa das 4 camadas restantes
- Integração com Kubernetes (K3S)
- Gerenciamento de containers Docker
- Interface para aplicações (Jellyfin, Nextcloud, etc.)

## 🤝 Contribuição

Este projeto foi desenvolvido como uma solução completa para gerenciamento de home servers. Contribuições são bem-vindas!

### Como Contribuir
1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## 🎯 Visão do Produto

Este projeto faz parte de uma visão maior de criar uma **solução completa de home server**, incluindo:

- **Hardware otimizado** para home servers
- **Software pré-configurado** com todas as camadas
- **Repositórios próprios** (Deb, Helm, Docker)
- **DDNS gratuito** para usuários
- **Suporte via IA** com agente treinado
- **Financiamento coletivo** para desenvolvimento do hardware

A interface web é apenas o primeiro passo dessa jornada ambiciosa! 🚀
