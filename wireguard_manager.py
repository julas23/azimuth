import subprocess
import json
import os
import tempfile
import base64
from pathlib import Path

class WireGuardManager:
    def __init__(self, config_dir=None, interface="wg0"):
        if config_dir is None:
            # Use local directory for development, /etc/wireguard for production
            if os.path.exists("/etc/wireguard") and os.access("/etc/wireguard", os.W_OK):
                config_dir = "/etc/wireguard"
            else:
                config_dir = os.path.expanduser("~/wireguard_config")
        
        self.config_dir = Path(config_dir)
        self.interface = interface
        self.config_file = self.config_dir / f"{interface}.conf"
        self.clients_dir = self.config_dir / "clients"
        
        # Create directories if they don't exist
        try:
            self.clients_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback to user directory if no permissions
            fallback_dir = os.path.expanduser("~/wireguard_config")
            self.config_dir = Path(fallback_dir)
            self.config_file = self.config_dir / f"{interface}.conf"
            self.clients_dir = self.config_dir / "clients"
            self.clients_dir.mkdir(parents=True, exist_ok=True)
    
    def get_status(self):
        """Get WireGuard interface status"""
        try:
            # Check if interface is up
            result = subprocess.run(['wg', 'show', self.interface], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    'service': 'wireguard',
                    'status': 'inactive',
                    'interface': self.interface,
                    'error': 'Interface not found or down'
                }
            
            # Parse wg show output
            lines = result.stdout.strip().split('\n')
            status_info = {
                'service': 'wireguard',
                'status': 'active',
                'interface': self.interface,
                'server_public_key': None,
                'listen_port': None,
                'peers': []
            }
            
            current_peer = None
            for line in lines:
                line = line.strip()
                if line.startswith('public key:'):
                    status_info['server_public_key'] = line.split(': ')[1]
                elif line.startswith('listening port:'):
                    status_info['listen_port'] = int(line.split(': ')[1])
                elif line.startswith('peer:'):
                    if current_peer:
                        status_info['peers'].append(current_peer)
                    current_peer = {'public_key': line.split(': ')[1]}
                elif line.startswith('allowed ips:') and current_peer:
                    current_peer['allowed_ips'] = line.split(': ')[1]
                elif line.startswith('latest handshake:') and current_peer:
                    current_peer['latest_handshake'] = line.split(': ')[1]
                elif line.startswith('transfer:') and current_peer:
                    transfer_parts = line.split(': ')[1].split(', ')
                    current_peer['transfer_rx'] = transfer_parts[0]
                    current_peer['transfer_tx'] = transfer_parts[1]
            
            if current_peer:
                status_info['peers'].append(current_peer)
            
            return status_info
            
        except Exception as e:
            return {
                'service': 'wireguard',
                'status': 'error',
                'error': str(e)
            }
    
    def generate_keys(self):
        """Generate a new WireGuard key pair"""
        try:
            # Generate private key
            private_result = subprocess.run(['wg', 'genkey'], 
                                          capture_output=True, text=True, check=True)
            private_key = private_result.stdout.strip()
            
            # Generate public key from private key
            public_result = subprocess.run(['wg', 'pubkey'], 
                                         input=private_key, 
                                         capture_output=True, text=True, check=True)
            public_key = public_result.stdout.strip()
            
            return {
                'private_key': private_key,
                'public_key': public_key
            }
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to generate keys: {e}")
    
    def get_next_client_ip(self, network="10.0.0.0/24"):
        """Get the next available IP address for a new client"""
        # Simple implementation - in production, this should be more robust
        import ipaddress
        
        network_obj = ipaddress.IPv4Network(network, strict=False)
        used_ips = set()
        
        # Add server IP (usually .1)
        used_ips.add(str(network_obj.network_address + 1))
        
        # Get IPs from existing clients
        clients = self.list_clients()
        for client in clients:
            if 'allowed_ips' in client:
                ip = client['allowed_ips'].split('/')[0]
                used_ips.add(ip)
        
        # Find next available IP
        for ip in network_obj.hosts():
            if str(ip) not in used_ips:
                return f"{ip}/32"
        
        raise Exception("No available IP addresses in the network")
    
    def create_client(self, name, server_endpoint="your_server_domain:51820"):
        """Create a new WireGuard client"""
        try:
            # Generate keys for client
            keys = self.generate_keys()
            
            # Get next available IP
            client_ip = self.get_next_client_ip()
            
            # Create client info
            client_info = {
                'name': name,
                'private_key': keys['private_key'],
                'public_key': keys['public_key'],
                'allowed_ips': client_ip,
                'created_at': subprocess.run(['date', '-Iseconds'], 
                                           capture_output=True, text=True).stdout.strip()
            }
            
            # Save client info
            client_file = self.clients_dir / f"{name}.json"
            with open(client_file, 'w') as f:
                json.dump(client_info, f, indent=2)
            
            # Generate client config
            server_status = self.get_status()
            server_public_key = server_status.get('server_public_key', 'SERVER_PUBLIC_KEY')
            
            client_config = f"""[Interface]
PrivateKey = {keys['private_key']}
Address = {client_ip}
DNS = 10.0.0.1

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
            
            # TODO: Add peer to server config and reload
            # This would require modifying /etc/wireguard/wg0.conf
            
            return {
                'id': name,
                'name': name,
                'public_key': keys['public_key'],
                'private_key': keys['private_key'],  # Only returned on creation
                'allowed_ips': client_ip,
                'status': 'enabled',
                'config': client_config
            }
            
        except Exception as e:
            raise Exception(f"Failed to create client: {e}")
    
    def list_clients(self):
        """List all configured clients"""
        clients = []
        
        if not self.clients_dir.exists():
            return clients
        
        for client_file in self.clients_dir.glob("*.json"):
            try:
                with open(client_file, 'r') as f:
                    client_info = json.load(f)
                    # Don't include private key in list
                    client_info.pop('private_key', None)
                    clients.append(client_info)
            except Exception as e:
                print(f"Error reading client file {client_file}: {e}")
        
        return clients
    
    def get_client_config(self, client_name):
        """Get client configuration and QR code"""
        client_file = self.clients_dir / f"{client_name}.json"
        
        if not client_file.exists():
            raise Exception(f"Client {client_name} not found")
        
        try:
            with open(client_file, 'r') as f:
                client_info = json.load(f)
            
            # Generate config content
            server_status = self.get_status()
            server_public_key = server_status.get('server_public_key', 'SERVER_PUBLIC_KEY')
            
            config_content = f"""[Interface]
PrivateKey = {client_info['private_key']}
Address = {client_info['allowed_ips']}
DNS = 10.0.0.1

[Peer]
PublicKey = {server_public_key}
Endpoint = your_server_domain:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
            
            # Generate QR code
            qr_result = subprocess.run(['qrencode', '-t', 'PNG', '-o', '-'], 
                                     input=config_content, 
                                     capture_output=True, text=True)
            
            if qr_result.returncode == 0:
                qr_base64 = base64.b64encode(qr_result.stdout.encode()).decode()
                qr_data_url = f"data:image/png;base64,{qr_base64}"
            else:
                qr_data_url = None
            
            return {
                'client_name': client_name,
                'config_content': config_content,
                'qr_code': qr_data_url
            }
            
        except Exception as e:
            raise Exception(f"Failed to get client config: {e}")
    
    def delete_client(self, client_name):
        """Delete a client"""
        client_file = self.clients_dir / f"{client_name}.json"
        
        if not client_file.exists():
            raise Exception(f"Client {client_name} not found")
        
        try:
            client_file.unlink()
            # TODO: Remove peer from server config and reload
            return True
        except Exception as e:
            raise Exception(f"Failed to delete client: {e}")
