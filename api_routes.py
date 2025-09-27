from flask import Blueprint, jsonify, request
import subprocess
import json
import os

api = Blueprint('api', __name__, url_prefix='/api/v1')

# ============================================================================
# Service Management Endpoints
# ============================================================================

@api.route('/services/<service_name>', methods=['GET'])
def get_service_status(service_name):
    """Get the status of a system service (nftables, wireguard, fail2ban)"""
    valid_services = ['nftables', 'wireguard', 'fail2ban']
    
    if service_name not in valid_services:
        return jsonify({'error': 'Invalid service name'}), 400
    
    try:
        # Use systemctl to check service status
        result = subprocess.run(['systemctl', 'is-active', service_name], 
                              capture_output=True, text=True)
        status = 'active' if result.returncode == 0 else 'inactive'
        
        return jsonify({
            'service': service_name,
            'status': status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/services/<service_name>/action', methods=['POST'])
def service_action(service_name):
    """Execute an action on a system service (start, stop, reload)"""
    valid_services = ['nftables', 'wireguard', 'fail2ban']
    valid_actions = ['start', 'stop', 'reload', 'restart']
    
    if service_name not in valid_services:
        return jsonify({'error': 'Invalid service name'}), 400
    
    data = request.get_json()
    action = data.get('action')
    
    if action not in valid_actions:
        return jsonify({'error': 'Invalid action'}), 400
    
    try:
        # Execute systemctl command
        subprocess.run(['sudo', 'systemctl', action, service_name], 
                      check=True, capture_output=True)
        
        # Get new status
        result = subprocess.run(['systemctl', 'is-active', service_name], 
                              capture_output=True, text=True)
        status = 'active' if result.returncode == 0 else 'inactive'
        
        return jsonify({
            'service': service_name,
            'status': status,
            'message': f'Service {action} executed successfully'
        })
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Failed to {action} service: {e}'}), 500

# ============================================================================
# Network Interfaces Endpoints
# ============================================================================

@api.route('/network/interfaces', methods=['GET'])
def get_network_interfaces():
    """List all network interfaces and their roles"""
    try:
        # Get network interfaces using ip command
        result = subprocess.run(['ip', 'addr', 'show'], 
                              capture_output=True, text=True, check=True)
        
        interfaces = []
        # Parse ip addr output (simplified for now)
        lines = result.stdout.split('\n')
        for line in lines:
            if ': ' in line and 'lo:' not in line:
                parts = line.split(': ')
                if len(parts) >= 2:
                    name = parts[1].split('@')[0]  # Remove @if suffix if present
                    interfaces.append({
                        'name': name,
                        'role': 'unassigned',  # Default role, will be configurable
                        'ip_address': 'N/A'  # Will be parsed from ip output
                    })
        
        return jsonify(interfaces)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/network/interfaces/<interface_name>', methods=['PUT'])
def set_interface_role(interface_name):
    """Set the role of a network interface (LAN, WAN, disabled)"""
    valid_roles = ['LAN', 'WAN', 'disabled']
    
    data = request.get_json()
    role = data.get('role')
    
    if role not in valid_roles:
        return jsonify({'error': 'Invalid role'}), 400
    
    # TODO: Store interface roles in configuration file
    # For now, just return success
    return jsonify({
        'name': interface_name,
        'role': role,
        'message': f'Interface {interface_name} role set to {role}'
    })

# ============================================================================
# NFTables Endpoints
# ============================================================================

@api.route('/nftables/ruleset', methods=['GET'])
def get_nftables_ruleset():
    """Get the complete nftables ruleset"""
    try:
        # Import nftables library
        import nftables
        
        nft = nftables.Nftables()
        nft.set_json_output(True)
        
        # Get current ruleset
        rc, output, error = nft.cmd("list ruleset")
        
        if rc != 0:
            return jsonify({'error': error}), 500
        
        return jsonify(json.loads(output))
    except ImportError:
        # Fallback to command line if library not available
        try:
            result = subprocess.run(['nft', '-j', 'list', 'ruleset'], 
                                  capture_output=True, text=True, check=True)
            return jsonify(json.loads(result.stdout))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/nftables/rules', methods=['POST'])
def add_nftables_rule():
    """Add a new nftables rule"""
    data = request.get_json()
    
    table = data.get('table')
    chain = data.get('chain')
    rule = data.get('rule')
    
    if not all([table, chain, rule]):
        return jsonify({'error': 'Missing required fields: table, chain, rule'}), 400
    
    try:
        # Construct nft command
        cmd = f"add rule {table} {chain} {rule}"
        
        # Execute using nftables library or command line
        import nftables
        nft = nftables.Nftables()
        rc, output, error = nft.cmd(cmd)
        
        if rc != 0:
            return jsonify({'error': error}), 500
        
        return jsonify({'message': 'Rule added successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/nftables/apply-defaults', methods=['POST'])
def apply_default_rules():
    """Apply default firewall rules (block WAN, allow LAN, allow VPN)"""
    try:
        # Default ruleset configuration
        default_rules = """
        table inet filter {
            chain input {
                type filter hook input priority 0; policy drop;
                
                # Allow loopback
                iifname "lo" accept
                
                # Allow established and related connections
                ct state established,related accept
                
                # Allow LAN traffic (assuming 192.168.0.0/16 and 10.0.0.0/8)
                ip saddr { 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 } accept
                
                # Allow WireGuard VPN
                udp dport 51820 accept
                
                # Allow SSH from VPN network only
                ip saddr 10.0.0.0/24 tcp dport 22 accept
            }
            
            chain forward {
                type filter hook forward priority 0; policy drop;
                
                # Allow VPN to LAN
                iifname "wg0" accept
                oifname "wg0" accept
            }
            
            chain output {
                type filter hook output priority 0; policy accept;
            }
        }
        """
        
        # Apply rules using nftables
        import nftables
        nft = nftables.Nftables()
        
        # Flush existing rules first
        nft.cmd("flush ruleset")
        
        # Apply new rules
        rc, output, error = nft.cmd(default_rules)
        
        if rc != 0:
            return jsonify({'error': error}), 500
        
        return jsonify({'message': 'Default rules applied successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# WireGuard Endpoints
# ============================================================================

from wireguard_manager import WireGuardManager
from fail2ban_manager import Fail2BanManager

# Initialize managers
wg_manager = WireGuardManager()
f2b_manager = Fail2BanManager()

@api.route('/wireguard/status', methods=['GET'])
def get_wireguard_status():
    """Get WireGuard service status and configuration"""
    try:
        status = wg_manager.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/wireguard/users', methods=['GET'])
def get_wireguard_users():
    """List all WireGuard users/peers"""
    try:
        users = wg_manager.list_clients()
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/wireguard/users', methods=['POST'])
def create_wireguard_user():
    """Create a new WireGuard user"""
    data = request.get_json()
    name = data.get('name')
    
    if not name:
        return jsonify({'error': 'User name is required'}), 400
    
    try:
        user = wg_manager.create_client(name)
        return jsonify(user), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/wireguard/users/<user_name>/config', methods=['GET'])
def get_wireguard_user_config(user_name):
    """Get WireGuard user configuration and QR code"""
    try:
        config = wg_manager.get_client_config(user_name)
        return jsonify(config)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/wireguard/users/<user_name>', methods=['DELETE'])
def delete_wireguard_user(user_name):
    """Delete a WireGuard user"""
    try:
        wg_manager.delete_client(user_name)
        return jsonify({'message': f'User {user_name} deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Fail2Ban Endpoints
# ============================================================================

@api.route('/fail2ban/status', methods=['GET'])
def get_fail2ban_status():
    """Get Fail2Ban service status"""
    try:
        status = f2b_manager.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/fail2ban/banned-ips', methods=['GET'])
def get_banned_ips():
    """Get list of currently banned IPs"""
    try:
        banned_ips = f2b_manager.get_banned_ips()
        return jsonify(banned_ips)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/fail2ban/ban-ip', methods=['POST'])
def ban_ip():
    """Manually ban an IP address"""
    data = request.get_json()
    jail_name = data.get('jail')
    ip_address = data.get('ip')
    
    if not all([jail_name, ip_address]):
        return jsonify({'error': 'Both jail and ip are required'}), 400
    
    try:
        result = f2b_manager.ban_ip(jail_name, ip_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/fail2ban/unban-ip', methods=['POST'])
def unban_ip():
    """Manually unban an IP address"""
    data = request.get_json()
    jail_name = data.get('jail')
    ip_address = data.get('ip')
    
    if not all([jail_name, ip_address]):
        return jsonify({'error': 'Both jail and ip are required'}), 400
    
    try:
        result = f2b_manager.unban_ip(jail_name, ip_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/fail2ban/jails/<jail_name>/reload', methods=['POST'])
def reload_fail2ban_jail(jail_name):
    """Reload a specific Fail2Ban jail"""
    try:
        result = f2b_manager.reload_jail(jail_name)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
