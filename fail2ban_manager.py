import subprocess
import json
import re
from datetime import datetime

class Fail2BanManager:
    def __init__(self):
        self.client_cmd = 'fail2ban-client'
    
    def get_status(self):
        """Get Fail2Ban service status"""
        try:
            # Check if fail2ban is running
            result = subprocess.run(['systemctl', 'is-active', 'fail2ban'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    'service': 'fail2ban',
                    'status': 'inactive',
                    'jails': []
                }
            
            # Get list of active jails
            jails_result = subprocess.run([self.client_cmd, 'status'], 
                                        capture_output=True, text=True)
            
            if jails_result.returncode != 0:
                return {
                    'service': 'fail2ban',
                    'status': 'error',
                    'error': jails_result.stderr
                }
            
            # Parse jail list
            jails = []
            lines = jails_result.stdout.split('\n')
            for line in lines:
                if 'Jail list:' in line:
                    jail_names = line.split('Jail list:')[1].strip()
                    if jail_names:
                        jail_list = [j.strip() for j in jail_names.split(',')]
                        for jail_name in jail_list:
                            if jail_name:
                                jail_info = self.get_jail_status(jail_name)
                                if jail_info:
                                    jails.append(jail_info)
            
            return {
                'service': 'fail2ban',
                'status': 'active',
                'jails': jails
            }
            
        except Exception as e:
            return {
                'service': 'fail2ban',
                'status': 'error',
                'error': str(e)
            }
    
    def get_jail_status(self, jail_name):
        """Get status of a specific jail"""
        try:
            result = subprocess.run([self.client_cmd, 'status', jail_name], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
            
            # Parse jail status
            jail_info = {
                'name': jail_name,
                'filter': None,
                'actions': [],
                'currently_failed': 0,
                'total_failed': 0,
                'currently_banned': 0,
                'total_banned': 0,
                'banned_ips': []
            }
            
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if 'Filter' in line:
                    jail_info['filter'] = line.split(':')[1].strip()
                elif 'Actions' in line:
                    actions_str = line.split(':')[1].strip()
                    jail_info['actions'] = [a.strip() for a in actions_str.split(',') if a.strip()]
                elif 'Currently failed:' in line:
                    jail_info['currently_failed'] = int(line.split(':')[1].strip())
                elif 'Total failed:' in line:
                    jail_info['total_failed'] = int(line.split(':')[1].strip())
                elif 'Currently banned:' in line:
                    jail_info['currently_banned'] = int(line.split(':')[1].strip())
                elif 'Total banned:' in line:
                    jail_info['total_banned'] = int(line.split(':')[1].strip())
                elif 'Banned IP list:' in line:
                    banned_ips_str = line.split(':')[1].strip()
                    if banned_ips_str:
                        jail_info['banned_ips'] = [ip.strip() for ip in banned_ips_str.split() if ip.strip()]
            
            return jail_info
            
        except Exception as e:
            print(f"Error getting jail status for {jail_name}: {e}")
            return None
    
    def get_banned_ips(self):
        """Get all currently banned IPs across all jails"""
        try:
            status = self.get_status()
            if status['status'] != 'active':
                return []
            
            all_banned = []
            for jail in status['jails']:
                for ip in jail['banned_ips']:
                    # Get ban time info if possible
                    ban_info = {
                        'ip': ip,
                        'jail': jail['name'],
                        'ban_time': None,  # Would need additional parsing
                        'unban_time': None  # Would need additional parsing
                    }
                    all_banned.append(ban_info)
            
            return all_banned
            
        except Exception as e:
            raise Exception(f"Failed to get banned IPs: {e}")
    
    def ban_ip(self, jail_name, ip_address):
        """Manually ban an IP address in a specific jail"""
        try:
            result = subprocess.run([self.client_cmd, 'set', jail_name, 'banip', ip_address], 
                                  capture_output=True, text=True, check=True)
            
            return {
                'success': True,
                'message': f'IP {ip_address} banned in jail {jail_name}',
                'output': result.stdout
            }
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to ban IP {ip_address}: {e.stderr}")
    
    def unban_ip(self, jail_name, ip_address):
        """Manually unban an IP address from a specific jail"""
        try:
            result = subprocess.run([self.client_cmd, 'set', jail_name, 'unbanip', ip_address], 
                                  capture_output=True, text=True, check=True)
            
            return {
                'success': True,
                'message': f'IP {ip_address} unbanned from jail {jail_name}',
                'output': result.stdout
            }
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to unban IP {ip_address}: {e.stderr}")
    
    def reload_jail(self, jail_name):
        """Reload a specific jail"""
        try:
            result = subprocess.run([self.client_cmd, 'reload', jail_name], 
                                  capture_output=True, text=True, check=True)
            
            return {
                'success': True,
                'message': f'Jail {jail_name} reloaded successfully',
                'output': result.stdout
            }
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to reload jail {jail_name}: {e.stderr}")
    
    def get_jail_log(self, jail_name, lines=50):
        """Get recent log entries for a jail"""
        try:
            # This is a simplified implementation
            # In practice, you'd parse /var/log/fail2ban.log
            result = subprocess.run(['tail', '-n', str(lines), '/var/log/fail2ban.log'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return []
            
            # Filter log entries for the specific jail
            log_entries = []
            for line in result.stdout.split('\n'):
                if jail_name in line and line.strip():
                    log_entries.append({
                        'timestamp': self._extract_timestamp(line),
                        'level': self._extract_log_level(line),
                        'message': line.strip()
                    })
            
            return log_entries
            
        except Exception as e:
            raise Exception(f"Failed to get jail log: {e}")
    
    def _extract_timestamp(self, log_line):
        """Extract timestamp from log line"""
        # Fail2ban log format: 2023-09-27 15:30:45,123 fail2ban.actions[1234]: NOTICE ...
        timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', log_line)
        if timestamp_match:
            return timestamp_match.group(1)
        return None
    
    def _extract_log_level(self, log_line):
        """Extract log level from log line"""
        if 'ERROR' in log_line:
            return 'ERROR'
        elif 'WARNING' in log_line:
            return 'WARNING'
        elif 'NOTICE' in log_line:
            return 'NOTICE'
        elif 'INFO' in log_line:
            return 'INFO'
        return 'UNKNOWN'
