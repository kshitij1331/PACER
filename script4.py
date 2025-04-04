import paramiko
import logging
import csv
import os
import socket
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed

# Configure logging to log only to a file
log_file_path = "precheck.log"
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(log_file_path)])

port_number = 80  # Change this to the desired port
global_username = "SI_Jiocompatch"  # Change this to your SSH username

def read_server_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def ping_server(ip):
    response = os.system(f"ping -n 1 {ip}" if os.name == "nt" else f"ping -c 1 {ip}")
    return response == 0

def check_ssh_connectivity(ip):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=global_username, timeout=5)
        ssh.close()
        return True
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.gaierror) as e:
        logging.error(f"SSH connection failed for {ip}: {e}")
    except Exception as e:
        logging.error(f"Unknown error connecting to {ip}: {e}")
    return False

def check_sudo_access(ssh):
    stdin, stdout, stderr = ssh.exec_command("sudo -n true")
    return stdout.channel.recv_exit_status() == 0

def check_port_connectivity(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
    return result == 0

def check_ssh_port_22(ip):
    """Checks if port 22 is open using a socket connection instead of telnet"""
    try:
        with socket.create_connection((ip, 22), timeout=5) as sock:
            return True
    except (socket.timeout, ConnectionRefusedError):
        logging.error(f"Port 22 is closed or unreachable for {ip}")
        return False

def get_disk_space(ssh, path):
    stdin, stdout, stderr = ssh.exec_command(f"df -BM {path} | tail -1 | awk '{{print $4}}'")
    return stdout.read().decode().strip() or "N/A"

def get_os(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release | grep -E '^(ID|VERSION_ID)='")
        os_info = stdout.read().decode().strip().split("\n")

        os_name, os_version = "", ""
        for line in os_info:
            if line.startswith("ID="):
                os_name = line.split("=")[1].replace('"', '').strip()
            elif line.startswith("VERSION_ID="):
                os_version = line.split("=")[1].replace('"', '').strip()

        stdin, stdout, stderr = ssh.exec_command("uname -r | grep -o 'el[0-9]\\+'")
        el_version = stdout.read().decode().strip()

        if os_name in ["ubuntu", "debian"]:
            return f"{os_name} {os_version}"
        elif os_name in ["rhel", "centos", "rocky", "almalinux", "oracle"]:
            return f"{os_name} ({el_version})"
        else:
            return f"Unknown OS: {os_name} {os_version}"
    except Exception as e:
        return f"Error: {str(e)}"

def check_server(ip):
    result = {'IP': ip}

    if not ping_server(ip):
        result['Reachability'] = 'Not Reachable'
        return result
    result['Reachability'] = 'Reachable'

    result['Port 22'] = 'Open' if check_ssh_port_22(ip) else 'Closed'

    if not check_ssh_connectivity(ip):
        result['SSH'] = 'Not Accessible'
        return result
    result['SSH'] = 'Accessible'

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=global_username, timeout=5)

        result['Sudo'] = 'Sudo Access' if check_sudo_access(ssh) else 'No Sudo Access'
        result['OS'] = get_os(ssh)
        result[f'Port {port_number}'] = 'Accessible' if check_port_connectivity(ip, port_number) else 'Not Accessible'
        result['/var/log'] = get_disk_space(ssh, '/var/log')
        result['/tmp'] = get_disk_space(ssh, '/tmp')

        ssh.close()
    except Exception as e:
        logging.error(f"Failed to perform checks on {ip}: {e}")
        result['Error'] = str(e)

    return result

def precheck_utility(servers, log_file):
    results = []
    max_workers = min(32, os.cpu_count() * 2)

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_server = {executor.submit(check_server, server): server for server in servers}
        for future in as_completed(future_to_server):
            results.append(future.result())

    fieldnames = ['IP', 'Reachability', 'Port 22', 'SSH', 'Sudo', 'OS', f'Port {port_number}', '/var/log', '/tmp', 'Error']
    with open(log_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow({key: result.get(key, 'N/A') for key in fieldnames})

if __name__ == '__main__':
    servers = read_server_list('server.txt')
    log_file = 'precheck_results.csv'
    precheck_utility(servers, log_file)
