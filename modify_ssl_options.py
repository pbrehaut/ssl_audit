import os
import yaml
from typing import List, Dict, Any, Tuple
from glob import glob


def parse_virtual_servers(yaml_data: str) -> List[Dict[str, Any]]:
    """Parse YAML data and return list of virtual servers."""
    data = yaml.safe_load(yaml_data)
    return data['virtual_servers']


def parse_ip_address(ip: str) -> Tuple[str, str]:
    """Extract IP address and route domain if present."""
    if '%' in ip:
        ip_addr, route_domain = ip.split('%')
        return ip_addr, route_domain
    return ip, ""


def generate_openssl_command(ip: str, route_domain: str, tls_version: str) -> str:
    """Generate OpenSSL command with route domain if present."""
    base_cmd = f"openssl s_client -connect {ip}:443 -{tls_version}"
    if route_domain:
        return f"rdexec {route_domain} {base_cmd}"
    return base_cmd


def generate_commands(virtual_servers: List[Dict[str, Any]]) -> List[Tuple[str, str, List[str]]]:
    """Generate both TMSH commands and OpenSSL test commands."""
    commands = []
    new_options = ['no-tlsv1', 'no-tlsv1.1']

    for vs in virtual_servers:
        vs_name = vs.get('name', '')
        ip_address = vs.get('ip_address', '')
        ip, route_domain = parse_ip_address(ip_address)

        for profile in vs.get('client_ssl_profiles', []):
            profile_name = profile.get('name')
            if not profile_name:
                continue

            current_options = profile.get('options', '').split()
            updated_options = list(set(current_options + new_options))

            # Generate TMSH command
            options_str = ' '.join(updated_options)
            if options_str:
                tmsh_cmd = (f"modify ltm profile client-ssl {profile_name} "
                            f"options {{ {options_str} }}")

                # Generate OpenSSL test commands for each disabled TLS version
                openssl_cmds = []
                if 'no-tlsv1' in updated_options:
                    openssl_cmds.append(generate_openssl_command(ip, route_domain, "tls1"))
                if 'no-tlsv1.1' in updated_options:
                    openssl_cmds.append(generate_openssl_command(ip, route_domain, "tls1_1"))
                # if 'no-tlsv1.3' in updated_options:
                #     openssl_cmds.append(generate_openssl_command(ip, route_domain, "tls1_3"))

                commands.append((tmsh_cmd, vs_name, openssl_cmds))

    return commands


def main(yaml_content: str):
    """Main function to process YAML and generate commands."""
    virtual_servers = parse_virtual_servers(yaml_content)
    commands = generate_commands(virtual_servers)

    if not commands:
        print("No client SSL profiles found that need updating.")
        return

    print("\n# F5 TMSH Commands and Verification Tests:")
    for tmsh_cmd, vs_name, openssl_cmds in commands:
        print(f"\n# Virtual Server: {vs_name}")
        print(f"# TMSH Command:")
        print(tmsh_cmd)

        if openssl_cmds:
            print("\n# Verification Commands:")
            print("# The following OpenSSL commands should fail after applying the changes:")
            for cmd in openssl_cmds:
                print(f"# {cmd}")
            print("# Expected output should include: 'Connection refused' or 'Protocol version not supported'")


yaml_files = glob('data/*')

for file in yaml_files:
    print(f"\nProcessing {os.path.basename(file)}")
    print("=" * 80)
    with open(file, 'r') as f:
        yaml_content = f.read()
        main(yaml_content)