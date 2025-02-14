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

                commands.append((tmsh_cmd, vs_name, openssl_cmds))

    return commands


def write_commands_to_file(commands: List[Tuple[str, str, List[str]]], output_file: str):
    """Write commands to output file."""
    with open(output_file, 'w') as f:
        f.write("# F5 TMSH Commands and Verification Tests:\n")
        for tmsh_cmd, vs_name, openssl_cmds in commands:
            f.write(f"\n# Virtual Server: {vs_name}\n")
            f.write(f"# TMSH Command:\n")
            f.write(f"{tmsh_cmd}\n")

            if openssl_cmds:
                f.write("\n# Verification Commands:\n")
                f.write("# The following OpenSSL commands should fail after applying the changes:\n")
                for cmd in openssl_cmds:
                    f.write(f"# {cmd}\n")
                f.write("# Expected output should include: 'Connection refused' or 'Protocol version not supported'\n")


def process_yaml_file(input_file: str):
    """Process a single YAML file and generate output file."""
    # Create output directory if it doesn't exist
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Generate output filename based on input filename
    base_name = os.path.basename(input_file)
    output_file = os.path.join(output_dir, f"{os.path.splitext(base_name)[0]}_commands.txt")

    # Process the file
    with open(input_file, 'r') as f:
        yaml_content = f.read()
        virtual_servers = parse_virtual_servers(yaml_content)
        commands = generate_commands(virtual_servers)

        if not commands:
            print(f"No client SSL profiles found in {base_name}")
            return

        write_commands_to_file(commands, output_file)
        print(f"Generated commands for {base_name} -> {output_file}")


def main():
    """Main function to process all YAML files."""
    yaml_files = glob('data/*')

    if not yaml_files:
        print("No YAML files found in data directory")
        return

    for file in yaml_files:
        process_yaml_file(file)


if __name__ == "__main__":
    main()