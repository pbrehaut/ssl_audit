import requests
import getpass
import urllib3
from collections import defaultdict
import subprocess

__version__ = '3.0'

# Disable SSL warnings
urllib3.disable_warnings()


def get_auth_token(username, password):
    """Authenticate with F5 and get token"""
    url = "https://localhost/mgmt/shared/authn/login"
    payload = {
        'username': username,
        'password': password,
        'loginProviderName': 'tmos'
    }
    response = requests.post(url, json=payload, verify=False)
    if response.status_code == 200:
        return response.json()['token']['token']
    else:
        raise Exception("Authentication failed")


def get_profile_statistics(token, profile_name):
    """
    Retrieve statistics for a specific SSL profile via the F5 iControl REST API.

    Args:
        token (str): Authentication token
        profile_name (str): Name of the SSL profile

    Returns:
        dict: Statistics for SSL protocol versions usage
    """
    base_url = "https://localhost/mgmt/tm/ltm/profile"

    headers = {
        'X-F5-Auth-Token': token,
        'Content-Type': 'application/json'
    }

    try:
        client_url = "{0}/client-ssl/{1}/stats".format(base_url, profile_name.replace('/', '~'))
        server_url = "{0}/server-ssl/{1}/stats".format(base_url, profile_name.replace('/', '~'))

        response = requests.get(client_url, headers=headers, verify=False)

        if response.status_code == 404:
            response = requests.get(server_url, headers=headers, verify=False)

        response.raise_for_status()

        stats_data = response.json()

        if 'entries' in stats_data:
            # Keep the existing statistics dictionary for future use
            profile_stats = {
                'totalConnections': 0,
                'currentConnections': 0,
                'handshakeFailures': 0,
                'sslFailures': 0,
                'protocolErrors': 0,
                'connectionMirroring': 0,
                'peercertValid': 0,
                'peercertInvalid': 0,
                'currentActiveHandshakes': 0,
                'currentPendingHandshakes': 0,
                'decryptedBytesIn': 0,
                'decryptedBytesOut': 0,
                'encryptedBytesIn': 0,
                'encryptedBytesOut': 0
            }

            # Initialize dictionary for protocol stats
            protocol_stats = {}

            # Extract statistics from the nested structure
            entries = stats_data['entries'].items()[0][1]['nestedStats']['entries']

            # Process all statistics (keeping for future use)
            for key, value in entries.items():
                if 'common.handshakeFailures' in key:
                    profile_stats['handshakeFailures'] = value.get('value', 0)
                elif 'common.curConns' in key:
                    profile_stats['currentConnections'] = value.get('value', 0)
                elif 'common.totConns' in key:
                    profile_stats['totalConnections'] = value.get('value', 0)
                elif 'common.sslFailures' in key:
                    profile_stats['sslFailures'] = value.get('value', 0)
                elif 'common.protocolErrors' in key:
                    profile_stats['protocolErrors'] = value.get('value', 0)
                elif 'common.currentActiveHandshakes' in key:
                    profile_stats['currentActiveHandshakes'] = value.get('value', 0)
                elif 'common.currentPendingHandshakes' in key:
                    profile_stats['currentPendingHandshakes'] = value.get('value', 0)
                elif 'common.decryptedBytesIn' in key:
                    profile_stats['decryptedBytesIn'] = value.get('value', 0)
                elif 'common.decryptedBytesOut' in key:
                    profile_stats['decryptedBytesOut'] = value.get('value', 0)
                elif 'common.encryptedBytesIn' in key:
                    profile_stats['encryptedBytesIn'] = value.get('value', 0)
                elif 'common.encryptedBytesOut' in key:
                    profile_stats['encryptedBytesOut'] = value.get('value', 0)

                # Extract protocol usage statistics
                if key.startswith('common.protocolUses.'):
                    protocol_name = key.split('.')[-1]
                    protocol_stats[protocol_name] = value.get('value', 0)

            # Return only the protocol statistics
            return protocol_stats

        else:
            raise ValueError("Unexpected response format for profile {0}".format(profile_name))

    except requests.exceptions.RequestException as e:
        raise Exception("Failed to get statistics for profile {0}: {1}".format(profile_name, str(e)))


def get_virtual_servers(token):
    """Get all enabled virtual servers"""
    url = "https://localhost/mgmt/tm/ltm/virtual"
    headers = {'X-F5-Auth-Token': token}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        virtuals = response.json()['items']
        return [v for v in virtuals if v.get('enabled')]
    return []


def get_cipher_details(cipher_string):
    """Execute tmm --clientciphers command and return output"""
    try:
        # Replace ! with \! but use raw string to avoid double escaping
        escaped_ciphers = cipher_string.replace('!', r'\!')

        # Use shell=True and pass the complete command as a string to preserve the escaping
        cmd = 'tmm --clientciphers {0}'.format(escaped_ciphers)
        print(cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()

        if process.returncode == 0:
            return ','.join(set([x.split()[4] for x in [line.strip() for line in output.strip().splitlines()[1:]]]))
        else:
            return "Error running tmm command: {0}".format(error)
    except Exception as e:
        return "Failed to execute tmm command: {0}".format(str(e))


def get_ssl_profiles(token, virtual_server):
    """Get SSL profiles (both client and server) linked to a virtual server"""
    profiles = {'client': [], 'server': []}
    vs_full_path = virtual_server['fullPath']
    vs_path = vs_full_path.replace('/Common/', '')

    url = "https://localhost/mgmt/tm/ltm/virtual/~Common~{0}/profiles".format(vs_path)
    headers = {'X-F5-Auth-Token': token}

    try:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            profile_data = response.json()

            if 'items' in profile_data:
                for profile in profile_data['items']:
                    profile_context = profile.get('context')
                    profile_full_path = profile.get('fullPath', '')
                    profile_path = profile_full_path.replace('/Common/', '')

                    if profile_context == 'clientside':
                        check_url = "https://localhost/mgmt/tm/ltm/profile/client-ssl/~Common~{0}".format(profile_path)
                        check_response = requests.get(check_url, headers=headers, verify=False)
                        if check_response.status_code == 200:
                            profiles['client'].append(profile_full_path)

                    elif profile_context == 'serverside':
                        check_url = "https://localhost/mgmt/tm/ltm/profile/server-ssl/~Common~{0}".format(profile_path)
                        check_response = requests.get(check_url, headers=headers, verify=False)
                        if check_response.status_code == 200:
                            profiles['server'].append(profile_full_path)
        print(profiles)
        return profiles

    except Exception as e:
        print("Error getting SSL profiles: {0}".format(str(e)))
        return {'client': [], 'server': []}


def get_ssl_profile_details(token, profile_name, profile_type):
    """Get cipher and SSL version information for a profile"""
    profile_path = profile_name.replace('/Common/', '')

    # Set the appropriate endpoint based on profile type
    endpoint = 'client-ssl' if profile_type == 'client' else 'server-ssl'
    url = "https://localhost/mgmt/tm/ltm/profile/{0}/~Common~{1}".format(endpoint, profile_path)
    headers = {'X-F5-Auth-Token': token}

    try:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            profile_data = response.json()

            options = profile_data.get('tmOptions', '').split()
            options = [x for x in options if 'tls' in x.lower()]
            options = ' '.join(options)

            # Get cipher details for client profiles
            ciphers = profile_data.get('ciphers', 'DEFAULT')
            cipher_details = get_cipher_details(ciphers)

            details = {
                'ciphers': ciphers,
                'cipher_details': cipher_details,
                'options': options,
                'cert': profile_data.get('cert', 'None'),
                'key': profile_data.get('key', 'None'),
                'chain': profile_data.get('chain', 'None')
            }

            # Add server-specific fields if it's a server profile
            if profile_type == 'server':
                details.update({
                    'authenticate': profile_data.get('authenticate', 'No'),
                    'authenticateDepth': profile_data.get('authenticateDepth', 'N/A'),
                    'caFile': profile_data.get('caFile', 'None')
                })

            return details
    except Exception as e:
        print("Error getting profile details: {0}".format(str(e)))
        return None


def generate_report(data):
    """Generate report file in YAML format"""

    def write_indented(f, content, indent_level=0):
        """Helper function to write indented YAML content"""
        indent = "  " * indent_level
        f.write(indent + content + "\n")

    def escape_yaml_value(value):
        """Helper function to properly escape YAML values"""
        if not isinstance(value, str):
            value = str(value)

        # Force quoting if the value contains ! or :
        if '!' in value or ':' in value:
            # Replace any existing quotes first
            value = value.replace('"', '\\"')
            # Ensure the entire value is quoted
            return '"{0}"'.format(value)
        return value

    with open('ssl_profile_report.yaml', 'w') as f:
        write_indented(f, "virtual_servers:")

        for vs_name, vs_data in data.items():
            # Virtual server details
            write_indented(f, "- name: " + vs_name, 1)
            write_indented(f, "description: " + str(vs_data.get('description', 'N/A')), 2)
            write_indented(f, "ip_address: " + vs_data['ip'], 2)

            # Client SSL Profiles
            write_indented(f, "client_ssl_profiles:", 2)
            if not vs_data['client_ssl_profiles']:
                write_indented(f, "[]", 3)
            else:
                for profile in vs_data['client_ssl_profiles']:
                    write_indented(f, "- name: " + profile['name'], 3)
                    if profile['details']:
                        write_indented(f, "options: " + escape_yaml_value(profile['details']['options']), 4)
                        write_indented(f, "ciphers: " + escape_yaml_value(profile['details']['ciphers']), 4)
                        write_indented(f, "certificate: " + profile['details']['cert'], 4)
                        write_indented(f, "key: " + profile['details']['key'], 4)
                        write_indented(f, "chain: " + profile['details']['chain'], 4)

                        if profile['details']['cipher_details']:
                            write_indented(f, "enabled_protocols:", 4)
                            for line in profile['details']['cipher_details'].split('\n'):
                                if line.strip():  # Only write non-empty lines
                                    write_indented(f, "- " + escape_yaml_value(line.strip()), 5)
                    else:
                        write_indented(f, "details: null  # Unable to retrieve profile details", 4)

                    # Protocol statistics
                    if 'protocol_stats' in profile:
                        write_indented(f, "protocol_usage_statistics:", 4)
                        for protocol, count in profile['protocol_stats'].items():
                            if count > 0:
                                write_indented(f, "{0}: {1}".format(
                                    protocol.upper(), count), 5)

            # Server SSL Profiles
            write_indented(f, "server_ssl_profiles:", 2)
            if not vs_data['server_ssl_profiles']:
                write_indented(f, "[]", 3)
            else:
                for profile in vs_data['server_ssl_profiles']:
                    write_indented(f, "- name: " + profile['name'], 3)
                    if profile['details']:
                        write_indented(f, "options: " + escape_yaml_value(profile['details']['options']), 4)
                        write_indented(f, "ciphers: " + escape_yaml_value(profile['details']['ciphers']), 4)
                        write_indented(f, "certificate: " + profile['details']['cert'], 4)
                        write_indented(f, "key: " + profile['details']['key'], 4)
                        write_indented(f, "chain: " + profile['details']['chain'], 4)
                        write_indented(f, "authenticate: " + str(profile['details']['authenticate']), 4)
                        write_indented(f, "authentication_depth: " + str(profile['details']['authenticateDepth']), 4)
                        write_indented(f, "ca_file: " + profile['details']['caFile'], 4)

                        if profile['details']['cipher_details']:
                            write_indented(f, "enabled_protocols:", 4)
                            for line in profile['details']['cipher_details'].split('\n'):
                                if line.strip():  # Only write non-empty lines
                                    write_indented(f, "- " + escape_yaml_value(line.strip()), 5)
                    else:
                        write_indented(f, "details: null  # Unable to retrieve profile details", 4)

                    # Protocol statistics
                    if 'protocol_stats' in profile:
                        write_indented(f, "protocol_usage_statistics:", 4)
                        for protocol, count in profile['protocol_stats'].items():
                            if count > 0:
                                write_indented(f, "{0}: {1}".format(
                                    protocol.upper(), count), 5)


def main():
    # For Python 2
    username = raw_input("Username: ")
    password = getpass.getpass("Password: ")
    try:
        # Get authentication token
        token = get_auth_token(username, password)
        print("Successfully authenticated")

        # Get enabled virtual servers
        virtuals = get_virtual_servers(token)
        print("Found {0} enabled virtual servers".format(len(virtuals)))

        # Collect data
        vs_data = defaultdict(dict)
        for virtual in virtuals:
            vs_name = virtual['fullPath']
            print("\nProcessing virtual server: {0}".format(vs_name))

            # Get destination IP
            destination = virtual.get('destination', '')
            ip = destination.split('/')[-1].split(':')[0] if '/' in destination else 'N/A'

            vs_data[vs_name]['ip'] = ip
            vs_data[vs_name]['description'] = virtual.get('description', '')
            vs_data[vs_name]['client_ssl_profiles'] = []
            vs_data[vs_name]['server_ssl_profiles'] = []

            # Get SSL profiles
            ssl_profiles = get_ssl_profiles(token, virtual)

            # For client SSL profiles:
            for profile_name in ssl_profiles['client']:
                print("Getting details for client profile: {0}".format(profile_name))
                profile_details = get_ssl_profile_details(token, profile_name, 'client')
                protocol_stats = get_profile_statistics(token, profile_name)
                vs_data[vs_name]['client_ssl_profiles'].append({
                    'name': profile_name,
                    'details': profile_details,
                    'protocol_stats': protocol_stats
                })

            # For server SSL profiles:
            for profile_name in ssl_profiles['server']:
                print("Getting details for server profile: {0}".format(profile_name))
                profile_details = get_ssl_profile_details(token, profile_name, 'server')
                protocol_stats = get_profile_statistics(token, profile_name)
                vs_data[vs_name]['server_ssl_profiles'].append({
                    'name': profile_name,
                    'details': profile_details,
                    'protocol_stats': protocol_stats
                })

        # Generate report
        generate_report(vs_data)
        print("\nReport generated successfully as 'ssl_profile_report.yaml'")

    except Exception as e:
        print("Error: {0}".format(str(e)))


if __name__ == "__main__":
    main()