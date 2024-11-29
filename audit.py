import requests
import json
import getpass
import urllib3
from collections import defaultdict
import subprocess

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
            return output.strip()
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
            cipher_details = get_cipher_details(ciphers) if profile_type == 'client' else None

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
    """Generate report file"""
    with open('ssl_profile_report.txt', 'w') as f:
        for vs_name, vs_data in data.items():
            f.write("\nVirtual Server: {0}\n".format(vs_name))
            f.write("Description: {0}\n".format(vs_data.get('description', 'N/A')))
            f.write("IP Address: {0}\n".format(vs_data['ip']))

            # Client SSL Profiles
            f.write("\nClient SSL Profiles:\n")
            if not vs_data['client_ssl_profiles']:
                f.write("  No client SSL profiles found\n")
            else:
                for profile in vs_data['client_ssl_profiles']:
                    f.write("\n  Profile Name: {0}\n".format(profile['name']))
                    if profile['details']:
                        f.write("  Options: {0}\n".format(profile['details']['options']))
                        f.write("  Ciphers: {0}\n".format(profile['details']['ciphers']))
                        f.write("  Certificate: {0}\n".format(profile['details']['cert']))
                        f.write("  Key: {0}\n".format(profile['details']['key']))
                        f.write("  Chain: {0}\n".format(profile['details']['chain']))
                        if profile['details']['cipher_details']:
                            f.write("\n  Cipher Details:\n")
                            # Indent each line of cipher details output
                            for line in profile['details']['cipher_details'].split('\n'):
                                f.write("    {0}\n".format(line))
                    else:
                        f.write("  Unable to retrieve profile details\n")

            # Server SSL Profiles
            f.write("\nServer SSL Profiles:\n")
            if not vs_data['server_ssl_profiles']:
                f.write("  No server SSL profiles found\n")
            else:
                for profile in vs_data['server_ssl_profiles']:
                    f.write("\n  Profile Name: {0}\n".format(profile['name']))
                    if profile['details']:
                        f.write("  Options: {0}\n".format(profile['details']['options']))
                        f.write("  Ciphers: {0}\n".format(profile['details']['ciphers']))
                        f.write("  Certificate: {0}\n".format(profile['details']['cert']))
                        f.write("  Key: {0}\n".format(profile['details']['key']))
                        f.write("  Chain: {0}\n".format(profile['details']['chain']))
                        f.write("  Authenticate: {0}\n".format(profile['details']['authenticate']))
                        f.write("  Authentication Depth: {0}\n".format(profile['details']['authenticateDepth']))
                        f.write("  CA File: {0}\n".format(profile['details']['caFile']))
                    else:
                        f.write("  Unable to retrieve profile details\n")

            f.write("\n" + "=" * 50 + "\n")


def main():
    with open('creds.txt') as f:
        username = f.readline().strip()
        password = f.readline().strip()
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

            # Process client SSL profiles
            for profile_name in ssl_profiles['client']:
                print("Getting details for client profile: {0}".format(profile_name))
                profile_details = get_ssl_profile_details(token, profile_name, 'client')
                vs_data[vs_name]['client_ssl_profiles'].append({
                    'name': profile_name,
                    'details': profile_details
                })

            # Process server SSL profiles
            for profile_name in ssl_profiles['server']:
                print("Getting details for server profile: {0}".format(profile_name))
                profile_details = get_ssl_profile_details(token, profile_name, 'server')
                vs_data[vs_name]['server_ssl_profiles'].append({
                    'name': profile_name,
                    'details': profile_details
                })

        # Generate report
        generate_report(vs_data)
        print("\nReport generated successfully as 'ssl_profile_report.txt'")

    except Exception as e:
        print("Error: {0}".format(str(e)))


if __name__ == "__main__":
    main()