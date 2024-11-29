import requests
import json
import getpass
import urllib3
from collections import defaultdict

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


def get_ssl_profiles(token, virtual_server):
    """Get SSL profiles linked to a virtual server"""
    profiles = []
    vs_full_path = virtual_server['fullPath']

    print("\nDEBUG: Processing virtual server fullPath: {0}".format(vs_full_path))

    # Remove the leading /Common/ from the path if it exists
    vs_path = vs_full_path.replace('/Common/', '')

    url = "https://localhost/mgmt/tm/ltm/virtual/~Common~{0}/profiles".format(vs_path)
    headers = {'X-F5-Auth-Token': token}

    print("\nDEBUG: Requesting profiles from URL: {0}".format(url))

    try:
        response = requests.get(url, headers=headers, verify=False)
        print("DEBUG: Profile request status code: {0}".format(response.status_code))

        if response.status_code == 200:
            profile_data = response.json()

            if 'items' in profile_data:
                print("\nDEBUG: Found {0} profile items".format(len(profile_data['items'])))
                for profile in profile_data['items']:
                    print("\nDEBUG: Processing profile:")
                    print(json.dumps(profile, indent=2))

                    profile_context = profile.get('context')
                    profile_name = profile.get('name', '')
                    profile_full_path = profile.get('fullPath', '')

                    print("DEBUG: Profile context: {0}".format(profile_context))
                    print("DEBUG: Profile name: {0}".format(profile_name))
                    print("DEBUG: Profile full path: {0}".format(profile_full_path))

                    # Process clientside profiles
                    if profile_context == 'clientside':
                        # Try to get the profile details from client-ssl endpoint
                        profile_path = profile_full_path.replace('/Common/', '')
                        check_url = "https://localhost/mgmt/tm/ltm/profile/client-ssl/~Common~{0}".format(profile_path)

                        print("DEBUG: Checking if client SSL profile at URL: {0}".format(check_url))
                        try:
                            check_response = requests.get(check_url, headers=headers, verify=False)
                            print("DEBUG: Profile check status: {0}".format(check_response.status_code))

                            if check_response.status_code == 200:
                                print("DEBUG: Found SSL profile: {0}".format(profile_full_path))
                                profiles.append(profile_full_path)
                            else:
                                print("DEBUG: Not a client-ssl profile (status code: {0})".format(
                                    check_response.status_code))
                        except Exception as e:
                            print("DEBUG: Error checking profile type: {0}".format(str(e)))
                    # Process serverside profiles
                    elif profile_context == 'serverside':
                        # Try to get the profile details from server-ssl endpoint
                        profile_path = profile_full_path.replace('/Common/', '')
                        check_url = "https://localhost/mgmt/tm/ltm/profile/server-ssl/~Common~{0}".format(profile_path)

                        print("DEBUG: Checking if server SSL profile at URL: {0}".format(check_url))
                        try:
                            check_response = requests.get(check_url, headers=headers, verify=False)
                            print("DEBUG: Profile check status: {0}".format(check_response.status_code))

                            if check_response.status_code == 200:
                                print("DEBUG: Found SSL profile: {0}".format(profile_full_path))
                                profiles.append(profile_full_path)
                            else:
                                print("DEBUG: Not a server-ssl profile (status code: {0})".format(
                                    check_response.status_code))
                        except Exception as e:
                            print("DEBUG: Error checking profile type: {0}".format(str(e)))

            else:
                print("DEBUG: No 'items' found in profile_data")

        print("\nDEBUG: Total SSL profiles found: {0}".format(len(profiles)))
        return profiles

    except Exception as e:
        print("DEBUG: Exception in get_ssl_profiles:")
        print(str(e))
        return []


def get_ssl_profile_details(token, profile_name):
    """Get cipher and SSL version information for a profile"""
    print("\nDEBUG: Getting details for SSL profile: {0}".format(profile_name))

    # Remove the leading /Common/ if it exists
    profile_path = profile_name.replace('/Common/', '')
    url = "https://localhost/mgmt/tm/ltm/profile/client-ssl/~Common~{0}".format(profile_path)
    headers = {'X-F5-Auth-Token': token}

    print("DEBUG: Requesting profile details from URL: {0}".format(url))

    try:
        response = requests.get(url, headers=headers, verify=False)
        print("DEBUG: Profile details status code: {0}".format(response.status_code))
        print("DEBUG: Profile details raw response:")
        print(response.text)

        if response.status_code == 200:
            profile_data = response.json()
            print("\nDEBUG: Parsed profile details:")
            print(json.dumps(profile_data, indent=2))

            options = profile_data.get('tmOptions', '').split()
            options = [x for x in options if 'tls' in x.lower()]
            options = ' '.join(options)

            details = {
                'ciphers': profile_data.get('ciphers', 'DEFAULT'),
                'options':  options
            }
            print("DEBUG: Extracted details:")
            print(json.dumps(details, indent=2))
            return details
        else:
            print("DEBUG: Failed to get profile details")
            return None
    except Exception as e:
        print("DEBUG: Exception in get_ssl_profile_details:")
        print(str(e))
        return None


def generate_report(data):
    """Generate report file"""
    with open('ssl_profile_report.txt', 'w') as f:
        for vs_name, vs_data in data.items():
            f.write("\nVirtual Server: {0}\n".format(vs_name))
            f.write("Description: {0}\n".format(vs_data.get('description', 'N/A')))
            f.write("IP Address: {0}\n".format(vs_data['ip']))
            f.write("SSL Profiles:\n")

            if not vs_data['ssl_profiles']:
                f.write("  No SSL profiles found\n")
            else:
                for profile in vs_data['ssl_profiles']:
                    f.write("\n  Profile Name: {0}\n".format(profile['name']))
                    if profile['details']:
                        f.write("  Options: {0}\n".format(profile['details']['options']))
                        f.write("  Ciphers: {0}\n".format(profile['details']['ciphers']))
                    else:
                        f.write("  Unable to retrieve profile details\n")
            f.write("\n" + "="*50 + "\n")


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
            vs_data[vs_name]['ssl_profiles'] = []

            # Get SSL profiles
            ssl_profiles = get_ssl_profiles(token, virtual)
            print("Found {0} SSL profiles".format(len(ssl_profiles)))

            for profile_name in ssl_profiles:
                print("Getting details for profile: {0}".format(profile_name))
                profile_details = get_ssl_profile_details(token, profile_name)
                vs_data[vs_name]['ssl_profiles'].append({
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