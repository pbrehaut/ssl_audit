import yaml
from glob import glob
from pathlib import Path


def parse_ssl_profile(data, device_name):
    """
    Parse SSL profile data into a flat dictionary structure.

    Args:
        data (dict): Input dictionary containing SSL profile information
        device_name (str): Name of the device/file being processed

    Returns:
        dict: Flattened dictionary containing all relevant fields
    """
    result = {
        'device_name': device_name,
        'name': data.get('name'),
        'ip_address': data.get('ip_address')
    }

    # Process client SSL profiles
    if data.get('client_ssl_profiles'):
        client_profile = data['client_ssl_profiles'][0]  # Taking first profile
        result['client_ssl_enabled_protocols'] = ','.join(client_profile.get('enabled_protocols', []))

        # Add client protocol usage stats
        stats = client_profile.get('protocol_usage_statistics')
        if stats and isinstance(stats, dict) and stats != 'none':
            for protocol, count in stats.items():
                result[f'client_ssl_{protocol.lower()}_usage'] = count
        else:
            result['client_ssl_stats'] = 'none'

    # Process server SSL profiles
    if data.get('server_ssl_profiles'):
        server_profile = data['server_ssl_profiles'][0]  # Taking first profile
        result['server_ssl_enabled_protocols'] = ','.join(server_profile.get('enabled_protocols', []))

        # Add server protocol usage stats
        stats = server_profile.get('protocol_usage_statistics')
        if stats and isinstance(stats, dict) and stats != 'none':
            for protocol, count in stats.items():
                result[f'server_ssl_{protocol.lower()}_usage'] = count
        else:
            result['server_ssl_stats'] = 'none'

    return result


def process_yaml_files(directory='data'):
    """
    Process all YAML files in the specified directory and extract SSL profile information.

    Args:
        directory (str): Directory containing YAML files

    Returns:
        list: List of flattened dictionaries containing SSL profile information
    """
    all_results = []

    # Process each YAML file in the directory
    for filename in glob(f'{directory}/*.yaml'):
        # Extract device name from filename (remove path and extension)
        device_name = Path(filename).stem

        # Load and process the YAML file
        with open(filename, 'r') as f:
            try:
                data = yaml.safe_load(f)

                # Process virtual servers if they exist
                if data and 'virtual_servers' in data:
                    for vs in data['virtual_servers']:
                        flattened_data = parse_ssl_profile(vs, device_name)
                        all_results.append(flattened_data)

            except yaml.YAMLError as e:
                print(f"Error processing {filename}: {e}")
                continue

    return all_results


if __name__ == "__main__":
    # Process all YAML files and get results
    results = process_yaml_files()

    # Optionally, you could save the results to a CSV file
    import pandas as pd
    df = pd.DataFrame(results)
    df.to_csv('ssl_profiles.csv', index=False)