import yaml
from glob import glob
from pathlib import Path
import pandas as pd
from datetime import datetime
from collections import OrderedDict


def parse_ssl_profile(data, device_name):
    """
    Parse SSL profile data into a flat dictionary structure.

    Args:
        data (dict): Input dictionary containing SSL profile information
        device_name (str): Name of the device/file being processed

    Returns:
        dict: Flattened dictionary containing all relevant fields
    """

    if data['client_ssl_profiles']:
        client_profile = data['client_ssl_profiles'][0]['name']  # Taking first profile
    else:
        client_profile = None
    if data['server_ssl_profiles']:
        server_profile = data['server_ssl_profiles'][0]['name']  # Taking first profile
    else:
        server_profile = None


    # Initialize with base fields
    result = OrderedDict([
        ('device_name', device_name.replace("_ssl_profile_report", "")),
        ('name', data.get('name')),
        ('ip_address', data.get('ip_address')),
        ('client_ssl_profile', client_profile),
        ('server_ssl_profile', server_profile),
        ('client_ssl_enabled_protocols', ''),
        ('server_ssl_enabled_protocols', ''),
        ('client_ssl_stats', ''),
        ('server_ssl_stats', '')
    ])

    # Initialize possible SSL version fields
    ssl_versions = ['tlsv1', 'tlsv1_1', 'tlsv1_2']
    for version in ssl_versions:
        result[f'client_ssl_{version}_usage'] = None

    for version in ssl_versions:
        result[f'server_ssl_{version}_usage'] = None

    # Process client SSL profiles
    if data.get('client_ssl_profiles'):
        client_profile = data['client_ssl_profiles'][0]  # Taking first profile
        result['client_ssl_enabled_protocols'] = ','.join(client_profile.get('enabled_protocols', []))

        # Add client protocol usage stats
        stats = client_profile.get('protocol_usage_statistics')
        if stats and isinstance(stats, dict) and stats != 'none':
            for protocol, count in stats.items():
                field_name = f'client_ssl_{protocol.lower()}_usage'
                if field_name in result:
                    result[field_name] = count
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
                field_name = f'server_ssl_{protocol.lower()}_usage'
                if field_name in result:
                    result[field_name] = count
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


def export_to_excel(results, output_file=None):
    """
    Export results to an Excel file with proper formatting.

    Args:
        results (list): List of dictionaries containing SSL profile data
        output_file (str): Optional output filename. If None, generates a timestamped filename
    """
    if not results:
        print("No results to export")
        return

    # Create DataFrame with ordered columns
    df = pd.DataFrame(results)

    # Generate filename if not provided
    if output_file is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f'ssl_profiles_{timestamp}.xlsx'

    # Create Excel writer object
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        # Write DataFrame to Excel
        df.to_excel(writer, sheet_name='SSL Profiles', index=False)

        # Get workbook and worksheet objects
        workbook = writer.book
        worksheet = writer.sheets['SSL Profiles']

        # Auto-adjust column widths
        for column in worksheet.columns:
            max_length = 0
            column = list(column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = (max_length + 2)
            worksheet.column_dimensions[column[0].column_letter].width = adjusted_width

    print(f"Results exported to: {output_file}")
    return output_file


if __name__ == "__main__":
    # Process all YAML files and get results
    results = process_yaml_files()

    # Print summary
    print(f"Processed {len(results)} virtual servers")

    # Export to Excel
    if results:
        export_to_excel(results)