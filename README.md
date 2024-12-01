# F5 SSL Profile Analyzer

A Python script for analyzing and reporting SSL profiles configuration and usage statistics across F5 virtual servers. This tool helps security teams and network administrators audit their F5 BIG-IP SSL configuration and monitor SSL/TLS protocol usage.

## Features

- Retrieves SSL profile information for all enabled virtual servers
- Analyzes both client-side and server-side SSL profiles
- Collects detailed cipher suite information
- Gathers SSL/TLS protocol usage statistics
- Generates a comprehensive report in text format
- Supports authentication with F5 iControl REST API

## Prerequisites

- Python 2.x
- Access to F5 BIG-IP system with API permissions
- Required Python packages:
  - requests
  - urllib3
- Local access to F5 system for tmm command execution

## Installation

1. Clone or download the script to your local machine
2. Install required dependencies:
```bash
pip install requests urllib3
```

## Usage

1. Run the script:
```bash
python ssl_profile_analyzer.py
```

2. Enter your F5 BIG-IP credentials when prompted:
```
Username: your_username
Password: your_password
```

3. The script will:
   - Authenticate with the F5 system
   - Collect data from all enabled virtual servers
   - Generate a report file named 'ssl_profile_report.txt'

## Cipher Analysis

### TMM Cipher Intersection

The script uses the F5 Traffic Management Microkernel (TMM) to analyze cipher suite compatibility. This is done through the `get_cipher_details()` function, which:

1. Takes a cipher string from the SSL profile configuration
2. Executes the `tmm --clientciphers` command locally on the F5 system
3. Analyzes the intersection between:
   - Ciphers specified in the profile configuration
   - Ciphers actually supported by the F5 hardware/software

This provides critical information about:
- Which ciphers are actually available for use
- Potential mismatches between configuration and system capabilities
- Actual cipher strength in use

### Cipher Command Details

The `tmm --clientciphers` command execution:
```python
def get_cipher_details(cipher_string):
    # Escapes exclamation marks in cipher strings
    # (important for cipher exclusion syntax)
    escaped_ciphers = cipher_string.replace('!', r'\!')
    
    # Executes TMM command and processes output
    cmd = 'tmm --clientciphers {0}'.format(escaped_ciphers)
    # Returns intersection of configured vs. available ciphers
```

The command output provides:
- Complete cipher specifications
- Key exchange methods
- Authentication mechanisms
- Encryption algorithms
- MAC algorithms

### Important Notes

- The TMM command must be run locally on the F5 system
- Requires appropriate permissions for command execution
- Handles special characters in cipher strings (like '!' for exclusions)
- Results show only ciphers that are both:
  - Specified in the profile configuration
  - Supported by the F5 system

## Report Contents

The generated report includes:

- Virtual server details (name, IP address, description)
- Client SSL profile information:
  - Profile name
  - SSL/TLS options
  - Configured cipher suites
  - Actual available ciphers (from TMM analysis)
  - Certificate details
  - Protocol usage statistics
- Server SSL profile information:
  - Profile name
  - SSL/TLS options
  - Cipher configuration
  - Authentication settings
  - Protocol usage statistics

## Security Considerations

- The script disables SSL warnings for F5 API communication
- Credentials are collected securely using getpass
- API tokens are used for authentication after initial login
- The script assumes local F5 access (localhost)
- TMM command execution requires appropriate system permissions

## Functions

- `get_auth_token()`: Authenticates with F5 and retrieves an access token
- `get_profile_statistics()`: Collects SSL profile usage statistics
- `get_virtual_servers()`: Retrieves list of enabled virtual servers
- `get_cipher_details()`: Executes tmm command to get cipher information
- `get_ssl_profiles()`: Gets SSL profiles associated with virtual servers
- `get_ssl_profile_details()`: Retrieves detailed profile configuration
- `generate_report()`: Creates the final analysis report

## Error Handling

The script includes comprehensive error handling for:
- Authentication failures
- API request errors
- Invalid profile configurations
- Command execution issues
- TMM command failures
- Invalid cipher strings

## Limitations

- Currently supports Python 2.x only
- Requires local access to F5 system
- SSL warnings are disabled for API communication
- Assumes default F5 API endpoint (localhost)
- TMM command must be run with appropriate permissions

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

[Include appropriate license information here]