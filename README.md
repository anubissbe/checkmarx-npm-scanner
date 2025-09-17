# Checkmarx NPM Package Scanner

This tool scans Checkmarx One projects to check if any of the specified NPM packages are being used.

## Setup

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Get your Checkmarx One API Key:
   - Log into Checkmarx One EU platform
   - Go to Settings → API Keys
   - Create a new API key (this will be your refresh token)

3. Configure credentials (recommended approach):
   - Copy `.env.example` to `.env`
   - Edit `.env` and add your API key and tenant name:
   ```bash
   cp .env.example .env
   # Edit .env with your actual values:
   # API_KEY=your_actual_api_key_here
   # TENANT=your_tenant_name_here
   ```

## Usage

### Basic usage with .env file (recommended):
```bash
# If you've configured .env with API_KEY and TENANT
python checkmarx_package_scanner.py
```

### Manual API key usage:
```bash
python checkmarx_package_scanner.py \
  --api-key "YOUR_API_KEY" \
  --tenant "YOUR_TENANT_NAME"
```

### Full options:
```bash
python checkmarx_package_scanner.py \
  --api-key "YOUR_API_KEY" \
  --tenant "YOUR_TENANT_NAME" \
  --packages-file target_packages.json \
  --output checkmarx_scan_report.json
```

### Parameters:
- `--api-key`: Your Checkmarx One API Key (refresh token) - REQUIRED
- `--tenant`: Your Checkmarx tenant name - REQUIRED
- `--packages-file`: JSON file containing target packages (default: target_packages.json)
- `--output`: Output report file (default: checkmarx_scan_report.json)

## What it does

1. **Authenticates** with Checkmarx One EU tenant using your API key
2. **Fetches** all projects from your organization
3. **Retrieves** the latest scan for each project
4. **Analyzes** SCA (Software Composition Analysis) data from each scan
5. **Identifies** any usage of the target NPM packages
6. **Generates** a comprehensive JSON report with findings

## Output Report

The script generates a JSON report containing:
- Scan timestamp
- Total projects scanned
- Projects containing target packages
- Specific packages found in each project
- Projects without SCA data enabled

## Target Packages

The `target_packages.json` file contains all the packages and versions to check for, including:
- Various @art-ws packages
- @crowdstrike packages
- @ctrl packages
- @nativescript-community packages
- And many more (170+ packages total)

## Notes

- The script works with Checkmarx One (SaaS) on the EU tenant
- SCA must be enabled for projects to scan their dependencies
- The script includes rate limiting protection (0.5s delay between projects)
- If a project doesn't have SCA enabled, it will be noted in the report

## Security

- Never commit your API key to version control
- Consider using environment variables for the API key:
  ```bash
  export CHECKMARX_API_KEY="your_key_here"
  python checkmarx_package_scanner.py --api-key "$CHECKMARX_API_KEY" --tenant "your_tenant"
  ```

## Troubleshooting

If you encounter authentication issues:
1. Verify your API key is correct
2. Ensure your tenant name is accurate
3. Check that you're using the EU region (the script is configured for EU by default)

If no package data is found:
- Verify that SCA is enabled for your projects
- Check that the projects have been scanned recently
- Ensure the scans included dependency analysis