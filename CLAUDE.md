# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose
This is a security scanning tool that checks if specific NPM packages (potentially compromised or suspicious) are being used in Checkmarx One projects via the Software Composition Analysis (SCA) API.

## Common Commands

### Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run the scanner with basic options
python checkmarx_package_scanner.py \
  --api-key "YOUR_API_KEY" \
  --tenant "YOUR_TENANT_NAME"

# Run with custom packages file and output
python checkmarx_package_scanner.py \
  --api-key "YOUR_API_KEY" \
  --tenant "YOUR_TENANT_NAME" \
  --packages-file target_packages.json \
  --output checkmarx_scan_report.json

# Use environment variable for API key (recommended)
export CHECKMARX_API_KEY="your_key_here"
python checkmarx_package_scanner.py --api-key "$CHECKMARX_API_KEY" --tenant "your_tenant"
```

### Testing
```bash
# No formal test suite exists - manual testing involves:
# 1. Authentication verification
# 2. Project retrieval confirmation
# 3. SCA data availability check
# 4. Report generation validation
```

## Architecture Overview

### Core Components

**CheckmarxScanner Class** (`checkmarx_package_scanner.py`):
- Handles all Checkmarx One API interactions for EU region
- Authentication flow: API key (refresh token) → OAuth2 → access token
- Paginated API requests for projects and packages
- Rate limiting protection (0.5s delay between project scans)

### API Integration Flow
1. **Authentication**: Uses Checkmarx One OAuth2 flow with refresh token
2. **Project Discovery**: Fetches all projects with pagination (100 per page)
3. **Scan Retrieval**: Gets latest scan for each project (sorted by creation date)
4. **Package Analysis**: Retrieves SCA package data from each scan
5. **Matching Logic**: Compares against target packages (name or name@version)
6. **Report Generation**: Creates JSON report with findings and summary

### Key Endpoints Used
- IAM: `https://eu.iam.checkmarx.net` (authentication)
- API: `https://eu.ast.checkmarx.net` (projects, scans, SCA data)

### Data Flow
- Input: `target_packages.json` containing 187 potentially compromised NPM packages
- Processing: Iterates through all projects, checking SCA data for package matches
- Output: `checkmarx_scan_report.json` with categorized findings

## Important Implementation Details

### Package Matching Strategy
The scanner matches packages in two ways:
- By package name alone (catches any version)
- By specific package@version combination

### Error Handling Considerations
- Projects without scans are marked as `no_scans` status
- Projects without SCA data are marked as `no_sca_data` status
- 404 responses on SCA endpoints indicate SCA is not enabled
- All API failures are handled gracefully with fallback to empty results

### Security Context
This tool is designed to detect potentially compromised NPM packages. The target packages list contains packages that may have been involved in supply chain attacks or other security incidents. Handle the API key securely and never commit it to version control.

### Rate Limiting
The scanner includes a 0.5-second delay between project scans to avoid rate limiting from the Checkmarx API.