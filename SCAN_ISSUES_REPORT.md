# Checkmarx NPM Scanner - Issues Report

## Current Status

### ✅ What's Working
1. **Authentication**: Successfully authenticating with Checkmarx One using OAuth2 refresh token
2. **Project Discovery**: Successfully retrieving all 1703 projects from Toyota Europe tenant
3. **Scan Retrieval**: Successfully getting scan information for each project
4. **SCA Detection**: Confirming that SCA engine is enabled in scans (shows `['sast', 'sca']`)

### ❌ Issue: SCA API Access Denied

Despite being an admin with all rights, the SCA package data endpoints return **403 Forbidden** errors.

#### Attempted Endpoints (all return 403):
- `/api/sca/scans/{scan_id}/packages`
- `/api/scans/{scan_id}/sca/packages`
- `/api/sca-results/packages?scan-id={scan_id}`
- `/api/results/{scan_id}/sca`
- `/api/scan-results/{scan_id}?engines=sca`

## Root Cause Analysis

The issue appears to be that **SCA data requires additional API permissions** beyond standard admin rights. Even though:
- You have admin rights in the Checkmarx UI
- SCA is enabled and running in your scans
- The API key works for other endpoints

The SCA-specific endpoints are restricted at the API level.

## Recommended Solutions

### Option 1: Request Additional API Permissions
Contact Checkmarx support or your Checkmarx administrator to:
1. Enable SCA API access for your API key
2. Add the necessary scopes/permissions for SCA data retrieval
3. Verify if there's a separate SCA API key requirement

### Option 2: Use Checkmarx CLI Tool
The official Checkmarx CLI might have the necessary permissions:
```bash
cx scan list --filter "sca-high>0" --format json
```

### Option 3: Access via UI Export
If API access cannot be granted:
1. Use the Checkmarx One UI to filter projects with vulnerable packages
2. Export the SCA results manually
3. Cross-reference with your target packages list

### Option 4: Contact Checkmarx Support
Provide them with:
- Your tenant: `toyotaeurope`
- The 403 errors on SCA endpoints
- Request for proper API documentation for SCA data access

## Technical Details for Support

When contacting support, mention:
- **Region**: EU (eu.ast.checkmarx.net)
- **Tenant**: toyotaeurope
- **API Endpoints Failing**: All SCA package endpoints return 403
- **Scan Engines**: Scans show both 'sast' and 'sca' engines active
- **Authentication**: OAuth2 refresh token flow working correctly
- **Other APIs**: Project and scan APIs work fine, only SCA is blocked

## Scanner Capabilities

Once SCA access is resolved, the scanner will:
- Check all 1703 projects for 187 potentially compromised NPM packages
- Generate detailed reports of affected projects
- Identify specific vulnerable package versions
- Provide comprehensive security assessment

## Next Steps

1. **Immediate**: Contact Checkmarx support about SCA API permissions
2. **Short-term**: Try alternative methods (CLI, UI export) if urgent
3. **Long-term**: Ensure proper API permissions are documented for future use