#!/usr/bin/env python3
"""
Checkmarx Package Scanner
Checks if specified NPM packages are being used in projects via Checkmarx One API
"""

import json
import requests
import argparse
import sys
import os
from typing import List, Dict, Set
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class CheckmarxScanner:
    def __init__(self, api_key: str = None, tenant_name: str = None, client_id: str = None, client_secret: str = None, region: str = "eu"):
        """
        Initialize Checkmarx scanner for EU region

        Args:
            api_key: Checkmarx One API Key (refresh token) - optional
            tenant_name: Your tenant name
            client_id: OAuth2 client ID - optional
            client_secret: OAuth2 client secret - optional
            region: Region (default: eu)
        """
        self.api_key = api_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_name = tenant_name
        self.region = region

        # Checkmarx One EU endpoints
        self.iam_base_url = f"https://eu.iam.checkmarx.net"
        self.api_base_url = f"https://eu.ast.checkmarx.net"

        self.access_token = None
        self.token_expiry = None
        self.headers = {}

    def authenticate(self):
        """Authenticate with Checkmarx One and get access token"""
        print("Authenticating with Checkmarx One...")

        auth_url = f"{self.iam_base_url}/auth/realms/{self.tenant_name}/protocol/openid-connect/token"

        # Try OAuth2 client credentials flow first if we have client_id and client_secret
        if self.client_id and self.client_secret:
            print("  Trying OAuth2 client credentials flow...")
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }

            try:
                response = requests.post(auth_url, data=data)

                if response.status_code != 200:
                    print(f"    DEBUG: OAuth2 client credentials status: {response.status_code}")
                    try:
                        error_detail = response.json()
                        print(f"    DEBUG: OAuth2 error: {error_detail}")
                    except:
                        print(f"    DEBUG: Response text: {response.text[:500]}")

                response.raise_for_status()

                token_data = response.json()
                self.access_token = token_data.get("access_token")

                # Set token expiry (usually 3600 seconds, but we'll refresh after 50 minutes to be safe)
                expires_in = token_data.get("expires_in", 3600)
                self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 600)  # Refresh 10 min before expiry

                if self.access_token:
                    self.headers = {
                        "Authorization": f"Bearer {self.access_token}",
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    }
                    print(f"✅ Authentication successful (OAuth2 client credentials, expires in {expires_in}s)")
                    return True

            except requests.exceptions.RequestException as e:
                print(f"  Client credentials failed: {e}")

        # If client credentials don't work or aren't provided, try refresh token
        if self.api_key:
            print("  Trying OAuth2 refresh token flow...")
            data = {
                "grant_type": "refresh_token",
                "refresh_token": self.api_key,
                "client_id": "ast-app"
            }

            try:
                response = requests.post(auth_url, data=data)

                if response.status_code != 200:
                    print(f"    DEBUG: OAuth2 refresh token status: {response.status_code}")
                    try:
                        error_detail = response.json()
                        print(f"    DEBUG: OAuth2 error: {error_detail}")
                    except:
                        print(f"    DEBUG: Response text: {response.text[:500]}")

                response.raise_for_status()

                token_data = response.json()
                self.access_token = token_data.get("access_token")

                # Set token expiry
                expires_in = token_data.get("expires_in", 3600)
                self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 600)  # Refresh 10 min before expiry

                if self.access_token:
                    self.headers = {
                        "Authorization": f"Bearer {self.access_token}",
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    }
                    print(f"✅ Authentication successful (OAuth2 refresh token, expires in {expires_in}s)")
                    return True

            except requests.exceptions.RequestException as e:
                print(f"  Refresh token failed: {e}")

        print("❌ Authentication failed")
        print("\n  Hint: Provide either:")
        print("  1. OAuth2 client credentials (CLIENT_ID and CLIENT_SECRET)")
        print("  2. A refresh token (API_KEY)")
        return False

    def check_and_refresh_token(self):
        """Check if token is expired and refresh if needed"""
        if self.token_expiry and datetime.now() >= self.token_expiry:
            print("  🔄 Token expired, refreshing...")
            return self.authenticate()
        return True

    def make_api_request(self, method, url, **kwargs):
        """Make API request with automatic token refresh on 401"""
        # Check token expiry before making request
        self.check_and_refresh_token()

        # Make the request
        response = requests.request(method, url, headers=self.headers, **kwargs)

        # If we get 401, try refreshing token once and retry
        if response.status_code == 401:
            print("  🔄 Got 401, refreshing token...")
            if self.authenticate():
                # Retry the request with new token
                response = requests.request(method, url, headers=self.headers, **kwargs)

        return response

    def get_projects(self) -> List[Dict]:
        """Get all projects from Checkmarx"""
        print("\nFetching projects...")

        url = f"{self.api_base_url}/api/projects"
        params = {
            "limit": 100,
            "offset": 0
        }

        all_projects = []

        try:
            while True:
                response = self.make_api_request("get", url, params=params)
                response.raise_for_status()

                data = response.json()
                projects = data.get("projects", [])
                all_projects.extend(projects)

                # Check if there are more pages
                if len(projects) < params["limit"]:
                    break

                params["offset"] += params["limit"]

            print(f"✅ Found {len(all_projects)} projects")
            return all_projects

        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to fetch projects: {e}")
            return []

    def get_latest_scan(self, project_id: str) -> Dict:
        """Get the latest scan for a project"""
        url = f"{self.api_base_url}/api/scans"
        params = {
            "project-id": project_id,
            "limit": 1,
            "sort": "-created_at"
        }

        try:
            response = self.make_api_request("get", url, params=params)
            response.raise_for_status()

            data = response.json()
            scans = data.get("scans", [])

            if scans and len(scans) > 0:
                # Debug: print available fields in scan object
                scan = scans[0]
                if not scan.get("created_at") and not scan.get("createdAt"):
                    # Try to find the date field
                    date_fields = [k for k in scan.keys() if 'date' in k.lower() or 'created' in k.lower() or 'time' in k.lower()]
                    if date_fields:
                        print(f"    DEBUG: Available date fields: {date_fields}")

                # Check what engines were used in this scan
                engines = scan.get("engines", [])
                if engines:
                    print(f"    DEBUG: Scan engines: {engines}")
                    if 'sca' not in [e.lower() for e in engines]:
                        print(f"    ⚠️  SCA engine was not used in this scan")

                return scan

            return None

        except requests.exceptions.RequestException as e:
            print(f"    DEBUG: Failed to get scan: {e}")
            return None

    def get_scan_packages(self, scan_id: str) -> List[Dict]:
        """Get packages/dependencies from a scan using scan-summary endpoint"""
        # Use scan-summary endpoint which works with OAuth2
        url = f"{self.api_base_url}/api/scan-summary"
        params = {"scan-ids": scan_id}

        try:
            response = self.make_api_request("get", url, params=params)
            if response.status_code == 403:
                print(f"    DEBUG: Access forbidden for scan-summary endpoint")
                return []

            response.raise_for_status()
            data = response.json()

            # Extract package information from scan summary
            summaries = data.get("scansSummaries", [])
            if not summaries:
                print(f"    DEBUG: No scan summaries found")
                return []

            summary = summaries[0]

            # Check SCA package counters to see if there are any packages
            sca_packages = summary.get("scaPackagesCounters", {})
            total_packages = sca_packages.get("totalCounter", 0)
            package_counters = sca_packages.get("packageCounters", [])

            print(f"    📊 SCA packages total: {total_packages}")

            if total_packages == 0:
                print(f"    ✅ No packages found in this scan")
                return []

            # If there are packages, try to get detailed package information from results endpoint
            print(f"    🔍 Found {total_packages} packages, getting details...")
            results_url = f"{self.api_base_url}/api/results"
            results_params = {"scan-id": scan_id, "limit": 100, "offset": 0}

            all_packages = []

            while True:
                try:
                    results_response = self.make_api_request("get", results_url, params=results_params)
                    if results_response.status_code != 200:
                        print(f"    DEBUG: Could not get detailed results: {results_response.status_code}")
                        break

                    results_data = results_response.json()
                    results = results_data.get("results", [])

                    if not results:
                        break

                    # Filter for SCA results that contain package information
                    sca_results = []
                    for result in results:
                        if result.get("type") == "sca" or "package" in str(result.get("data", {})).lower():
                            sca_results.append(result)

                    all_packages.extend(sca_results)

                    # Check if we got less than the limit (last page)
                    if len(results) < results_params["limit"]:
                        break

                    results_params["offset"] += results_params["limit"]

                except requests.exceptions.RequestException as e:
                    print(f"    DEBUG: Error getting detailed results: {e}")
                    break

            if all_packages:
                print(f"    ✅ Found {len(all_packages)} detailed package results")
            else:
                print(f"    ⚠️  Found {total_packages} packages in summary but no detailed results")
                # Return package counter information as fallback
                return [{"package_counter": counter} for counter in package_counters]

            return all_packages

        except requests.exceptions.RequestException as e:
            print(f"    DEBUG: Error with scan-summary endpoint: {e}")
            return []

    def check_packages_in_project(self, project: Dict, target_packages: Set[str]) -> Dict:
        """Check if any target packages are used in a project"""
        project_name = project.get("name", "Unknown")
        project_id = project.get("id")

        print(f"\nScanning project: {project_name}")

        # Get latest scan
        scan = self.get_latest_scan(project_id)
        if not scan:
            print(f"  ⚠️  No scans found")
            return {
                "project": project_name,
                "project_id": project_id,
                "status": "no_scans",
                "found_packages": []
            }

        scan_id = scan.get("id")
        # Try multiple possible date field names
        scan_date = scan.get("created_at") or scan.get("createdAt") or scan.get("createdOn") or "Unknown"

        print(f"  📊 Using scan from: {scan_date}")

        # Get packages from scan
        packages = self.get_scan_packages(scan_id)

        if not packages:
            print(f"  ℹ️  No package data available (SCA might not be enabled)")
            return {
                "project": project_name,
                "project_id": project_id,
                "scan_id": scan_id,
                "scan_date": scan_date,
                "status": "no_sca_data",
                "found_packages": []
            }

        # Check for matching packages
        found_packages = []

        for package in packages:
            # Try different package data structures
            package_name = ""
            package_version = ""

            # Standard package format
            if "name" in package:
                package_name = package.get("name", "")
                package_version = package.get("version", "")
            # Checkmarx results API format (vulnerability with package in data field)
            elif "data" in package:
                data_field = package.get("data", {})
                # Extract package info from packageIdentifier field
                if "packageIdentifier" in data_field:
                    pkg_identifier = data_field.get("packageIdentifier", "")
                    # Parse package identifier format: NPM-package@version or Maven-group:artifact-version
                    if pkg_identifier.startswith("NPM-"):
                        # NPM format: NPM-package@version or NPM-@scope/package@version
                        npm_part = pkg_identifier[4:]  # Remove "NPM-" prefix
                        if "@" in npm_part:
                            # Find the last @ for version (handles scoped packages)
                            last_at = npm_part.rfind("@")
                            if last_at > 0:  # Not the first character (which would be scope)
                                package_name = npm_part[:last_at]
                                package_version = npm_part[last_at+1:]
                            else:
                                package_name = npm_part
                        else:
                            package_name = npm_part
                    elif pkg_identifier.startswith("Maven-"):
                        # Maven format: Maven-groupId:artifactId-version
                        # For now, just store the whole identifier
                        package_name = pkg_identifier
                    else:
                        # Unknown format, use as-is
                        package_name = pkg_identifier
                # Direct package info in data field
                elif "packageName" in data_field:
                    package_name = data_field.get("packageName", "")
                    package_version = data_field.get("packageVersion", "")
                elif "package" in data_field:
                    pkg = data_field.get("package", {})
                    package_name = pkg.get("name", "") or pkg.get("packageName", "")
                    package_version = pkg.get("version", "") or pkg.get("packageVersion", "")
            # Vulnerability details format
            elif "vulnerabilityDetails" in package:
                vuln_details = package.get("vulnerabilityDetails", {})
                package_name = vuln_details.get("packageName", "")
                package_version = vuln_details.get("packageVersion", "")
            # Results API format (vulnerability with package info)
            elif "packageData" in package:
                pkg_data = package.get("packageData", {})
                package_name = pkg_data.get("name", "") or pkg_data.get("packageName", "")
                package_version = pkg_data.get("version", "") or pkg_data.get("packageVersion", "")
            # Alternative format
            elif "packageName" in package:
                package_name = package.get("packageName", "")
                package_version = package.get("packageVersion", "")

            # Skip if we couldn't extract package info
            if not package_name:
                continue

            package_id = f"{package_name}@{package_version}" if package_version else package_name

            # Check if this package is in our target list
            if package_name in target_packages or package_id in target_packages:
                found_packages.append({
                    "name": package_name,
                    "version": package_version,
                    "id": package_id
                })
                print(f"  🔴 Found: {package_id}")

        if found_packages:
            print(f"  ⚠️  Found {len(found_packages)} target packages")
        else:
            print(f"  ✅ No target packages found")

        return {
            "project": project_name,
            "project_id": project_id,
            "scan_id": scan_id,
            "scan_date": scan_date,
            "status": "scanned",
            "total_packages": len(packages),
            "found_packages": found_packages
        }

    def scan_all_projects(self, target_packages: Set[str]) -> List[Dict]:
        """Scan all projects for target packages"""
        projects = self.get_projects()

        if not projects:
            print("No projects to scan")
            return []

        results = []
        total = len(projects)
        print(f"\n📊 Starting scan of {total} projects...")

        for idx, project in enumerate(projects, 1):
            # Show progress every 10 projects
            if idx % 10 == 0:
                print(f"\n⏳ Progress: {idx}/{total} projects scanned ({idx*100//total}%)")
                # Check token refresh
                self.check_and_refresh_token()

            result = self.check_packages_in_project(project, target_packages)
            results.append(result)

            # Add small delay to avoid rate limiting
            time.sleep(0.5)

        print(f"\n✅ Completed scanning all {total} projects!")
        return results


def load_target_packages(filename: str) -> Set[str]:
    """Load target packages from JSON file"""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)

        # Create set of package names and package@version combinations
        packages = set()

        for package_name, versions in data.items():
            # Add package name (to catch any version)
            packages.add(package_name)

            # Add specific versions
            if isinstance(versions, list):
                for version in versions:
                    packages.add(f"{package_name}@{version}")
            elif isinstance(versions, str):
                packages.add(f"{package_name}@{versions}")

        return packages

    except Exception as e:
        print(f"Error loading target packages: {e}")
        return set()


def generate_report(results: List[Dict], output_file: str):
    """Generate a report of findings"""
    timestamp = datetime.now().isoformat()

    report = {
        "scan_timestamp": timestamp,
        "total_projects_scanned": len(results),
        "projects_with_findings": [],
        "projects_without_sca": [],
        "projects_without_scans": [],
        "projects_scanned_successfully": 0,
        "all_findings": []
    }

    for result in results:
        if result["found_packages"]:
            report["projects_with_findings"].append({
                "project": result["project"],
                "project_id": result["project_id"],
                "scan_date": result.get("scan_date"),
                "packages_found": result["found_packages"]
            })

            # Add to all findings
            for package in result["found_packages"]:
                report["all_findings"].append({
                    "project": result["project"],
                    "package": package["id"]
                })

        if result["status"] == "no_sca_data":
            report["projects_without_sca"].append(result["project"])
        elif result["status"] == "no_scans":
            report["projects_without_scans"].append(result["project"])
        elif result["status"] == "scanned":
            report["projects_scanned_successfully"] += 1

    # Save report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Report saved to: {output_file}")

    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Total projects scanned: {report['total_projects_scanned']}")
    print(f"Projects successfully analyzed: {report['projects_scanned_successfully']}")
    print(f"Projects with target packages: {len(report['projects_with_findings'])}")
    print(f"Projects without SCA data: {len(report['projects_without_sca'])}")
    print(f"Projects without any scans: {len(report['projects_without_scans'])}")
    print(f"Total package findings: {len(report['all_findings'])}")

    if report['projects_with_findings']:
        print("\n🔴 PROJECTS WITH TARGET PACKAGES:")
        for project in report['projects_with_findings']:
            print(f"\n  {project['project']}:")
            for pkg in project['packages_found']:
                print(f"    - {pkg['id']}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan Checkmarx projects for specific NPM packages"
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("API") or os.getenv("API_KEY"),
        help="Checkmarx One API Key (refresh token). Defaults to API or API_KEY from .env file"
    )
    parser.add_argument(
        "--client-id",
        default=os.getenv("CLIENT_ID"),
        help="OAuth2 client ID. Defaults to CLIENT_ID from .env file"
    )
    parser.add_argument(
        "--client-secret",
        default=os.getenv("CLIENT_SECRET"),
        help="OAuth2 client secret. Defaults to CLIENT_SECRET from .env file"
    )
    parser.add_argument(
        "--tenant",
        default=os.getenv("TENANT"),
        required=False,
        help="Checkmarx tenant name. Defaults to TENANT from .env file"
    )
    parser.add_argument(
        "--packages-file",
        default="target_packages.json",
        help="JSON file containing target packages (default: target_packages.json)"
    )
    parser.add_argument(
        "--output",
        default="checkmarx_scan_report.json",
        help="Output report file (default: checkmarx_scan_report.json)"
    )
    parser.add_argument(
        "--project",
        help="Scan specific project by name (optional)"
    )

    args = parser.parse_args()

    # Validate required arguments
    if not args.tenant:
        print("❌ Error: Tenant name is required. Set TENANT in .env file or use --tenant")
        sys.exit(1)

    # Check if we have either client credentials or API key
    if not ((args.client_id and args.client_secret) or args.api_key):
        print("❌ Error: Authentication credentials required.")
        print("   Provide either:")
        print("   - OAuth2 client credentials (CLIENT_ID and CLIENT_SECRET in .env)")
        print("   - API refresh token (API_KEY in .env)")
        sys.exit(1)

    # Initialize scanner with available credentials
    scanner = CheckmarxScanner(
        api_key=args.api_key,
        client_id=args.client_id,
        client_secret=args.client_secret,
        tenant_name=args.tenant,
        region="eu"
    )

    # Authenticate
    if not scanner.authenticate():
        sys.exit(1)

    # Load target packages
    print("\nLoading target packages...")
    target_packages = load_target_packages(args.packages_file)
    print(f"✅ Loaded {len(target_packages)} package identifiers")

    # Scan projects
    results = scanner.scan_all_projects(target_packages)

    # Generate report
    if results:
        generate_report(results, args.output)
    else:
        print("\n⚠️  No results to report")


if __name__ == "__main__":
    main()