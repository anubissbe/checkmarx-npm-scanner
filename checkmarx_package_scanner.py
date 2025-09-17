#!/usr/bin/env python3
"""
Checkmarx Package Scanner
Checks if specified NPM packages are being used in projects via Checkmarx One API
"""

import json
import requests
import argparse
import sys
from typing import List, Dict, Set
import time
from datetime import datetime

class CheckmarxScanner:
    def __init__(self, api_key: str, tenant_name: str, region: str = "eu"):
        """
        Initialize Checkmarx scanner for EU region

        Args:
            api_key: Checkmarx One API Key
            tenant_name: Your tenant name
            region: Region (default: eu)
        """
        self.api_key = api_key
        self.tenant_name = tenant_name
        self.region = region

        # Checkmarx One EU endpoints
        self.iam_base_url = f"https://eu.iam.checkmarx.net"
        self.api_base_url = f"https://eu.api.checkmarx.net"

        self.access_token = None
        self.headers = {}

    def authenticate(self):
        """Authenticate with Checkmarx One and get access token"""
        print("Authenticating with Checkmarx One...")

        auth_url = f"{self.iam_base_url}/auth/realms/{self.tenant_name}/protocol/openid-connect/token"

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.api_key,
            "client_id": "ast-app"
        }

        try:
            response = requests.post(auth_url, data=data)
            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data.get("access_token")

            if not self.access_token:
                raise ValueError("No access token received")

            self.headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }

            print("✅ Authentication successful")
            return True

        except requests.exceptions.RequestException as e:
            print(f"❌ Authentication failed: {e}")
            return False

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
                response = requests.get(url, headers=self.headers, params=params)
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
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()

            data = response.json()
            scans = data.get("scans", [])

            return scans[0] if scans else None

        except requests.exceptions.RequestException:
            return None

    def get_scan_packages(self, scan_id: str) -> List[Dict]:
        """Get packages/dependencies from a scan"""
        url = f"{self.api_base_url}/api/sca/scans/{scan_id}/packages"

        all_packages = []
        params = {
            "limit": 100,
            "offset": 0
        }

        try:
            while True:
                response = requests.get(url, headers=self.headers, params=params)

                if response.status_code == 404:
                    # SCA might not be enabled for this scan
                    return []

                response.raise_for_status()

                data = response.json()
                packages = data.get("packages", [])
                all_packages.extend(packages)

                if len(packages) < params["limit"]:
                    break

                params["offset"] += params["limit"]

            return all_packages

        except requests.exceptions.RequestException:
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
        scan_date = scan.get("created_at", "Unknown")

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
            package_name = package.get("name", "")
            package_version = package.get("version", "")
            package_id = f"{package_name}@{package_version}"

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

        for project in projects:
            result = self.check_packages_in_project(project, target_packages)
            results.append(result)

            # Add small delay to avoid rate limiting
            time.sleep(0.5)

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

        elif result["status"] == "no_sca_data":
            report["projects_without_sca"].append(result["project"])

    # Save report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Report saved to: {output_file}")

    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Total projects scanned: {report['total_projects_scanned']}")
    print(f"Projects with target packages: {len(report['projects_with_findings'])}")
    print(f"Projects without SCA data: {len(report['projects_without_sca'])}")
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
        required=True,
        help="Checkmarx One API Key (refresh token)"
    )
    parser.add_argument(
        "--tenant",
        required=True,
        help="Checkmarx tenant name"
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

    # Initialize scanner
    scanner = CheckmarxScanner(
        api_key=args.api_key,
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