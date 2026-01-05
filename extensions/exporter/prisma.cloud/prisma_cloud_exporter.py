#!/usr/bin/env python3
"""
Prisma Cloud CSPM Exporter for Xygeni

Exports Prisma Cloud CSPM alerts and asset inventory to JSON files
compatible with Xygeni report-upload.

Usage:
    python prisma_cloud_exporter.py -c prisma.cloud.config [options]

See README.md for full documentation.
"""

import argparse
import configparser
import json
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)


# ANSI colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def log_info(msg: str) -> None:
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def log_success(msg: str) -> None:
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}")


def log_warning(msg: str) -> None:
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {msg}")


def log_error(msg: str) -> None:
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}", file=sys.stderr)


def log_verbose(msg: str, verbose: bool) -> None:
    if verbose:
        print(f"{Colors.BLUE}[VERBOSE]{Colors.NC} {msg}")


# Prisma Cloud API URLs by region
PRISMA_CLOUD_REGIONS = {
    'us': 'api.prismacloud.io',
    'us-2': 'api2.prismacloud.io',
    'us-3': 'api3.prismacloud.io',
    'eu': 'api.eu.prismacloud.io',
    'eu-2': 'api2.eu.prismacloud.io',
    'ca': 'api.ca.prismacloud.io',
    'sg': 'api.sg.prismacloud.io',
    'anz': 'api.anz.prismacloud.io',
    'ind': 'api.ind.prismacloud.io',
    'jp': 'api.jp.prismacloud.io',
    'uk': 'api.uk.prismacloud.io',
    'fr': 'api.fr.prismacloud.io',
    'de': 'api.de.prismacloud.io',
}


class PrismaCloudExporter:
    """Exports data from Prisma Cloud CSPM API."""

    def __init__(self, config: Dict[str, Any], verbose: bool = False, dry_run: bool = False):
        self.config = config
        self.verbose = verbose
        self.dry_run = dry_run
        self.access_token: Optional[str] = None
        self.api_url = self._get_api_url()
        self.session = requests.Session()

    def _get_api_url(self) -> str:
        """Get the API URL based on region configuration."""
        region = self.config.get('region', 'us').lower()

        # Check if it's a custom URL
        if region.startswith('http'):
            return region.rstrip('/')

        # Check if it's a known region
        if region in PRISMA_CLOUD_REGIONS:
            return f"https://{PRISMA_CLOUD_REGIONS[region]}"

        # Try as-is (might be a custom hostname)
        log_warning(f"Unknown region '{region}', using as hostname")
        return f"https://{region}"

    def authenticate(self) -> bool:
        """Authenticate with Prisma Cloud API and get access token."""
        log_info("Authenticating with Prisma Cloud API...")

        if self.dry_run:
            log_info("[DRY-RUN] Would authenticate with Prisma Cloud API")
            self.access_token = "dry-run-token"
            return True

        login_url = f"{self.api_url}/login"
        payload = {
            "username": self.config['access_key'],
            "password": self.config['secret_key']
        }

        try:
            response = self.session.post(
                login_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )

            log_verbose(f"Login response status: {response.status_code}", self.verbose)

            if response.status_code == 401:
                log_error("Authentication failed: Invalid credentials")
                return False

            if response.status_code != 200:
                log_error(f"Authentication failed: HTTP {response.status_code}")
                log_verbose(f"Response: {response.text}", self.verbose)
                return False

            data = response.json()
            self.access_token = data.get('token')

            if not self.access_token:
                log_error("Authentication failed: No token in response")
                return False

            log_success("Authentication successful")
            return True

        except requests.exceptions.RequestException as e:
            log_error(f"Authentication failed: {e}")
            return False

    def _make_request(self, method: str, endpoint: str,
                      params: Optional[Dict] = None,
                      json_data: Optional[Dict] = None) -> Optional[Dict]:
        """Make an authenticated API request."""
        if not self.access_token:
            log_error("Not authenticated. Call authenticate() first.")
            return None

        url = f"{self.api_url}{endpoint}"
        headers = {
            "x-redlock-auth": self.access_token,
            "Content-Type": "application/json"
        }

        log_verbose(f"Request: {method} {url}", self.verbose)
        if json_data:
            log_verbose(f"Payload: {json.dumps(json_data, indent=2)}", self.verbose)

        if self.dry_run:
            log_info(f"[DRY-RUN] Would call {method} {url}")
            return {"items": [], "totalCount": 0}

        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_data,
                timeout=60
            )

            if response.status_code == 401:
                log_warning("Token expired, re-authenticating...")
                if self.authenticate():
                    return self._make_request(method, endpoint, params, json_data)
                return None

            if response.status_code not in (200, 201):
                log_error(f"API request failed: HTTP {response.status_code}")
                log_verbose(f"Response: {response.text}", self.verbose)
                return None

            return response.json()

        except requests.exceptions.RequestException as e:
            log_error(f"API request failed: {e}")
            return None

    def export_alerts(self, output_file: str) -> bool:
        """Export security alerts from Prisma Cloud."""
        log_info("Exporting security alerts...")

        # Build time range
        time_range_days = int(self.config.get('alerts_time_range_days', 30))
        time_range = {
            "type": "relative",
            "value": {
                "unit": "day",
                "amount": time_range_days
            }
        }

        # Build filters
        filters = []

        alert_status = self.config.get('alerts_status', 'open')
        if alert_status:
            filters.append({
                "name": "alert.status",
                "operator": "=",
                "value": alert_status
            })

        cloud_types = self.config.get('alerts_cloud_types', '')
        if cloud_types:
            for cloud_type in cloud_types.split(','):
                filters.append({
                    "name": "cloud.type",
                    "operator": "=",
                    "value": cloud_type.strip()
                })

        severity = self.config.get('alerts_severity', '')
        if severity:
            filters.append({
                "name": "policy.severity",
                "operator": "=",
                "value": severity
            })

        # Build request payload
        payload = {
            "timeRange": time_range,
            "filters": filters,
            "detailed": True,
            "limit": int(self.config.get('alerts_limit', 10000))
        }

        all_alerts = []
        next_page_token = None
        page = 1

        while True:
            if next_page_token:
                payload["pageToken"] = next_page_token

            log_verbose(f"Fetching alerts page {page}...", self.verbose)
            response = self._make_request("POST", "/v2/alert", json_data=payload)

            if response is None:
                log_error("Failed to fetch alerts")
                return False

            items = response.get("items", [])
            all_alerts.extend(items)

            log_verbose(f"Page {page}: fetched {len(items)} alerts", self.verbose)

            next_page_token = response.get("nextPageToken")
            if not next_page_token:
                break

            # Rate limiting
            delay = float(self.config.get('request_delay', 0.5))
            time.sleep(delay)
            page += 1

        # Build output
        output = {
            "items": all_alerts,
            "totalCount": len(all_alerts),
            "nextPageToken": None
        }

        # Write to file
        if not self.dry_run:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)

        log_success(f"Exported {len(all_alerts)} alerts to: {output_file}")
        return True

    def export_assets(self, output_file: str) -> bool:
        """Export cloud asset inventory from Prisma Cloud."""
        log_info("Exporting cloud asset inventory...")

        # Build time range
        time_range_days = int(self.config.get('assets_time_range_days', 1))
        time_range = {
            "type": "relative",
            "value": {
                "unit": "day",
                "amount": time_range_days
            }
        }

        # Build filters
        filters = []

        cloud_types = self.config.get('assets_cloud_types', '')
        if cloud_types:
            for cloud_type in cloud_types.split(','):
                filters.append({
                    "name": "cloud.type",
                    "operator": "=",
                    "value": cloud_type.strip()
                })

        resource_types = self.config.get('assets_resource_types', '')
        if resource_types:
            for resource_type in resource_types.split(','):
                filters.append({
                    "name": "resource.type",
                    "operator": "=",
                    "value": resource_type.strip()
                })

        # Build request payload
        payload = {
            "timeRange": time_range,
            "filters": filters,
            "limit": int(self.config.get('assets_limit', 10000))
        }

        all_resources = []
        next_page_token = None
        page = 1

        while True:
            if next_page_token:
                payload["pageToken"] = next_page_token

            log_verbose(f"Fetching assets page {page}...", self.verbose)
            response = self._make_request("POST", "/resource", json_data=payload)

            if response is None:
                log_error("Failed to fetch assets")
                return False

            # Handle different response formats
            resources = response.get("resources", response.get("items", []))
            if isinstance(resources, list):
                all_resources.extend(resources)
            else:
                log_warning(f"Unexpected response format on page {page}")

            log_verbose(f"Page {page}: fetched {len(resources) if isinstance(resources, list) else 0} resources", self.verbose)

            next_page_token = response.get("nextPageToken")
            if not next_page_token:
                break

            # Rate limiting
            delay = float(self.config.get('request_delay', 0.5))
            time.sleep(delay)
            page += 1

        # Build output
        output = {
            "resources": all_resources,
            "totalCount": len(all_resources),
            "nextPageToken": None
        }

        # Write to file
        if not self.dry_run:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)

        log_success(f"Exported {len(all_resources)} resources to: {output_file}")
        return True


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from file."""
    if not os.path.exists(config_file):
        log_error(f"Configuration file not found: {config_file}")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(config_file)

    # Extract configuration values
    result = {}

    if 'credentials' in config:
        result['access_key'] = config['credentials'].get('access_key', '')
        result['secret_key'] = config['credentials'].get('secret_key', '')
        result['region'] = config['credentials'].get('region', 'us')

    if 'output' in config:
        result['output_dir'] = config['output'].get('output_dir', './output')

    if 'alerts' in config:
        result['alerts_time_range_days'] = config['alerts'].get('time_range_days', '30')
        result['alerts_status'] = config['alerts'].get('status', 'open')
        result['alerts_severity'] = config['alerts'].get('severity', '')
        result['alerts_cloud_types'] = config['alerts'].get('cloud_types', '')
        result['alerts_limit'] = config['alerts'].get('limit', '10000')

    if 'assets' in config:
        result['assets_time_range_days'] = config['assets'].get('time_range_days', '1')
        result['assets_cloud_types'] = config['assets'].get('cloud_types', '')
        result['assets_resource_types'] = config['assets'].get('resource_types', '')
        result['assets_limit'] = config['assets'].get('limit', '10000')

    if 'advanced' in config:
        result['request_delay'] = config['advanced'].get('request_delay', '0.5')

    # Override with environment variables if set
    if os.environ.get('PRISMA_CLOUD_ACCESS_KEY'):
        result['access_key'] = os.environ['PRISMA_CLOUD_ACCESS_KEY']
    if os.environ.get('PRISMA_CLOUD_SECRET_KEY'):
        result['secret_key'] = os.environ['PRISMA_CLOUD_SECRET_KEY']
    if os.environ.get('PRISMA_CLOUD_REGION'):
        result['region'] = os.environ['PRISMA_CLOUD_REGION']

    # Validate required fields
    if not result.get('access_key'):
        log_error("access_key is required in config file or PRISMA_CLOUD_ACCESS_KEY env var")
        sys.exit(1)

    if not result.get('secret_key'):
        log_error("secret_key is required in config file or PRISMA_CLOUD_SECRET_KEY env var")
        sys.exit(1)

    return result


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Prisma Cloud CSPM Exporter for Xygeni",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export all findings
  %(prog)s -c prisma.cloud.config --all

  # Export only alerts to custom directory
  %(prog)s -c prisma.cloud.config --alerts -o ./exports

  # Export only assets
  %(prog)s -c prisma.cloud.config --assets

  # Dry run (show what would be done)
  %(prog)s -c prisma.cloud.config --all --dry-run
"""
    )

    parser.add_argument('-c', '--config', required=True,
                        help='Path to configuration file (e.g., prisma.cloud.config)')
    parser.add_argument('-o', '--output', default='./output',
                        help='Output directory (default: ./output)')
    parser.add_argument('--alerts', action='store_true',
                        help='Export security alerts')
    parser.add_argument('--assets', action='store_true',
                        help='Export cloud asset inventory')
    parser.add_argument('--all', action='store_true',
                        help='Export all data types (default if no type specified)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without executing')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Load configuration
    config = load_config(args.config)

    # Override output directory if specified on command line
    if args.output:
        config['output_dir'] = args.output

    output_dir = config.get('output_dir', './output')

    # Determine what to export
    export_alerts = args.alerts
    export_assets = args.assets

    # If --all or nothing specified, export everything
    if args.all or (not export_alerts and not export_assets):
        export_alerts = True
        export_assets = True

    # Create exporter
    exporter = PrismaCloudExporter(config, verbose=args.verbose, dry_run=args.dry_run)

    # Authenticate
    if not exporter.authenticate():
        return 1

    # Create output directory
    if not args.dry_run:
        os.makedirs(output_dir, exist_ok=True)

    success = True

    # Export alerts
    if export_alerts:
        alerts_file = os.path.join(output_dir, "prisma_cloud_alerts.json")
        if not exporter.export_alerts(alerts_file):
            success = False

    # Export assets
    if export_assets:
        assets_file = os.path.join(output_dir, "prisma_cloud_assets.json")
        if not exporter.export_assets(assets_file):
            success = False

    if success:
        log_success("Export completed!")

        if not args.dry_run:
            print()
            log_info("To upload to Xygeni, run:")
            print()
            if export_alerts:
                print(f"  xygeni report-upload --report={output_dir}/prisma_cloud_alerts.json --format iac-prisma-cloud")
            if export_assets:
                print(f"  xygeni report-upload --report={output_dir}/prisma_cloud_assets.json --format inventory-prisma-cloud")
            print()

        return 0
    else:
        log_error("Export completed with errors")
        return 1


if __name__ == "__main__":
    sys.exit(main())