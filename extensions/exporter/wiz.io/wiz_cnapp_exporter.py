#!/usr/bin/env python3
# /// script
# requires-python = ">=3.7"
# dependencies = [
#   "requests",
# ]
# ///
"""
Wiz CNAPP Exporter for Xygeni

Exports Wiz CNAPP findings to JSON files compatible with Xygeni report-upload.
Supports vulnerability findings, issues, configuration findings, and cloud resources.

Usage:
    python wiz_cnapp_exporter.py -c wiz.config [options]

See README.md for full documentation.
"""

import argparse
import configparser
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

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


# Script directory (for finding query files)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Query file paths relative to script directory
QUERY_FILES = {
    'vulnerabilities': 'queries/vulnerability_findings.graphql',
    'issues': 'queries/issues.graphql',
    'config_findings': 'queries/configuration_findings.graphql',
    'cloud_resources': 'queries/cloud_resources.graphql',
}


class WizExporter:
    """Exports data from Wiz CNAPP GraphQL API."""

    def __init__(self, config: Dict[str, Any], verbose: bool = False, dry_run: bool = False):
        self.config = config
        self.verbose = verbose
        self.dry_run = dry_run
        self.access_token: Optional[str] = None
        self.session = requests.Session()

        # Set API URLs based on region
        region = config.get('region', 'us1').lower()
        self.api_url = f"https://api.{region}.app.wiz.io/graphql"
        self.token_url = "https://auth.app.wiz.io/oauth/token"

    def authenticate(self) -> bool:
        """Authenticate with Wiz API and get access token."""
        log_info("Authenticating with Wiz API...")

        if self.dry_run:
            log_info("[DRY-RUN] Would authenticate with Wiz API")
            self.access_token = "dry-run-token"
            return True

        payload = {
            "client_id": self.config['client_id'],
            "client_secret": self.config['client_secret'],
            "grant_type": "client_credentials",
            "audience": "wiz-api"
        }

        try:
            response = self.session.post(
                self.token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30
            )

            log_verbose(f"Auth response status: {response.status_code}", self.verbose)

            if response.status_code == 401 or response.text == "Unauthorized":
                log_error("Authentication failed: Invalid credentials")
                return False

            if response.status_code != 200:
                log_error(f"Authentication failed: HTTP {response.status_code}")
                log_verbose(f"Response: {response.text}", self.verbose)
                return False

            data = response.json()
            self.access_token = data.get('access_token')

            if not self.access_token:
                error_msg = data.get('error_description', data.get('error', 'Unknown error'))
                log_error(f"Authentication failed: {error_msg}")
                return False

            log_success("Authentication successful")
            return True

        except requests.exceptions.RequestException as e:
            log_error(f"Authentication failed: {e}")
            return False

    def _load_query(self, query_file: str) -> Optional[str]:
        """Load a GraphQL query from file."""
        full_path = os.path.join(SCRIPT_DIR, query_file)

        if not os.path.exists(full_path):
            log_error(f"Query file not found: {full_path}")
            return None

        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Remove comments and normalize whitespace
        lines = [line for line in content.split('\n') if not line.strip().startswith('#')]
        return ' '.join(lines)

    def _execute_query(self, query: str, variables: Dict[str, Any],
                       data_path: str, output_file: str) -> bool:
        """Execute a GraphQL query with pagination and save results."""
        if not self.access_token:
            log_error("Not authenticated. Call authenticate() first.")
            return False

        log_verbose(f"Query variables: {json.dumps(variables, indent=2)}", self.verbose)

        if self.dry_run:
            log_info(f"[DRY-RUN] Would execute query and save to: {output_file}")
            return True

        all_nodes = []
        cursor = None
        page = 1
        max_pages = int(self.config.get('max_pages', 0))
        request_delay = float(self.config.get('request_delay', 0.5))

        while True:
            # Add cursor for pagination
            current_vars = variables.copy()
            if cursor:
                current_vars['after'] = cursor

            # Build request
            body = {
                "query": query,
                "variables": current_vars
            }

            try:
                response = self.session.post(
                    self.api_url,
                    json=body,
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json"
                    },
                    timeout=60
                )

                if response.status_code != 200:
                    log_error(f"GraphQL request failed: HTTP {response.status_code}")
                    log_verbose(f"Response: {response.text}", self.verbose)
                    return False

                data = response.json()

                # Check for GraphQL errors
                if 'errors' in data and data['errors']:
                    error_msg = data['errors'][0].get('message', 'Unknown error')
                    log_error(f"GraphQL error: {error_msg}")
                    log_verbose(f"Full response: {json.dumps(data, indent=2)}", self.verbose)
                    return False

                # Extract nodes and pagination info
                result = data.get('data', {}).get(data_path, {})
                nodes = result.get('nodes', [])
                page_info = result.get('pageInfo', {})

                all_nodes.extend(nodes)
                log_verbose(f"Page {page}: fetched {len(nodes)} items", self.verbose)

                # Check for more pages
                has_next_page = page_info.get('hasNextPage', False)
                cursor = page_info.get('endCursor')

                if not has_next_page or not cursor:
                    break

                # Check max pages limit
                if max_pages > 0 and page >= max_pages:
                    log_warning(f"Reached maximum page limit ({max_pages})")
                    break

                # Rate limiting
                time.sleep(request_delay)
                page += 1

            except requests.exceptions.RequestException as e:
                log_error(f"GraphQL request failed: {e}")
                return False

        # Build output
        output = {
            "nodes": all_nodes,
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": None
            }
        }

        # Write to file
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)

        log_success(f"Exported {len(all_nodes)} items to: {output_file}")
        return True

    def export_vulnerabilities(self, output_file: str) -> bool:
        """Export vulnerability findings."""
        log_info("Exporting vulnerability findings...")

        query = self._load_query(QUERY_FILES['vulnerabilities'])
        if not query:
            return False

        # Parse filter configuration
        status_list = self._parse_json_list(self.config.get('vuln_status', '["UNRESOLVED"]'))
        severity_list = self._parse_json_list(self.config.get('vuln_severity', '["CRITICAL", "HIGH"]'))

        variables = {
            "first": int(self.config.get('vuln_first', 500)),
            "filter": {
                "status": status_list,
                "vendorSeverity": severity_list
            }
        }

        return self._execute_query(query, variables, 'vulnerabilityFindings', output_file)

    def export_issues(self, output_file: str) -> bool:
        """Export issues (toxic combinations, threats, misconfigurations)."""
        log_info("Exporting issues...")

        query = self._load_query(QUERY_FILES['issues'])
        if not query:
            return False

        status_list = self._parse_json_list(self.config.get('issues_status', '["OPEN", "IN_PROGRESS"]'))
        types_list = self._parse_json_list(self.config.get('issues_types', '["TOXIC_COMBINATION", "THREAT_DETECTION", "CLOUD_CONFIGURATION"]'))

        variables = {
            "first": int(self.config.get('issues_first', 500)),
            "filterBy": {
                "status": status_list,
                "type": types_list
            },
            "orderBy": {
                "field": "CREATED_AT",
                "direction": "DESC"
            }
        }

        return self._execute_query(query, variables, 'issues', output_file)

    def export_config_findings(self, output_file: str) -> bool:
        """Export cloud configuration findings."""
        log_info("Exporting cloud configuration findings...")

        query = self._load_query(QUERY_FILES['config_findings'])
        if not query:
            return False

        result_list = self._parse_json_list(self.config.get('config_result', '["FAIL", "ERROR"]'))
        severity_list = self._parse_json_list(self.config.get('config_severity', '["CRITICAL", "HIGH", "MEDIUM"]'))

        variables = {
            "first": int(self.config.get('config_first', 500)),
            "filter": {
                "result": result_list,
                "severity": severity_list
            }
        }

        return self._execute_query(query, variables, 'configurationFindings', output_file)

    def export_cloud_resources(self, output_file: str) -> bool:
        """Export cloud resources inventory."""
        log_info("Exporting cloud resources inventory...")

        query = self._load_query(QUERY_FILES['cloud_resources'])
        if not query:
            return False

        types_list = self._parse_json_list(self.config.get('cloud_resources_types', '["VIRTUAL_MACHINE", "CONTAINER", "SERVERLESS", "KUBERNETES_CLUSTER"]'))
        status_list = self._parse_json_list(self.config.get('cloud_resources_status', '["ACTIVE"]'))

        variables = {
            "first": int(self.config.get('cloud_resources_first', 500)),
            "filter": {
                "type": types_list,
                "status": status_list
            }
        }

        return self._execute_query(query, variables, 'cloudResources', output_file)

    def export_custom_query(self, query_file: str, output_file: str) -> bool:
        """Export using a custom GraphQL query file."""
        log_info(f"Exporting with custom query: {query_file}")

        # Try relative to script dir first, then absolute/relative to cwd
        if not os.path.isabs(query_file):
            full_path = os.path.join(SCRIPT_DIR, query_file)
            if not os.path.exists(full_path):
                full_path = query_file
        else:
            full_path = query_file

        if not os.path.exists(full_path):
            log_error(f"Query file not found: {query_file}")
            return False

        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Remove comments and normalize whitespace
        lines = [line for line in content.split('\n') if not line.strip().startswith('#')]
        query = ' '.join(lines)

        variables = {"first": 500}

        # Try to detect data path from query
        import re
        match = re.search(r'\{\s*(\w+)', query)
        data_path = match.group(1) if match else "data"

        log_warning(f"Using detected data path: {data_path} (modify if incorrect)")

        return self._execute_query(query, variables, data_path, output_file)

    @staticmethod
    def _parse_json_list(value: str) -> List[str]:
        """Parse a JSON array string or return as-is if already a list."""
        if isinstance(value, list):
            return value
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return [value] if value else []


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from file."""
    if not os.path.exists(config_file):
        log_error(f"Configuration file not found: {config_file}")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(config_file)

    result = {}

    if 'credentials' in config:
        result['client_id'] = config['credentials'].get('client_id', '')
        result['client_secret'] = config['credentials'].get('client_secret', '')
        result['region'] = config['credentials'].get('region', 'us1')

    if 'output' in config:
        result['output_dir'] = config['output'].get('output_dir', './output')

    if 'vulnerabilities' in config:
        result['vuln_first'] = config['vulnerabilities'].get('first', '500')
        result['vuln_status'] = config['vulnerabilities'].get('status', '["UNRESOLVED"]')
        result['vuln_severity'] = config['vulnerabilities'].get('severity', '["CRITICAL", "HIGH"]')

    if 'issues' in config:
        result['issues_first'] = config['issues'].get('first', '500')
        result['issues_status'] = config['issues'].get('status', '["OPEN", "IN_PROGRESS"]')
        result['issues_types'] = config['issues'].get('types', '["TOXIC_COMBINATION", "THREAT_DETECTION", "CLOUD_CONFIGURATION"]')

    if 'config_findings' in config:
        result['config_first'] = config['config_findings'].get('first', '500')
        result['config_result'] = config['config_findings'].get('result', '["FAIL", "ERROR"]')
        result['config_severity'] = config['config_findings'].get('severity', '["CRITICAL", "HIGH", "MEDIUM"]')

    if 'cloud_resources' in config:
        result['cloud_resources_first'] = config['cloud_resources'].get('first', '500')
        result['cloud_resources_types'] = config['cloud_resources'].get('types', '["VIRTUAL_MACHINE", "CONTAINER", "SERVERLESS", "KUBERNETES_CLUSTER"]')
        result['cloud_resources_status'] = config['cloud_resources'].get('status', '["ACTIVE"]')

    if 'advanced' in config:
        result['max_pages'] = config['advanced'].get('max_pages', '0')
        result['request_delay'] = config['advanced'].get('request_delay', '0.5')

    # Override with environment variables
    if os.environ.get('WIZ_CLIENT_ID'):
        result['client_id'] = os.environ['WIZ_CLIENT_ID']
    if os.environ.get('WIZ_CLIENT_SECRET'):
        result['client_secret'] = os.environ['WIZ_CLIENT_SECRET']
    if os.environ.get('WIZ_REGION'):
        result['region'] = os.environ['WIZ_REGION']

    # Validate required fields
    if not result.get('client_id'):
        log_error("client_id is required in config file or WIZ_CLIENT_ID env var")
        sys.exit(1)

    if not result.get('client_secret'):
        log_error("client_secret is required in config file or WIZ_CLIENT_SECRET env var")
        sys.exit(1)

    return result


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Wiz CNAPP Exporter for Xygeni",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export all findings
  %(prog)s -c wiz.config --all

  # Export only vulnerabilities
  %(prog)s -c wiz.config --vulnerabilities

  # Export only issues to custom directory
  %(prog)s -c wiz.config --issues -o ./exports

  # Export with custom query
  %(prog)s -c wiz.config --query queries/custom.graphql

  # Dry run (show what would be done)
  %(prog)s -c wiz.config --all --dry-run
"""
    )

    parser.add_argument('-c', '--config', required=True,
                        help='Path to configuration file (e.g., wiz.config)')
    parser.add_argument('-o', '--output', default='./output',
                        help='Output directory (default: ./output)')
    parser.add_argument('--vulnerabilities', action='store_true',
                        help='Export vulnerability findings')
    parser.add_argument('--issues', action='store_true',
                        help='Export issues (toxic combinations, threats, misconfigurations)')
    parser.add_argument('--config-findings', action='store_true',
                        help='Export cloud configuration findings')
    parser.add_argument('--cloud-resources', action='store_true',
                        help='Export cloud resources inventory')
    parser.add_argument('--all', action='store_true',
                        help='Export all finding types (default if no type specified)')
    parser.add_argument('--query', metavar='FILE',
                        help='Export using a custom GraphQL query file')
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

    # Override output directory
    if args.output:
        config['output_dir'] = args.output

    output_dir = config.get('output_dir', './output')

    # Determine what to export
    export_vulns = args.vulnerabilities
    export_issues = args.issues
    export_config = args.config_findings
    export_resources = args.cloud_resources
    custom_query = args.query

    # If --all or nothing specified, export everything (except custom query)
    if args.all or (not export_vulns and not export_issues and not export_config
                    and not export_resources and not custom_query):
        export_vulns = True
        export_issues = True
        export_config = True
        export_resources = True

    # Create exporter
    exporter = WizExporter(config, verbose=args.verbose, dry_run=args.dry_run)

    # Authenticate
    if not exporter.authenticate():
        return 1

    # Create output directory
    if not args.dry_run:
        os.makedirs(output_dir, exist_ok=True)

    success = True

    # Export based on options
    if custom_query:
        basename = os.path.splitext(os.path.basename(custom_query))[0]
        output_file = os.path.join(output_dir, f"wiz_{basename}.json")
        if not exporter.export_custom_query(custom_query, output_file):
            success = False
    else:
        if export_vulns:
            output_file = os.path.join(output_dir, "wiz_cnapp_vulnerabilities.json")
            if not exporter.export_vulnerabilities(output_file):
                success = False

        if export_issues:
            output_file = os.path.join(output_dir, "wiz_cnapp_issues.json")
            if not exporter.export_issues(output_file):
                success = False

        if export_config:
            output_file = os.path.join(output_dir, "wiz_cnapp_config_findings.json")
            if not exporter.export_config_findings(output_file):
                success = False

        if export_resources:
            output_file = os.path.join(output_dir, "wiz_cnapp_cloud_resources.json")
            if not exporter.export_cloud_resources(output_file):
                success = False

    if success:
        log_success("Export completed!")

        if not args.dry_run:
            print()
            log_info("To upload to Xygeni, run:")
            print()
            if export_vulns:
                print(f"  xygeni report-upload --report={output_dir}/wiz_cnapp_vulnerabilities.json --format sca-wiz-cnapp")
            if export_issues:
                print(f"  xygeni report-upload --report={output_dir}/wiz_cnapp_issues.json --format iac-wiz-issues")
            if export_config:
                print(f"  xygeni report-upload --report={output_dir}/wiz_cnapp_config_findings.json --format iac-wiz-config")
            if export_resources:
                print(f"  xygeni report-upload --report={output_dir}/wiz_cnapp_cloud_resources.json --format inventory-wiz-cnapp")
            print()

        return 0
    else:
        log_error("Export completed with errors")
        return 1


if __name__ == "__main__":
    sys.exit(main())