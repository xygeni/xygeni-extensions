#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
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
import random
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

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


class ConfigError(Exception):
    """A configuration value the user must fix, reported with the key that produced it."""


# Script directory (for finding query files)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Query file paths relative to script directory
QUERY_FILES = {
    'vulnerabilities': 'queries/vulnerability_findings.graphql',
    'issues': 'queries/issues.graphql',
    'config_findings': 'queries/configuration_findings.graphql',
    'cloud_resources': 'queries/cloud_resources.graphql',
}

# Root field of each query's response, i.e. where the nodes live under `data`.
DATA_PATHS = {
    'vulnerabilities': 'vulnerabilityFindings',
    'issues': 'issuesV2',
    'config_findings': 'configurationFindings',
    'cloud_resources': 'cloudResourcesV2',
}

# Wiz runs two auth backends and a tenant is on one or the other. Picking the wrong one fails at
# login with an unhelpful message, so the flavour is a first-class setting.
AUTH_FLAVOURS = {
    'cognito': ('https://auth.app.wiz.io/oauth/token', 'wiz-api'),
    'cognito-gov': ('https://auth.gov.wiz.io/oauth/token', 'wiz-api'),
    'auth0': ('https://auth.wiz.io/oauth/token', 'beyond-api'),
    'auth0-gov': ('https://auth0.gov.wiz.io/oauth/token', 'beyond-api'),
}
DEFAULT_AUTH_FLAVOUR = 'cognito'

# Enum members we have confirmed against the API. Anything outside these is rejected before the
# request, because Wiz's own error for a bad enum does not name the config key that produced it.
VALID_ENUMS = {
    'vuln_status': {'OPEN', 'RESOLVED', 'REJECTED', 'IN_PROGRESS'},
    'issues_status': {'OPEN', 'IN_PROGRESS', 'RESOLVED', 'REJECTED'},
    'issues_types': {'TOXIC_COMBINATION', 'THREAT_DETECTION', 'CLOUD_CONFIGURATION'},
    'severity': {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'NONE'},
}

# api.<region>.app.wiz.io — validate the shape, not a fixed list, since Wiz keeps adding regions.
REGION_PATTERN = re.compile(r'^[a-z]{2,4}\d+$')

# Retry policy for transient failures. Without it, one rate-limited page discards the whole run.
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 5
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 60.0

# Refresh the token this long before its stated expiry, to absorb clock skew and slow requests.
TOKEN_SKEW_SECONDS = 60


class WizExporter:
    """Exports data from Wiz CNAPP GraphQL API."""

    def __init__(self, config: Dict[str, Any], verbose: bool = False, dry_run: bool = False):
        self.config = config
        self.verbose = verbose
        self.dry_run = dry_run
        self.access_token: Optional[str] = None
        self.token_expires_at: float = 0.0
        self.session = requests.Session()

        self.api_url = config['api_url']
        self.token_url = config['token_url']
        self.audience = config['audience']

    # ------------------------------------------------------------------ auth

    def authenticate(self, force: bool = False) -> bool:
        """Fetch an access token, unless a valid one is already cached."""
        if not force and self.access_token and time.time() < self.token_expires_at:
            return True

        log_info("Authenticating with Wiz API...")

        if self.dry_run:
            log_info(f"[DRY-RUN] Would authenticate at {self.token_url} (audience: {self.audience})")
            self.access_token = "dry-run-token"
            self.token_expires_at = time.time() + 3600
            return True

        payload = {
            "client_id": self.config['client_id'],
            "client_secret": self.config['client_secret'],
            "grant_type": "client_credentials",
            "audience": self.audience,
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
                log_error(f"  Check the auth flavour: this run used '{self.config['auth_flavour']}' "
                          f"({self.token_url}, audience {self.audience}). "
                          f"Tenants on the other backend must set auth_flavour accordingly.")
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

            expires_in = int(data.get('expires_in', 3600))
            self.token_expires_at = time.time() + max(expires_in - TOKEN_SKEW_SECONDS, 0)

            log_success("Authentication successful")
            return True

        except requests.exceptions.RequestException as e:
            log_error(f"Authentication failed: {e}")
            return False

    # ------------------------------------------------------------- transport

    def _post_graphql(self, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        POST one GraphQL request, retrying transient failures and re-authenticating once on 401.

        Returns the decoded response, or None when the request could not be completed.
        """
        for attempt in range(1, MAX_ATTEMPTS + 1):
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
            except requests.exceptions.RequestException as e:
                if attempt >= MAX_ATTEMPTS:
                    log_error(f"GraphQL request failed after {attempt} attempts: {e}")
                    return None
                self._sleep_backoff(attempt, None, f"request error: {e}")
                continue

            if response.status_code == 200:
                return response.json()

            # An expired token mid-export is ordinary on a long run: re-auth once and carry on.
            if response.status_code == 401 and attempt < MAX_ATTEMPTS:
                log_warning("Access token rejected; re-authenticating")
                if not self.authenticate(force=True):
                    return None
                continue

            if response.status_code in RETRY_STATUSES and attempt < MAX_ATTEMPTS:
                self._sleep_backoff(attempt, response.headers.get("Retry-After"),
                                    f"HTTP {response.status_code}")
                continue

            log_error(f"GraphQL request failed: HTTP {response.status_code}")
            log_verbose(f"Response: {response.text}", self.verbose)
            return None

        return None

    def _sleep_backoff(self, attempt: int, retry_after: Optional[str], reason: str) -> None:
        """Exponential backoff with jitter, honouring Retry-After when the server sends one."""
        delay = None
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = None
        if delay is None:
            delay = min(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), BACKOFF_MAX_SECONDS)
            delay += random.uniform(0, delay * 0.1)

        log_warning(f"{reason}; retrying in {delay:.1f}s (attempt {attempt}/{MAX_ATTEMPTS})")
        time.sleep(delay)

    # --------------------------------------------------------------- queries

    @staticmethod
    def load_query(path: str) -> Optional[str]:
        """
        Load a GraphQL query, dropping whole-line comments.

        Lines are joined with a newline rather than a space: collapsing the query to one physical
        line lets any trailing inline comment swallow the rest of it. GraphQL is newline-tolerant,
        so the collapse bought nothing.
        """
        if not os.path.exists(path):
            log_error(f"Query file not found: {path}")
            return None

        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = [line for line in content.split('\n') if not line.strip().startswith('#')]
        return '\n'.join(lines)

    def _execute_query(self, query: str, variables: Dict[str, Any],
                       data_path: str, output_file: str) -> bool:
        """
        Execute a GraphQL query with pagination and save results.

        Pages are appended to a `.part` file as they arrive, so a run that dies on page 40 of 50
        leaves those 40 pages on disk instead of discarding them.
        """
        if not self.access_token:
            log_error("Not authenticated. Call authenticate() first.")
            return False

        log_verbose(f"Query variables: {json.dumps(variables, indent=2)}", self.verbose)

        if self.dry_run:
            log_info(f"[DRY-RUN] Would execute query and save to: {output_file}")
            return True

        max_pages = int(self.config.get('max_pages', 0))
        request_delay = float(self.config.get('request_delay', 0.5))

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        part_file = output_file + '.part'

        cursor = None
        page = 1
        total = 0
        latest_timestamp = None

        with open(part_file, 'w', encoding='utf-8') as partial:
            while True:
                current_vars = dict(variables)
                if cursor:
                    current_vars['after'] = cursor

                data = self._post_graphql({"query": query, "variables": current_vars})
                if data is None:
                    log_error(f"Export failed on page {page}; {total} item(s) kept in {part_file}")
                    return False

                if 'errors' in data and data['errors']:
                    error_msg = data['errors'][0].get('message', 'Unknown error')
                    log_error(f"GraphQL error: {error_msg}")
                    log_verbose(f"Full response: {json.dumps(data, indent=2)}", self.verbose)
                    return False

                result = data.get('data', {}).get(data_path) or {}
                nodes = result.get('nodes', [])
                page_info = result.get('pageInfo', {})

                for node in nodes:
                    partial.write(json.dumps(node) + '\n')
                    latest_timestamp = _later(latest_timestamp, node.get('updatedAt'))
                partial.flush()

                total += len(nodes)
                log_verbose(f"Page {page}: fetched {len(nodes)} items ({total} so far)", self.verbose)

                has_next_page = page_info.get('hasNextPage', False)
                cursor = page_info.get('endCursor')

                if not has_next_page or not cursor:
                    break

                if max_pages > 0 and page >= max_pages:
                    log_warning(f"Reached maximum page limit ({max_pages}); export is incomplete")
                    break

                time.sleep(request_delay)
                page += 1

        self._assemble(part_file, output_file, total)

        if latest_timestamp:
            log_info(f"Newest updatedAt in this export: {latest_timestamp} "
                     f"(pass as --updated-after for the next incremental pull)")

        log_success(f"Exported {total} items to: {output_file}")
        return True

    @staticmethod
    def _assemble(part_file: str, output_file: str, total: int) -> None:
        """Turn the streamed NDJSON into the {nodes, pageInfo} envelope report-upload expects."""
        with open(part_file, 'r', encoding='utf-8') as partial, \
             open(output_file, 'w', encoding='utf-8') as out:
            out.write('{\n  "nodes": [\n')
            for i, line in enumerate(partial):
                line = line.strip()
                if not line:
                    continue
                out.write('    ' + line + (',\n' if i < total - 1 else '\n'))
            out.write('  ],\n  "pageInfo": {"hasNextPage": false, "endCursor": null},\n')
            out.write(f'  "totalCount": {total}\n}}\n')
        os.remove(part_file)

    # --------------------------------------------------------------- exports

    def _filters_for(self, kind: str) -> Dict[str, Any]:
        """
        Build the `filterBy` object for one export.

        Wiz's filter grammar is mixed per field, not per API version: `status` takes a bare array
        while `updatedAt` takes an object, and the v2 cloud-resource filters take `{equals: [...]}`
        objects throughout. Each field is therefore shaped explicitly.
        """
        cfg = self.config
        filters: Dict[str, Any] = {}

        if kind == 'vulnerabilities':
            filters['status'] = cfg['vuln_status']
            filters['vendorSeverity'] = cfg['vuln_severity']
            # `lastDetectedAt` is a separate axis from `updatedAt` and the two AND together, so a
            # finding updated today but first detected months ago would drop out if both were set.
            # Only set it when the user asks for it explicitly.
            _add_after(filters, 'lastDetectedAt', cfg.get('detected_after'))

        elif kind == 'issues':
            filters['status'] = cfg['issues_status']
            filters['type'] = cfg['issues_types']

        elif kind == 'config_findings':
            filters['result'] = cfg['config_result']
            filters['severity'] = cfg['config_severity']
            filters['includeDeleted'] = False

        elif kind == 'cloud_resources':
            # v2 object grammar
            filters['type'] = {'equals': cfg['cloud_resources_types']}
            if cfg.get('cloud_resources_status'):
                filters['status'] = {'equals': cfg['cloud_resources_status']}

        if kind != 'cloud_resources':
            _add_after(filters, 'updatedAt', cfg.get('updated_after'))

        return filters

    def export(self, kind: str, output_file: str) -> bool:
        """Run one of the four built-in exports."""
        log_info(f"Exporting {kind.replace('_', ' ')}...")

        query = self.load_query(os.path.join(SCRIPT_DIR, QUERY_FILES[kind]))
        if not query:
            return False

        variables: Dict[str, Any] = {
            "first": int(self.config.get(f'{kind}_first', 500)),
            "filterBy": self._filters_for(kind),
        }
        if kind == 'issues':
            variables["orderBy"] = {"field": "CREATED_AT", "direction": "DESC"}

        return self._execute_query(query, variables, DATA_PATHS[kind], output_file)

    def export_custom_query(self, query_file: str, output_file: str,
                            data_path: Optional[str]) -> bool:
        """Export using a custom GraphQL query file."""
        log_info(f"Exporting with custom query: {query_file}")

        full_path = query_file
        if not os.path.isabs(query_file):
            candidate = os.path.join(SCRIPT_DIR, query_file)
            full_path = candidate if os.path.exists(candidate) else query_file

        query = self.load_query(full_path)
        if not query:
            return False

        if not data_path:
            data_path = _guess_data_path(query)
            if not data_path:
                log_error("Could not determine which field holds the results. "
                          "Pass --data-path <rootField> (the query's top-level field, or its alias).")
                return False
            log_warning(f"Using detected data path: {data_path} (override with --data-path)")

        # Supply only the variables the query actually declares, so a query taking $filterBy or
        # $after is not silently run unfiltered, and one taking neither is not sent junk.
        declared = _declared_variables(query)
        variables: Dict[str, Any] = {}
        if 'first' in declared:
            variables['first'] = int(self.config.get('custom_first', 500))
        if 'filterBy' in declared and self.config.get('custom_filter'):
            variables['filterBy'] = self.config['custom_filter']

        missing = [v for v, required in declared.items() if required and v not in variables]
        if missing:
            log_error(f"Custom query declares required variable(s) with no value: {', '.join(missing)}. "
                      f"Make them nullable, or provide them via [custom] in the config file.")
            return False

        return self._execute_query(query, variables, data_path, output_file)


# ------------------------------------------------------------------ helpers

def _later(current: Optional[str], candidate: Optional[str]) -> Optional[str]:
    """Highest ISO8601 timestamp seen; lexicographic order is correct for UTC ISO8601."""
    if not candidate:
        return current
    return candidate if current is None or candidate > current else current


def _add_after(filters: Dict[str, Any], key: str, timestamp: Optional[str]) -> None:
    if timestamp:
        filters[key] = {'after': timestamp}


def _strip_strings(query: str) -> str:
    """Blank out string literals so brace scanning is not confused by braces inside them."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', query)


def _declared_variables(query: str) -> Dict[str, bool]:
    """
    Map each variable the operation declares to whether it is required (non-null).

    Only the operation's own signature is read, so a fragment definition earlier in the file does
    not confuse it.
    """
    match = re.search(r'\b(?:query|mutation)\b[^({]*\(([^)]*)\)', _strip_strings(query), re.S)
    if not match:
        return {}
    return {
        name: type_.strip().endswith('!')
        for name, type_ in re.findall(r'\$(\w+)\s*:\s*([^,$)]+)', match.group(1))
    }


def _guess_data_path(query: str) -> Optional[str]:
    """
    Best-effort guess at the response key holding the results: the first field selected inside the
    operation's own selection set.

    Skips fragment definitions and any braces in variable defaults, both of which defeat a naive
    scan. Aliases are returned as written, which is correct — the response is keyed by the alias.
    """
    stripped = _strip_strings(query)

    # Start after the operation's signature, so `fragment F on T { id }` earlier in the file and a
    # variable default such as `$f: F = {a: 1}` are both stepped over.
    op = re.search(r'\b(?:query|mutation)\b[^({]*(?:\([^)]*\))?\s*\{', stripped)
    if not op:
        return None

    match = re.search(r'\s*(\w+)', stripped[op.end():])
    return match.group(1) if match else None


def _parse_list(value: Any, key: str) -> List[str]:
    """
    Parse a config list, accepting both a JSON array and the natural ini spelling.

    A bare `A, B` used to fall through to `["A, B"]` — one member, and not a valid enum — which
    surfaced later as a GraphQL error naming neither the key nor the value.
    """
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if value is None:
        return []

    text = str(value).strip()
    if not text:
        return []

    if text.startswith('['):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ConfigError(f"{key}: not valid JSON ({e.msg}). "
                              f"Use a JSON array like [\"A\", \"B\"] or a plain list like A, B")
        if not isinstance(parsed, list):
            raise ConfigError(f"{key}: expected a list, got {type(parsed).__name__}")
        return [str(v).strip() for v in parsed if str(v).strip()]

    return [part.strip() for part in text.split(',') if part.strip()]


def _validate_enum(values: List[str], key: str, allowed_key: str) -> List[str]:
    """Reject unknown enum members before the request, naming the config key that produced them."""
    allowed = VALID_ENUMS[allowed_key]
    unknown = [v for v in values if v.upper() not in allowed]
    if unknown:
        raise ConfigError(f"{key}: {', '.join(unknown)} is not accepted by the Wiz API. "
                          f"Valid values: {', '.join(sorted(allowed))}")
    return [v.upper() for v in values]


def resolve_endpoints(result: Dict[str, Any]) -> None:
    """Derive the API and token endpoints, honouring individual overrides."""
    region = str(result.get('region', 'us1')).lower()
    if not REGION_PATTERN.match(region):
        raise ConfigError(f"region: '{region}' does not look like a Wiz region (e.g. us1, eu2, ap23). "
                          f"It appears in the API host, api.<region>.app.wiz.io — not in the portal URL.")

    flavour = str(result.get('auth_flavour', DEFAULT_AUTH_FLAVOUR)).lower()
    if flavour not in AUTH_FLAVOURS:
        raise ConfigError(f"auth_flavour: '{flavour}' is unknown. "
                          f"Valid values: {', '.join(sorted(AUTH_FLAVOURS))}")

    default_token_url, default_audience = AUTH_FLAVOURS[flavour]
    result['auth_flavour'] = flavour
    result['token_url'] = result.get('token_url') or default_token_url
    result['audience'] = result.get('audience') or default_audience
    # A full override also covers self-hosted and FedRAMP tenants on other hosts.
    result['api_url'] = result.get('api_url') or f"https://api.{region}.app.wiz.io/graphql"


def load_config(config_file: Optional[str]) -> Dict[str, Any]:
    """Load configuration from file and/or environment."""
    config = configparser.ConfigParser()

    if config_file:
        if not os.path.exists(config_file):
            log_error(f"Configuration file not found: {config_file}")
            sys.exit(1)
        config.read(config_file)

    def get(section: str, option: str, default: Any = None) -> Any:
        return config[section].get(option, default) if section in config else default

    result: Dict[str, Any] = {
        'client_id': get('credentials', 'client_id', ''),
        'client_secret': get('credentials', 'client_secret', ''),
        'region': get('credentials', 'region', 'us1'),
        'auth_flavour': get('credentials', 'auth_flavour', DEFAULT_AUTH_FLAVOUR),
        'token_url': get('credentials', 'token_url'),
        'audience': get('credentials', 'audience'),
        'api_url': get('credentials', 'api_url'),
        'output_dir': get('output', 'output_dir', './output'),

        'vulnerabilities_first': get('vulnerabilities', 'first', '500'),
        'vuln_status': get('vulnerabilities', 'status', 'OPEN'),
        'vuln_severity': get('vulnerabilities', 'severity', 'CRITICAL, HIGH'),

        'issues_first': get('issues', 'first', '500'),
        'issues_status': get('issues', 'status', 'OPEN, IN_PROGRESS'),
        'issues_types': get('issues', 'types', 'TOXIC_COMBINATION, THREAT_DETECTION, CLOUD_CONFIGURATION'),

        'config_findings_first': get('config_findings', 'first', '500'),
        'config_result': get('config_findings', 'result', 'FAIL, ERROR'),
        'config_severity': get('config_findings', 'severity', 'CRITICAL, HIGH, MEDIUM'),

        'cloud_resources_first': get('cloud_resources', 'first', '500'),
        'cloud_resources_types': get('cloud_resources', 'types',
                                     'VIRTUAL_MACHINE, CONTAINER, SERVERLESS, KUBERNETES_CLUSTER'),
        'cloud_resources_status': get('cloud_resources', 'status', ''),

        'custom_first': get('custom', 'first', '500'),
        'custom_filter_raw': get('custom', 'filter'),

        'max_pages': get('advanced', 'max_pages', '0'),
        'request_delay': get('advanced', 'request_delay', '0.5'),
    }

    # Environment overrides, so the secret need never sit in a file.
    for env, key in (('WIZ_CLIENT_ID', 'client_id'), ('WIZ_CLIENT_SECRET', 'client_secret'),
                     ('WIZ_REGION', 'region'), ('WIZ_AUTH_FLAVOUR', 'auth_flavour'),
                     ('WIZ_TOKEN_URL', 'token_url'), ('WIZ_AUDIENCE', 'audience'),
                     ('WIZ_API_URL', 'api_url')):
        if os.environ.get(env):
            result[key] = os.environ[env]

    if not result.get('client_id'):
        log_error("client_id is required in the config file or the WIZ_CLIENT_ID env var")
        sys.exit(1)
    if not result.get('client_secret'):
        log_error("client_secret is required in the config file or the WIZ_CLIENT_SECRET env var")
        sys.exit(1)

    try:
        resolve_endpoints(result)

        result['vuln_status'] = _validate_enum(_parse_list(result['vuln_status'], 'vulnerabilities.status'),
                                               'vulnerabilities.status', 'vuln_status')
        result['vuln_severity'] = _validate_enum(_parse_list(result['vuln_severity'], 'vulnerabilities.severity'),
                                                 'vulnerabilities.severity', 'severity')
        result['issues_status'] = _validate_enum(_parse_list(result['issues_status'], 'issues.status'),
                                                 'issues.status', 'issues_status')
        result['issues_types'] = _validate_enum(_parse_list(result['issues_types'], 'issues.types'),
                                                'issues.types', 'issues_types')
        result['config_result'] = _parse_list(result['config_result'], 'config_findings.result')
        result['config_severity'] = _validate_enum(_parse_list(result['config_severity'], 'config_findings.severity'),
                                                   'config_findings.severity', 'severity')
        result['cloud_resources_types'] = _parse_list(result['cloud_resources_types'], 'cloud_resources.types')
        result['cloud_resources_status'] = _parse_list(result['cloud_resources_status'], 'cloud_resources.status')

        if result.get('custom_filter_raw'):
            try:
                result['custom_filter'] = json.loads(result['custom_filter_raw'])
            except json.JSONDecodeError as e:
                raise ConfigError(f"custom.filter: not valid JSON ({e.msg}). "
                                  f"It is passed straight through as the query's $filterBy value.")
    except ConfigError as e:
        log_error(f"Invalid configuration — {e}")
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

  # Credentials from the environment, no config file
  WIZ_CLIENT_ID=... WIZ_CLIENT_SECRET=... WIZ_REGION=eu1 %(prog)s --all

  # Incremental pull: only what changed since the last export
  %(prog)s -c wiz.config --all --updated-after 2026-09-01T00:00:00Z

  # Export with a custom query
  %(prog)s -c wiz.config --query queries/custom.graphql --data-path issuesV2

  # Dry run (validates configuration without calling the API)
  %(prog)s -c wiz.config --all --dry-run
"""
    )

    parser.add_argument('-c', '--config',
                        help='Path to configuration file (e.g., wiz.config). '
                             'Optional when credentials come from the environment.')
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
    parser.add_argument('--updated-after', metavar='ISO8601',
                        help='Only export findings updated after this time, for incremental pulls. '
                             'Each run reports the newest timestamp it saw, to use as the next value.')
    parser.add_argument('--detected-after', metavar='ISO8601',
                        help='Vulnerabilities only: filter on lastDetectedAt instead of update time. '
                             'A separate axis from --updated-after; setting both narrows to their overlap.')
    parser.add_argument('--query', metavar='FILE',
                        help='Export using a custom GraphQL query file')
    parser.add_argument('--data-path', metavar='FIELD',
                        help='Response field holding the results of --query (default: guessed)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without executing')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

    return parser.parse_args()


EXPORTS: List[Tuple[str, str, str]] = [
    ('vulnerabilities', 'wiz_cnapp_vulnerabilities.json', 'sca-wiz-cnapp'),
    ('issues', 'wiz_cnapp_issues.json', 'iac-wiz-issues'),
    ('config_findings', 'wiz_cnapp_config_findings.json', 'iac-wiz-config'),
    ('cloud_resources', 'wiz_cnapp_cloud_resources.json', 'inventory-wiz-cnapp'),
]


def main() -> int:
    """Main entry point."""
    args = parse_args()

    config = load_config(args.config)
    if args.output:
        config['output_dir'] = args.output
    if args.updated_after:
        config['updated_after'] = args.updated_after
    if args.detected_after:
        config['detected_after'] = args.detected_after

    output_dir = config.get('output_dir', './output')

    selected = {
        'vulnerabilities': args.vulnerabilities,
        'issues': args.issues,
        'config_findings': args.config_findings,
        'cloud_resources': args.cloud_resources,
    }
    if args.all or (not any(selected.values()) and not args.query):
        selected = {kind: True for kind in selected}

    exporter = WizExporter(config, verbose=args.verbose, dry_run=args.dry_run)

    if not exporter.authenticate():
        return 1

    if not args.dry_run:
        os.makedirs(output_dir, exist_ok=True)

    succeeded: List[Tuple[str, str]] = []
    failed: List[str] = []

    if args.query:
        basename = os.path.splitext(os.path.basename(args.query))[0]
        output_file = os.path.join(output_dir, f"wiz_{basename}.json")
        if exporter.export_custom_query(args.query, output_file, args.data_path):
            succeeded.append((output_file, ''))
        else:
            failed.append(args.query)
    else:
        for kind, filename, report_format in EXPORTS:
            if not selected[kind]:
                continue
            output_file = os.path.join(output_dir, filename)
            if exporter.export(kind, output_file):
                succeeded.append((output_file, report_format))
            else:
                failed.append(kind)

    if failed:
        log_error(f"Export completed with errors: {', '.join(failed)}")

    if succeeded and not args.dry_run:
        print()
        log_info("To upload to Xygeni, run:")
        print()
        for output_file, report_format in succeeded:
            if report_format:
                print(f"  xygeni report-upload --report={output_file} --format {report_format}")
            else:
                print(f"  xygeni report-upload --report={output_file} --format <format>")
        print()

    if failed:
        return 1

    log_success("Export completed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
