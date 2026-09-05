# Wiz CNAPP Exporter for Xygeni

This script exports Wiz CNAPP findings to JSON files compatible with Xygeni's report-upload feature.

## About

Wiz (wiz.io) is a CNAPP (Cloud-Native Application Protection Platform) that provides a GraphQL API to export findings.

The following Wiz CNAPP report formats can be ingested by `xygeni report-upload`:

| Export Type | Xygeni Format | Description |
|-------------|---------------|-------------|
| Vulnerabilities | `sca-wiz-cnapp` | Vulnerability findings (CVEs) |
| Issues | `iac-wiz-issues` | Issues (Toxic Combinations, Threats, Cloud Misconfigurations) |
| Config Findings | `iac-wiz-config` | Cloud Configuration Findings (CSPM) |
| Cloud Resources | `inventory-wiz-cnapp` | Cloud Resources inventory (VMs, containers, serverless, Kubernetes) |

## Prerequisites

- Python 3.7+
- Wiz Service Account with API access and appropriate permissions

## Quick Start

The script uses [PEP 723 inline script metadata](https://packaging.python.org/en/latest/specifications/inline-script-metadata/) to declare dependencies. You can run it with tools that support this standard:

### Option A: Using `uv` (Recommended)

```bash
# No manual dependency installation needed
uv run wiz_cnapp_exporter.py -c wiz.config --all
```

### Option B: Using `pipx`

```bash
pipx run wiz_cnapp_exporter.py -c wiz.config --all
```

### Option C: Traditional pip install

```bash
pip install requests
python wiz_cnapp_exporter.py -c wiz.config --all
```

### Configuration Steps

1. **Create configuration file:**
   ```bash
   cp wiz.config.example wiz.config
   ```

2. **Edit configuration with your credentials:**
   ```ini
   [credentials]
   client_id = your-service-account-client-id
   client_secret = your-service-account-client-secret
   region = us1
   ```

3. **Run the exporter:**
   ```bash
   python wiz_cnapp_exporter.py -c wiz.config --all
   ```

4. **Upload to Xygeni:**
   ```bash
   xygeni report-upload --report=output/wiz_cnapp_vulnerabilities.json --format sca-wiz-cnapp
   xygeni report-upload --report=output/wiz_cnapp_issues.json --format iac-wiz-issues
   xygeni report-upload --report=output/wiz_cnapp_config_findings.json --format iac-wiz-config
   xygeni report-upload --report=output/wiz_cnapp_cloud_resources.json --format inventory-wiz-cnapp
   ```

## Getting Wiz API Credentials

1. Log in to Wiz console
2. Navigate to **Settings > Service Accounts**
3. Create a new Service Account with required permissions:
   - `read:vulnerabilities` - for vulnerability findings
   - `read:issues` - for issues
   - `read:cloud_configuration` - for configuration findings
   - `read:resources` - for cloud resources inventory
4. Save the Client ID and Client Secret

See: [Wiz API Documentation](https://docs.wiz.io/wiz-docs/docs/using-the-wiz-api)

## Usage

```
usage: wiz_cnapp_exporter.py [-h] -c CONFIG [-o OUTPUT] [--vulnerabilities]
                             [--issues] [--config-findings] [--cloud-resources]
                             [--all] [--query FILE] [--dry-run] [-v]

Wiz CNAPP Exporter for Xygeni

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to configuration file (e.g., wiz.config)
  -o OUTPUT, --output OUTPUT
                        Output directory (default: ./output)
  --vulnerabilities     Export vulnerability findings
  --issues              Export issues (toxic combinations, threats, misconfigurations)
  --config-findings     Export cloud configuration findings
  --cloud-resources     Export cloud resources inventory
  --all                 Export all finding types (default if no type specified)
  --query FILE          Export using a custom GraphQL query file
  --dry-run             Show what would be done without executing
  -v, --verbose         Enable verbose output

Examples:
  # Export all findings
  wiz_cnapp_exporter.py -c wiz.config --all

  # Export only vulnerabilities
  wiz_cnapp_exporter.py -c wiz.config --vulnerabilities

  # Export only issues to custom directory
  wiz_cnapp_exporter.py -c wiz.config --issues -o ./exports

  # Export with custom query
  wiz_cnapp_exporter.py -c wiz.config --query queries/custom.graphql

  # Dry run (show what would be done)
  wiz_cnapp_exporter.py -c wiz.config --all --dry-run
```

## Configuration

Copy `wiz.config.example` to `wiz.config` and edit:

```ini
[credentials]
client_id = your-service-account-client-id
client_secret = your-service-account-client-secret
region = us1
auth_flavour = cognito

[output]
output_dir = ./output

[vulnerabilities]
first = 500
status = OPEN
severity = CRITICAL, HIGH

[issues]
first = 500
status = OPEN, IN_PROGRESS
types = TOXIC_COMBINATION, THREAT_DETECTION, CLOUD_CONFIGURATION

[config_findings]
first = 500
result = FAIL, ERROR
severity = CRITICAL, HIGH, MEDIUM

[cloud_resources]
first = 500
types = VIRTUAL_MACHINE, CONTAINER, SERVERLESS, KUBERNETES_CLUSTER

[advanced]
max_pages = 0
request_delay = 0.5
```

Lists accept either a plain comma-separated list (`A, B`) or a JSON array (`["A", "B"]`).
Enum values are validated before any request is made, and an invalid one is reported with the
key that produced it rather than surfacing later as an opaque GraphQL error.

### Auth backends

Wiz runs two auth backends and a tenant is on one or the other. If authentication is refused,
this is the first thing to check.

| `auth_flavour` | Token endpoint | Audience |
|---|---|---|
| `cognito` (default) | `auth.app.wiz.io` | `wiz-api` |
| `auth0` | `auth.wiz.io` | `beyond-api` |
| `cognito-gov` | `auth.gov.wiz.io` | `wiz-api` |
| `auth0-gov` | `auth0.gov.wiz.io` | `beyond-api` |

`token_url`, `audience` and `api_url` can each be overridden individually for self-hosted or
otherwise non-standard tenants.

### Incremental exports

A full export pulls everything matching the filters. For a daily delta, pass the newest timestamp
from the previous run:

```bash
python wiz_cnapp_exporter.py -c wiz.config --all --updated-after 2026-09-01T00:00:00Z
```

Each run prints the newest `updatedAt` it saw, to use as the next run's value. Vulnerabilities
also accept `--detected-after`, which filters on `lastDetectedAt` — a separate axis, so setting
both narrows to their overlap.

### Environment Variables

Credentials can also be provided via environment variables:

```bash
export WIZ_CLIENT_ID="your-client-id"
export WIZ_CLIENT_SECRET="your-client-secret"
export WIZ_REGION="us1"
```

With those two credentials set, no config file is needed at all — `-c` is optional and the
defaults above apply. `WIZ_AUTH_FLAVOUR`, `WIZ_TOKEN_URL`, `WIZ_AUDIENCE` and `WIZ_API_URL`
override the corresponding settings.

### Wiz Regions

| Region | API URL |
|--------|---------|
| `us1` | api.us1.app.wiz.io |
| `us2` | api.us2.app.wiz.io |
| `eu1` | api.eu1.app.wiz.io |
| `eu2` | api.eu2.app.wiz.io |
| `ap1` | api.ap1.app.wiz.io |
| `ap2` | api.ap2.app.wiz.io |

The region appears in your **API endpoint host**, `api.<region>.app.wiz.io`, which you can read
off the service account's API endpoint URL in the Wiz console. It is not part of the portal URL.
The value is validated by shape rather than against a fixed list, so regions Wiz adds later work
without a script change.

## Directory Structure

```
wiz.io/
├── README.md                           # This documentation
├── wiz_cnapp_exporter.py               # Main Python export script
├── wiz.config.example                  # Example configuration (INI format)
├── queries/
│   ├── vulnerability_findings.graphql  # Vulnerability findings query
│   ├── issues.graphql                   # Issues V2 query
│   ├── configuration_findings.graphql  # Cloud configuration findings query
│   └── cloud_resources.graphql         # Cloud resources inventory query
├── templates/
│   └── custom_query.graphql.template   # Template for custom queries
└── output/                             # Default output directory
```

## Output Files

| File | Description | Xygeni Format |
|------|-------------|---------------|
| `wiz_cnapp_vulnerabilities.json` | Vulnerability findings | `sca-wiz-cnapp` |
| `wiz_cnapp_issues.json` | Issues (toxic combos, threats) | `iac-wiz-issues` |
| `wiz_cnapp_config_findings.json` | Cloud config findings | `iac-wiz-config` |
| `wiz_cnapp_cloud_resources.json` | Cloud resources inventory | `inventory-wiz-cnapp` |

## Adding Custom Queries

1. Copy an existing query or the template:
   ```bash
   cp templates/custom_query.graphql.template queries/my_custom.graphql
   ```

2. Modify the GraphQL query as needed (use Wiz API Console to explore fields)

3. Run with custom query:
   ```bash
   python wiz_cnapp_exporter.py -c wiz.config --query queries/my_custom.graphql
   ```

   The exporter supplies `$first` and `$after` itself, and `$filterBy` from the `[custom]`
   section, but only for variables the query actually declares. A required variable (`$x: T!`)
   with no value is refused rather than sent empty.

   The field holding the results is guessed from the query. If the guess is wrong — or the query
   begins with a fragment definition — name it explicitly:
   ```bash
   python wiz_cnapp_exporter.py -c wiz.config --query queries/my_custom.graphql --data-path issuesV2
   ```

4. If needed, create a custom converter in Xygeni for the new data structure

## Reliability

- Transient failures (429 and 5xx) are retried with exponential backoff, honouring `Retry-After`.
- An access token that expires mid-export triggers one re-authentication and the run continues.
- Pages are appended to a `.part` file as they arrive. A run that fails on page 40 of 50 leaves
  those 40 pages on disk (as NDJSON) instead of discarding them, and says where.

## Known limitations

- **Cloud resources is not validated end to end.** Unlike the other three exports, no response
  from a live tenant has been seen for it, and no public Wiz integration queries v1
  `cloudResources` successfully. The query targets `cloudResourcesV2` and reads per-resource
  attributes from `graphEntity.properties`, which is where four independent integrations agree
  they live — but confirm by introspection before relying on it.
- `THREAT_DETECTION` issues require a Wiz Defend licence. Without one that type simply returns
  nothing rather than erroring.

## Rate Limits

Wiz GraphQL API has the following rate limits:
- Maximum 3 API requests per second
- Maximum 500-5000 results per query (depending on endpoint)

The script handles pagination automatically and respects rate limits via the `request_delay` configuration.

## Troubleshooting

### Authentication Failed

- Verify Client ID and Client Secret are correct
- Check that the Service Account has not been disabled
- Ensure the region matches your Wiz tenant

### No Data Exported

- Check filter settings (status, severity, types)
- Verify the Service Account has the required permissions
- Use `--verbose` flag to see API responses

### Rate Limiting

- Increase `request_delay` in configuration
- Reduce `first` to fetch smaller pages

## Security Notes

- Keep `wiz.config` secure and never commit it to version control
- The config file is excluded via `.gitignore`
- Consider using environment variables for CI/CD pipelines
- Use least-privilege Service Accounts with only read permissions