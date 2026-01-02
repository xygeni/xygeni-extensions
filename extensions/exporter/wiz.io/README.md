# Report exporter for Wiz

## About

Wiz (wiz.io) is a CNAPP platform.

Wiz CNAPP provides a GraphQL API to export findings. The Wiz CNAPP report formats that can be ingested by `xygeni report-load` are:

- `sca-wiz-cnapp`: Vulnerability findings.
- `iac-wiz-issues`: Issues (Toxic Combinations, Threats, Cloud Misconfigurations)
- `iac-wiz-config`: Cloud Configuration Findings (CSPM)
- `inventory-wiz-cnapp`: Cloud Resources inventory (VMs, containers, serverless, Kubernetes)

To produce the expected reports for ingestion, specific GraphQL queries could be used. This module provides such queries, and a bash script that can be used to generate the reports to upload to Xygeni.

## Prerequisites

- **Wiz Service Account** with API access and appropriate permissions
- **curl** - for API requests
- **jq** - for JSON processing

## Quick Start

1. Copy the example configuration:
   ```bash
   cp wiz.config.example wiz.config
   ```

2. Edit `wiz.config` with your Wiz credentials:
   ```bash
   WIZ_CLIENT_ID="your-service-account-client-id"
   WIZ_CLIENT_SECRET="your-service-account-client-secret"
   WIZ_REGION="us1"
   ```

3. Run the exporter:
   ```bash
   ./wiz_cnapp_exporter.sh -c wiz.config --all
   ```

4. Upload to Xygeni:
   ```bash
   xygeni report-upload --report=output/wiz_cnapp_vulnerabilities.json --format sca-wiz-cnapp
   xygeni report-upload --report=output/wiz_cnapp_issues.json --format iac-wiz-issues
   xygeni report-upload --report=output/wiz_cnapp_config_findings.json --format iac-wiz-config
   xygeni report-upload --report=output/wiz_cnapp_cloud_resources.json --format inventory-wiz-cnapp
   ```

## Usage

```
Usage: wiz_cnapp_exporter.sh -c <config_file> [options]

Required:
  -c, --config FILE          Path to configuration file

Export Options:
  --vulnerabilities          Export vulnerability findings
  --issues                   Export issues (toxic combinations, threats, misconfigurations)
  --config-findings          Export cloud configuration findings
  --cloud-resources          Export cloud resources inventory (VMs, containers, serverless)
  --all                      Export all finding types (default)
  --query FILE               Export using a custom GraphQL query file

Output Options:
  -o, --output DIR           Output directory (default: ./output)

Other Options:
  --dry-run                  Show what would be done without executing
  -v, --verbose              Enable verbose output
  -h, --help                 Show this help message
```

## Directory Structure

```
wiz.io/
├── README.md                           # This documentation
├── wiz_cnapp_exporter.sh              # Main export script
├── wiz.config.example                  # Example configuration
├── queries/
│   ├── vulnerability_findings.graphql  # Vulnerability findings query
│   ├── issues.graphql                   # Issues V2 query
│   ├── configuration_findings.graphql  # Cloud configuration findings query
│   └── cloud_resources.graphql         # Cloud resources inventory query
└── templates/
    └── custom_query.graphql.template   # Template for custom queries
```

## Adding Custom Queries

1. Copy the template:
   ```bash
   cp templates/custom_query.graphql.template queries/my_custom.graphql
   ```

2. Modify the GraphQL query as needed (use Wiz API Console to explore fields)

3. Run with custom query:
   ```bash
   ./wiz_cnapp_exporter.sh -c wiz.config --query queries/my_custom.graphql
   ```

4. If needed, create a custom converter in Xygeni for the new data structure

## Limitations

Wiz GraphQL API Rate Limits:

- Maximum 3 API requests per second
- Maximum 500-5000 results per query (depending on endpoint)
- Use pagination (after cursor) for larger datasets
