# Prisma Cloud CSPM Exporter for Xygeni

This script exports security alerts and cloud asset inventory from Prisma Cloud CSPM (Cloud Security Posture Management) to JSON files compatible with Xygeni's report-upload feature.

## Prerequisites

- Python 3.7+
- Prisma Cloud account with API access
- Access Key and Secret Key from Prisma Cloud console

## Quick Start

The script uses [PEP 723 inline script metadata](https://packaging.python.org/en/latest/specifications/inline-script-metadata/) to declare dependencies. You can run it with tools that support this standard:

### Option A: Using `uv` (Recommended)

```bash
# No manual dependency installation needed
uv run prisma_cloud_exporter.py -c prisma.cloud.config --all
```

### Option B: Using `pipx`

```bash
pipx run prisma_cloud_exporter.py -c prisma.cloud.config --all
```

### Option C: Traditional pip install

```bash
pip install requests
python prisma_cloud_exporter.py -c prisma.cloud.config --all
```

### Configuration Steps

1. **Create configuration file:**
   ```bash
   cp prisma.cloud.config.example prisma.cloud.config
   ```

2. **Edit configuration with your credentials:**
   ```bash
   # Edit prisma.cloud.config with your Access Key and Secret Key
   ```

3. **Run the exporter:**
   ```bash
   python prisma_cloud_exporter.py -c prisma.cloud.config --all
   ```

4. **Upload to Xygeni:**
   ```bash
   xygeni report-upload --report=./output/prisma_cloud_alerts.json --format iac-prisma-cloud
   xygeni report-upload --report=./output/prisma_cloud_assets.json --format inventory-prisma-cloud
   ```

## Getting Prisma Cloud API Credentials

1. Log in to Prisma Cloud console
2. Navigate to **Settings > Access Control > Access Keys**
3. Click **Add > Access Key**
4. Save the Access Key ID and Secret Key (shown only once)

See: [Prisma Cloud Access Keys Documentation](https://docs.prismacloud.io/en/enterprise-edition/content-collections/administration/create-access-keys)

## Usage

```
usage: prisma_cloud_exporter.py [-h] -c CONFIG [-o OUTPUT] [--alerts] [--assets] [--all] [--dry-run] [-v]

Prisma Cloud CSPM Exporter for Xygeni

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to configuration file (e.g., prisma.cloud.config)
  -o OUTPUT, --output OUTPUT
                        Output directory (default: ./output)
  --alerts              Export security alerts
  --assets              Export cloud asset inventory
  --all                 Export all data types (default if no type specified)
  --dry-run             Show what would be done without executing
  -v, --verbose         Enable verbose output

Examples:
  # Export all findings
  prisma_cloud_exporter.py -c prisma.cloud.config --all

  # Export only alerts to custom directory
  prisma_cloud_exporter.py -c prisma.cloud.config --alerts -o ./exports

  # Export only assets
  prisma_cloud_exporter.py -c prisma.cloud.config --assets

  # Dry run (show what would be done)
  prisma_cloud_exporter.py -c prisma.cloud.config --all --dry-run
```

## Configuration

Copy `prisma.cloud.config.example` to `prisma.cloud.config` and edit:

```ini
[credentials]
access_key = your-access-key-id
secret_key = your-secret-key
region = us

[output]
output_dir = ./output

[alerts]
time_range_days = 30
status = open
severity =
cloud_types =
limit = 10000

[assets]
time_range_days = 1
cloud_types =
resource_types =
limit = 10000

[advanced]
request_delay = 0.5
```

### Environment Variables

Credentials can also be provided via environment variables:

```bash
export PRISMA_CLOUD_ACCESS_KEY="your-access-key"
export PRISMA_CLOUD_SECRET_KEY="your-secret-key"
export PRISMA_CLOUD_REGION="us"
```

### Prisma Cloud Regions

| Region Code | API URL | Description |
|-------------|---------|-------------|
| `us` | api.prismacloud.io | United States |
| `us-2` | api2.prismacloud.io | United States (Region 2) |
| `us-3` | api3.prismacloud.io | United States (Region 3) |
| `eu` | api.eu.prismacloud.io | Europe |
| `eu-2` | api2.eu.prismacloud.io | Europe (Region 2) |
| `ca` | api.ca.prismacloud.io | Canada |
| `sg` | api.sg.prismacloud.io | Singapore |
| `anz` | api.anz.prismacloud.io | Australia/New Zealand |
| `ind` | api.ind.prismacloud.io | India |
| `jp` | api.jp.prismacloud.io | Japan |
| `uk` | api.uk.prismacloud.io | United Kingdom |
| `fr` | api.fr.prismacloud.io | France |
| `de` | api.de.prismacloud.io | Germany |

Check your Prisma Cloud portal URL to determine your region (e.g., `app.eu.prismacloud.io` → `eu`).

## Output Files

| File | Description | Xygeni Format |
|------|-------------|---------------|
| `prisma_cloud_alerts.json` | Security alerts (policy violations) | `iac-prisma-cloud` |
| `prisma_cloud_assets.json` | Cloud asset inventory | `inventory-prisma-cloud` |

## Xygeni Report Upload

After exporting, upload the reports to Xygeni:

```bash
# Upload security alerts
xygeni report-upload \
  --report=./output/prisma_cloud_alerts.json \
  --format iac-prisma-cloud \
  --project "my-project"

# Upload cloud asset inventory
xygeni report-upload \
  --report=./output/prisma_cloud_assets.json \
  --format inventory-prisma-cloud \
  --project "my-project"
```

## Filtering Options

### Alerts

- **status**: `open`, `dismissed`, `resolved`, `snoozed`
- **severity**: `critical`, `high`, `medium`, `low`, `informational`
- **cloud_types**: `aws`, `azure`, `gcp`, `alibaba_cloud`, `oci`

### Assets

- **cloud_types**: `aws`, `azure`, `gcp`, `alibaba_cloud`, `oci`
- **resource_types**: e.g., `aws_ec2_instance`, `azure_vm`, `gcp_compute_instance`

## API Documentation

- [Prisma Cloud API Overview](https://pan.dev/prisma-cloud/api/cspm/)
- [Login API](https://pan.dev/prisma-cloud/api/cspm/app-login/)
- [Alerts API v2](https://pan.dev/prisma-cloud/api/cspm/get-alerts-v-2/)
- [Resource API](https://pan.dev/prisma-cloud/api/cspm/get-resource/)

## Security Notes

- Keep `prisma.cloud.config` secure and never commit it to version control
- The config file is excluded via `.gitignore`
- Consider using environment variables for CI/CD pipelines
- Use least-privilege access keys with only read permissions

## Troubleshooting

### Authentication Failed

- Verify Access Key and Secret Key are correct
- Check that the region matches your Prisma Cloud tenant
- Ensure the Access Key has not expired

### No Data Exported

- Check filter settings (status, severity, cloud_types)
- Verify the time range includes data
- Use `--verbose` flag to see API responses

### Rate Limiting

- Increase `request_delay` in configuration
- Reduce `limit` to fetch smaller batches