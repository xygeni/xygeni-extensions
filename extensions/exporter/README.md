# Xygeni Exporters

Export scripts for extracting security and inventory data from third-party platforms, generating reports compatible with Xygeni's `report-upload` command.

## Available Exporters

| Exporter | Description | Format(s) |
|----------|-------------|-----------|
| [kiuwan](kiuwan/README.md) | Kiuwan SAST platform | `sast-kiuwan` |
| [kubinv](kubinv/README.md) | Kubernetes Cluster Inventory | `inventory-xygeni` |
| [prisma.cloud](prisma.cloud/README.md) | Prisma Cloud CSPM/CNAPP platform | `iac-prisma-cloud`, `inventory-prisma-cloud` |
| [sonarqube](sonarqube/README.md) | SonarQube/SonarCloud SAST | `sast-sonarqube`, `sast-sonarcloud` |
| [wiz.io](wiz.io/README.md) | Wiz Cloud CNAPP platform | Multiple formats |

## Usage

Each exporter generates a JSON report that can be uploaded to Xygeni:

```bash
# 1. Run the exporter script to generate the report
python <exporter>/<script>.py [options] -o report.json

# 2. Upload the report to Xygeni
xygeni report-upload --report=report.json --format <format>
```

## Exporter Details

### Kiuwan (SAST)

Exports SAST findings from Kiuwan platform.

```bash
python kiuwan/kiuwan_exporter.py -o kiuwan_report.json
xygeni report-upload --report=kiuwan_report.json --format sast-kiuwan
```

### Kubernetes Inventory

Extracts workload inventory from a Kubernetes cluster (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Pods, Services, container images).

```bash
python kubinv/k8s_inventory_exporter.py -o k8s_inventory.json
xygeni report-upload --report=k8s_inventory.json --format inventory-xygeni
```

### Prisma Cloud (CSPM/CNAPP)

Exports IaC findings and cloud inventory from Prisma Cloud platform.

```bash
python prisma.cloud/prisma_cloud_exporter.py -o prisma_report.json
xygeni report-upload --report=prisma_report.json --format iac-prisma-cloud
```

### SonarQube/SonarCloud (SAST)

Exports SAST findings from SonarQube or SonarCloud.

```bash
python sonarqube/sonarqube_exporter.py -o sonar_report.json
xygeni report-upload --report=sonar_report.json --format sast-sonarqube
```

### Wiz (Cloud CNAPP)

Exports cloud security findings from Wiz platform.

```bash
python wiz.io/wiz_cnapp_exporter.py -o wiz_report.json
xygeni report-upload --report=wiz_report.json --format <appropriate-format>
```

## Requirements

- Python 3.8+
- Dependencies vary by exporter (see individual README files)

## See Also

- [Xygeni ASPM - Importing reports from 3rd party tools](https://docs.xygeni.io/xygeni-products/application-security-posture-management-aspm/importing-reports-from-3rd-party-tools)
- Individual exporter README files for detailed configuration options
