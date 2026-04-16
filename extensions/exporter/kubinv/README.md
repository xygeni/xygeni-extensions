# Kubernetes Inventory Exporter for Xygeni

Exports Kubernetes cluster workload inventory to a JSON file compatible with Xygeni's `InventoryReport` format for ASPM (Application Security Posture Management) correlation.

## Features

- **Workload Extraction**: Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, ReplicaSets, Pods
- **Container Image Tracking**: Extracts all container images used by workloads with full image metadata
- **Hierarchical Relationships**: Maintains proper hierarchy (Deployment -> ReplicaSet -> Pod)
- **Service Discovery**: Extracts Services with ports, selectors, and load balancer info
- **Security Context**: Captures pod and container security settings
- **RBAC Support**: Optional extraction of Roles, RoleBindings, and ServiceAccounts
- **Network Policies**: Optional extraction of NetworkPolicy resources
- **Multiple Authentication Methods**: kubeconfig, in-cluster, token-based

## Requirements

- Python 3.8+
- `kubernetes` Python library (>=28.0.0)
- Access to a Kubernetes cluster with appropriate permissions

## Installation

```bash
# Install dependencies
pip install kubernetes>=28.0.0 pyyaml>=6.0

# Or using uv (recommended)
uv pip install kubernetes>=28.0.0 pyyaml>=6.0
```

## Usage

### Basic Usage

```bash
# Export inventory using default kubeconfig (~/.kube/config)
python k8s_inventory_exporter.py -o k8s_inventory.json

# Export from a specific Kubernetes context
python k8s_inventory_exporter.py --context=production -o prod_inventory.json

# Export specific namespaces only
python k8s_inventory_exporter.py -n default,kube-system,my-app -o inventory.json

# Export using a specific kubeconfig file
python k8s_inventory_exporter.py --kubeconfig=/path/to/kubeconfig -o inventory.json
```

### Advanced Usage

```bash
# Include RBAC resources (Roles, RoleBindings)
python k8s_inventory_exporter.py --include-rbac -o inventory.json

# Include NetworkPolicy resources
python k8s_inventory_exporter.py --include-network-policies -o inventory.json

# Full extraction with all optional resources
python k8s_inventory_exporter.py \
  --include-rbac \
  --include-network-policies \
  --project-name "my-project" \
  -o full_inventory.json

# Exclude security context (for smaller output)
python k8s_inventory_exporter.py --exclude-security-context -o inventory.json

# Dry run (show what would be done)
python k8s_inventory_exporter.py --dry-run -o inventory.json

# Verbose output for debugging
python k8s_inventory_exporter.py -v -o inventory.json
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-o, --output FILE` | Output JSON file path (default: ./k8s_inventory.json) |
| `--kubeconfig FILE` | Path to kubeconfig file (default: ~/.kube/config) |
| `--context NAME` | Kubernetes context to use |
| `-n, --namespaces NS1,NS2` | Comma-separated list of namespaces (default: all) |
| `--project-name NAME` | Project name for the report (default: cluster name) |
| `--include-rbac` | Include RBAC resources (Roles, RoleBindings) |
| `--include-network-policies` | Include NetworkPolicy resources |
| `--exclude-security-context` | Exclude security context from pods/containers |
| `--dry-run` | Show what would be done without executing |
| `-v, --verbose` | Enable verbose output |

## Authentication Methods

### 1. Default kubeconfig

The exporter uses the default kubeconfig at `~/.kube/config`:

```bash
python k8s_inventory_exporter.py -o inventory.json
```

### 2. Custom kubeconfig File

```bash
python k8s_inventory_exporter.py --kubeconfig=/path/to/kubeconfig -o inventory.json
```

### 3. Specific Context

```bash
python k8s_inventory_exporter.py --context=my-context -o inventory.json
```

### 4. In-Cluster Configuration

When running inside a Kubernetes pod (e.g., as a Job or CronJob), the exporter automatically uses the in-cluster service account:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: k8s-inventory-export
spec:
  template:
    spec:
      serviceAccountName: inventory-exporter
      containers:
      - name: exporter
        image: python:3.11-slim
        command: ["python", "/scripts/k8s_inventory_exporter.py", "-o", "/output/inventory.json"]
        volumeMounts:
        - name: scripts
          mountPath: /scripts
        - name: output
          mountPath: /output
      restartPolicy: Never
      volumes:
      - name: scripts
        configMap:
          name: inventory-exporter-scripts
      - name: output
        emptyDir: {}
```

### 5. Cloud Provider Authentication

**AWS EKS:**
```bash
# Update kubeconfig for EKS cluster
aws eks update-kubeconfig --name my-cluster --region us-west-2

# Run exporter
python k8s_inventory_exporter.py -o eks_inventory.json
```

**Google GKE:**
```bash
# Get credentials for GKE cluster
gcloud container clusters get-credentials my-cluster --zone us-central1-a

# Run exporter
python k8s_inventory_exporter.py -o gke_inventory.json
```

**Azure AKS:**
```bash
# Get credentials for AKS cluster
az aks get-credentials --resource-group my-rg --name my-cluster

# Run exporter
python k8s_inventory_exporter.py -o aks_inventory.json
```

## Required Permissions

The service account or user needs the following RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: inventory-exporter
rules:
# Core resources
- apiGroups: [""]
  resources: ["namespaces", "pods", "services", "serviceaccounts"]
  verbs: ["get", "list"]
# Workloads
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
  verbs: ["get", "list"]
# Batch jobs
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list"]
# Optional: RBAC (if --include-rbac)
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list"]
# Optional: Network policies (if --include-network-policies)
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list"]
```

## Output Format

The exporter generates a JSON file following Xygeni's `InventoryReport` format:

```json
{
  "metadata": {
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-01-15T10:30:00Z",
    "projectName": "my-cluster",
    "sourceType": "REPO",
    "scanType": "inventory",
    "format": "inventory.1"
  },
  "statistics": {
    "assets": 42,
    "assetsByKind": {
      "cloud_resource": 35,
      "container_image": 7
    },
    "links": 50,
    "linksByKind": {
      "belongs_to": 40,
      "uses": 10
    }
  },
  "errors": [],
  "assets": [
    {
      "kind": "cloud_resource",
      "id": "cloud_resource:kubernetes:my-cluster:default:deployment:nginx",
      "name": "nginx",
      "type": "kubernetes_deployment",
      "properties": {
        "namespace": "default",
        "replicas": 3
      }
    },
    {
      "kind": "container_image",
      "id": "container_image:docker.io:library:nginx:1.25",
      "name": "nginx:1.25",
      "image": {
        "registry": "docker.io",
        "repository": "nginx",
        "tag": "1.25"
      }
    }
  ],
  "graph": {
    "links": [
      {
        "from": "cloud_resource:kubernetes:my-cluster:default:deployment:nginx",
        "to": "container_image:docker.io:library:nginx:1.25",
        "type": "uses"
      }
    ]
  }
}
```

## Asset Types

| Kubernetes Resource | Asset Kind | Asset Type |
|---------------------|------------|------------|
| Cluster | `cloud_resource` | `kubernetes_cluster` |
| Namespace | `cloud_resource` | `kubernetes_namespace` |
| Deployment | `cloud_resource` | `kubernetes_deployment` |
| StatefulSet | `cloud_resource` | `kubernetes_statefulset` |
| DaemonSet | `cloud_resource` | `kubernetes_daemonset` |
| Job | `cloud_resource` | `kubernetes_job` |
| CronJob | `cloud_resource` | `kubernetes_cronjob` |
| ReplicaSet | `cloud_resource` | `kubernetes_replicaset` |
| Pod | `cloud_resource` | `kubernetes_pod` |
| Service | `cloud_resource` | `kubernetes_service` |
| NetworkPolicy | `cloud_resource` | `kubernetes_networkpolicy` |
| Container Image | `container_image` | - |
| ServiceAccount | `user` | `serviceaccount` |
| Role | `group` | `role` |

## Link Types

| Relationship | Link Type | Description |
|--------------|-----------|-------------|
| Namespace -> Cluster | `belongs_to` | Namespace belongs to cluster |
| Workload -> Namespace | `belongs_to` | Workload belongs to namespace |
| Pod -> ReplicaSet | `belongs_to` | Pod belongs to ReplicaSet |
| ReplicaSet -> Deployment | `belongs_to` | ReplicaSet belongs to Deployment |
| Workload -> Container Image | `uses` | Workload uses container image |
| ServiceAccount -> Namespace | `member_of` | ServiceAccount is member of namespace |
| ServiceAccount -> Role | `member_of` | ServiceAccount is member of role |

## Uploading to Xygeni

After generating the inventory report:

```bash
# Upload to Xygeni platform
xygeni report-upload --report=k8s_inventory.json --format inventory-xygeni
```

## Use Cases

### ASPM Correlation

The extracted inventory enables:

1. **Container Image Traceability**: Track where container images are deployed across clusters
2. **Vulnerability Correlation**: Link CVEs in container images to running workloads
3. **Secrets Exposure Analysis**: Identify if secrets found in source code are exposed in running pods
4. **Reachability Analysis**: Determine if vulnerable code is exposed to the internet via services

### Security Auditing

- Review pod security contexts across namespaces
- Audit RBAC configurations
- Analyze network segmentation via NetworkPolicies
- Track service account usage

### Compliance

- Generate inventory reports for compliance audits
- Track workload configurations over time
- Document container image provenance

## Troubleshooting

### Connection Issues

```bash
# Test kubectl connectivity first
kubectl cluster-info

# Check current context
kubectl config current-context

# List available contexts
kubectl config get-contexts
```

### Permission Errors

```bash
# Check if you can list pods
kubectl auth can-i list pods --all-namespaces

# Check RBAC permissions
kubectl auth can-i --list
```

### Certificate Errors

```bash
# Skip TLS verification (not recommended for production)
kubectl config set-cluster my-cluster --insecure-skip-tls-verify=true
```

## Contributing

Contributions are welcome! Please follow the existing code style and add tests for new features.

## License

This project is part of the Xygeni Extensions repository and follows the same license terms.