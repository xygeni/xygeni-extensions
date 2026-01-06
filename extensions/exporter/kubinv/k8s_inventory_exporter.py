#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "kubernetes>=28.0.0",
#   "pyyaml>=6.0",
# ]
# ///
"""
Kubernetes Inventory Exporter for Xygeni

Exports Kubernetes cluster workload inventory to a JSON file compatible with
Xygeni's InventoryReport format for ASPM correlation.

Extracts:
- Workloads: Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Pods
- Container images used by workloads
- Hierarchical relationships (Deployment -> ReplicaSet -> Pod)
- Optional: RBAC, NetworkPolicies, ServiceAccounts

Usage:
    python k8s_inventory_exporter.py [options]

See README.md for full documentation.
"""

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except ImportError:
    print("ERROR: 'kubernetes' library is required. Install with: pip install kubernetes")
    sys.exit(1)


# ANSI colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
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
        print(f"{Colors.CYAN}[VERBOSE]{Colors.NC} {msg}")


class K8sInventoryExporter:
    """Exports Kubernetes cluster inventory to Xygeni InventoryReport format."""

    # Asset kind constants (matching Xygeni AssetKind enum)
    KIND_CLOUD_RESOURCE = "cloud_resource"
    KIND_CONTAINER_IMAGE = "container_image"
    KIND_CLOUD_CONFIGURATION = "cloud_configuration"
    KIND_ORGANIZATION = "organization"
    KIND_USER = "user"
    KIND_GROUP = "group"

    # Link type constants (matching Xygeni LinkType enum)
    LINK_BELONGS_TO = "belongs_to"
    LINK_USES = "uses"
    LINK_OWNS = "owns"
    LINK_MANAGES = "manages"
    LINK_MEMBER_OF = "member_of"
    LINK_DEPLOYS = "deploys"

    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None,
                 namespaces: Optional[List[str]] = None, verbose: bool = False,
                 dry_run: bool = False, include_rbac: bool = False,
                 include_network_policies: bool = False,
                 include_security_context: bool = True,
                 project_name: Optional[str] = None):
        self.kubeconfig = kubeconfig
        self.context = context
        self.namespaces = namespaces or []
        self.verbose = verbose
        self.dry_run = dry_run
        self.include_rbac = include_rbac
        self.include_network_policies = include_network_policies
        self.include_security_context = include_security_context
        self.project_name = project_name

        # API clients (initialized on connect)
        self.core_v1: Optional[client.CoreV1Api] = None
        self.apps_v1: Optional[client.AppsV1Api] = None
        self.batch_v1: Optional[client.BatchV1Api] = None
        self.rbac_v1: Optional[client.RbacAuthorizationV1Api] = None
        self.networking_v1: Optional[client.NetworkingV1Api] = None

        # Cluster info
        self.cluster_name: str = "unknown-cluster"
        self.cluster_url: str = ""

        # Collected assets and links
        self.assets: List[Dict[str, Any]] = []
        self.links: List[Dict[str, Any]] = []
        self.asset_ids: Set[str] = set()
        self.errors: List[Dict[str, Any]] = []

        # Statistics
        self.stats: Dict[str, int] = {
            "assets": 0,
            "links": 0,
            "assetsByKind": {},
            "linksByKind": {},
        }

    def connect(self) -> bool:
        """Connect to the Kubernetes cluster."""
        log_info("Connecting to Kubernetes cluster...")

        if self.dry_run:
            log_info("[DRY-RUN] Would connect to Kubernetes cluster")
            self.cluster_name = "dry-run-cluster"
            return True

        try:
            # Load kubeconfig
            if self.kubeconfig:
                config.load_kube_config(config_file=self.kubeconfig, context=self.context)
            else:
                try:
                    # Try in-cluster config first (for running inside K8s)
                    config.load_incluster_config()
                    log_info("Using in-cluster configuration")
                except config.ConfigException:
                    # Fall back to default kubeconfig
                    config.load_kube_config(context=self.context)

            # Initialize API clients
            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.batch_v1 = client.BatchV1Api()

            if self.include_rbac:
                self.rbac_v1 = client.RbacAuthorizationV1Api()

            if self.include_network_policies:
                self.networking_v1 = client.NetworkingV1Api()

            # Get cluster info
            self._get_cluster_info()

            log_success(f"Connected to cluster: {self.cluster_name}")
            return True

        except config.ConfigException as e:
            log_error(f"Failed to load kubeconfig: {e}")
            return False
        except ApiException as e:
            log_error(f"Failed to connect to cluster: {e}")
            return False
        except Exception as e:
            log_error(f"Unexpected error connecting to cluster: {e}")
            return False

    def _get_cluster_info(self) -> None:
        """Get cluster name and URL from configuration."""
        try:
            # Try to get cluster info from kubeconfig
            _, active_context = config.list_kube_config_contexts(
                config_file=self.kubeconfig
            )
            if active_context:
                self.cluster_name = active_context.get('context', {}).get('cluster', 'unknown-cluster')
                # Get cluster URL from the active context
                contexts, _ = config.list_kube_config_contexts(config_file=self.kubeconfig)
                for ctx in contexts:
                    if ctx['name'] == active_context['name']:
                        cluster_name = ctx.get('context', {}).get('cluster', '')
                        # Load full config to get cluster URL
                        kube_config = config.kube_config.KubeConfigLoader(
                            config_file=self.kubeconfig
                        )
                        for cluster in kube_config._config.get('clusters', []):
                            if cluster.get('name') == cluster_name:
                                self.cluster_url = cluster.get('cluster', {}).get('server', '')
                                break
                        break
        except Exception as e:
            log_verbose(f"Could not get cluster info from kubeconfig: {e}", self.verbose)
            # Try to get from API server
            try:
                version_info = client.VersionApi().get_code()
                self.cluster_name = f"k8s-{version_info.git_version}"
            except Exception:
                pass

    def _get_namespaces(self) -> List[str]:
        """Get list of namespaces to scan."""
        if self.namespaces:
            return self.namespaces

        # Get all namespaces
        try:
            ns_list = self.core_v1.list_namespace()
            return [ns.metadata.name for ns in ns_list.items]
        except ApiException as e:
            log_warning(f"Could not list namespaces (may lack permissions): {e}")
            return ["default"]

    def _generate_asset_id(self, kind: str, *parts: str) -> str:
        """Generate a unique asset ID in the format kind:part1:part2:..."""
        clean_parts = [p.replace(":", "_") for p in parts if p]
        return f"{kind}:{':'.join(clean_parts)}"

    def _add_asset(self, asset: Dict[str, Any]) -> None:
        """Add an asset to the collection."""
        asset_id = asset.get("id", "")
        if asset_id in self.asset_ids:
            return  # Skip duplicates

        self.assets.append(asset)
        self.asset_ids.add(asset_id)
        self.stats["assets"] += 1

        kind = asset.get("kind", "unknown")
        self.stats["assetsByKind"][kind] = self.stats["assetsByKind"].get(kind, 0) + 1

    def _add_link(self, from_id: str, to_id: str, link_type: str) -> None:
        """Add a link between two assets."""
        # Only add link if both assets exist
        if from_id not in self.asset_ids or to_id not in self.asset_ids:
            return

        link = {
            "from": from_id,
            "to": to_id,
            "type": link_type
        }
        self.links.append(link)
        self.stats["links"] += 1
        self.stats["linksByKind"][link_type] = self.stats["linksByKind"].get(link_type, 0) + 1

    def _add_error(self, description: str, resource: str = "", fatal: bool = False) -> None:
        """Add an error to the collection."""
        if len(self.errors) < 64:  # Match Xygeni's error limit
            self.errors.append({
                "description": description,
                "file": resource,
                "fatal": fatal,
                "analyzer": "k8s-inventory-exporter",
                "code": "K8S_ERROR"
            })

    def _timestamp_to_millis(self, dt: Optional[datetime]) -> Optional[int]:
        """Convert datetime to milliseconds since epoch."""
        if dt is None:
            return None
        return int(dt.timestamp() * 1000)

    def _parse_image_name(self, image: str) -> Dict[str, Any]:
        """Parse a container image name into components."""
        result = {
            "registry": "",
            "namespace": "",
            "repository": "",
            "tag": "latest",
            "digest": "",
            "shortName": "",
            "tagOrDigest": ""
        }

        # Handle digest
        if "@sha256:" in image:
            image_part, digest = image.rsplit("@sha256:", 1)
            result["digest"] = f"sha256:{digest}"
            image = image_part
        elif "@" in image:
            image_part, digest = image.rsplit("@", 1)
            result["digest"] = digest
            image = image_part

        # Handle tag
        if ":" in image.split("/")[-1]:
            image_part, tag = image.rsplit(":", 1)
            result["tag"] = tag
            image = image_part

        # Parse registry/namespace/repository
        parts = image.split("/")

        if len(parts) == 1:
            # Simple image name (e.g., "nginx")
            result["registry"] = "docker.io"
            result["namespace"] = "library"
            result["repository"] = parts[0]
        elif len(parts) == 2:
            # Could be registry/image or namespace/image
            if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
                result["registry"] = parts[0]
                result["namespace"] = "library"
                result["repository"] = parts[1]
            else:
                result["registry"] = "docker.io"
                result["namespace"] = parts[0]
                result["repository"] = parts[1]
        else:
            # Full path with registry
            result["registry"] = parts[0]
            result["namespace"] = "/".join(parts[1:-1])
            result["repository"] = parts[-1]

        result["shortName"] = result["repository"]
        result["tagOrDigest"] = result["digest"] if result["digest"] else result["tag"]

        return result

    def _extract_security_context(self, container: Any) -> Dict[str, Any]:
        """Extract security context from a container spec."""
        context = {}

        if not self.include_security_context:
            return context

        sc = getattr(container, 'security_context', None)
        if sc:
            if sc.run_as_user is not None:
                context["runAsUser"] = sc.run_as_user
            if sc.run_as_group is not None:
                context["runAsGroup"] = sc.run_as_group
            if sc.run_as_non_root is not None:
                context["runAsNonRoot"] = sc.run_as_non_root
            if sc.read_only_root_filesystem is not None:
                context["readOnlyRootFilesystem"] = sc.read_only_root_filesystem
            if sc.privileged is not None:
                context["privileged"] = sc.privileged
            if sc.allow_privilege_escalation is not None:
                context["allowPrivilegeEscalation"] = sc.allow_privilege_escalation
            if sc.capabilities:
                if sc.capabilities.add:
                    context["capabilitiesAdd"] = list(sc.capabilities.add)
                if sc.capabilities.drop:
                    context["capabilitiesDrop"] = list(sc.capabilities.drop)

        return context

    def _create_cluster_asset(self) -> str:
        """Create the cluster asset and return its ID."""
        cluster_id = self._generate_asset_id(
            self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name
        )

        cluster_asset = {
            "kind": self.KIND_CLOUD_RESOURCE,
            "id": cluster_id,
            "name": self.cluster_name,
            "qualifiedName": f"kubernetes/{self.cluster_name}",
            "type": "kubernetes_cluster",
            "properties": {
                "resource_type": "kubernetes_cluster",
                "resource_category": "Container",
                "provider": "kubernetes"
            }
        }

        if self.cluster_url:
            cluster_asset["properties"]["url"] = self.cluster_url

        self._add_asset(cluster_asset)
        return cluster_id

    def _create_namespace_asset(self, namespace: str, cluster_id: str) -> str:
        """Create a namespace asset and return its ID."""
        ns_id = self._generate_asset_id(
            self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name, "namespace", namespace
        )

        ns_asset = {
            "kind": self.KIND_CLOUD_RESOURCE,
            "id": ns_id,
            "name": namespace,
            "qualifiedName": f"kubernetes/{self.cluster_name}/namespace/{namespace}",
            "type": "kubernetes_namespace",
            "belongsTo": cluster_id,
            "properties": {
                "resource_type": "kubernetes_namespace",
                "resource_category": "Container",
                "provider": "kubernetes"
            }
        }

        self._add_asset(ns_asset)
        self._add_link(ns_id, cluster_id, self.LINK_BELONGS_TO)
        return ns_id

    def _create_container_image_asset(self, image: str) -> str:
        """Create a container image asset and return its ID."""
        parsed = self._parse_image_name(image)

        # Use digest if available, otherwise use tag for uniqueness
        unique_suffix = parsed["digest"] if parsed["digest"] else f"{parsed['tag']}"
        image_id = self._generate_asset_id(
            self.KIND_CONTAINER_IMAGE,
            parsed["registry"],
            parsed["namespace"],
            parsed["repository"],
            unique_suffix
        )

        # Check if already exists
        if image_id in self.asset_ids:
            return image_id

        image_asset = {
            "kind": self.KIND_CONTAINER_IMAGE,
            "id": image_id,
            "name": image,
            "qualifiedName": image,
            "image": {
                "registry": parsed["registry"],
                "namespace": parsed["namespace"],
                "repository": parsed["repository"],
                "tag": parsed["tag"],
                "digest": parsed["digest"],
                "shortName": parsed["shortName"],
                "tagOrDigest": parsed["tagOrDigest"]
            },
            "properties": {}
        }

        self._add_asset(image_asset)
        return image_id

    def _extract_workload_containers(self, pod_spec: Any, workload_id: str,
                                      workload_name: str) -> List[str]:
        """Extract container images from a pod spec and create links."""
        image_ids = []

        containers = []
        if pod_spec.containers:
            containers.extend(pod_spec.containers)
        if pod_spec.init_containers:
            containers.extend(pod_spec.init_containers)

        for container in containers:
            if container.image:
                image_id = self._create_container_image_asset(container.image)
                image_ids.append(image_id)
                self._add_link(workload_id, image_id, self.LINK_USES)

                log_verbose(f"  Container {container.name}: {container.image}", self.verbose)

        return image_ids

    def _extract_deployments(self, namespace: str, ns_id: str) -> None:
        """Extract Deployment resources from the cluster."""
        log_verbose(f"Extracting Deployments in namespace {namespace}...", self.verbose)

        try:
            deployments = self.apps_v1.list_namespaced_deployment(namespace)

            for deploy in deployments.items:
                deploy_name = deploy.metadata.name
                deploy_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "deployment", deploy_name
                )

                deploy_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": deploy_id,
                    "name": deploy_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/deployment/{deploy_name}",
                    "type": "kubernetes_deployment",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(deploy.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_deployment",
                        "resource_category": "Container",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "replicas": deploy.spec.replicas or 1,
                        "availableReplicas": deploy.status.available_replicas or 0,
                        "readyReplicas": deploy.status.ready_replicas or 0,
                        "strategy": deploy.spec.strategy.type if deploy.spec.strategy else "RollingUpdate"
                    }
                }

                if deploy.metadata.labels:
                    deploy_asset["properties"]["labels"] = dict(deploy.metadata.labels)

                if deploy.spec.selector and deploy.spec.selector.match_labels:
                    deploy_asset["properties"]["selector"] = dict(deploy.spec.selector.match_labels)

                self._add_asset(deploy_asset)
                self._add_link(deploy_id, ns_id, self.LINK_BELONGS_TO)

                # Extract container images
                if deploy.spec.template and deploy.spec.template.spec:
                    self._extract_workload_containers(
                        deploy.spec.template.spec, deploy_id, deploy_name
                    )

                log_verbose(f"  Deployment: {deploy_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list deployments in {namespace}: {e}", namespace)
            log_warning(f"Could not list deployments in {namespace}: {e}")

    def _extract_statefulsets(self, namespace: str, ns_id: str) -> None:
        """Extract StatefulSet resources from the cluster."""
        log_verbose(f"Extracting StatefulSets in namespace {namespace}...", self.verbose)

        try:
            statefulsets = self.apps_v1.list_namespaced_stateful_set(namespace)

            for sts in statefulsets.items:
                sts_name = sts.metadata.name
                sts_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "statefulset", sts_name
                )

                sts_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": sts_id,
                    "name": sts_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/statefulset/{sts_name}",
                    "type": "kubernetes_statefulset",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(sts.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_statefulset",
                        "resource_category": "Container",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "replicas": sts.spec.replicas or 1,
                        "readyReplicas": sts.status.ready_replicas or 0,
                        "serviceName": sts.spec.service_name
                    }
                }

                if sts.metadata.labels:
                    sts_asset["properties"]["labels"] = dict(sts.metadata.labels)

                self._add_asset(sts_asset)
                self._add_link(sts_id, ns_id, self.LINK_BELONGS_TO)

                # Extract container images
                if sts.spec.template and sts.spec.template.spec:
                    self._extract_workload_containers(
                        sts.spec.template.spec, sts_id, sts_name
                    )

                log_verbose(f"  StatefulSet: {sts_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list statefulsets in {namespace}: {e}", namespace)
            log_warning(f"Could not list statefulsets in {namespace}: {e}")

    def _extract_daemonsets(self, namespace: str, ns_id: str) -> None:
        """Extract DaemonSet resources from the cluster."""
        log_verbose(f"Extracting DaemonSets in namespace {namespace}...", self.verbose)

        try:
            daemonsets = self.apps_v1.list_namespaced_daemon_set(namespace)

            for ds in daemonsets.items:
                ds_name = ds.metadata.name
                ds_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "daemonset", ds_name
                )

                ds_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": ds_id,
                    "name": ds_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/daemonset/{ds_name}",
                    "type": "kubernetes_daemonset",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(ds.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_daemonset",
                        "resource_category": "Container",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "desiredNumberScheduled": ds.status.desired_number_scheduled or 0,
                        "currentNumberScheduled": ds.status.current_number_scheduled or 0,
                        "numberReady": ds.status.number_ready or 0
                    }
                }

                if ds.metadata.labels:
                    ds_asset["properties"]["labels"] = dict(ds.metadata.labels)

                self._add_asset(ds_asset)
                self._add_link(ds_id, ns_id, self.LINK_BELONGS_TO)

                # Extract container images
                if ds.spec.template and ds.spec.template.spec:
                    self._extract_workload_containers(
                        ds.spec.template.spec, ds_id, ds_name
                    )

                log_verbose(f"  DaemonSet: {ds_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list daemonsets in {namespace}: {e}", namespace)
            log_warning(f"Could not list daemonsets in {namespace}: {e}")

    def _extract_jobs(self, namespace: str, ns_id: str) -> None:
        """Extract Job resources from the cluster."""
        log_verbose(f"Extracting Jobs in namespace {namespace}...", self.verbose)

        try:
            jobs = self.batch_v1.list_namespaced_job(namespace)

            for job in jobs.items:
                job_name = job.metadata.name
                job_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "job", job_name
                )

                # Determine job status
                succeeded = job.status.succeeded or 0
                failed = job.status.failed or 0
                active = job.status.active or 0

                if succeeded > 0:
                    status = "Succeeded"
                elif failed > 0:
                    status = "Failed"
                elif active > 0:
                    status = "Running"
                else:
                    status = "Pending"

                job_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": job_id,
                    "name": job_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/job/{job_name}",
                    "type": "kubernetes_job",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(job.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_job",
                        "resource_category": "Container",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "status": status,
                        "succeeded": succeeded,
                        "failed": failed,
                        "active": active,
                        "completions": job.spec.completions or 1,
                        "parallelism": job.spec.parallelism or 1
                    }
                }

                if job.metadata.labels:
                    job_asset["properties"]["labels"] = dict(job.metadata.labels)

                # Check if owned by a CronJob
                if job.metadata.owner_references:
                    for owner in job.metadata.owner_references:
                        if owner.kind == "CronJob":
                            job_asset["properties"]["cronJobOwner"] = owner.name

                self._add_asset(job_asset)
                self._add_link(job_id, ns_id, self.LINK_BELONGS_TO)

                # Extract container images
                if job.spec.template and job.spec.template.spec:
                    self._extract_workload_containers(
                        job.spec.template.spec, job_id, job_name
                    )

                log_verbose(f"  Job: {job_name} ({status})", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list jobs in {namespace}: {e}", namespace)
            log_warning(f"Could not list jobs in {namespace}: {e}")

    def _extract_cronjobs(self, namespace: str, ns_id: str) -> None:
        """Extract CronJob resources from the cluster."""
        log_verbose(f"Extracting CronJobs in namespace {namespace}...", self.verbose)

        try:
            cronjobs = self.batch_v1.list_namespaced_cron_job(namespace)

            for cj in cronjobs.items:
                cj_name = cj.metadata.name
                cj_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "cronjob", cj_name
                )

                cj_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": cj_id,
                    "name": cj_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/cronjob/{cj_name}",
                    "type": "kubernetes_cronjob",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(cj.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_cronjob",
                        "resource_category": "Container",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "schedule": cj.spec.schedule,
                        "suspend": cj.spec.suspend or False,
                        "concurrencyPolicy": cj.spec.concurrency_policy or "Allow"
                    }
                }

                if cj.metadata.labels:
                    cj_asset["properties"]["labels"] = dict(cj.metadata.labels)

                if cj.status.last_schedule_time:
                    cj_asset["properties"]["lastScheduleTime"] = cj.status.last_schedule_time.isoformat()

                if cj.status.last_successful_time:
                    cj_asset["properties"]["lastSuccessfulTime"] = cj.status.last_successful_time.isoformat()

                self._add_asset(cj_asset)
                self._add_link(cj_id, ns_id, self.LINK_BELONGS_TO)

                # Extract container images from job template
                if cj.spec.job_template and cj.spec.job_template.spec:
                    if cj.spec.job_template.spec.template and cj.spec.job_template.spec.template.spec:
                        self._extract_workload_containers(
                            cj.spec.job_template.spec.template.spec, cj_id, cj_name
                        )

                log_verbose(f"  CronJob: {cj_name} ({cj.spec.schedule})", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list cronjobs in {namespace}: {e}", namespace)
            log_warning(f"Could not list cronjobs in {namespace}: {e}")

    def _extract_pods(self, namespace: str, ns_id: str) -> None:
        """Extract Pod resources from the cluster."""
        log_verbose(f"Extracting Pods in namespace {namespace}...", self.verbose)

        try:
            pods = self.core_v1.list_namespaced_pod(namespace)

            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "pod", pod_name
                )

                pod_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": pod_id,
                    "name": pod_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/pod/{pod_name}",
                    "type": "kubernetes_pod",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(pod.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_pod",
                        "resource_category": "Container",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "phase": pod.status.phase,
                        "nodeName": pod.spec.node_name or "",
                        "hostIP": pod.status.host_ip or "",
                        "podIP": pod.status.pod_ip or "",
                        "serviceAccount": pod.spec.service_account_name or "default"
                    }
                }

                if pod.metadata.labels:
                    pod_asset["properties"]["labels"] = dict(pod.metadata.labels)

                # Track owner references for linking
                owner_kind = None
                owner_name = None
                if pod.metadata.owner_references:
                    for owner in pod.metadata.owner_references:
                        if owner.controller:
                            owner_kind = owner.kind.lower()
                            owner_name = owner.name
                            pod_asset["properties"]["ownerKind"] = owner.kind
                            pod_asset["properties"]["ownerName"] = owner.name
                            break

                # Extract container statuses
                container_statuses = []
                if pod.status.container_statuses:
                    for cs in pod.status.container_statuses:
                        container_statuses.append({
                            "name": cs.name,
                            "ready": cs.ready,
                            "restartCount": cs.restart_count,
                            "image": cs.image,
                            "imageID": cs.image_id or ""
                        })
                pod_asset["properties"]["containerStatuses"] = container_statuses

                # Extract security context if enabled
                if self.include_security_context and pod.spec.security_context:
                    sc = pod.spec.security_context
                    pod_security = {}
                    if sc.run_as_user is not None:
                        pod_security["runAsUser"] = sc.run_as_user
                    if sc.run_as_group is not None:
                        pod_security["runAsGroup"] = sc.run_as_group
                    if sc.run_as_non_root is not None:
                        pod_security["runAsNonRoot"] = sc.run_as_non_root
                    if sc.fs_group is not None:
                        pod_security["fsGroup"] = sc.fs_group
                    if pod_security:
                        pod_asset["properties"]["securityContext"] = pod_security

                self._add_asset(pod_asset)
                self._add_link(pod_id, ns_id, self.LINK_BELONGS_TO)

                # Link to owner workload
                if owner_kind and owner_name:
                    # Map replicaset to its potential deployment owner
                    if owner_kind == "replicaset":
                        # ReplicaSets created by Deployments have names like: deployment-name-hash
                        # Try to find the parent deployment
                        owner_id = self._generate_asset_id(
                            self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                            namespace, "replicaset", owner_name
                        )
                    else:
                        owner_id = self._generate_asset_id(
                            self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                            namespace, owner_kind, owner_name
                        )
                    if owner_id in self.asset_ids:
                        self._add_link(pod_id, owner_id, self.LINK_BELONGS_TO)

                # Extract container images
                if pod.spec:
                    self._extract_workload_containers(pod.spec, pod_id, pod_name)

                log_verbose(f"  Pod: {pod_name} ({pod.status.phase})", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list pods in {namespace}: {e}", namespace)
            log_warning(f"Could not list pods in {namespace}: {e}")

    def _extract_replicasets(self, namespace: str, ns_id: str) -> None:
        """Extract ReplicaSet resources to complete the hierarchy."""
        log_verbose(f"Extracting ReplicaSets in namespace {namespace}...", self.verbose)

        try:
            replicasets = self.apps_v1.list_namespaced_replica_set(namespace)

            for rs in replicasets.items:
                rs_name = rs.metadata.name
                rs_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "replicaset", rs_name
                )

                rs_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": rs_id,
                    "name": rs_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/replicaset/{rs_name}",
                    "type": "kubernetes_replicaset",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(rs.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_replicaset",
                        "resource_category": "Container",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "replicas": rs.spec.replicas or 0,
                        "readyReplicas": rs.status.ready_replicas or 0,
                        "availableReplicas": rs.status.available_replicas or 0
                    }
                }

                # Track owner (usually a Deployment)
                if rs.metadata.owner_references:
                    for owner in rs.metadata.owner_references:
                        if owner.controller and owner.kind == "Deployment":
                            rs_asset["properties"]["deploymentOwner"] = owner.name
                            # Link to deployment
                            deploy_id = self._generate_asset_id(
                                self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                                namespace, "deployment", owner.name
                            )
                            if deploy_id in self.asset_ids:
                                rs_asset["belongsTo"] = deploy_id
                            break

                self._add_asset(rs_asset)

                # Add link to namespace or deployment
                if rs_asset.get("belongsTo") and rs_asset["belongsTo"] != ns_id:
                    self._add_link(rs_id, rs_asset["belongsTo"], self.LINK_BELONGS_TO)
                else:
                    self._add_link(rs_id, ns_id, self.LINK_BELONGS_TO)

                log_verbose(f"  ReplicaSet: {rs_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list replicasets in {namespace}: {e}", namespace)
            log_warning(f"Could not list replicasets in {namespace}: {e}")

    def _extract_services(self, namespace: str, ns_id: str) -> None:
        """Extract Service resources from the cluster."""
        log_verbose(f"Extracting Services in namespace {namespace}...", self.verbose)

        try:
            services = self.core_v1.list_namespaced_service(namespace)

            for svc in services.items:
                svc_name = svc.metadata.name
                svc_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "service", svc_name
                )

                svc_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": svc_id,
                    "name": svc_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/service/{svc_name}",
                    "type": "kubernetes_service",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(svc.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_service",
                        "resource_category": "Network",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "type": svc.spec.type,
                        "clusterIP": svc.spec.cluster_ip or "",
                        "ports": []
                    }
                }

                # Add ports
                if svc.spec.ports:
                    for port in svc.spec.ports:
                        svc_asset["properties"]["ports"].append({
                            "name": port.name or "",
                            "port": port.port,
                            "targetPort": str(port.target_port) if port.target_port else "",
                            "protocol": port.protocol or "TCP"
                        })

                # Add selector
                if svc.spec.selector:
                    svc_asset["properties"]["selector"] = dict(svc.spec.selector)

                # Add external IPs/LoadBalancer info
                if svc.spec.type == "LoadBalancer" and svc.status.load_balancer:
                    ingress = svc.status.load_balancer.ingress
                    if ingress:
                        external_ips = []
                        for ing in ingress:
                            if ing.ip:
                                external_ips.append(ing.ip)
                            if ing.hostname:
                                external_ips.append(ing.hostname)
                        if external_ips:
                            svc_asset["properties"]["externalIPs"] = external_ips

                if svc.spec.external_i_ps:
                    svc_asset["properties"]["externalIPs"] = list(svc.spec.external_i_ps)

                if svc.metadata.labels:
                    svc_asset["properties"]["labels"] = dict(svc.metadata.labels)

                self._add_asset(svc_asset)
                self._add_link(svc_id, ns_id, self.LINK_BELONGS_TO)

                log_verbose(f"  Service: {svc_name} ({svc.spec.type})", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list services in {namespace}: {e}", namespace)
            log_warning(f"Could not list services in {namespace}: {e}")

    def _extract_service_accounts(self, namespace: str, ns_id: str) -> None:
        """Extract ServiceAccount resources from the cluster."""
        log_verbose(f"Extracting ServiceAccounts in namespace {namespace}...", self.verbose)

        try:
            service_accounts = self.core_v1.list_namespaced_service_account(namespace)

            for sa in service_accounts.items:
                sa_name = sa.metadata.name
                sa_id = self._generate_asset_id(
                    self.KIND_USER, "kubernetes", self.cluster_name,
                    namespace, "serviceaccount", sa_name
                )

                sa_asset = {
                    "kind": self.KIND_USER,
                    "id": sa_id,
                    "name": sa_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/serviceaccount/{sa_name}",
                    "system": "kubernetes",
                    "properties": {
                        "namespace": namespace,
                        "type": "serviceaccount"
                    }
                }

                if sa.metadata.labels:
                    sa_asset["properties"]["labels"] = dict(sa.metadata.labels)

                # Track secrets
                if sa.secrets:
                    sa_asset["properties"]["secrets"] = [s.name for s in sa.secrets]

                self._add_asset(sa_asset)
                self._add_link(sa_id, ns_id, self.LINK_MEMBER_OF)

                log_verbose(f"  ServiceAccount: {sa_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list service accounts in {namespace}: {e}", namespace)
            log_warning(f"Could not list service accounts in {namespace}: {e}")

    def _extract_rbac(self, namespace: str, ns_id: str) -> None:
        """Extract RBAC resources (Roles, RoleBindings) from the cluster."""
        if not self.include_rbac or not self.rbac_v1:
            return

        log_verbose(f"Extracting RBAC in namespace {namespace}...", self.verbose)

        # Extract Roles
        try:
            roles = self.rbac_v1.list_namespaced_role(namespace)

            for role in roles.items:
                role_name = role.metadata.name
                role_id = self._generate_asset_id(
                    self.KIND_GROUP, "kubernetes", self.cluster_name,
                    namespace, "role", role_name
                )

                rules = []
                if role.rules:
                    for rule in role.rules:
                        rules.append({
                            "apiGroups": list(rule.api_groups) if rule.api_groups else [],
                            "resources": list(rule.resources) if rule.resources else [],
                            "verbs": list(rule.verbs) if rule.verbs else []
                        })

                role_asset = {
                    "kind": self.KIND_GROUP,
                    "id": role_id,
                    "name": role_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/role/{role_name}",
                    "system": "kubernetes",
                    "properties": {
                        "namespace": namespace,
                        "type": "role",
                        "rules": rules
                    }
                }

                self._add_asset(role_asset)
                self._add_link(role_id, ns_id, self.LINK_BELONGS_TO)

                log_verbose(f"  Role: {role_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list roles in {namespace}: {e}", namespace)

        # Extract RoleBindings
        try:
            role_bindings = self.rbac_v1.list_namespaced_role_binding(namespace)

            for rb in role_bindings.items:
                rb_name = rb.metadata.name

                # Link subjects to roles
                if rb.subjects and rb.role_ref:
                    role_ref_kind = rb.role_ref.kind.lower()
                    role_ref_name = rb.role_ref.name

                    # Get role ID
                    if role_ref_kind == "clusterrole":
                        role_id = self._generate_asset_id(
                            self.KIND_GROUP, "kubernetes", self.cluster_name,
                            "clusterrole", role_ref_name
                        )
                    else:
                        role_id = self._generate_asset_id(
                            self.KIND_GROUP, "kubernetes", self.cluster_name,
                            namespace, "role", role_ref_name
                        )

                    for subject in rb.subjects:
                        if subject.kind == "ServiceAccount":
                            subject_ns = subject.namespace or namespace
                            subject_id = self._generate_asset_id(
                                self.KIND_USER, "kubernetes", self.cluster_name,
                                subject_ns, "serviceaccount", subject.name
                            )
                            if subject_id in self.asset_ids and role_id in self.asset_ids:
                                self._add_link(subject_id, role_id, self.LINK_MEMBER_OF)

                log_verbose(f"  RoleBinding: {rb_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list role bindings in {namespace}: {e}", namespace)

    def _extract_network_policies(self, namespace: str, ns_id: str) -> None:
        """Extract NetworkPolicy resources from the cluster."""
        if not self.include_network_policies or not self.networking_v1:
            return

        log_verbose(f"Extracting NetworkPolicies in namespace {namespace}...", self.verbose)

        try:
            network_policies = self.networking_v1.list_namespaced_network_policy(namespace)

            for np in network_policies.items:
                np_name = np.metadata.name
                np_id = self._generate_asset_id(
                    self.KIND_CLOUD_RESOURCE, "kubernetes", self.cluster_name,
                    namespace, "networkpolicy", np_name
                )

                np_asset = {
                    "kind": self.KIND_CLOUD_RESOURCE,
                    "id": np_id,
                    "name": np_name,
                    "qualifiedName": f"kubernetes/{self.cluster_name}/{namespace}/networkpolicy/{np_name}",
                    "type": "kubernetes_networkpolicy",
                    "belongsTo": ns_id,
                    "createdAt": self._timestamp_to_millis(np.metadata.creation_timestamp),
                    "properties": {
                        "resource_type": "kubernetes_networkpolicy",
                        "resource_category": "Network",
                        "provider": "kubernetes",
                        "namespace": namespace,
                        "policyTypes": list(np.spec.policy_types) if np.spec.policy_types else []
                    }
                }

                # Add pod selector
                if np.spec.pod_selector and np.spec.pod_selector.match_labels:
                    np_asset["properties"]["podSelector"] = dict(np.spec.pod_selector.match_labels)

                if np.metadata.labels:
                    np_asset["properties"]["labels"] = dict(np.metadata.labels)

                self._add_asset(np_asset)
                self._add_link(np_id, ns_id, self.LINK_BELONGS_TO)

                log_verbose(f"  NetworkPolicy: {np_name}", self.verbose)

        except ApiException as e:
            self._add_error(f"Failed to list network policies in {namespace}: {e}", namespace)
            log_warning(f"Could not list network policies in {namespace}: {e}")

    def extract_inventory(self) -> bool:
        """Extract the full inventory from the cluster."""
        log_info("Extracting Kubernetes inventory...")

        if self.dry_run:
            log_info("[DRY-RUN] Would extract inventory from cluster")
            return True

        # Create cluster asset
        cluster_id = self._create_cluster_asset()

        # Get namespaces to scan
        namespaces = self._get_namespaces()
        log_info(f"Scanning {len(namespaces)} namespace(s): {', '.join(namespaces)}")

        for namespace in namespaces:
            log_info(f"Processing namespace: {namespace}")

            # Create namespace asset
            ns_id = self._create_namespace_asset(namespace, cluster_id)

            # Extract workloads (order matters for hierarchy linking)
            self._extract_deployments(namespace, ns_id)
            self._extract_statefulsets(namespace, ns_id)
            self._extract_daemonsets(namespace, ns_id)
            self._extract_cronjobs(namespace, ns_id)
            self._extract_jobs(namespace, ns_id)
            self._extract_replicasets(namespace, ns_id)
            self._extract_pods(namespace, ns_id)

            # Extract services
            self._extract_services(namespace, ns_id)

            # Extract service accounts
            self._extract_service_accounts(namespace, ns_id)

            # Extract optional resources
            self._extract_rbac(namespace, ns_id)
            self._extract_network_policies(namespace, ns_id)

        log_success(f"Extracted {self.stats['assets']} assets and {self.stats['links']} links")
        return True

    def generate_report(self, output_file: str) -> bool:
        """Generate the InventoryReport JSON file."""
        log_info(f"Generating inventory report: {output_file}")

        if self.dry_run:
            log_info(f"[DRY-RUN] Would write inventory report to: {output_file}")
            return True

        # Build metadata
        timestamp = datetime.now(timezone.utc)
        report_uuid = str(uuid.uuid4())

        metadata = {
            "uuid": report_uuid,
            "timestamp": timestamp.isoformat(),
            "projectName": self.project_name or self.cluster_name,
            "directory": f"kubernetes://{self.cluster_name}",
            "sourceType": "REPO",
            "scanType": "inventory",
            "format": "inventory.1",
            "developerHashes": [],
            "reportProperties": {
                "generator": "k8s-inventory-exporter",
                "clusterName": self.cluster_name,
                "clusterUrl": self.cluster_url,
                "extractedAt": timestamp.isoformat()
            }
        }

        # Build statistics
        statistics = {
            "files": 0,
            "assets": self.stats["assets"],
            "assetsByKind": self.stats["assetsByKind"],
            "links": self.stats["links"],
            "linksByKind": self.stats["linksByKind"],
            "detectors": 1,
            "elapsedTime": "PT0S"
        }

        # Build the report
        report = {
            "metadata": metadata,
            "statistics": statistics,
            "errors": self.errors,
            "assets": self.assets,
            "graph": {
                "links": self.links
            }
        }

        # Write to file
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        log_success(f"Inventory report written to: {output_file}")
        return True


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Kubernetes Inventory Exporter for Xygeni",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export inventory using default kubeconfig
  %(prog)s -o k8s_inventory.json

  # Export from specific context
  %(prog)s --context=production -o prod_inventory.json

  # Export specific namespaces only
  %(prog)s -n default,kube-system -o inventory.json

  # Export with RBAC and network policies
  %(prog)s --include-rbac --include-network-policies -o full_inventory.json

  # Export using specific kubeconfig file
  %(prog)s --kubeconfig=/path/to/kubeconfig -o inventory.json

  # Dry run (show what would be done)
  %(prog)s --dry-run -o inventory.json
"""
    )

    parser.add_argument('-o', '--output', default='./k8s_inventory.json',
                        help='Output JSON file path (default: ./k8s_inventory.json)')
    parser.add_argument('--kubeconfig', metavar='FILE',
                        help='Path to kubeconfig file (default: ~/.kube/config)')
    parser.add_argument('--context', metavar='NAME',
                        help='Kubernetes context to use')
    parser.add_argument('-n', '--namespaces', metavar='NS1,NS2',
                        help='Comma-separated list of namespaces to scan (default: all)')
    parser.add_argument('--project-name', metavar='NAME',
                        help='Project name for the report (default: cluster name)')
    parser.add_argument('--include-rbac', action='store_true',
                        help='Include RBAC resources (Roles, RoleBindings)')
    parser.add_argument('--include-network-policies', action='store_true',
                        help='Include NetworkPolicy resources')
    parser.add_argument('--exclude-security-context', action='store_true',
                        help='Exclude security context information from pods/containers')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without executing')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Parse namespaces
    namespaces = None
    if args.namespaces:
        namespaces = [ns.strip() for ns in args.namespaces.split(',')]

    # Create exporter
    exporter = K8sInventoryExporter(
        kubeconfig=args.kubeconfig,
        context=args.context,
        namespaces=namespaces,
        verbose=args.verbose,
        dry_run=args.dry_run,
        include_rbac=args.include_rbac,
        include_network_policies=args.include_network_policies,
        include_security_context=not args.exclude_security_context,
        project_name=args.project_name
    )

    # Connect to cluster
    if not exporter.connect():
        return 1

    # Extract inventory
    if not exporter.extract_inventory():
        return 1

    # Generate report
    if not exporter.generate_report(args.output):
        return 1

    if not args.dry_run:
        print()
        log_info("To upload to Xygeni, run:")
        print()
        print(f"  xygeni report-upload --report={args.output} --format inventory-k8s")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())