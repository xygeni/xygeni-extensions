#!/bin/bash
#
# Wiz CNAPP Exporter for Xygeni
#
# Exports Wiz CNAPP findings to JSON files compatible with Xygeni report-upload.
#
# Usage:
#   ./wiz_cnapp_exporter.sh -c wiz.config [options]
#
# See README.md for full documentation.
#

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
CONFIG_FILE=""
OUTPUT_DIR="./output"
EXPORT_VULNERABILITIES=false
EXPORT_ISSUES=false
EXPORT_CONFIG_FINDINGS=false
EXPORT_CLOUD_RESOURCES=false
EXPORT_ALL=false
CUSTOM_QUERY=""
DRY_RUN=false
VERBOSE=false
ENABLE_PAGINATION=true
MAX_PAGES=0
REQUEST_DELAY=0.5

# Output file names (without directory prefix)
OUTPUT_FILE_VULNERABILITIES="wiz_cnapp_vulnerabilities.json"
OUTPUT_FILE_ISSUES="wiz_cnapp_issues.json"
OUTPUT_FILE_CONFIG_FINDINGS="wiz_cnapp_config_findings.json"
OUTPUT_FILE_CLOUD_RESOURCES="wiz_cnapp_cloud_resources.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

# Show usage
usage() {
    cat << EOF
Wiz CNAPP Exporter for Xygeni

Usage: $(basename "$0") -c <config_file> [options]

Required:
  -c, --config FILE          Path to configuration file (e.g., wiz.config)

Export Options:
  --vulnerabilities          Export vulnerability findings
  --issues                   Export issues (toxic combinations, threats, misconfigurations)
  --config-findings          Export cloud configuration findings
  --cloud-resources          Export cloud resources inventory (VMs, containers, serverless)
  --all                      Export all finding types (default if no type specified)
  --query FILE               Export using a custom GraphQL query file

Output Options:
  -o, --output DIR           Output directory (default: ./output)

Other Options:
  --dry-run                  Show what would be done without executing
  -v, --verbose              Enable verbose output
  -h, --help                 Show this help message

Examples:
  # Export all findings
  $(basename "$0") -c wiz.config --all

  # Export only vulnerabilities to custom directory
  $(basename "$0") -c wiz.config --vulnerabilities -o ./exports

  # Export with custom query
  $(basename "$0") -c wiz.config --query queries/custom.graphql

EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --vulnerabilities)
                EXPORT_VULNERABILITIES=true
                shift
                ;;
            --issues)
                EXPORT_ISSUES=true
                shift
                ;;
            --config-findings)
                EXPORT_CONFIG_FINDINGS=true
                shift
                ;;
            --cloud-resources)
                EXPORT_CLOUD_RESOURCES=true
                shift
                ;;
            --all)
                EXPORT_ALL=true
                shift
                ;;
            --query)
                CUSTOM_QUERY="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Validate configuration
validate_config() {
    if [[ -z "$CONFIG_FILE" ]]; then
        log_error "Configuration file is required. Use -c or --config."
        exit 1
    fi

    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    # Source the config file
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"

    # Validate required fields
    if [[ -z "${WIZ_CLIENT_ID:-}" ]]; then
        log_error "WIZ_CLIENT_ID is required in config file"
        exit 1
    fi

    if [[ -z "${WIZ_CLIENT_SECRET:-}" ]]; then
        log_error "WIZ_CLIENT_SECRET is required in config file"
        exit 1
    fi

    # Set defaults from config
    WIZ_REGION="${WIZ_REGION:-us1}"
    OUTPUT_DIR="${OUTPUT_DIR:-./output}"
    ENABLE_PAGINATION="${ENABLE_PAGINATION:-true}"
    MAX_PAGES="${MAX_PAGES:-0}"
    REQUEST_DELAY="${REQUEST_DELAY:-0.5}"
    VERBOSE="${VERBOSE:-false}"

    # If --all or no specific type selected, export all
    if [[ "$EXPORT_ALL" == "true" ]] || \
       { [[ "$EXPORT_VULNERABILITIES" == "false" ]] && \
         [[ "$EXPORT_ISSUES" == "false" ]] && \
         [[ "$EXPORT_CONFIG_FINDINGS" == "false" ]] && \
         [[ "$EXPORT_CLOUD_RESOURCES" == "false" ]] && \
         [[ -z "$CUSTOM_QUERY" ]]; }; then
        EXPORT_VULNERABILITIES=true
        EXPORT_ISSUES=true
        EXPORT_CONFIG_FINDINGS=true
        EXPORT_CLOUD_RESOURCES=true
    fi

    # Set API URLs
    WIZ_API_URL="https://api.${WIZ_REGION}.app.wiz.io/graphql"
    WIZ_TOKEN_URL="https://auth.app.wiz.io/oauth/token"

    log_verbose "Configuration loaded from: $CONFIG_FILE"
    log_verbose "API URL: $WIZ_API_URL"
    log_verbose "Output directory: $OUTPUT_DIR"
}

# Get OAuth access token
get_access_token() {
    log_info "Authenticating with Wiz API..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would authenticate with Wiz API"
        ACCESS_TOKEN="dry-run-token"
        return
    fi

    local body
    body="client_id=${WIZ_CLIENT_ID}&client_secret=${WIZ_CLIENT_ID}&grant_type=client_credentials&audience=wiz-api"

    local response
    response=$(curl -s -X POST "$WIZ_TOKEN_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$body")

    if [[ "$response" == "Unauthorized" ]]; then
      log_error "Failed to authenticate. Check your WIZ_CLIENT_ID / WIZ_CLIENT_ID"
      exit 1
    fi

    log_verbose "Authentication response: $response"
    ACCESS_TOKEN=$(echo "$response" | jq -r '.access_token // empty')

    if [[ -z "$ACCESS_TOKEN" ]]; then
        local error_msg
        error_msg=$(echo "$response" | jq -r '.error_description // .error // "Unknown error"')
        log_error "Failed to authenticate: $error_msg"
        exit 1
    fi

    log_success "Authentication successful"
}

# Load GraphQL query from file
load_query() {
    local query_file="$1"

    if [[ ! -f "$query_file" ]]; then
        log_error "Query file not found: $query_file"
        exit 1
    fi

    # Read query, remove comments and normalize whitespace
    cat "$query_file" | grep -v "^#" | tr '\n' ' ' | sed 's/  */ /g'
}

# Execute GraphQL query with pagination
execute_query() {
    local query="$1"
    local variables="$2"
    local output_file="$3"
    local data_path="$4"

    log_verbose "Query: $query"
    log_verbose "Variables: $variables"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would execute query and save to: $output_file"
        return
    fi

    local all_nodes="[]"
    local cursor=""
    local page=1
    local has_next_page=true

    while [[ "$has_next_page" == "true" ]]; do
        log_verbose "Fetching page $page..."

        # Add cursor to variables if not first page
        local current_vars="$variables"
        if [[ -n "$cursor" ]]; then
            current_vars=$(echo "$variables" | jq --arg cursor "$cursor" '. + {after: $cursor}')
        fi

        # Build request body
        local body
        body=$(jq -n --arg query "$query" --argjson vars "$current_vars" \
            '{query: $query, variables: $vars}')

        # Execute query
        local response
        response=$(curl -s -X POST "$WIZ_API_URL" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body")

        # Check for errors
        local errors
        errors=$(echo "$response" | jq -r '.errors // empty')
        if [[ -n "$errors" && "$errors" != "null" ]]; then
            log_error "GraphQL error: $(echo "$errors" | jq -r '.[0].message // "Unknown error"')"
            log_verbose "Full response: $response"
            exit 1
        fi

        # Extract nodes and pagination info
        local nodes
        nodes=$(echo "$response" | jq -r ".data.${data_path}.nodes // []")

        local page_info
        page_info=$(echo "$response" | jq -r ".data.${data_path}.pageInfo // {}")

        has_next_page=$(echo "$page_info" | jq -r '.hasNextPage // false')
        cursor=$(echo "$page_info" | jq -r '.endCursor // empty')

        # Merge nodes
        all_nodes=$(echo "$all_nodes" "$nodes" | jq -s 'add')

        local count
        count=$(echo "$nodes" | jq 'length')
        log_verbose "Page $page: fetched $count items (hasNextPage: $has_next_page)"

        # Check pagination limits
        if [[ "$ENABLE_PAGINATION" != "true" ]]; then
            break
        fi

        if [[ "$MAX_PAGES" -gt 0 ]] && [[ "$page" -ge "$MAX_PAGES" ]]; then
            log_warning "Reached maximum page limit ($MAX_PAGES)"
            break
        fi

        # Rate limiting
        if [[ "$has_next_page" == "true" ]]; then
            sleep "$REQUEST_DELAY"
        fi

        ((page++))
    done

    # Build final output with nodes and pageInfo
    local total_count
    total_count=$(echo "$all_nodes" | jq 'length')

    local output
    output=$(jq -n --argjson nodes "$all_nodes" \
        '{nodes: $nodes, pageInfo: {hasNextPage: false, endCursor: null}}')

    echo "$output" > "$output_file"
    log_success "Exported $total_count items to: $output_file"
}

# Export vulnerability findings
export_vulnerabilities() {
    log_info "Exporting vulnerability findings..."

    local query_file="${SCRIPT_DIR}/queries/vulnerability_findings.graphql"
    local query
    query=$(load_query "$query_file")

    # Build variables from config
    local variables
    variables=$(jq -n \
        --argjson first "${VULN_FIRST:-500}" \
        --argjson status "${VULN_STATUS:-'[\"UNRESOLVED\"]'}" \
        --argjson severity "${VULN_SEVERITY:-'[\"CRITICAL\", \"HIGH\"]'}" \
        '{
            first: $first,
            filter: {
                status: $status,
                vendorSeverity: $severity
            }
        }')

    execute_query "$query" "$variables" "${OUTPUT_DIR}/${OUTPUT_FILE_VULNERABILITIES}" "vulnerabilityFindings"
}

# Export issues
export_issues() {
    log_info "Exporting issues..."

    local query_file="${SCRIPT_DIR}/queries/issues.graphql"
    local query
    query=$(load_query "$query_file")

    # Build variables from config
    local variables
    variables=$(jq -n \
        --argjson first "${ISSUES_FIRST:-500}" \
        --argjson status "${ISSUES_STATUS:-'[\"OPEN\", \"IN_PROGRESS\"]'}" \
        --argjson types "${ISSUES_TYPES:-'[\"TOXIC_COMBINATION\", \"THREAT_DETECTION\", \"CLOUD_CONFIGURATION\"]'}" \
        '{
            first: $first,
            filterBy: {
                status: $status,
                type: $types
            },
            orderBy: {field: "CREATED_AT", direction: "DESC"}
        }')

    execute_query "$query" "$variables" "${OUTPUT_DIR}/${OUTPUT_FILE_ISSUES}" "issues"
}

# Export configuration findings
export_config_findings() {
    log_info "Exporting cloud configuration findings..."

    local query_file="${SCRIPT_DIR}/queries/configuration_findings.graphql"
    local query
    query=$(load_query "$query_file")

    # Build variables from config
    local variables
    variables=$(jq -n \
        --argjson first "${CONFIG_FIRST:-500}" \
        --argjson result "${CONFIG_RESULT:-'[\"FAIL\", \"ERROR\"]'}" \
        --argjson severity "${CONFIG_SEVERITY:-'[\"CRITICAL\", \"HIGH\", \"MEDIUM\"]'}" \
        '{
            first: $first,
            filter: {
                result: $result,
                severity: $severity
            }
        }')

    execute_query "$query" "$variables" "${OUTPUT_DIR}/${OUTPUT_FILE_CONFIG_FINDINGS}" "configurationFindings"
}

# Export cloud resources inventory
export_cloud_resources() {
    log_info "Exporting cloud resources inventory..."

    local query_file="${SCRIPT_DIR}/queries/cloud_resources.graphql"
    local query
    query=$(load_query "$query_file")

    # Build variables from config
    local variables
    variables=$(jq -n \
        --argjson first "${CLOUD_RESOURCES_FIRST:-500}" \
        --argjson types "${CLOUD_RESOURCES_TYPES:-'[\"VIRTUAL_MACHINE\", \"CONTAINER\", \"SERVERLESS\", \"KUBERNETES_CLUSTER\"]'}" \
        --argjson status "${CLOUD_RESOURCES_STATUS:-'[\"ACTIVE\"]'}" \
        '{
            first: $first,
            filter: {
                type: $types,
                status: $status
            }
        }')

    execute_query "$query" "$variables" "${OUTPUT_DIR}/${OUTPUT_FILE_CLOUD_RESOURCES}" "cloudResources"
}

# Export with custom query
export_custom() {
    log_info "Exporting with custom query: $CUSTOM_QUERY"

    local query
    query=$(load_query "$CUSTOM_QUERY")

    # Use basic variables - user should modify for their query
    local variables='{"first": 500}'

    # Determine output filename from query file
    local basename
    basename=$(basename "$CUSTOM_QUERY" .graphql)
    local output_file="${OUTPUT_DIR}/wiz_${basename}.json"

    # Try to detect data path from query (look for first query field)
    local data_path
    data_path=$(echo "$query" | grep -oP '(?<=\{\s*)[a-zA-Z]+(?=[\s\(])' | head -1 || echo "data")

    log_warning "Using detected data path: $data_path (modify script if incorrect)"
    execute_query "$query" "$variables" "$output_file" "$data_path"
}

# Main function
main() {
    parse_args "$@"
    validate_config

    # Check dependencies
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed. Install it with: apt-get install jq"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed."
        exit 1
    fi

    # Create output directory
    if [[ "$DRY_RUN" != "true" ]]; then
        mkdir -p "$OUTPUT_DIR"
    fi

    # Get access token
    get_access_token

    # Execute exports
    if [[ -n "$CUSTOM_QUERY" ]]; then
        export_custom
    else
        if [[ "$EXPORT_VULNERABILITIES" == "true" ]]; then
            export_vulnerabilities
        fi

        if [[ "$EXPORT_ISSUES" == "true" ]]; then
            export_issues
        fi

        if [[ "$EXPORT_CONFIG_FINDINGS" == "true" ]]; then
            export_config_findings
        fi

        if [[ "$EXPORT_CLOUD_RESOURCES" == "true" ]]; then
            export_cloud_resources
        fi
    fi

    log_success "Export completed!"

    if [[ "$DRY_RUN" != "true" ]]; then
        echo ""
        log_info "To upload to Xygeni, run:"
        echo ""
        if [[ "$EXPORT_VULNERABILITIES" == "true" ]]; then
            echo "  xygeni report-upload --report=${OUTPUT_DIR}/${OUTPUT_FILE_VULNERABILITIES} --format sca-wiz-cnapp"
        fi
        if [[ "$EXPORT_ISSUES" == "true" ]]; then
            echo "  xygeni report-upload --report=${OUTPUT_DIR}/${OUTPUT_FILE_ISSUES} --format iac-wiz-issues"
        fi
        if [[ "$EXPORT_CONFIG_FINDINGS" == "true" ]]; then
            echo "  xygeni report-upload --report=${OUTPUT_DIR}/${OUTPUT_FILE_CONFIG_FINDINGS} --format iac-wiz-config"
        fi
        if [[ "$EXPORT_CLOUD_RESOURCES" == "true" ]]; then
            echo "  xygeni report-upload --report=${OUTPUT_DIR}/${OUTPUT_FILE_CLOUD_RESOURCES} --format inventory-wiz-cnapp"
        fi
        echo ""
    fi
}

# Run main
main "$@"