from fastmcp import FastMCP
import requests
import json
import urllib3
import logging
import time
from typing import Optional, Dict, Any, List
from datetime import datetime
import os
from dataclasses import dataclass
import socket

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BASE_URL = os.getenv("NESSUS_URL", "https://localhost:8834")
ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", "Nhap key vao day")
SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", "Nhap key vao day")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NessusConfig:
    base_url: str = BASE_URL
    access_key: str = ACCESS_KEY
    secret_key: str = SECRET_KEY
    timeout: int = 60  # Increased timeout
    max_retries: int = 5  # Increased retries
    retry_delay: int = 2  # Shorter initial delay
    backoff_multiplier: float = 1.5  # Exponential backoff


config = NessusConfig()


class NessusAPIError(Exception):
    """Custom exception for Nessus API errors"""
    pass


class NessusAPI:
    def __init__(self, config: NessusConfig):
        self.config = config
        self.headers = {
            "X-ApiKeys": f"accessKey={config.access_key}; secretKey={config.secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "NessusMCP/1.0"
        }
        # Create session with better settings
        self.session = requests.Session()
        self.session.verify = False

        # Configure session with connection pooling and keep-alive
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=0,  # We handle retries manually
            pool_block=False
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set connection timeout and read timeout
        self.session.timeout = (10, config.timeout)

    def _check_connectivity(self) -> bool:
        """Check if we can reach the Nessus server"""
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.config.base_url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 8834)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()

            return result == 0
        except Exception as e:
            logger.warning(f"Connectivity check failed: {e}")
            return False

    def _make_request(self, endpoint: str, method: str = "GET",
                      payload: Optional[Dict] = None, retries: int = 0) -> Dict[str, Any]:
        """Enhanced API call with exponential backoff and better error handling"""
        url = f"{self.config.base_url}{endpoint}"

        # Check basic connectivity first
        if retries == 0 and not self._check_connectivity():
            return {
                "error": True,
                "message": f"Cannot connect to Nessus server at {self.config.base_url}. Check if server is running and accessible."
            }

        try:
            # Prepare request parameters
            request_kwargs = {
                "headers": self.headers,
                "timeout": (10, self.config.timeout),
                "verify": False,
                "allow_redirects": True
            }

            if payload:
                request_kwargs["data"] = json.dumps(payload, ensure_ascii=False)

            # Make the request
            if method == "GET":
                response = self.session.get(url, **request_kwargs)
            elif method == "POST":
                response = self.session.post(url, **request_kwargs)
            elif method == "DELETE":
                response = self.session.delete(url, **request_kwargs)
            elif method == "PUT":
                response = self.session.put(url, **request_kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            # Log response details for debugging
            logger.debug(f"{method} {endpoint} -> {response.status_code}")

            # Handle successful responses
            if response.status_code in [200, 201, 202]:
                try:
                    if response.content:
                        return response.json()
                    else:
                        return {"success": True, "message": "Operation completed successfully"}
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON response: {e}")
                    return {"success": True, "message": "Operation completed", "raw_response": response.text[:200]}

            # Handle authentication errors
            elif response.status_code == 401:
                error_msg = "Authentication failed. Check your API keys."
                logger.error(error_msg)
                return {"error": True, "status_code": response.status_code, "message": error_msg}

            # Handle forbidden access
            elif response.status_code == 403:
                error_msg = "Access forbidden. Check your API permissions."
                logger.error(error_msg)
                return {"error": True, "status_code": response.status_code, "message": error_msg}

            # Handle not found
            elif response.status_code == 404:
                error_msg = f"Endpoint not found: {endpoint}"
                logger.error(error_msg)
                return {"error": True, "status_code": response.status_code, "message": error_msg}

            # Handle rate limiting
            elif response.status_code == 429:
                if retries < self.config.max_retries:
                    delay = self.config.retry_delay * (self.config.backoff_multiplier ** retries)
                    logger.warning(f"Rate limited, retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    return self._make_request(endpoint, method, payload, retries + 1)
                else:
                    error_msg = "Rate limit exceeded. Try again later."
                    return {"error": True, "status_code": response.status_code, "message": error_msg}

            # Handle other client/server errors
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', response.text)
                except:
                    error_msg = response.text

                logger.error(f"API Error - {method} {endpoint}: {response.status_code} - {error_msg}")
                return {"error": True, "status_code": response.status_code,
                        "message": f"HTTP {response.status_code}: {error_msg}"}

        except requests.exceptions.ConnectionError as e:
            if retries < self.config.max_retries:
                delay = self.config.retry_delay * (self.config.backoff_multiplier ** retries)
                logger.warning(
                    f"Connection error, retrying in {delay:.1f}s... (attempt {retries + 1}/{self.config.max_retries})")
                time.sleep(delay)
                return self._make_request(endpoint, method, payload, retries + 1)
            else:
                error_msg = f"Connection failed after {self.config.max_retries} retries. Check network connectivity and server status."
                logger.error(f"{error_msg} - {str(e)}")
                return {"error": True, "message": error_msg, "details": str(e)}

        except requests.exceptions.Timeout as e:
            if retries < self.config.max_retries:
                delay = self.config.retry_delay * (self.config.backoff_multiplier ** retries)
                logger.warning(
                    f"Request timeout, retrying in {delay:.1f}s... (attempt {retries + 1}/{self.config.max_retries})")
                time.sleep(delay)
                return self._make_request(endpoint, method, payload, retries + 1)
            else:
                error_msg = f"Request timeout after {self.config.timeout}s. Server may be overloaded."
                logger.error(f"{error_msg} - {str(e)}")
                return {"error": True, "message": error_msg, "details": str(e)}

        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            return {"error": True, "message": error_msg}

        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(f"{error_msg} - {type(e).__name__}")
            return {"error": True, "message": error_msg, "error_type": type(e).__name__}


# Initialize API client
nessus_api = NessusAPI(config)

# === FastMCP Setup ===
mcp = FastMCP("MBAL_SEC TOOLS")


@mcp.tool()
def list_nessus_scans() -> str:
    """List all Nessus scans with their current status.

    Returns:
        JSON string containing scan information including ID, name, status, and dates.
    """
    try:
        logger.info("Listing Nessus scans...")
        result = nessus_api._make_request("/scans")

        if result.get("error"):
            logger.error(f"Failed to list scans: {result.get('message')}")
            return json.dumps({"error": result.get("message")})

        # Extract and format scan information
        scans = result.get("scans", [])
        formatted_scans = []

        for scan in scans:
            formatted_scan = {
                "scan_id": str(scan.get("id", "")),
                "name": scan.get("name", ""),
                "status": scan.get("status", "unknown"),
                "creation_date": scan.get("creation_date", 0),
                "last_modification_date": scan.get("last_modification_date", 0)
            }
            formatted_scans.append(formatted_scan)

        logger.info(f"Found {len(formatted_scans)} scans")
        return json.dumps(formatted_scans, indent=2)

    except Exception as e:
        error_msg = f"Failed to list scans: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def create_nessus_scan(name: str, targets: str, template_name: str = "basic", policy_id: Optional[str] = None) -> str:
    """Create a new Nessus scan.

    Args:
        name: Name for the new scan
        targets: Target IP addresses or hostnames (comma-separated or range format)
        template_name: Scan template to use (default: "basic")
        policy_id: Optional policy ID to use

    Returns:
        JSON string with scan creation result including scan ID.
    """
    try:
        logger.info(f"Creating scan '{name}' for targets '{targets}' with template '{template_name}'")

        # Get available templates first
        logger.info("Fetching scan templates...")
        templates_result = nessus_api._make_request("/editor/scan/templates")

        if templates_result.get("error"):
            error_msg = f"Failed to get templates: {templates_result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        # Find template UUID
        template_uuid = None
        templates = templates_result.get("templates", [])

        # Map common template names to actual names
        template_mapping = {
            "basic": "Basic Network Scan",
            "discovery": "Host Discovery",
            "full": "Advanced Scan",
            "web": "Web Application Tests"
        }

        actual_template_name = template_mapping.get(template_name.lower(), template_name)

        for template in templates:
            if (template.get("name", "").lower() == template_name.lower() or
                    template.get("title", "").lower() == template_name.lower() or
                    template.get("name") == actual_template_name):
                template_uuid = template.get("uuid")
                logger.info(f"Found template: {template.get('name')} ({template_uuid})")
                break

        if not template_uuid:
            available_templates = [{"name": t.get("name", ""), "title": t.get("title", "")} for t in templates]
            error_msg = f"Template '{template_name}' not found"
            logger.error(f"{error_msg}. Available templates: {available_templates}")
            return json.dumps({
                "error": error_msg,
                "available_templates": available_templates
            })

        # Prepare scan payload
        payload = {
            "uuid": template_uuid,
            "settings": {
                "name": name,
                "enabled": True,
                "text_targets": targets.strip(),
                "launch_now": False  # Don't auto-launch
            }
        }

        if policy_id:
            payload["settings"]["policy_id"] = policy_id

        logger.info(f"Creating scan with payload: {json.dumps(payload, indent=2)}")

        # Create the scan
        result = nessus_api._make_request("/scans", method="POST", payload=payload)

        if result.get("error"):
            error_msg = f"Failed to create scan: {result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        scan_info = result.get("scan", {})
        scan_id = str(scan_info.get("id", ""))

        logger.info(f"Successfully created scan with ID: {scan_id}")

        return json.dumps({
            "success": True,
            "scan_id": scan_id,
            "name": name,
            "template": template_name,
            "targets": targets,
            "uuid": scan_info.get("uuid", ""),
            "message": "Scan created successfully"
        }, indent=2)

    except Exception as e:
        error_msg = f"Failed to create scan: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def launch_nessus_scan(scan_id: str) -> str:
    """Launch a Nessus scan by ID.

    Args:
        scan_id: ID of the scan to launch

    Returns:
        JSON string with launch result including scan UUID.
    """
    try:
        logger.info(f"Launching scan {scan_id}")
        result = nessus_api._make_request(f"/scans/{scan_id}/launch", method="POST")

        if result.get("error"):
            error_msg = f"Failed to launch scan: {result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        scan_uuid = result.get("scan_uuid", "")
        logger.info(f"Successfully launched scan {scan_id} with UUID: {scan_uuid}")

        return json.dumps({
            "success": True,
            "scan_id": scan_id,
            "scan_uuid": scan_uuid,
            "message": f"Scan {scan_id} launched successfully"
        }, indent=2)

    except Exception as e:
        error_msg = f"Failed to launch scan: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def get_nessus_scan_status(scan_id: str) -> str:
    """Get the current status of a Nessus scan.

    Args:
        scan_id: ID of the scan to check

    Returns:
        JSON string with scan status and details.
    """
    try:
        logger.info(f"Getting status for scan {scan_id}")
        result = nessus_api._make_request(f"/scans/{scan_id}")

        if result.get("error"):
            error_msg = f"Failed to get scan status: {result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        info = result.get("info", {})

        status_info = {
            "scan_id": scan_id,
            "name": info.get("name", ""),
            "status": info.get("status", "unknown"),
            "start_time": info.get("scan_start", 0),
            "end_time": info.get("scan_end", 0),
            "progress": info.get("progress", "N/A"),
            "targets": info.get("targets", ""),
            "host_count": info.get("hostcount", 0),
            "policy": info.get("policy", ""),
            "scanner_name": info.get("scanner_name", "")
        }

        logger.info(f"Scan {scan_id} status: {status_info['status']}")
        return json.dumps(status_info, indent=2)

    except Exception as e:
        error_msg = f"Failed to get scan status: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def get_nessus_scan_results(scan_id: str, format_type: str = "summary") -> str:
    """Get Nessus scan results.

    Args:
        scan_id: ID of the scan to get results for
        format_type: Type of results to return ("summary" or "detailed")

    Returns:
        JSON string with scan results.
    """
    try:
        logger.info(f"Getting results for scan {scan_id} (format: {format_type})")
        result = nessus_api._make_request(f"/scans/{scan_id}")

        if result.get("error"):
            error_msg = f"Failed to get scan results: {result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        info = result.get("info", {})

        if format_type == "summary":
            # Count vulnerabilities by severity
            vuln_counts = {}
            hosts = result.get("hosts", [])
            vulnerabilities = result.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                severity = vuln.get("severity_name", "Unknown")
                vuln_counts[severity] = vuln_counts.get(severity, 0) + vuln.get("count", 1)

            summary = {
                "scan_id": scan_id,
                "name": info.get("name", ""),
                "status": info.get("status", "unknown"),
                "total_hosts": len(hosts),
                "vulnerabilities": vuln_counts,
                "scan_duration": info.get("scan_end", 0) - info.get("scan_start", 0) if info.get("scan_end") else None
            }

            logger.info(f"Scan {scan_id} summary: {len(hosts)} hosts, {sum(vuln_counts.values())} vulnerabilities")
            return json.dumps(summary, indent=2)

        else:  # detailed
            return json.dumps(result, indent=2)

    except Exception as e:
        error_msg = f"Failed to get scan results: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def delete_nessus_scan(scan_id: str) -> str:
    """Delete a Nessus scan.

    Args:
        scan_id: ID of the scan to delete

    Returns:
        JSON string with deletion result.
    """
    try:
        logger.info(f"Deleting scan {scan_id}")
        result = nessus_api._make_request(f"/scans/{scan_id}", method="DELETE")

        if result.get("error"):
            error_msg = f"Failed to delete scan: {result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        logger.info(f"Successfully deleted scan {scan_id}")
        return json.dumps({
            "success": True,
            "scan_id": scan_id,
            "message": f"Scan {scan_id} deleted successfully"
        }, indent=2)

    except Exception as e:
        error_msg = f"Failed to delete scan: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def list_nessus_policies() -> str:
    """List all available Nessus scan policies.

    Returns:
        JSON string with policy information.
    """
    try:
        logger.info("Listing Nessus policies...")
        result = nessus_api._make_request("/policies")

        if result.get("error"):
            error_msg = f"Failed to list policies: {result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        policies = result.get("policies", [])
        formatted_policies = []

        for policy in policies:
            formatted_policy = {
                "policy_id": str(policy.get("id", "")),
                "name": policy.get("name", ""),
                "description": policy.get("description", ""),
                "template_uuid": policy.get("template_uuid", ""),
                "creation_date": policy.get("creation_date", 0)
            }
            formatted_policies.append(formatted_policy)

        logger.info(f"Found {len(formatted_policies)} policies")
        return json.dumps(formatted_policies, indent=2)

    except Exception as e:
        error_msg = f"Failed to list policies: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def list_nessus_templates() -> str:
    """List all available Nessus scan templates.

    Returns:
        JSON string with template information.
    """
    try:
        logger.info("Listing Nessus templates...")
        result = nessus_api._make_request("/editor/scan/templates")

        if result.get("error"):
            error_msg = f"Failed to list templates: {result.get('message')}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        templates = result.get("templates", [])
        formatted_templates = []

        for template in templates:
            formatted_template = {
                "uuid": template.get("uuid", ""),
                "name": template.get("name", ""),
                "title": template.get("title", ""),
                "description": template.get("desc", "N/A"),
                "subscription_only": template.get("subscription_only", False)
            }
            formatted_templates.append(formatted_template)

        logger.info(f"Found {len(formatted_templates)} templates")
        return json.dumps(formatted_templates, indent=2)

    except Exception as e:
        error_msg = f"Failed to list templates: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


@mcp.tool()
def bulk_scan_operations(operation: str, scan_ids: str) -> str:
    """Perform bulk operations on multiple scans.

    Args:
        operation: Operation to perform ("launch", "delete", "status")
        scan_ids: Comma-separated list of scan IDs

    Returns:
        JSON string with bulk operation results.
    """
    try:
        logger.info(f"Performing bulk {operation} operation on scans: {scan_ids}")
        scan_id_list = [sid.strip() for sid in scan_ids.split(",") if sid.strip()]
        results = []

        for scan_id in scan_id_list:
            logger.info(f"Processing scan {scan_id} for {operation}")

            if operation == "launch":
                result = json.loads(launch_nessus_scan(scan_id))
            elif operation == "delete":
                result = json.loads(delete_nessus_scan(scan_id))
            elif operation == "status":
                result = json.loads(get_nessus_scan_status(scan_id))
            else:
                result = {"error": f"Unsupported operation: {operation}"}

            results.append({
                "scan_id": scan_id,
                "operation": operation,
                "success": not result.get("error"),
                "result": result.get("message") if not result.get("error") else result.get("error"),
                "details": result
            })

        logger.info(f"Bulk operation completed: {len(results)} scans processed")
        return json.dumps(results, indent=2)

    except Exception as e:
        error_msg = f"Failed bulk operation: {str(e)}"
        logger.error(error_msg)
        return json.dumps({"error": error_msg})


def _perform_health_check() -> Dict[str, Any]:
    """Internal health check function that returns a dict."""
    try:
        logger.info(f"Performing health check on {config.base_url}")

        # Try to get server properties
        result = nessus_api._make_request("/server/properties")

        if result.get("error"):
            logger.error(f"Health check failed: {result.get('message')}")
            return {
                "healthy": False,
                "error": result.get("message"),
                "server_url": config.base_url,
                "timestamp": datetime.now().isoformat()
            }

        health_info = {
            "healthy": True,
            "server_version": result.get("server_version", "Unknown"),
            "nessus_type": result.get("nessus_type", "Unknown"),
            "server_url": config.base_url,
            "license": result.get("license", {}),
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"Health check passed - Version: {health_info['server_version']}")
        return health_info

    except Exception as e:
        error_msg = f"Health check failed: {str(e)}"
        logger.error(error_msg)
        return {
            "healthy": False,
            "error": error_msg,
            "server_url": config.base_url,
            "timestamp": datetime.now().isoformat()
        }


@mcp.tool()
def nessus_health_check() -> str:
    """Check Nessus server health and connectivity.

    Returns:
        JSON string with health status.
    """
    health_info = _perform_health_check()
    return json.dumps(health_info, indent=2)


if __name__ == "__main__":
    # Validate configuration
    if ACCESS_KEY == "YOUR_ACCESS_KEY" or SECRET_KEY == "YOUR_SECRET_KEY":
        logger.warning("Please set your Nessus API keys in environment variables or update the code")
        logger.info("Set NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY environment variables")

    # Perform initial health check
    logger.info("Performing initial health check...")
    health_result = _perform_health_check()

    if health_result.get("healthy"):
        logger.info(
            f" Connected to Nessus {health_result.get('nessus_type', 'Unknown')} v{health_result.get('server_version', 'Unknown')}")
    else:
        logger.error(f" Failed to connect to Nessus server: {health_result.get('error')}")
        logger.info("Please check your configuration and server status")

    logger.info(f"Starting Nessus MCP server connecting to: {BASE_URL}")
    mcp.run()