import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("storm")

BASE_URL = "http://localhost:8080/api"


# ── 1. Port Scan ──────────────────────────────────────────────────────────────

@mcp.tool()
def port_scan(
    host: str,
    start_port: int,
    end_port: int,
    threads: int = 100,
    timeout_ms: int = 200,
) -> dict:
    """
    Scan TCP ports on a target host.

    Args:
        host: Target IP or hostname (e.g. 192.168.1.1)
        start_port: First port to scan (1-65535)
        end_port: Last port to scan (1-65535)
        threads: Number of threads (1-500, default 100)
        timeout_ms: Timeout per port in milliseconds (50-10000, default 200)
    """
    payload = {
        "host": host,
        "startPort": start_port,
        "endPort": end_port,
        "threads": threads,
        "timeoutMs": timeout_ms,
    }
    response = httpx.post(f"{BASE_URL}/scan/ports", json=payload, timeout=300)
    response.raise_for_status()
    return response.json()


# ── 2. Host Discovery ─────────────────────────────────────────────────────────

@mcp.tool()
def host_discovery(
    target: str,
    threads: int = 10,
    timeout_ms: int = 200,
) -> dict:
    """
    Discover live hosts in a network range.

    Args:
        target: CIDR (192.168.1.0/24), IP range (192.168.1.1-192.168.1.254), or single IP
        threads: Number of threads (default 10)
        timeout_ms: Timeout in milliseconds (default 200)
    """
    payload = {
        "target": target,
        "threads": threads,
        "timeoutMs": timeout_ms,
    }
    response = httpx.post(f"{BASE_URL}/scan/discover", json=payload, timeout=300)
    response.raise_for_status()
    return response.json()


# ── 3. Service Fingerprint ────────────────────────────────────────────────────

@mcp.tool()
def service_fingerprint(
    host: str,
    ports: str,
    timeout_ms: int = 500,
) -> dict:
    """
    Identify services and detect vulnerabilities on specific ports.

    Args:
        host: Target IP or hostname
        ports: Comma-separated list of ports (e.g. "22,80,443,3306")
        timeout_ms: Timeout in milliseconds (default 500)

    Detects risks on: FTP(21), SSH(22), Telnet(23), SMTP(25/587),
    DNS(53), HTTP(80/8080), HTTPS(443/8443), SMB(445),
    MySQL(3306), RDP(3389), VNC(5900)
    """
    payload = {
        "host": host,
        "ports": ports,
        "timeoutMs": timeout_ms,
    }
    response = httpx.post(f"{BASE_URL}/scan/fingerprint", json=payload, timeout=300)
    response.raise_for_status()
    return response.json()


# ── 4. Directory Fuzz ─────────────────────────────────────────────────────────

@mcp.tool()
def directory_fuzz(
    target: str,
    wordlist: str = "common.txt",
    threads: int = 10,
) -> dict:
    """
    Discover hidden paths and endpoints on a web server.

    Args:
        target: Target URL (e.g. http://example.com)
        wordlist: Wordlist to use — "common.txt" or "subdomains.txt" (default common.txt)
        threads: Number of threads (default 10)
    """
    payload = {
        "target": target,
        "wordlist": wordlist,
        "threads": threads,
    }
    response = httpx.post(f"{BASE_URL}/scan/fuzz", json=payload, timeout=300)
    response.raise_for_status()
    return response.json()


# ── 5. Scan History ───────────────────────────────────────────────────────────

@mcp.tool()
def get_scan_history() -> list:
    """
    Get all past scans ordered by most recent.
    Returns scan id, target, type, startedAt, completedAt, and results.
    """
    response = httpx.get(f"{BASE_URL}/scan/history", timeout=30)
    response.raise_for_status()
    return response.json()


# ── 6. Get Scan by ID ─────────────────────────────────────────────────────────

@mcp.tool()
def get_scan_by_id(scan_id: int) -> dict:
    """
    Get a specific scan with all its results.

    Args:
        scan_id: The ID of the scan to retrieve
    """
    response = httpx.get(f"{BASE_URL}/scan/history/{scan_id}", timeout=30)
    response.raise_for_status()
    return response.json()


# ── 7. Delete Scan ────────────────────────────────────────────────────────────

@mcp.tool()
def delete_scan(scan_id: int) -> str:
    """
    Delete a scan and all its results.

    Args:
        scan_id: The ID of the scan to delete
    """
    response = httpx.delete(f"{BASE_URL}/scan/history/{scan_id}", timeout=30)
    if response.status_code == 204:
        return f"✅ Scan {scan_id} deleted successfully."
    response.raise_for_status()
    return f"Deleted scan {scan_id}."


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")