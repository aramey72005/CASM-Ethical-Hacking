import time

import requests
from urllib.parse import quote  # (not currently used, but useful if encoding queries later)

# Base endpoint for NVD CVE API (version 2.0)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Public NVD requests without an API key are rate limited. The delay plus
# in-process cache keep normal classroom/lab scans from hammering the API.
NVD_REQUEST_DELAY_SECONDS = 6.2
NVD_QUERY_CACHE = {}
LAST_NVD_REQUEST_AT = 0.0


def throttle_nvd_request():
    global LAST_NVD_REQUEST_AT

    # Sleep only for the remaining time needed since the last outgoing request.
    elapsed = time.monotonic() - LAST_NVD_REQUEST_AT
    wait_for = NVD_REQUEST_DELAY_SECONDS - elapsed

    if wait_for > 0:
        time.sleep(wait_for)

    LAST_NVD_REQUEST_AT = time.monotonic()


def build_search_queries(service: str, product: str | None = None, version: str | None = None) -> list[str]:
    """
    Builds NVD keyword searches from scanner service data.

    Nmap and NVD do not always use the same product names. For example,
    Nmap often reports Apache as "Apache httpd", while NVD commonly uses
    "Apache HTTP Server" or the CPE product name "http_server".
    """
    candidates = []

    product_lower = (product or "").lower()
    service_lower = (service or "").lower()
    is_apache_httpd = (
        "apache" in product_lower and ("httpd" in product_lower or "http" in service_lower)
    )

    if is_apache_httpd:
        if version:
            # Apache is the main place Nmap/NVD naming differs in this project:
            # Nmap reports "Apache httpd", while NVD often matches
            # "Apache HTTP Server" or CPE-like "http_server".
            candidates.extend([
                f"Apache HTTP Server {version}",
                f"Apache http_server {version}",
                f"http_server {version}",
            ])

    if product and version:
        candidates.append(f"{product} {version}")
    elif product:
        candidates.append(product)
    elif service and service_lower not in {"tcpwrapped", "unknown"}:
        # Only fall back to service name when no product was detected. Broad
        # names like "rtsp" can cause false-positive CVEs, so product/version
        # data is strongly preferred.
        candidates.append(service)

    queries = []
    seen = set()

    for candidate in candidates:
        query = str(candidate or "").strip()
        key = query.lower()
        if query and key not in seen:
            queries.append(query)
            seen.add(key)

    return queries


def get_severity(score: float) -> str:
    """
    Converts a numeric CVSS score into a severity label.

    CVSS ranges:
    9.0–10.0 → CRITICAL
    7.0–8.9  → HIGH
    4.0–6.9  → MEDIUM
    0.1–3.9  → LOW
    0        → UNKNOWN
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def extract_cvss(cve_obj: dict) -> tuple[float, str]:
    """
    Extracts CVSS score and severity from an NVD CVE object.

    NVD provides multiple CVSS versions:
    - v3.1 (most recent)
    - v3.0
    - v2 (fallback)

    This function:
    1. Checks each version in priority order
    2. Extracts the base score
    3. Determines severity (uses provided value or calculates it)
    """
    metrics = cve_obj.get("metrics", {})

    # Try CVSS versions in order of preference
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)

        # Ensure the metric exists and is a list
        if arr and isinstance(arr, list):
            first = arr[0]  # Take first scoring entry
            cvss_data = first.get("cvssData", {})

            # Extract base score (default 0 if missing)
            score = cvss_data.get("baseScore", 0.0)

            # Try to get severity directly from NVD, otherwise compute it
            severity = (
                first.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or get_severity(float(score or 0))
            )

            return float(score or 0), severity

    # If no CVSS data found
    return 0.0, "UNKNOWN"


def lookup_cves(service: str, product: str | None = None, version: str | None = None) -> list[dict]:
    """
    Queries the NVD API to find CVEs related to a given service/product/version.

    Priority of search query:
    1. product + version (most specific)
    2. product only
    3. service name fallback

    Returns:
    A list of CVE dictionaries:
    [
        {
            "cve_id": "...",
            "cvss": float,
            "severity": "CRITICAL/HIGH/etc",
            "title": short description
        }
    ]
    """

    queries = build_search_queries(service, product, version)

    # If nothing to search, return empty
    if not queries:
        return []

    try:
        results = []
        seen_cves = set()

        for query in queries:
            print(f"[DEBUG] NVD search: {query}")

            cache_key = query.lower()
            if cache_key in NVD_QUERY_CACHE:
                # Repeated products across hosts should reuse the same response
                # instead of making duplicate NVD calls.
                data = NVD_QUERY_CACHE[cache_key]
                print(f"[DEBUG] NVD cache hit: {query}")
            else:
                throttle_nvd_request()

                # Send request to NVD API.
                resp = requests.get(
                    NVD_API_URL,
                    params={
                        "keywordSearch": query,   # keyword-based search
                        "resultsPerPage": 20,     # keep one focused request richer than many broad ones
                    },
                    timeout=20,  # prevent hanging requests
                )

                if resp.status_code == 429:
                    # A 429 means "unknown right now", not "no CVEs". Preserve
                    # partial results and let the terminal warning explain why
                    # later aliases for this service were skipped.
                    retry_after = resp.headers.get("Retry-After")
                    print(
                        "[WARN] NVD rate limit hit. "
                        f"Skipping remaining queries for this service. Retry-After={retry_after or 'unknown'}"
                    )
                    break

                # Raise error if request failed (HTTP != 200)
                resp.raise_for_status()

                # Parse JSON response
                data = resp.json()
                NVD_QUERY_CACHE[cache_key] = data

            # Loop through returned CVE entries
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})

                # Extract CVE ID (e.g., CVE-2021-41773)
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen_cves:
                    continue

                seen_cves.add(cve_id)

                # Extract CVSS score + severity
                score, severity = extract_cvss(cve)

                print(f"[DEBUG] CVE {cve_id} → score={score}, severity={severity}")

                # Extract English description (if available)
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # Store simplified CVE object for your system
                results.append({
                    "cve_id": cve_id,
                    "cvss": score,
                    "severity": severity,
                    "title": desc[:200] if desc else "",  # trim long descriptions
                })

        return results

    except Exception as e:
        # Handle network/API errors safely
        print(f"[ERROR] NVD lookup failed: {e}")
        return []
