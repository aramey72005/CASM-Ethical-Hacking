import requests
from urllib.parse import quote  # (not currently used, but useful if encoding queries later)

# Base endpoint for NVD CVE API (version 2.0)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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

    # Build search query based on available data
    query = ""
    if product and version:
        query = f"{product} {version}"
    elif product:
        query = product
    else:
        query = service or ""

    query = query.strip()

    # If nothing to search, return empty
    if not query:
        return []

    print(f"[DEBUG] NVD search: {query}")

    try:
        # Send request to NVD API
        resp = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch": query,   # keyword-based search
                "resultsPerPage": 5,      # limit results (performance control)
            },
            timeout=20,  # prevent hanging requests
        )

        # Raise error if request failed (HTTP != 200)
        resp.raise_for_status()

        # Parse JSON response
        data = resp.json()

        results = []

        # Loop through returned CVE entries
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            # Extract CVE ID (e.g., CVE-2021-41773)
            cve_id = cve.get("id")

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