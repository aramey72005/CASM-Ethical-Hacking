# ip_parser.py
import ipaddress


def normalize_target_spec(target):
    """
    Normalize a scan target into an Nmap-friendly host spec.

    Supports:
    - single IPs
    - CIDR notation such as 192.168.1.0/24
    - hostnames
    - comma-separated target lists
    """
    if target is None:
        raise ValueError("Scan target cannot be empty.")

    raw_target = str(target).strip()
    if not raw_target:
        raise ValueError("Scan target cannot be empty.")

    normalized_parts = []

    for part in raw_target.split(","):
        candidate = part.strip()
        if not candidate:
            continue

        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=False)
            normalized_parts.append(str(network))
            continue

        try:
            ipaddress.ip_address(candidate)
            normalized_parts.append(candidate)
            continue
        except ValueError:
            normalized_parts.append(candidate)

    if not normalized_parts:
        raise ValueError("Scan target cannot be empty.")

    return ",".join(normalized_parts)


def expand_targets(target):
    """
    Accepts:
    - single IP
    - CIDR (192.168.1.0/24)

    Returns list of IPs
    """
    normalized_target = normalize_target_spec(target)

    if "," in normalized_target:
        expanded = []
        for part in normalized_target.split(","):
            expanded.extend(expand_targets(part))
        return expanded

    if "/" in normalized_target:
        net = ipaddress.ip_network(normalized_target, strict=False)
        return [str(ip) for ip in net.hosts()]

    return [normalized_target]
