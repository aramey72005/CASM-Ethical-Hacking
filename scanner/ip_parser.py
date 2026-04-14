#ip_parser.py
import ipaddress

def expand_targets(target):
    """
    Accepts:
    - single IP
    - CIDR (192.168.1.0/24)
    - simple range shorthand (optional custom)

    Returns list of IPs
    """

    # CIDR support
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]

    # single IP
    try:
        ipaddress.ip_address(target)
        return [target]
    except:
        pass

    # fallback
    return [target]