def transform(param):
    import re
    iocs = []
    
    # IPv4 addresses
    ipv4_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ips = re.findall(ipv4_pattern, param)
    for ip in ips:
        # Filter out common non-IOC IPs
        if not ip.startswith(('0.', '127.', '255.')):
            iocs.append('IP:' + ip)
    
    # URLs
    url_pattern = r'(https?://[^\s\'"<>]+)'
    urls = re.findall(url_pattern, param, re.IGNORECASE)
    for url in urls[:5]:  # Limit to first 5
        url = url.rstrip('.,;:)]\'"')
        iocs.append('URL:' + url[:100])
    
    # Domains (simplified)
    domain_pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz))\b'
    domains = re.findall(domain_pattern, param, re.IGNORECASE)
    for domain in set(domains):
        iocs.append('DOMAIN:' + domain)
    
    return '|'.join(iocs[:20]) if iocs else ''  # Limit total IOCs
