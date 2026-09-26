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

    # Domains (simplified): what
    #   re.findall(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|...))\b', param, re.I)
    # returns, in linear time. A domain is the run of [-a-zA-Z0-9] that ends
    # where a TLD begins, from its first start at a word boundary. The findall
    # form retries every start inside a run, and a run such as 'a-a-a-...' has
    # a word boundary after every hyphen, which makes it quadratic. Starting
    # from the TLD matches, which are few, and walking back over the run
    # visits each character at most once: runs never cross the '.' of a TLD.
    run_char = re.compile(r'[-a-zA-Z0-9]', re.IGNORECASE)
    start_re = re.compile(r'\b[a-zA-Z0-9]', re.IGNORECASE)
    tld_re = re.compile(r'\.(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz)\b', re.IGNORECASE)
    domains = []
    pos = 0
    for tld in tld_re.finditer(param):
        end = tld.start()
        begin = end
        while begin > pos and run_char.match(param, begin - 1):
            begin -= 1
        start = start_re.search(param, begin, end)
        if start is None:
            continue
        domains.append(param[start.start():tld.end()])
        pos = tld.end()
    for domain in set(domains):
        iocs.append('DOMAIN:' + domain)

    return '|'.join(iocs[:20]) if iocs else ''  # Limit total IOCs
