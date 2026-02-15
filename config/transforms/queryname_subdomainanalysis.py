def transform(param):
    import re
    findings = []
    domain = param.rstrip('.')
    parts = domain.split('.')

    if len(parts) < 3:
        return ''

    # Subdomain depth (everything before registered domain + TLD)
    # Approximate: last 2 parts are domain+TLD
    common_cctld_sld = ['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']
    if len(parts) >= 3 and parts[-2] in common_cctld_sld:
        subdomain_parts = parts[:-3]
    else:
        subdomain_parts = parts[:-2]

    if not subdomain_parts:
        return ''

    subdomain = '.'.join(subdomain_parts)
    depth = len(subdomain_parts)

    # Deep subdomain nesting
    if depth > 3:
        findings.append('DNS:DEEP_SUB:' + str(depth))

    # Long subdomain (data encoding indicator)
    if len(subdomain) > 30:
        findings.append('DNS:LONG_SUB:' + str(len(subdomain)))

    # Hex patterns in subdomain
    if re.search(r'[0-9a-f]{16,}', subdomain, re.IGNORECASE):
        findings.append('DNS:HEX_SUBDOMAIN')

    # Base64-like patterns
    if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', subdomain):
        findings.append('DNS:B64_SUBDOMAIN')

    # High entropy subdomain (Shannon entropy)
    if len(subdomain) > 10:
        clean = subdomain.replace('.', '').lower()
        if clean:
            freq_map = {}
            for c in clean:
                freq_map[c] = freq_map.get(c, 0) + 1
            ent = 0.0
            for cnt in freq_map.values():
                f = cnt / len(clean)
                if f > 0:
                    ent -= f * math.log2(f)
            if ent > 3.5 and len(clean) > 15:
                findings.append('DNS:HIGH_ENTROPY_SUB')

    # Numeric-heavy subdomain
    if len(subdomain) > 5:
        digit_count = sum(1 for c in subdomain if c.isdigit())
        if digit_count / len(subdomain) > 0.5:
            findings.append('DNS:NUMERIC_SUB')

    return '|'.join(findings[:4]) if findings else ''
