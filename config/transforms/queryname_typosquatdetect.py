def transform(param):
    # Known legitimate domains to protect against typosquatting
    # Format: (domain_pattern, category)
    official_domains = [
        # US Government
        ('irs', 'GOV_US'), ('ssa', 'GOV_US'), ('medicare', 'GOV_US'),
        ('usps', 'GOV_US'), ('uscis', 'GOV_US'), ('state', 'GOV_US'),
        ('treasury', 'GOV_US'), ('whitehouse', 'GOV_US'), ('usa', 'GOV_US'),
        ('dmv', 'GOV_US'), ('fbi', 'GOV_US'), ('cia', 'GOV_US'),
        ('dhs', 'GOV_US'), ('doj', 'GOV_US'), ('epa', 'GOV_US'),
        # UK Government
        ('hmrc', 'GOV_UK'), ('nhs', 'GOV_UK'), ('dvla', 'GOV_UK'),
        ('gov', 'GOV_UK'),
        # EU/Other Government
        ('europa', 'GOV_EU'), ('gouv', 'GOV_FR'), ('bund', 'GOV_DE'),
        # Banking & Finance
        ('chase', 'BANK'), ('wellsfargo', 'BANK'), ('bankofamerica', 'BANK'),
        ('citibank', 'BANK'), ('usbank', 'BANK'), ('capitalone', 'BANK'),
        ('americanexpress', 'BANK'), ('amex', 'BANK'), ('discover', 'BANK'),
        ('paypal', 'BANK'), ('venmo', 'BANK'), ('zelle', 'BANK'),
        ('schwab', 'BANK'), ('fidelity', 'BANK'), ('vanguard', 'BANK'),
        ('coinbase', 'CRYPTO'), ('binance', 'CRYPTO'), ('kraken', 'CRYPTO'),
        # Tech Giants
        ('microsoft', 'TECH'), ('google', 'TECH'), ('apple', 'TECH'),
        ('amazon', 'TECH'), ('facebook', 'TECH'), ('meta', 'TECH'),
        ('netflix', 'TECH'), ('linkedin', 'TECH'), ('twitter', 'TECH'),
        ('instagram', 'TECH'), ('whatsapp', 'TECH'), ('telegram', 'TECH'),
        ('dropbox', 'TECH'), ('zoom', 'TECH'), ('slack', 'TECH'),
        ('github', 'TECH'), ('gitlab', 'TECH'), ('adobe', 'TECH'),
        ('salesforce', 'TECH'), ('oracle', 'TECH'), ('vmware', 'TECH'),
        # Email/Cloud
        ('outlook', 'EMAIL'), ('hotmail', 'EMAIL'), ('gmail', 'EMAIL'),
        ('yahoo', 'EMAIL'), ('icloud', 'EMAIL'), ('protonmail', 'EMAIL'),
        ('office365', 'CLOUD'), ('office', 'CLOUD'), ('onedrive', 'CLOUD'),
        ('sharepoint', 'CLOUD'), ('azure', 'CLOUD'), ('aws', 'CLOUD'),
        # Security vendors
        ('norton', 'SECURITY'), ('mcafee', 'SECURITY'), ('kaspersky', 'SECURITY'),
        ('avast', 'SECURITY'), ('malwarebytes', 'SECURITY'), ('crowdstrike', 'SECURITY'),
        # Shipping/Logistics
        ('fedex', 'SHIPPING'), ('ups', 'SHIPPING'), ('dhl', 'SHIPPING'),
        ('usps', 'SHIPPING'),
    ]
    
    # Simple edit distance
    def edit_distance(s1, s2):
        if len(s1) < len(s2):
            return edit_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]
    
    # Extract domain parts
    domain = param.rstrip('.').lower()
    parts = domain.split('.')
    
    if len(parts) < 2:
        return ''
    
    # Get the main domain (second-level domain)
    # Handle cases like co.uk, com.br, etc.
    common_cctld_sld = ['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']
    if len(parts) >= 3 and parts[-2] in common_cctld_sld:
        main_domain = parts[-3]
    else:
        main_domain = parts[-2]
    
    # Skip very short domains
    if len(main_domain) < 3:
        return ''
    
    findings = []
    for legit, category in official_domains:
        # Skip if exact match (legitimate)
        if main_domain == legit:
            return ''
        
        # Skip very short patterns
        if len(legit) < 3:
            continue
        
        dist = edit_distance(main_domain, legit)
        
        # Detect close matches
        threshold = 1 if len(legit) <= 5 else 2
        
        if 0 < dist <= threshold:
            # Identify typosquatting technique
            techniques = []
            
            # Homoglyph detection (0/o, 1/l/i, rn/m, vv/w)
            if any(c in main_domain for c in ['0', '1', 'vv', 'rn']):
                techniques.append('HOMOGLYPH')
            
            # Added/missing characters
            if abs(len(main_domain) - len(legit)) == 1:
                techniques.append('CHAR_MANIP')
            
            # Character swap
            if len(main_domain) == len(legit):
                diffs = sum(1 for a, b in zip(main_domain, legit) if a != b)
                if diffs <= 2:
                    techniques.append('CHAR_SWAP')
            
            # Prefix/suffix additions (common phishing)
            if main_domain.startswith(legit) or main_domain.endswith(legit):
                techniques.append('AFFIX')
            if legit in main_domain:
                techniques.append('EMBEDDED')
            
            tech_str = ','.join(techniques) if techniques else 'SIMILAR'
            findings.append(f'TYPOSQUAT_{category}:{legit}({tech_str})')
    
    # Also check for suspicious TLD combinations
    tld = parts[-1]
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link', 'info']
    if tld in suspicious_tlds and findings:
        findings.append(f'SUSPICIOUS_TLD:{tld}')
    
    return '|'.join(findings[:3]) if findings else ''  # Limit output
