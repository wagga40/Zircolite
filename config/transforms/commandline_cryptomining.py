def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # Mining protocols
    if re.search(r'stratum\+tcp://|stratum\+ssl://|stratum2\+tcp://', param_lower):
        findings.append('MINING:PROTOCOL')

    # Known mining pools
    pools = ['nanopool', 'f2pool', 'ethermine', 'nicehash', 'unmineable',
             'moneroocean', 'minexmr', 'hashvault', 'supportxmr',
             'minergate', 'antpool', 'poolin', 'viabtc', 'slushpool',
             'flexpool', 'hiveon', 'crazypool', 'herominers']
    for pool in pools:
        if pool in param_lower:
            findings.append('MINING:POOL:' + pool)
            break

    # Wallet patterns
    # Monero (95 chars starting with 4)
    if re.search(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', param):
        findings.append('MINING:WALLET:MONERO')
    # Bitcoin
    if re.search(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', param):
        findings.append('MINING:WALLET:BITCOIN')
    # Ethereum
    if re.search(r'\b0x[0-9a-fA-F]{40}\b', param):
        findings.append('MINING:WALLET:ETHEREUM')

    # Known miner tools
    miners = ['xmrig', 'nbminer', 't-rex', 'phoenixminer', 'gminer',
              'lolminer', 'teamredminer', 'nanominer', 'cpuminer',
              'cgminer', 'bfgminer', 'ethminer', 'minerd']
    for miner in miners:
        if miner in param_lower:
            findings.append('MINING:TOOL:' + miner)
            break

    # Mining-specific arguments
    if re.search(r'--algo\s|--donate-level|--cpu-priority|--coin\s|--threads\s.*--algo', param_lower):
        findings.append('MINING:MINER_ARGS')

    return '|'.join(findings[:4]) if findings else ''
