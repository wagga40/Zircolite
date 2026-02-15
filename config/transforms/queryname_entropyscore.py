def transform(param):
    import re
    # Remove TLD and calculate entropy-like metric
    domain = param.rstrip('.').split('.')[0] if '.' in param else param
    
    # Simple character frequency analysis
    if len(domain) == 0:
        return '0'
    
    char_count = {}
    for c in domain.lower():
        char_count[c] = char_count.get(c, 0) + 1
    
    # Calculate simple entropy approximation
    entropy = 0
    for count in char_count.values():
        freq = count / len(domain)
        if freq > 0:
            # Simplified entropy calculation without math.log
            entropy += freq * (1 - freq)
    
    # High entropy suggests DGA
    entropy_score = round(entropy * 100, 2)
    return str(entropy_score)
