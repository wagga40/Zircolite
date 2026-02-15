def transform(param):
    if len(param) < 2:
        return 'LOW:0.00'
    n = len(param)
    freq_map = {}
    for c in param:
        freq_map[c] = freq_map.get(c, 0) + 1
    entropy = 0.0
    for count in freq_map.values():
        freq = count / n
        if freq > 0:
            entropy -= freq * math.log2(freq)
    score = round(entropy, 2)
    if score < 3.0:
        return 'LOW:' + str(score)
    elif score < 4.0:
        return 'MEDIUM:' + str(score)
    elif score < 4.5:
        return 'NORMAL:' + str(score)
    elif score < 5.0:
        return 'HIGH:' + str(score)
    else:
        return 'VERY_HIGH:' + str(score)
