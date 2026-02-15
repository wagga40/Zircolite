def transform(param):
    length = len(param)
    if length < 50:
        return 'SHORT:' + str(length)
    elif length < 200:
        return 'NORMAL:' + str(length)
    elif length < 500:
        return 'LONG:' + str(length)
    elif length < 1000:
        return 'VERY_LONG:' + str(length)
    else:
        return 'EXTREME:' + str(length)
