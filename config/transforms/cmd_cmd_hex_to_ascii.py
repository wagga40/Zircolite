def transform(param):
  return bytes.fromhex(param).decode('ascii').replace('\x00',' ')
