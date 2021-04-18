#!python3
# -*- coding: utf-8 -*-

# Zircolite **example** server
# Make you own if you want to use it in production

from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/logs',methods=['POST'])
def logs():
    print(request.headers.get('User-Agent'))
    with open("results.json", 'a') as f:
        f.write(base64.b64decode(dict(request.form)["data"].encode('ascii')).decode('utf-8') + '\n')
    return {"status": "200"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port = 8080, debug=True)
