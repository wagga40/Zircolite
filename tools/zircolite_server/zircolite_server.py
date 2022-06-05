#!python3
# -*- coding: utf-8 -*-

# Zircolite **example** server
# Make you own if you want to use it in production

from flask import Flask, request
from jinja2 import Template
import base64
import json

app = Flask(__name__)

tmpl = open("jsonl.tmpl", 'r', encoding='utf-8')
template = Template(tmpl.read())
tmpl.close()

@app.route('/logs',methods=['POST'])
def logs():
    try:
        with open("results.json", 'a') as f: 
            f.write(template.render(data=request.get_json()))
    except Exception as e:
        return {"status": "400"}
    return {"status": "200"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port = 8080, debug=True)
