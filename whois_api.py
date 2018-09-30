# -*- coding: utf-8 -*-
"""
Created on Mon Feb 19 03:28:05 2018

@author: methylDragon
"""

from flask import Flask, jsonify, abort
from werkzeug.contrib.cache import SimpleCache
import whois_utils

app = Flask(__name__)
cache = SimpleCache()

whois_utils.update_geolite_dbs()
readers = whois_utils.initialise_readers()

@app.route('/')
def index():
    return """URL WHOIS INFO API (v1.0)

Author: http://github.com/methylDragon
Usage: /url_whois/api/v1.0/URL-TO-ANALYSE"""

@app.route('/url_whois/api/v1.0/<url>/', methods=['GET'])
def get_data(url):
    url = whois_utils.sanitise_urls(url)
    rv = cache.get(str(url))

    if rv is None:
        print("COMPUTING", url)
        rv = whois_utils.probe_website(url, geoip_readers = readers)

        # 1 day cache timeout
        cache.set(str(url), rv, timeout=86400)
    else:
        print("FETCHED CACHED RESULT FOR", url)

    if len(url) == 0:
        abort(404)

    return jsonify(rv)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)