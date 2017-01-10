#!/usr/bin/python

import requests
import sys
import json
import yaml
import time
import logging
from os import path
from base64 import b64encode, b64decode

class Vadc(object):

    DEBUG = False

    def __init__(self, host, user, passwd, logger=None):
        requests.packages.urllib3.disable_warnings()
        if host.endswith('/') == False:
            host += "/"
        self.host = host
        self.user = user
        self.passwd = passwd
        self.logger = logger if logger else logging.getLogger()
        self.client = None
        self._cache = {}

    def _debug(self, message):
        if Vadc.DEBUG:
            self.logger.debug(message)

    def _get_api_version(self, apiRoot):
        url = self.host + apiRoot
        res = self._get_config(url)
        if res.status_code != 200:
            raise Exception("Failed to locate API: {}, {}".format(res.status_code, res.text))
        versions = res.json()
        versions = versions["children"]
        major=max([int(ver["name"].split('.')[0]) for ver in versions])
        minor=max([int(ver["name"].split('.')[1]) for ver in versions if 
            ver["name"].startswith(str(major))])
        version = "{}.{}".format(major, minor)
        self._debug("API Version: {}".format(version))
        return version

    def _init_http(self):
        self.client = requests.Session()
        self.client.auth = (self.user, self.passwd)

    def _get_config(self, url, headers=None, params=None):
        self._debug("URL: " + url)
        try:
            self._init_http()
            response = self.client.get(url, verify=False, headers=headers, params=params)
        except:
            self.logger.error("Error: Unable to connect to API")
            raise Exception("Error: Unable to connect to API")
        self._debug("Status: {}".format(response.status_code))
        self._debug("Body: " + response.text)
        return response

    def _push_config(self, url, config, method="PUT", ct="application/json", params=None, extra=None):
        self._debug("URL: " + url)
        try:
            self._init_http()
            if ct == "application/json":
                if extra is not None:
                    try:
                        if extra.startswith("{"):
                            extra = json.loads(extra, encoding="utf-8")
                        else:
                            extra = yaml.load( extra )
                        self._merge_extra(config, extra)
                    except Exception as e:
                        self.logger.warn("Failed to merge extra properties: {}".format(e))
                config = json.dumps(config)
            if method == "PUT":
                response = self.client.put(url, verify=False, data=config,
                    headers={"Content-Type": ct}, params=params)
            else:
                response = self.client.post(url, verify=False, data=config,
                    headers={"Content-Type": ct}, params=params)
        except requests.exceptions.ConnectionError:
            self.logger.error("Error: Unable to connect to API")
            raise Exception("Error: Unable to connect to API")

        self._debug("DATA: " + config)
        self._debug("Status: {}".format(response.status_code))
        self._debug("Body: " + response.text)
        return response

    def _del_config(self, url):
        self._debug("URL: " + url)
        try:
            self._init_http()
            response = self.client.delete(url, verify=False)
        except requests.exceptions.ConnectionError:
            sys.stderr.write("Error: Unable to connect to API {}".format(url))
            raise Exception("Error: Unable to connect to API")

        self._debug("Status: {}".format(response.status_code))
        self._debug("Body: " + response.text)
        return response

    def _upload_raw_binary(self, url, filename):
        if path.isfile(filename) is False:
            raise Exception("File: {} does not exist".format(filename))
        if path.getsize(filename) > 20480000:
            raise Exception("File: {} is too large.".format(filename))
        handle = open(filename, "rb")
        body = handle.read()
        handle.close()
        return self._push_config(url, body, ct="application/octet-stream")

    def _dictify(self, listing, keyName):
        dictionary = {}
        for item in listing:
            k = item.pop(keyName)
            dictionary[k] = item

    def _merge_extra(self, obj1, obj2):
        for section in obj2["properties"].keys():
            if section in obj1["properties"].keys():
                obj1["properties"][section].update(obj2["properties"][section])
            else:
                obj1["properties"][section] = obj2["properties"][section]

    def _cache_store(self, key, data, timeout=10):
        exp = time.time() + timeout
        self._debug("Cache Store: {}".format(key))
        self._cache[key] = {"exp": exp, "data": data}

    def _cache_lookup(self, key):
        now = time.time()
        if key in self._cache:
            entry = self._cache[key]
            if entry["exp"] > now:
                self._debug("Cache Hit: {}".format(key))
                return entry["data"]
        self._debug("Cache Miss: {}".format(key))
        return None

    def dump_cache(self):
        return json.dumps(self._cache, encoding="utf-8")

    def load_cache(self, cache):
        self._cache = json.loads(cache, encoding="utf-8")

