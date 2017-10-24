"""Scans and sanitzes HAR files containing sensitive information."""

# Copyright 2017, Google Inc.
# Authors: Garrett Anderson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import datetime
import json
import decorators
from flask import Flask, request, Response, render_template
from harsanitizer import Har, HarSanitizer

from google.cloud import storage
from google.cloud.storage import Blob

WORDLIST_PATH = "./static/wordlist.json"
try:
  CLOUD_STORAGE_BUCKET = os.environ["CLOUD_STORAGE_BUCKET"]
  STATIC_URL_PATH = os.environ["STATIC_URL_PATH"]
  CLOUD_WORDLIST_LOCATION = os.environ["CLOUD_WORDLIST_LOCATION"]
except Exception:
  pass

# Serialize utility
def json_serial(obj):
  """JSON serializer for datetime.datetime not serializable by default json code."""
  if isinstance(obj, datetime.datetime):
    serial = obj.isoformat()
    return serial
  raise TypeError("Object not of type datetime.datetime.")

app = Flask(__name__)

@app.route("/")
def index():
  index_content = ""

  try:
    gcs = storage.Client()
    bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)
    blob = bucket.blob(STATIC_URL_PATH + "index.html")
    index_content = blob.download_as_string()
  except Exception:
    pass

  if index_content:
    return Response(index_content, 200, mimetype="text/html")
  else:
    with open("./config.json", "r") as config:
      static_files = json.load(config)["static_files"]
    return render_template("index.html", static_files=static_files)

@app.route("/get_wordlist", methods=["GET"])
def get_wordlist():
  """Returns default HarSanitizer wordlist."""
  hs = HarSanitizer()

  try:
    wordlist = hs.load_wordlist(wordlist_path=WORDLIST_PATH)
  except Exception:
    try:
      gcs = storage.Client()
      bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)
      blob = bucket.blob(CLOUD_WORDLIST_LOCATION)
      wordlist_json = json.loads(blob.download_as_string())
      wordlist = hs.load_wordlist(wordlist=wordlist_json)
    except Exception:
      message = {"message": "Error: wordlist.json not found."}
      data = json.dumps(message, default=json_serial)
      return Response(data, 500, mimetype="application/json")

  data = json.dumps(wordlist, default=json_serial)

  return Response(data, 200, mimetype="application/json")


@app.route("/default_mimetype_scrublist", methods=["GET"])
def get_mimetype_scrublist():
  """Returns default HarSanitizer mimeTypes scrub list."""
  hs = HarSanitizer()

  content_list = [content["value_to_match"] for content
                  in hs.default_content_scrub_list]

  data = json.dumps(content_list, default=json_serial)

  return Response(data, 200, mimetype="application/json")


@app.route("/cookies", methods=["POST"])
@decorators.accept("application/json")
@decorators.require("application/json")
def req_cookie_names():
  """Returns all cookie names found in POSTed Har (json)."""
  data = request.json
  hs = HarSanitizer()

  har = Har(har=data)
  cookies = hs.get_hartype_names(har, "cookies").keys()

  data = json.dumps(cookies, default=json_serial)

  return Response(data, 200, mimetype="application/json")


@app.route("/headers", methods=["POST"])
@decorators.accept("application/json")
@decorators.require("application/json")
def req_header_names():
  """Returns all header names found in POSTed Har (json)."""
  data = request.json
  hs = HarSanitizer()

  har = Har(har=data)
  headers = hs.get_hartype_names(har, "headers").keys()

  data = json.dumps(headers, default=json_serial)

  return Response(data, 200, mimetype="application/json")


@app.route("/params", methods=["POST"])
@decorators.accept("application/json")
@decorators.require("application/json")
def req_urlparams():
  """Returns all URL Query and POSTData Parameter names found in POSTed Har (json)."""
  data = request.json
  hs = HarSanitizer()
  cond_table = {}

  har = Har(har=data)
  url_pattern = hs.gen_hartype_names_pattern(har, "queryString")
  postdata_pattern = hs.gen_hartype_names_pattern(har, "params")
  cond_table.update(url_pattern)
  cond_table.update(postdata_pattern)
  iter_har_dict = hs.iter_eval_exec(my_iter=har.har_dict, cond_table=cond_table)
  har = hs.har
  urlparams = har.category["queryString"].keys()

  if isinstance(har.category["params"].keys(), list):
    postdata_params = har.category["params"].keys()
    params = urlparams + postdata_params
  else:
    params = urlparams

  data = json.dumps(params, default=json_serial)

  return Response(data, 200, mimetype="application/json")


@app.route("/mimetypes", methods=["POST"])
@decorators.accept("application/json")
@decorators.require("application/json")
def req_mimetypes():
  """Returns all content mimeTypes found in POSTed Har (json)."""
  data = request.json
  hs = HarSanitizer()

  har = Har(har=data)
  mimetypes = hs.get_mimetypes(har).keys()

  data = json.dumps(mimetypes, default=json_serial)

  return Response(data, 200, mimetype="application/json")


@app.route("/scrub_har", methods=["POST"])
@decorators.accept("application/json")
@decorators.require("application/json")
def scrub():
  """Scrubs data["har"] with optional wordlists,
  content types, and scrub_all type bools.
  """
  hs = HarSanitizer()
  hs_kwargs = {}

  data = request.json
  har = Har(har=data["har"])

  if "wordlist" in data.keys():
    hs_kwargs["wordlist"] = data["wordlist"]
  if "content_list" in data.keys():
    hs_kwargs["content_list"] = data["content_list"]
  if "all_cookies" in data.keys():
    hs_kwargs["all_cookies"] = data["all_cookies"]
  if "all_headers" in data.keys():
    hs_kwargs["all_headers"] = data["all_headers"]
  if "all_params" in data.keys():
    hs_kwargs["all_params"] = data["all_params"]
  if "all_content_mimetypes" in data.keys():
    hs_kwargs["all_content_mimetypes"] = data["all_content_mimetypes"]

  sanitized_har = hs.scrub(har, **hs_kwargs)

  data = json.dumps(sanitized_har.har_dict, indent=2, separators=(",", ": "))
  return Response(data, 200, mimetype="text/plain")

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8080, debug=False)
