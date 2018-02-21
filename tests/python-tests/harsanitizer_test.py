# Copyright 2017, Google Inc.
# Authors: Garrett Anderson

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import json
from six import string_types

import pytest

import requests
from flask import url_for

from harsanitizer.harsanitizer import Har, HarSanitizer
from harsanitizer.harsan_api import app

@pytest.fixture
def client():
  """Flask application pytest fixture"""
  test_client = app.test_client()

  return test_client

def response_json(response):
  """Decode json from response"""
  return json.loads(response.data.decode('utf8'))

def test_Har_init_file():
  """Tests Har object init with valid demo.har"""
  dir_path = os.path.dirname(os.path.realpath(__file__))
  har_path = dir_path + "/demo.har"
  with open(har_path, "r") as har_file:
    har_json = json.load(har_file)
  har = Har(har=har_json)
  assert isinstance(har, Har)
  assert isinstance(har.har_dict, dict)

@pytest.mark.parametrize("invalid_str", [
  ("not a har"),
  ("{'logs': {'entries': 'also not a har'}}")
])
def test_Har_init_invalid_string(invalid_str):
  """Tests Har object initialization failure with non-Har string data"""
  with pytest.raises(ValueError):
    har = Har(har=invalid_str)

@pytest.mark.parametrize("invalid_har", [
  ({"logs": {"entries": "not a har"}}),
  ({"log": {"not": "a har"}}),
  ({"log": {"entries": []}}),
  ({"log": {"entries": [{"not": "a har"}]}}),
])
def test_Har_init_invalid_dict(invalid_har):
  """Tests Har object initialization failure with non-Har dict data"""
  with pytest.raises(ValueError):
    har = Har(har=invalid_har)

def test_HarSanitizer_load_wordlist():
  """Test successful HarSantizer.load_wordlist()"""
  hs = HarSanitizer()
  word_list = hs.load_wordlist(wordlist=['word1', u'word2', 'word3'])
  assert isinstance(word_list, list)
  assert word_list[2] == "word3"

@pytest.mark.parametrize("invalid_wordlist", [
  (["what", "is", 12]),
  ("words words more WORDS"),
  ({"wordlist": {"list": ["one", "two", "three"]}
  })
])
def test_HarSanitizer_load_wordlist_failure(invalid_wordlist):
  """Test unsuccessful HarSantizer.load_wordlist()"""
  hs = HarSanitizer()
  with pytest.raises(TypeError):
    word_list = hs.load_wordlist(wordlist=invalid_wordlist)

def test_HarSanitizer_trim_wordlist():
  """Test HarSanitizer.trim_wordlist()."""
  hs = HarSanitizer()
  wordlist = ["one", "two", "three"]
  test_str = "Hello I have one thing, not two."
  result = ["one", "two"]
  fake_json = {"log": {"entries": [{"request": {"one": "two"}}]}}
  har = Har(har=fake_json)

  trimlist = hs.trim_wordlist(har=har, wordlist=wordlist)
  assert trimlist == result

## REST API Tests
## TODO: Put these into their own file/class
def test_GET_wordlist(client):
  """Test API GET default scrub wordlist"""
  response = client.get("/get_wordlist")
  data = response_json(response)
  assert response.status_code == 200
  assert isinstance(data, list)
  assert all(isinstance(item, string_types) for item in data)

