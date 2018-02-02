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

import pytest
from six import string_types

from harsanitizer.harsanitizer import Har, HarSanitizer

def test_Har_init_file():
  """Tests Har object init with demo.har"""
  dir_path = os.path.dirname(os.path.realpath(__file__))
  har_path = dir_path + "/demo.har"
  with open(har_path, "r") as har_file:
    har_json = json.load(har_file)
  har = Har(har=har_json)
  assert isinstance(har, Har)
  assert isinstance(har.har_dict, dict)


def test_Har_init_invalid_string():
  """Tests Har object initialization failure with non-Har string data"""
  with pytest.raises(AttributeError):
    har = Har(har="not a har")
