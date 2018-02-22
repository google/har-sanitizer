"""Scans and sanitzes HAR files containing sensitive information."""

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
import re
import urllib2


# Config local/remote file locations
CURRENT_DIR = os.path.abspath("./")

# Load/sanity check config.json
try:
  with open("./config.json", "r") as config:
    STATIC_FOLDER = json.load(config)["static_folder"]
except IOError:
  raise IOError(
    "'config.json' not found in '{}'. Please ensure that script is "
    "being run from root './har-sanitizer/' directory.".format(CURRENT_DIR))
except KeyError:
  raise KeyError("KeyError: 'STATIC_FOLDER' key not found in config.json")

WORDLIST_PATH = "{}/wordlist.json".format(STATIC_FOLDER)
MIMETYPES_PATH = "{}/mimetypesScrubList.json".format(STATIC_FOLDER)


class Har(object):
  """An object that represents a HAR file.

  Typical usage example:
    har_instance = Har(har=har) # where [har] is either a HAR JSON dict or str
    -or-
    har_instance = Har(har_path="/path/to/har.json")
  """

  def __init__(self, har=None, har_path=None):
    super(Har, self).__init__()
    self.load_har(har=har, har_path=har_path)
    self.category = {}

  def load_har(self, har=None, har_path=None):
    """Loads the har and sets self.har_str, self.har_dict.

  Args:
    har: a HAR json either as a str, or a dict

  Raises:
    AttributeError: Requires [har] (str or dict)
    TypeError: Invalid HAR provided
    """

    try:
      if isinstance(har, dict):
        self.har_str = json.dumps(har)
        self.har_dict = har
      elif isinstance(har, basestring):
        self.har_dict = json.loads(har)
        self.har_str = har
      else:
        raise ValueError
      assert("request" in self.har_dict["log"]["entries"][0])
    except (TypeError, ValueError, AssertionError, KeyError, IndexError):
      raise ValueError("Missing/Invalid HAR: Requires valid [har] (str or dict)")
    except Exception:
      raise


class HarSanitizer(object):
  """Base HAR sanitizer class.

  A collection of utilities for scrubbing sensitive information from HAR jsons.

  Methods:
    load_wordlist: load/sanity check for scrub pattern wordlist
    trim_wordlist: trims scrub pattern wordlist to only words found in a given HAR
    gen_regex: generates and returns regex patterns for generic and word scrub patterns
    iter_eval_exec: recursive iterator traversal algorithm that matches conditional 
                    python expressions, executes associated callback functions on the
                    iterator and current child nodes, and returns the (possibly modified)
                    iterator.
    get_hartype_names: returns list of [cookie, header, url query parameter] names found
                        in HAR object
    get_mimetypes: returns embedded content mimeTypes found in a HAR object
    scrub_generic: Scrubs a HAR object for generic patterns.  Returns redacted HAR object.
    scrub_wordlist: Scrubs a HAR object for wordlist patterns.  Returns redacted HAR object.
    scrub: Loads and trims wordlist, generates iter_eval_exec conditional patterns and executes
            them on HAR object, generates and scrubs generic and wordlist regex patterns on 
            HAR object, and returns final redacted version of HAR object.

  Args:
    har: (optional) HAR object
  """

  # Class variables
  valid_hartypes = ["cookies", "headers", "queryString", "params"]

  def __init__(self, har=None):
    super(HarSanitizer, self).__init__()

    if isinstance(har, Har):
      self.har = Har

  def load_wordlist(self, wordlist=None, wordlist_path=None):
    """Load/sanity checks wordlist from a filesystem path [wordlist_path] (str)
    or a [wordlist] list of str's.  Note that
    wordlist_path is prioritized if both arguments are provided.

    Returns wordlist as a list of str's.

    Args:
      wordlist: list of str scrub pattern words
      -or-
      wordlist_path: str file path to a list of scrub pattern words

    Returns: 
      [wordlist] as a list of str's

    Raises:
      IOError: error loading wordlist_path file
      TypeError: wordlist or wordlist_path is incorrect format
  """

    if not (
      (isinstance(wordlist, list) 
      and all(isinstance(s, basestring) for s in wordlist))
    or isinstance(wordlist_path, basestring)):
      raise TypeError(
          "Requires either wordlist_path (str of wordlist file path), "
          "or wordlist (list of strs).")
    elif isinstance(wordlist_path, basestring):
      try:
        with open(wordlist_path, "r") as wordlist_f:
          wordlist = json.load(wordlist_f)
      except IOError:
        raise IOError("Cannot open wordlist file at path: {}".format(wordlist_path))

    return wordlist

  def trim_wordlist(self, har, wordlist):
    """Trims wordlist to only words found in har.

    Args:
      har: a Har() object
      wordlist: list of str scrub pattern words

    Returns:
      [trimmedlist] as a list of str's found in HAR

    Raises:
      TypeError: har must be a Har() object
      """
    if not isinstance(har, Har):
       raise TypeError("'har' must be a Har() object")

    trimmedlist = [word for word in wordlist if word.lower() in har.har_str.lower()]

    return trimmedlist

  def gen_regex(self, word="word"):
    """Generates known HAR regex patterns for [word] (str).

    Args:
      word: (str) word to generate regex patterns for.  Default="word"

    Returns:
      A dict of generic and word-based patterns:

      regex_patterns = {
        "single_use": {
          "generic regex pattern": "redacted text",
        },
        "word_patterns": {
          "regex pattern": "redacted text",
        }
      }
    """

    # regex_patterns = {regex_pattern: redacted str}
    regex_patterns = {
        "single_use": {
            # user:pass URL:
            # whatever[://]user:[capture][@]whatever
            r"""(\://[\w+-.%!*()`~']*?\:)"""
            r"""(?P<capture>[\w+-.%!*()`~']+)(@)""":
            r"\g<1>[password redacted]\g<3>",
        },
        "word_patterns": {
            # [full word]=[capture][& | ", | "\s | "} | ;]
            r"""([\s";,&?]+{}=)"""
            r"""(?P<capture>[\w+-_/=#|.%&:!*()`~'"]+?)"""
            r"""(&|",|"\s|"}}|;){{1}}""".format(word):
            r"\g<1>[{} redacted]\g<3>".format(word),

            # Set up this way in case "value" isn't directly after "name", but
            # excludes {} to prevent grabbing the next object
            # {
            #    "name": "[word]",
            #    "something": "not wanted",
            #    "value": "[capture]["]
            # }
            # {
            #   "name": "not wanted",
            #   "value": "unwanted capture"
            # }
            r"""("name": "{}",[\s\w+:"-\\%!*()`~'.#]*?"value": ")"""
            r"""(?P<capture>[\w+-_:&\+=#~/$()\\.\,\*\!|%"\s;]+?)"""
            r"""("[\s,}}]+){{1}}""".format(word):
            r"\g<1>[{} redacted]\g<3>".format(word),

            # Same as above, but backwards in case "name" comes after "value"
            # {
            #   "name": "not wanted/captured"
            #   "value": "unwanted capture"
            # }
            # {
            #    "value": "[capture]["],
            #    "something": "not wanted",
            #    "name": "[word]"
            # }
            r"""("value": ")"""
            r"""(?P<capture>[\w+-_:&\+=#$~/()\\.\,\*\!|%"\s;]+){{1}}"""
            r"""("[\s,}}]+){{1}}"""
            r"""([\s\w+:"-\\%!*()`~'#.]*"name": "{}"){{1}}""".format(word):
            r"\g<1>[{} redacted]\g<3>\g<4>".format(word),
        }
    }
    return regex_patterns

  def iter_eval_exec(self, my_iter, cond_table):
    """Traverses through every nested level of dict/list 'my_iter'
    until it finds a condition in cond_table.keys()
    that evals to True, then runs associated callback function as:
    ```
      callback(self, my_iter, key, value)
    ```

    [my_iter] may be a whole har_dict, or a child node dict/list.

    The cond_table keys are python expressions as strs (eval to True/False),
    and the values are callback functions taking
    (self, my_iter, key, value) args.  Note that nested callbacks are
    supported.

    Args:
      my_iter: (dict or list) Iterator object, or iterable child branch
      cond_table: (dict) Conditional python patterns and associated callback
                  functions:

                  cond_table = {
                    "conditional python expression": callback_function,
                  }

    Returns:
      my_iter: updated, if any modifcations were made


    Typical usage example:

      har_dict = {
        "a_list" : [
          {
            "not_a_password": "doesn't matter"
          },
          {
            "password": "my password"
          }
        ]
      }

      def callback(self, my_iter, key, value):
        value = "redacted"

      cond_table = {"key = 'password'": callback}
      har_redacted = iter_eval_exec(my_iter=har_dict, cond_table=cond_table)
    """

    if isinstance(my_iter, dict):
      for key, value in my_iter.iteritems():
        # Makes it run faster, even though it seems counterintuitive
        if any([eval(cond) for cond in cond_table.keys()]):
          for cond, callback in cond_table.iteritems():
            # Security risks have been mitigated by
            # preventing any possible code-injection
            # attempt into cond_table keys
            if eval(cond):
              callback(self, my_iter, key, value)
        elif isinstance(value, (dict, list)):
          self.iter_eval_exec(
              value,
              cond_table)
    elif isinstance(my_iter, list):
      for value in my_iter:
        self.iter_eval_exec(
            value,
            cond_table)

    return my_iter

  def gen_hartype_names_pattern(self, har, hartype):
    """Generates cond_table pattern to return all names of
    hartype ['cookies' | 'headers' | 'queryString']

    Args:
      har: a Har() object
      hartype: (str) one of ['cookies' | 'headers' | 'queryString' | 'params']

    Returns:
      cond_table: cond_table to be used with iter_eval_exec().  Pattern will
                  create har.category[hartype] in the har object, and generate
                  a dict of (example uses hartype='cookies'):
                  har.category[cookies] = {
                    "cookie1": # of cookie1s found,
                    "cookie2": # of cookie2s found,
                  }

    Raises:
      TypeError: har must be a Har() object
      ValueError: hartype must be one of ['cookies' | 'headers' | 'queryString' | 'params']
    """

    if not isinstance(har, Har):
      raise TypeError("'har' must be a Har() object")

    if hartype not in self.valid_hartypes:
      raise ValueError(
          "'hartype' must be one of the following: {}"
          .format(self.valid_hartypes))

    def outer_callback(self, my_iter, key, value):
      """Callback function to generate names of
      hartype ['cookies' | 'headers' | 'queryString' | 'params']
      """
      def inner_callback(self, my_iter, key, value):
        if value in har.category[hartype]:
          har.category[hartype][value] += 1
        else:
          har.category[hartype][value] = 1

      self.iter_eval_exec(
          value,
          {"key == 'name'": inner_callback}
      )

    har.category[hartype] = {}

    cond_table = {
        "key == '{}'".format(hartype): outer_callback
    }

    return cond_table

  def get_hartype_names(self, har, hartype):
    """Returns list of hartype names for hartype
    ['cookies' | 'headers' | 'queryString' | 'params'] in har

    This is a wrapper to simplify the use of gen_hartype_names_pattern().

    Args:
      har: a Har() object
      hartype: (str) one of ['cookies' | 'headers' | 'queryString' | 'params']

    Returns:
      namelist: list of [hartype] names found in har

    Raises:
      TypeError: har must be a Har() object
    """
    if not isinstance(har, Har):
      raise TypeError("'har' must be a Har() object")

    namelist = []

    pattern = self.gen_hartype_names_pattern(har, hartype)
    self.iter_eval_exec(my_iter=har.har_dict, cond_table=pattern)

    namelist = har.category[hartype]

    return namelist

  def load_keyvalue_conds(self, keyvalues):
    """Returns cond_table with the following:
    {
      "[key_to_match]": "[value_to_match]",
      "[key_to_redact]": [value_to_match redacted]
    }
    patterns from keyvalues. 

    Args:
      keyvalues:
        {
          "key_to_match": "[key_to_match]",
          "value_to_match": "[value_to_match]",
          "key_to_redact": "[key_to_redact]"
        },

    Returns:
      cond_table: cond_table to be used with iter_eval_exec(). 
                  Matches [key_to_match] to [value_to_match] in an dict object, 
                  and redacts the value of [key_to_redact]
    """
    cond_table = {}
    table = keyvalues
    def callback(self, my_iter, key, value):
      my_iter[keyvalues["key_to_redact"]] = "[{} redacted]".format(
        keyvalues["value_to_match"])
    cond_table.update({
          "key == '{}' and '{}' in value and '{}' in my_iter.keys()"
          .format(
              keyvalues["key_to_match"],
              keyvalues["value_to_match"],
              keyvalues["key_to_redact"]): callback
          })

    return cond_table

  def get_mimetypes(self, har):
    """Returns all content mimeTypes found in 'har' (a Har object).

    Args:
      har: a Har() object

    Returns:
      namelist: list of content mimeTypes found in har

    Raises:
      TypeError: har must be a Har() object
    """

    if not isinstance(har, Har):
      raise TypeError("'har' must be a Har object")

    def callback(self, my_iter, key, value):
      if value in self.har.category["mimetypes"]:
        self.har.category["mimetypes"][value] += 1
      else:
        self.har.category["mimetypes"][value] = 1

    namelist = []
    self.har = har
    self.har.category["mimetypes"] = {}

    cond_table = {
        "key == 'mimeType'": callback
    }

    self.iter_eval_exec(my_iter=har.har_dict, cond_table=cond_table)
    namelist = har.category["mimetypes"]

    return namelist

  def gen_all_mimetypes_scrub_pattern(self):
    """Returns cond_table to scrub all content mimeTypes.
    """

    def callback(self, my_iter, key, value):
      value["text"] = "[{} redacted]".format(value["mimeType"])

    cond_table = {
        "key == 'content' and 'text' in value.keys()": callback
    }

    return cond_table

  def gen_content_type_scrub_patterns(self, content_list=None):
    """
    Returns cond_table with content mimeType scrub patterns
    using load_keyvalue_conds() on content_list.
    If content_list is not provided, loads default_content_scrub_list

    Args:
      content_list: (optional) list of content mimeTypes (str) 
                    to append to default content mimeType scrub list

    Returns:
      cond_table: cond_table to be used with iter_eval_exec().
    """

    # Gets rid of troublesome js/html/css/base64/etc text.
    content_scrub_list = self.default_content_scrub_list[:]
    with open(MIMETYPES_PATH, "r") as mimetypes_file:
        default_mimetypes = json.load(mimetypes_file)
    # default_mimetypes = [elem['value_to_match'] for elem in self.default_content_scrub_list]

    if content_list:
      content_list = [obj for obj in content_list if isinstance(obj,basestring)]
      new_scrub_list = [{
        "key_to_match": "mimeType",
        "value_to_match": mimetype,
        "key_to_redact": "text"
      } for mimetype in content_list if mimetype not in default_mimetypes]
      content_scrub_list.extend(new_scrub_list)

    cond_table = {}
    for table in content_scrub_list:
      cond_table.update(self.load_keyvalue_conds(table))
    return cond_table

  def scrub_generic(self, har):
    """Return Har scrubbed of generic,
    single-use regex patterns against Har() object.

    Args:
      har: a Har() object
    Returns:
      har: scrubbed har
    Raises:
      TypeError: har must be a Har() object
    """

    if not isinstance(har, Har):
       raise TypeError("'har' must be a Har object")

    patterns = self.gen_regex()["single_use"]
    scrubbed_str = har.har_str

    for pattern, redacted in patterns.iteritems():
       scrubbed_str = re.sub(pattern, redacted, scrubbed_str)

    clean_har = Har(har=scrubbed_str)

    return clean_har

  def scrub_wordlist(self, har, wordlist):
    """Scrubs HAR against wordlist regex patterns

    Args:
     har: a Har() object
     wordlist: list of str scrub pattern words 

    Returns:
      har: scrubbed har
    Raises:
      TypeError: har must be a Har() object
    """

    if not isinstance(har, Har):
      raise TypeError("'har' must be a Har object")

    # Trims the wordlist to only words that are found in the HAR
    trimmedlist = self.trim_wordlist(har=har, wordlist=wordlist)

    # Scrub words in trimmedlist
    har_str_scrubbed = har.har_str
    for word in trimmedlist:
      wordpatterns = self.gen_regex(word)["word_patterns"]

      # Scrub har_str for word patterns
      for pattern, redacted in wordpatterns.iteritems():
        har_str_scrubbed = re.sub(
            pattern,
            redacted,
            har_str_scrubbed,
            flags=re.I)

    clean_har = Har(har=har_str_scrubbed)

    return clean_har

  def scrub(
      self,
      har,
      wordlist=None,
      content_list=None,
      all_cookies=False,
      all_headers=False,
      all_params=False,
      all_content_mimetypes=False):
    """Full scrub/redaction of sensitive HAR fields.

    Args:
      har: a Har() object
      wordlist=None, (list of strs) appends to default wordlist
      content_list=None, (list of strs) appends to default content_list
      all_cookies=False,  (Boolean) Redacts all cookies
      all_headers=False, (Boolean) Redacts all headers
      all_params=False, (Boolean) Redacts all URLQuery/POSTData parameters
      all_content_mimetypes=False (Boolean) Redacts all content mimeTypes

    Returns:
      har: scrubbed har

    Typical usage:
      har = Har(har=har_json)
      hs = HarSanitizer()
      har_redacted = hs.scrub(har, all_cookies=True, content_list=['image/gif'])
    """

    if not isinstance(har, Har):
      raise TypeError("'har' must be a Har object")

    if WORDLIST_PATH[:4] == "http":
      wordlist_json = json.loads(urllib2.urlopen(WORDLIST_PATH).read())
      scrub_wordlist = self.load_wordlist(wordlist=wordlist_json)
    else:
      scrub_wordlist = self.load_wordlist(wordlist_path=WORDLIST_PATH)

    if isinstance(wordlist, list):
      if all(isinstance(word, basestring) for word in wordlist):
        scrub_wordlist.extend(wordlist)
      else:
        raise TypeError("All words in wordlist must be strings")

    cond_table = {}

    if all_cookies:
      pattern = self.gen_hartype_names_pattern(har, "cookies")
      cond_table.update(pattern)
    if all_headers:
      pattern = self.gen_hartype_names_pattern(har, "headers")
      cond_table.update(pattern)
    if all_params:
      url_pattern = self.gen_hartype_names_pattern(har, "queryString")
      postdata_pattern = self.gen_hartype_names_pattern(har, "params")
      cond_table.update(url_pattern)
      cond_table.update(postdata_pattern)

    # Loads default content scrub patterns
    if all_content_mimetypes:
      content_patterns = self.gen_all_mimetypes_scrub_pattern()
    elif content_list:
      # Prevent malicious injections
      mimetypes = self.get_mimetypes(har).keys()
      content_list_trimmed = [mimetype for mimetype in content_list
                              if mimetype in mimetypes]
      content_patterns = self.gen_content_type_scrub_patterns(
          content_list=content_list_trimmed)
    else:
      content_patterns = self.gen_content_type_scrub_patterns()
    cond_table.update(content_patterns)

    # Runs iter_eval_exec on self.my_dict against self.cond_table
    iter_har_dict = self.iter_eval_exec(
        my_iter=har.har_dict,
        cond_table=cond_table)
    har = Har(har=iter_har_dict)

    # Scrub generic patterns
    har_clean = self.scrub_generic(har)
    har = har_clean

    # Appends wordlist
    if all_cookies:
      scrub_wordlist.extend(self.har.category["cookies"].keys())
    if all_headers:
      scrub_wordlist.extend(self.har.category["headers"].keys())
    if all_params:
      scrub_wordlist.extend(self.har.category["queryString"].keys())
      if self.har.category["params"]:
        scrub_wordlist.extend(self.har.category["params"].keys())

    # Scrub wordList patterns
    har_sanitized = self.scrub_wordlist(har, scrub_wordlist)

    return har_sanitized
