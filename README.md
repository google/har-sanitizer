# HAR Sanitizer

## Description

HAR files are JSON-formatted "recordings" of web traffic activity for a user's browser session, which are often used to troubleshoot web front-ends, REST APIs, authentication issues, etc.  However, HAR files will capture everything in a web session, including passwords, sensitive form information, authentication cookies and headers, and any content embedded in HTTP requests.  This makes HAR files extremely sensitive, and highly prone to privacy breaches if handled incorrectly.

This tool aims to help mitigate these concerns by offering a simple, flexible interface to redact HAR file contents of any potentially sensitive information.  It collects the names and values of all passwords, cookies, headers, URLQuery/POSTData/HTML-Form parameters, and embedded content mimetypes, and redacts values either already known to be sensitive, or those specified by the user.  It currently exists as a both a client-side web tool and Flask REST API.

Live version may be found at https://har-sanitizer.appspot.com/

(This is NOT an official Google product)

## Installation

```
$ git clone https://github.com/google/har-sanitizer.git
$ cd har-sanitizer
$ virtualenv -p $(which python2.7) venv --no-site-packages
$ source venv/bin/activate
$ pip install -r requirements.txt
```

#### Local Flask site (CLI @ root "./har-sanitizer/" directory)

1. (If virtual environment not already activated)
```
$ source venv/bin/activate
```

2. If desired, change static files location in config.json. Examples:
```
{
  "static_files": "./harsanitizer/static"
}

-or-

{
  "static_files": "https://storage.googleapis.com/har-sanitizer/static"
}

```

3. Change port, debug, and other options in ./harsanitizer/harsan_api.py under:
```
app.run(...)
```

4. Launch Flask server:
```
$ PYTHONPATH=. python ./harsanitizer/harsan_api.py
```

5. Load the Har-Sanitizer web tool by visiting "http://localhost:8080" in Chrome or Firefox (substituting '8080' with the port #, if modified).


## Usage

#### Web Tool

1. Load HAR JSON file using 'Load HAR' button.

2. Select names of cookies/headers/parameters/content mimetypes to scrub.

3. Preview changes before committing, modifying scrub options as necessary.

4. Export scrubbed HAR file once ready.

#### API Endpoint

* /get_wordlist - Returns default HarSanitizer wordlist.

* /default_mimetype_scrublist - Returns default HarSanitizer mimeTypes scrub list.

* /cookies - Returns all cookie names found in POSTed Har (json). Example (Python w/ 'requests' package):
  ```
  import json, requests
  with open("har_file.har", "r") as har_file:
      har = json.load(har_file)
  url = 'http://localhost:8080/cookies'
  headers = {"Content-Type": "application/json"}
  r = requests.post(url, data=json.dumps(har), headers=headers)
  ```

* /headers - Returns all header names found in POSTed Har (json). See /cookies for example.

* /params - Returns all URL Query and POSTData Parameter names found in POSTed Har (json).  See /cookies for example.

* /mimetypes - Returns all content mimeTypes found in POSTed Har (json). See /cookies for example.

* /scrub_har - Full scrub/redaction of sensitive HAR fields.

  Args:

    * har: the har json to be scrubbed

    * wordlist=None, (list of strs) appends to default wordlist

    * content_list=None, (list of strs) appends to default content_list

    * all_cookies=False,  (Boolean) Redacts all cookies

    * all_headers=False, (Boolean) Redacts all headers

    * all_params=False, (Boolean) Redacts all URLQuery/POSTData parameters

    * all_content_mimetypes=False (Boolean) Redacts all content mimeTypes

    Example:

    ```
    import json, requests
    with open("har_file.har", "r") as har_file:
      har = json.load(har_file)
    url = 'http://localhost:8080/scrub_har'
    headers = {"Content-Type": "application/json"}
    data = {"har": har, "wordlist": ['mycookie', 'mycookie2'], "all_params": True}
    r = requests.post(url, data=json.dumps(data), headers=headers)
    ```

## TODO

1. Implement promises in JS iterEvalExec() calls.

2. Change Python HarSanitizer.get_hartype_names() to write to Har() object passed in argument, not HarSanitizer() instance.  Be sure to update harsan_api.py to reflect changes.

3. Update Python wordlist patterns to mimick JS values-based patterns in order to better support foreign Unicode.

4. Separate 'default_content_scrub_list' out of Python harsanitizer.py into static .json file.

5. Make Javascript load defaultWordList and defaultContentList from static .json files.

6. Develop a CLI tool.

#### Contact

Garrett Anderson: 
* gaanderson@google.com

* jga@nulldestinations.com

Greg Cochard: 
* gcochard@google.com

Geoffrey Coulter: 
* gcoulter@google.com

## License
Copyright 2017, Google Inc.

Authors: Garrett Anderson

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 
