# HAR Sanitizer

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

## Installation

```
$ git clone https://github.com/google/har-sanitizer.git
$ cd har-sanitizer
$ virtualenv -p [location of python2.7 interpreter] venv --no-site-packages
$ source venv/bin/activate
$ pip install -r requirements.txt
```

#### Local Flask site (CLI in root har-sanitizer directory)

1. If virtual environment not already activated
```
$ source venv/bin/activate
```

2. Change static file location in config.json. Example: (can use local dir as well)
```
{
  "static_files": "https://storage.googleapis.com/har-sanitizer/static"
}
```

3. Change port, debug, and other options in ./harsanitizer/harsan_api.py

4. Launch Flask server:
```
$ PYTHONPATH=. python ./harsanitizer/harsan_api.py
```

#### Google App Engine Flex Deployment
1. Create GCS Bucket, set access permissions to public view

2. Add app.yaml to root dir

3. Add the following to app.yaml, changing values as needed:
```
runtime: python
env: flex
entrypoint: gunicorn -b :$PORT harsanitizer.harsan_api:app

env_variables:
    CLOUD_STORAGE_BUCKET: [GCS Bucket Name, i.e. 'har-sanitizer']
    STATIC_URL_PATH: static/
    CLOUD_WORDLIST_LOCATION: static/wordlist.json

skip_files:
  - ^(.*/)?venv$
  - ^(.*/)?.git$
  - ^(.*/)?.python-version$
  - ^(.*/)?harfiles$
  - ^(.*/)?tests$
  - ^(.*/)?har-sanitizer.log$
  - ^(.*/)?har_sanitizer_cli.py$
  - ^(.*/)?ipynb$
```

4. $ gsutil -m rsync -r ./harsanitizer/static gs://[bucket name]/static


5. $ gcloud app deploy

## Usage
[API Endpoint: Usage]
* /get_wordlist - Returns default HarSanitizer wordlist.

* /default_mimetype_scrublist - Returns default HarSanitizer mimeTypes scrub list.

* /cookies - Returns all cookie names found in POSTed Har (json). Example (Python):
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

2. Update Python patterns to mimick JS values-based patterns in order to better support foreign Unicode.

#### Contact

Garrett Anderson: 
* gaanderson@google.com

* jga@nulldestinations.com

Greg Cochard: 
* gcochard@google.com

Geoffrey Coulter: 
* gcoulter@google.com
