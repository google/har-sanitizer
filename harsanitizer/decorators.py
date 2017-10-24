"""Decorators to enforce mimeType accept/requirements in Flask endpoints"""

# Copyright 2017, Google Inc.
# Authors: Garrett Anderson, Jay Goldberg
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

import json
from functools import wraps

from flask import request, Response

def accept(mimetype):
    def decorator(func):
        """
        Decorator which returns a 406 Not Acceptable if the client won't accept 
        a certain mimetype
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "application/json" in request.accept_mimetypes:
                return func(*args, **kwargs)
            message = "Request must accept {} data".format(mimetype)
            data = json.dumps({"message": message})
            return Response(data, 406, mimetype="application/json")
        return wrapper
    return decorator

def require(mimetype):
    def decorator(func):
        """
        Decorator which returns a 415 Unsupported Media Type if the client sends
        something other than a certain mimetype
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            if (request.mimetype ==  mimetype):
                return func(*args, **kwargs)
            message = "Request must contain {} data".format(mimetype)
            data = json.dumps({"message": message})
            return Response(data, 415, mimetype="application/json")
        return wrapper
    return decorator
