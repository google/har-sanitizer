/**
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Garrett Anderson
 */
var escapeRegExp = function(text) {
    return text.replace(/[-[\]{}();:=*+?.,\\^$|#\s ]/g, '\\$&');
}

var toLower = function(x) {
  return x.toLowerCase();
}

var HarSanitizer = function(harJson) {
  this.harJson = harJson;
  this.harElems = {
  "cookies": {},
  "headers": {},
  "queryString": {},
  "params": {},
  "mimeTypes": [],
  };
}

HarSanitizer.prototype = {
  get harStr() {
    return JSON.stringify(this.harJson);
  }
}

HarSanitizer.prototype.trimWordlist = function(wordlist) {
  var trimmedlist = [];
  wordListLower = wordlist.map(toLower);
  harStrLower = this.harStr.toLowerCase();

  for (var word of wordListLower) {
    if (harStrLower.includes(word)) {
      trimmedlist.push(word);
    }
  }
  return trimmedlist;
}

HarSanitizer.prototype.iterEvalExec = function(myIter, condTable) {
  var iter = myIter;
  var table = condTable;

  // because Array is a type of Object, check to see if it is an Array first
  if (Array.isArray(iter)) {
    for (let value of iter) {
      this.iterEvalExec(value, table);
    }
  } else if (typeof iter === 'object') {
    for (let key in iter) {
      let value = iter[key];
      let cond = table[0](iter, key, value);
        if (cond === true) {
          let callback = table[1];
          callback(iter, key, value);
        }
      // Have to catch and ignore errors because 'value' can often be null
      try {
        if (Array.isArray(value) || typeof value === 'object') {
          this.iterEvalExec(value, table);
        }
      } catch(err) {}
    }
  }
}

HarSanitizer.prototype.getTypeNames = function(harType) {
  // harType must be one of the following:
    // "cookies",
    // "headers",
    // "queryString"
    // "params" (found under postData of mimeType "application/x-www-form-urlencoded")

  var field = harType;

  let condTable = [];
  let innerCondTable = [];
  let outerCond = (iter, key, value) => {
    return key == field;
  };

  let callback = (iter, key, value) => {
    let innerCond = (iter, key, value) => {
      return key == 'name';
    };
    let inner_callback = (iter, key, value) => {
      // rawValue is created here to preserve backslashes
      // that will be present in the final JSON string due to 
      // escaped double-quotes, so that the regexes for 
      // these values will correctly match.
      let rawValue = iter["value"].replace(/"/g, '\\"');
      if (value in this.harElems[field]) {
        if (!(this.harElems[field][value].includes(rawValue))) {
          this.harElems[field][value].push(rawValue);
        }
      } else {
        this.harElems[field][value] = [rawValue];
      }
    };
    innerCondTable = [innerCond, inner_callback.bind(this)];
    this.iterEvalExec(value, innerCondTable);
  };

  condTable = [outerCond, callback.bind(this)];
  this.iterEvalExec(this.harJson, condTable);

  return this.harElems[field];
}

HarSanitizer.prototype.getMimeTypes = function() {
  let condTable = [];
  let callback = (iter, key, value) => {
    if (!(this.harElems["mimeTypes"].includes(value))) {
      this.harElems["mimeTypes"].push(value);
    }
  };
  let cond = (iter, key, value) => {
    return key == 'mimeType';
  };
  condTable = [cond, callback.bind(this)];
  this.iterEvalExec(this.harJson, condTable);
  return this.harElems["mimeTypes"];
}

HarSanitizer.prototype.scrubMimeTypes = function(mimeTypes) {
  let condTable = {};

  for (let mimeType of mimeTypes) {
    let cond = (iter, key, value) => {
      let isKeyMimetype = (key == 'mimeType');
      let isValueMimetype = (value == mimeType);
      let isText = Object.keys(iter).includes('text');
      let isAll = (isKeyMimetype && isValueMimetype && isText);
      return isAll;
    };

    let callback = (iter, key, value) => {
      iter["text"] = "[" + mimeType + " redacted]";
    };

    condTable = [cond, callback.bind(this)];
    this.iterEvalExec(this.harJson, condTable);
  }
  return this.harJson;
}

HarSanitizer.prototype.scrubUrlPass = function() {
  let harStrRedacted = this.harStr;
  let harJsonRedacted = {};

  const re = /(:\/\/.+:)([\w.%!*()`~'-]+)(@)/g;
  let redacted = "$1[password redacted]$3";
  harStrRedacted = harStrRedacted.replace(re, redacted);
  harJsonRedacted = JSON.parse(harStrRedacted);
  return harJsonRedacted;
}

HarSanitizer.prototype.redactHar = function(scrublist) {
  this.harJson = this.scrubUrlPass();
  let harStrRedacted = this.harStr;
  let harJsonRedacted = {};
  let scrubList = this.trimWordlist(scrublist);
  let scrubListLower = scrubList.map(toLower);

  for (let type of Object.keys(this.harElems)) {
    for (let key of Object.keys(this.harElems[type])) {
      let keyLower = key.toLowerCase();
      let keyInList = scrubListLower.includes(keyLower);
      if (keyInList) {
        for (let value of this.harElems[type][key]) {
          let valueFormatted = escapeRegExp(value.toString());
          let regex = ""
          +"(" + key + "[^{}\\[\\]]*)"
          +"(\"value\":\"|=)"
          +"(" + valueFormatted + ")"
          +"(\",|\"}|\"]|;|&){1}";
          let redacted = "$1$2[" + key + " redacted]$4";
          let re = new RegExp(regex, "g");
          harStrRedacted = harStrRedacted.replace(re, redacted);
          // key/value order flipped regex
          let regexBackwards = ""
          +"(\"value\":\")"
          +"(" + valueFormatted + ")"
          +"([^{}\\[\\]]*\"name\":\"" + key + "\")";
          let redactedBackwards = "$1[" + key + " redacted]$3";
          let reBackwards = new RegExp(regexBackwards, "g");
          harStrRedacted = harStrRedacted.replace(reBackwards, redactedBackwards);
        }
      }
    }
  }
  harJsonRedacted = JSON.parse(harStrRedacted);
  return harJsonRedacted;
}
