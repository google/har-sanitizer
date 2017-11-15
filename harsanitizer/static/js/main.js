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

var defaultWordList = [
    "state",
    "shdf",
    "usg",
    "password",
    "email",
    "code",
    "code_verifier",
    "client_secret",
    "client_id",
    "token",
    "access_token",
    "authenticity_token",
    "id_token",
    "appID",
    "challenge",
    "facetID",
    "assertion",
    "fcParams",
    "serverData",
    "Authorization",
    "auth",
    "x-client-data",
    "SAMLRequest",
    "SAMLResponse"
];

var defaultContentList = [
    "application/javascript",
    "text/javascript",
    "text/html",
    "text/css",
    "text/xml",
];

var destroyClickedElement = function(event) {
  document.body.removeChild(event.target);
};

var toLower = function(x) {
  return x.toLowerCase();
};

var hsweb = function() {
  this.defaultWordList = defaultWordList;
  this.defaultContentList = defaultContentList;
  this.pageContent = $(".page-content");
  this.uploadForm = $("#upload-form");
  this.fileInput = $("#file-input");
  this.fileInput.change(this.onFileAdded.bind(this));

  this.tabs = $(".mdl-tabs");
  this.tabsBar = $("#tabs-bar");
  this.tabsSpinner = $("#tabs-spinner");
  this.cookiesTable = $("#cookies-table");
  this.headersTable = $("#headers-table");
  this.paramsTable = $("#params-table");
  this.mimetypesTable = $("#mimetypes-table");
  this.tableSelectAlls = $.find('thead .mdl-data-table__select');

  this.bottomButtons = $(".bottom-buttons");

  this.changesDialog = $("#change-dialog");

  this.changesDialogClose = $("#change-dialog-close");
  this.changesDialogConfirm = $("#change-dialog-confirm");

  this.previewBody = $("#preview-body");
  this.previewText = $("#preview-text");

  this.initVars();
  this.clickActionBehavior();

};

hsweb.prototype.initVars = function() {
  this.checkBoxesObj = {};
  this.harStr = null;
  this.harJson = null;
  this.cookies = [];
  this.headers = [];
  this.params = [];
  this.postparams = [];
  this.params = [];
  this.mimetypes = [];
  this.wordList = [];
  this.contentList = [];
  this.originalHarText = "";
  this.redactedFilename = "";
  this.formChanged = false;
  this.hs = null;
  this.harElems = {};
};

hsweb.prototype.clickActionBehavior = function() {
  this.fileUpload = $("#load-har");
  this.fileUpload.click(this.onFileUploadClicked.bind(this));
  this.previewButton = $("#preview");
  this.previewButton.click(this.onPreviewButtonClicked.bind(this));
  this.scrubButton = $("#scrub");
  this.scrubButton.click(this.onScrubButtonClicked.bind(this));
  this.exportButton = $("#export");
  this.exportButton.click(this.onExportButtonClicked.bind(this));
  this.previewBackButton = $("#preview-back");
  this.previewBackButton.click(this.hidePreview.bind(this));
};

hsweb.prototype.applyChangesDiag = function(callback) {
  this.changesDialog.get(0).showModal();
  this.changesDialogClose.click(() => {
    this.changesDialog.get(0).close();
    callback.call(this);
  });
  this.changesDialogConfirm.click(() => {
    this.changesDialog.get(0).close();
    this.onScrubButtonClicked().done(() => {
      callback.call(this);
    });
  });
};

hsweb.prototype.onPreviewButtonClicked = function(event) {
  var callback = () => {
    var content = this.harStr;
    this.showPreview(content);
  };
  if (this.formChanged) {
    // Callback would be permanently set after the 1st time if
    // not unbound here
    this.changesDialogClose.unbind();
    this.changesDialogConfirm.unbind();
    this.applyChangesDiag(callback);
  } else {
    callback.call(this);
  }
};

hsweb.prototype.onExportButtonClicked = function(event) {
  var callback = () => {
    content = new Blob([this.harStr], {type:"text/plain"});
    var downloadLink = document.createElement("a");
    downloadLink.download = this.redactedFilename;
    downloadLink.innerHTML = "Download File";
    if (window.URL != null) {
      // Chrome allows the link to be clicked
      // without actually adding it to the DOM.
      downloadLink.href = window.URL.createObjectURL(content);
    } else {
      // Firefox requires the link to be added to the DOM
      // before it can be clicked.
      downloadLink.href = window.URL.createObjectURL(content);
      downloadLink.onclick = destroyClickedElement;
      downloadLink.style.display = "none";
      document.body.appendChild(downloadLink);
    }
    downloadLink.click();
  };

  if (this.formChanged) {
    // Callback would be permanently set after the 1st time if
    // not unbound here
    this.changesDialogClose.unbind();
    this.changesDialogConfirm.unbind();
    this.applyChangesDiag(callback);
  } else {
    callback.call(this);
  }
};

hsweb.prototype.onFileUploadClicked = function(event) {
  this.fileInput.click();
};

hsweb.prototype.onFileAdded = function(event) {
  var file = this.fileInput[0].files[0];
  var filename = file.name;
  if (file) {
    var reader = new FileReader();
    reader.onload = this.loadFile.bind(this, reader, filename);
    reader.readAsText(file);
  } else {
      this.disableElements.call(this);
      this.tabsSpinner.removeClass("is-active");
      componentHandler.upgradeDom();
      alert("Failed to load file");
    }
  this.fileInput[0].value = '';
};

hsweb.prototype.loadFile = function(reader, filename) {
  var fileText = reader.result;
  try {
    var harJson = JSON.parse(fileText);
    if (!(harJson["log"]["entries"].length >= 1)) {
      throw("Invalid HAR JSON");
    }
  } catch(err) {
    this.disableElements();
    this.tabsSpinner.removeClass("is-active");
    componentHandler.upgradeDom();
    alert("File not a valid HAR JSON");
    return;
  }
  this.initVars();
  this.disableElements();
  this.originalHarText = fileText;
  this.redactedFilename = "redacted_" + filename;
  // Clear previously checked "All *" checkboxes
  $.each(this.tableSelectAlls, (index, element) => {
    element.MaterialCheckbox.uncheck();
    element.MaterialCheckbox.updateClasses_();
  });
  this.scrubHar(harJson, [], []).done(() => {
    this.onLoadedHarData();
  });
};

hsweb.prototype.scrubHar = function(harJson, wordlist, contentlist) {
  var deferred = $.Deferred();
  var self = this;
  let hs = new HarSanitizer(harJson);
  let contentListConcat = self.defaultContentList.concat(contentlist);
  let wordListConcat = self.defaultWordList.concat(wordlist);
  // Remove duplicate list entries
  self.wordList = [...new Set(wordListConcat)];
  self.contentList = [...new Set(contentListConcat)];

  var scrubMimeTypes = (self, hs) => {
    let mimeDeferred = $.Deferred();
    // setTimeout used throughout to make expensive functions run async
    setTimeout((self, hs, mimeDeferred) => {
      hs.harJson = hs.scrubMimeTypes(self.contentList);
      mimeDeferred.resolve();
    }, 400, self, hs, mimeDeferred);
    return mimeDeferred.promise();
  };

  $.when(
      scrubMimeTypes(self, hs),
      self.getHarData(hs),
    ).then(() => {
      let redactDeferred = $.Deferred();
      setTimeout((self, hs, redactDeferred) => {
        hs.harJson = hs.redactHar(self.wordList);
        redactDeferred.resolve();
      }, 400, self, hs, redactDeferred);
    return redactDeferred.promise();
  }).then(() => {
      self.harJson = hs.harJson;
      self.harStr = JSON.stringify(self.harJson, null, 2);
      self.formChanged = false;
      deferred.resolve();
  }).fail(() => {
      console.log("scrubHar() failed");
      self.disableElements();
      self.tabsSpinner.removeClass("is-active");
      deferred.reject();
      componentHandler.upgradeDom();
      alert("Error submitting HAR.  Please contact support.");
  });
  return deferred.promise();
};

hsweb.prototype.getHarData = function (hs) {
  var deferred = $.Deferred();
  var self = this;

  var getCookies = (self) => {
    let getDeferred = $.Deferred();
    setTimeout((self, hs, getDeferred) => {
      try {
        self.cookies = Object.keys(hs.getTypeNames("cookies"));
        getDeferred.resolve();
      } catch(err) {
        console.log("Error getting HarType: ", err);
        getDeferred.reject();
      }
    }, 400, self, hs, getDeferred);
    return getDeferred.promise();
  };
  var getHeaders = (self) => {
    let getDeferred = $.Deferred();
    setTimeout((self, hs, getDeferred) => {
      try {
        self.headers = Object.keys(hs.getTypeNames("headers"));
        getDeferred.resolve();
      } catch(err) {
        console.log("Error getting HarType: ", err);
        getDeferred.reject();
      }
    }, 400, self, hs, getDeferred);
    return getDeferred.promise();
  };
  var getUrlparams = (self) => {
    let getDeferred = $.Deferred();
    setTimeout((self, hs, getDeferred) => {
      try {
        self.urlparams = Object.keys(hs.getTypeNames("queryString"));
        getDeferred.resolve();
      } catch(err) {
        console.log("Error getting HarType: ", err);
        getDeferred.reject();
      }
    }, 400, self, hs, getDeferred);
    return getDeferred.promise();
  };
  var getPostparams = (self) => {
    let getDeferred = $.Deferred();
    setTimeout((self, hs, getDeferred) => {
      try {
        self.postparams = Object.keys(hs.getTypeNames("params"));
        getDeferred.resolve();
      } catch(err) {
        console.log("Error getting HarType: ", err);
        getDeferred.reject();
      }
    }, 400, self, hs, getDeferred);
    return getDeferred.promise();
  };
  var getMimetypes = (self) => {
    let getDeferred = $.Deferred();
    setTimeout((self, hs, getDeferred) => {
      try {
        self.mimetypes = hs.getMimeTypes();
        getDeferred.resolve();
      } catch(err) {
        console.log("Error getting HarType: ", err);
        getDeferred.reject();
      }
    }, 400, self, hs, getDeferred);
    return getDeferred.promise();
  };
  $.when(
    getCookies(self),
    getHeaders(self),
    getUrlparams(self),
    getPostparams(self),
    getMimetypes(self)).then(() => {
      // Combine self.urlparams and self.postparams to self.params
      try {
        self.params = self.urlparams.concat(self.postparams);
      } catch(err) {
        console.log("Error assigning self.params: ", err);
        deferred.reject();
      }
      deferred.resolve();
      }).fail(() => {
        console.log("Error getting harElems.");
        deferred.reject();
      });
    return deferred.promise();
  };

hsweb.prototype.onLoadedHarData = function() {
  // Populate tables with Har's type [cookies | headers | params | mimetypes] names
  let typesTable = {
    "cookies": this.cookies,
    "headers": this.headers,
    "params": this.params,
    "mimetypes": this.mimetypes,
  };
  // NOTE: I used $.each to iterate this object in order to avoid closure problems
  $.each(typesTable, (key, value) => {
    $('#'+key+'-table > tbody').empty();
    $.each(value, (index, element) => {
      let ident = key + '-' + index;
      // Limit list entries to 50 characters or less
      if (element.length >= 50) {
        var elementText = element.slice(0,50) + "...";
      } else {
        var elementText = element;
      }
      $('#'+key+'-table > tbody:last-child').append(
        '<tr>'
        +'<td>'
        +'<label class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect mdl-data-table__select"'
        +'for="'+ident+'-checkbox" value="'+element+'" id="'+ident+'-label">'
        +'<input type="checkbox" value="'+element+'" id="'+ident+'-checkbox" '
        +'class="mdl-checkbox__input" />'
        +'</label>'
        +'<td class="mdl-data-table__cell--non-numeric" id="'+ident+'-td">'
        +elementText+'</td>'
        +'</tr>'
        );
      componentHandler.upgradeDom();

      // Strike out default scrub list elements, check others
      let elementLower = element.toLowerCase();
      let defaultWordListLower = this.defaultWordList.map(toLower);
      let defaultContentListLower = this.defaultContentList.map(toLower);
      let isInDefaultWordList = $.inArray(elementLower, defaultWordListLower) != -1;
      let isInDefaultContentList = $.inArray(elementLower, defaultContentListLower) != -1;
      let isInWordList = $.inArray(element, this.wordList) != -1;
      let isInContentList = $.inArray(element, this.contentList) != -1;
      if (isInWordList == true || isInContentList == true) {
        $('#'+ident+'-label').get(0).MaterialCheckbox.check();
        $('#'+ident+'-label').get(0).MaterialCheckbox.updateClasses_();
      }
      if (isInDefaultWordList == true || isInDefaultContentList == true) {
        $('#'+ident+'-label').empty();
        $('#'+ident+'-td').css("color", "red");
        $('#'+ident+'-td').css("text-decoration", "line-through");
      }
    });

    elemTable = key + 'Table';
    headerCheckbox = key + 'HeaderCheckbox';
    this.checkBoxesObj[elemTable] = $('#' + key + '-table');
    this.checkBoxesObj[headerCheckbox] = this.checkBoxesObj[elemTable]
      .find('#' + key + '-table-header');
    this.checkBoxesObj[key + 'Boxes'] = this.checkBoxesObj[elemTable]
      .find('tbody .mdl-data-table__select');

    // Select All checkbox event handling
    this.checkBoxesObj[key + 'HeaderCheckHandler'] = function(event) {
      if (event.target.checked) {
        this.checkBoxesObj[key + 'Boxes'].each((index, element) => {
          element.MaterialCheckbox.check();
          element.MaterialCheckbox.updateClasses_();
        });
      } else {
        this.checkBoxesObj[key + 'Boxes'].each((index, element) => {
          element.MaterialCheckbox.uncheck();
          element.MaterialCheckbox.updateClasses_();
        });
      }
      this.formChanged = true;
    };
    // Select All checkbox event handling
    this.checkBoxesObj[headerCheckbox].change(
      this.checkBoxesObj[key + 'HeaderCheckHandler'].bind(this));

    // Update this.formChanged if any checkboxes were clicked
    this.checkBoxesObj[key + 'Boxes'].change(() => {
      this.formChanged = true;
    });
  });

  // Tables have been populated, DOM needs to be refreshed
  componentHandler.upgradeDom();
  // Show hidden elements
  this.enableElements.call(this);
};

hsweb.prototype.onScrubButtonClicked = function(event) {
  var deferred = $.Deferred();
  this.disableElements();
  this.wordList = [];
  this.contentList = [];
  this.harJson = JSON.parse(this.originalHarText);
  componentHandler.upgradeDom();
  // Populate lists
  $.each(['cookies', 'headers', 'params', 'mimetypes'], (index, type) => {
    elemTable = type + 'Table';
    this.checkBoxesObj[elemTable] = $('#' + type + '-table');
    this.checkBoxesObj[type + 'Boxes'] = this.checkBoxesObj[elemTable]
      .find('tbody .mdl-checkbox__input');
    this.checkBoxesObj[type + 'Boxes'].each((index, element) => {
      if (element.checked == true) {
        var elemValue = element.value;
        if (type == 'mimetypes') {
          this.contentList.push(elemValue);
        } else {
          this.wordList.push(elemValue);
        }
      }
    });
  });
  // Run the scrub
  this.scrubHar(this.harJson, this.wordList, this.contentList).done(() => {
    this.onLoadedHarData();
    deferred.resolve();
  });
  return deferred.promise();
};

hsweb.prototype.disableElements = function() {
  // Make tabs bar spinner visible and disables DOM elements
  this.tabsSpinner.addClass("is-active");
  this.pageContent.hide('medium');
  this.bottomButtons.hide('medium');
  this.previewBody.hide('medium');
  this.previewBackButton.hide('medium');
  componentHandler.upgradeDom();
};

hsweb.prototype.enableElements = function() {
  // Make tabs bar spinner invisible and enables DOM elements
  this.tabsSpinner.removeClass("is-active");
  this.pageContent.show('medium');
  this.bottomButtons.show('medium').css('display', 'flex');
  this.previewButton.show("medium").css('display', 'flex');
  this.scrubButton.show("medium").css('display', 'flex');
  componentHandler.upgradeDom();
};

hsweb.prototype.showPreview = function(content) {
  this.pageContent.hide("medium");
  this.previewButton.hide("medium");
  this.scrubButton.hide("medium");
  this.previewBackButton.show('medium').css('display', 'flex');
  this.previewText.text(content);
  this.previewBody.show('medium');
  componentHandler.upgradeDom();
};

hsweb.prototype.hidePreview = function() {
  this.previewBackButton.hide('medium');
  this.previewBody.hide('medium');
  this.previewText.text('');
  this.pageContent.show('medium').css('display', 'flex');
  this.previewButton.show("medium").css('display', 'flex');
  this.scrubButton.show("medium").css('display', 'flex');
  componentHandler.upgradeDom();
}

// Init page w/ hsweb class
$(document).ready(function() {
    window.app = new hsweb();
});
