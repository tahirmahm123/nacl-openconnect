// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

"use strict";

var clientCert = undefined;

function enableSave() {
  var button = $("#save");
  button.removeAttr("disabled");
  button.text("Save changes");
  $("#cancel").text("Cancel");
}

function disableSave() {
  var button = $("#save");
  button.attr("disabled", "disabled");
  button.text("Saved");
  $("#cancel").text("Close");
}

function saveChanges() {
  var conn = {
    "url": $("#url").val(),
    "username": $("#username").val(),
    "password": $("#password").val(),
    "clientCert": clientCert
  };
  chrome.storage.local.set({"connection": conn}, function() {
    disableSave();
    reloadConfig();
  });
}

function setCert(digest) {
  if (digest === undefined) {
    $("#selected-cert").html("No certificate selected");
    clientCert = undefined;
  } else {
    $("#selected-cert").html(digest);
    clientCert = digest;
  }
}

function selectCert() {
  chrome.platformKeys.selectClientCertificates({
    interactive: true,
    request: {
      certificateTypes: [ "rsaSign" ],
      certificateAuthorities: []
    }
  }, function(certlist) {
    if (certlist.length === 0) {
      if (clientCert !== undefined) {
        enableSave();
      }
      setCert(undefined);
    } else {
      sha256(certlist[0].certificate).then(function(digest) {
        if (clientCert !== digest) {
          enableSave();
        }
        setCert(digest);
      });
    }
  });
}

$(document).ready(function() {
  disableSave();
  $("#select-cert").click(selectCert);
  $("#save").click(saveChanges);
  $("#cancel").click(function() { window.close(); });
  $("input").keyup(enableSave);

  chrome.storage.local.get("connection", function(res) {
    var conn = res.connection;
    if (conn !== undefined) {
      $("#url").val(conn.url);
      $("#username").val(conn.username);
      $("#password").val(conn.password);
      setCert(conn.clientCert);
    }
  });
});
