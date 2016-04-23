// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

"use strict";

var foo;

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
    "password": $("#password").val()
  };
  chrome.storage.local.set({"connection": conn}, function() {
    disableSave();
    reloadConfig();
  });
}

$(document).ready(function() {
  disableSave();
  $("#save").click(saveChanges);
  $("#cancel").click(function() { window.close(); });
  $("input").keyup(enableSave);

  chrome.storage.local.get("connection", function(res) {
    var conn = res.connection;
    if (conn !== undefined) {
      $("#url").val(conn.url);
      $("#username").val(conn.username);
      $("#password").val(conn.password);
    }
  });
});
