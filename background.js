// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/* globals buildcfg */

"use strict";

// connection state machine
var state_ = "idle";

// for attempting reconnections after resume
var retry_timer_ = undefined;

// state of our nacl process, null if stopped
var nacl_ = null;

// does this app own the system VPN from shill's perspective?
var vpnOwned_ = false;

// user's VPN configuration (URL, username, etc.)
var config_;

function startNative() {
  if (nacl_ !== null)
    return;
  var element = document.createElement('embed');
  if (buildcfg.portable) {
    element.setAttribute("type", "application/x-pnacl");
    element.setAttribute("src", "portable.nmf");
  } else {
    element.setAttribute("type", "application/x-nacl");
    element.setAttribute("src", "native.nmf");
  }
  element.setAttribute("width", 0);
  element.setAttribute("height", 0);
  element.addEventListener('load', function() {
    console.debug("<-nacl loaded");
  });
  element.addEventListener('crash', function() {
    console.debug("<-nacl crashed");
    setConnectionState("failure");
    stopNative();
  });
  element.addEventListener('message', handleMessage);
  document.body.appendChild(element);
  nacl_ = {"element": element};
}

function stopNative() {
  if (nacl_ !== null) {
    document.body.removeChild(nacl_.element);
    console.log("terminating NaCl module");
  }
  nacl_ = null;
}

function postMessage(m) {
  if (nacl_ === null) {
    console.log("tried to post '" + m.cmd + "' while nacl is down");
    return;
  }
  nacl_.element.postMessage(m);
}

function setConnectionState(newState) {
  // notifyConnectionStateChanged throws an exception if our extension ID
  // isn't permitted to manipulate the VPN interface
  if (vpnOwned_ !== true)
    return;
  chrome.vpnProvider.notifyConnectionStateChanged(newState, function() {
    console.debug("->notifyConnectionStateChanged: " + newState);
  });
}

function handleConnectDisconnect(d) {
  if (d.data === "connected") {
    advanceStateMachine("nacl_connected");
  } else if (d.data === "disconnected") {
    advanceStateMachine("nacl_disconnected");
  } else if (d.data === "reconnected") {
    sendIpParameters();
  } else {
    console.error("unknown state: " + d.data);
  }
}

function sendIpParameters() {
  if (!nacl_.ipParams)
    return;
  var log_cb = function() { console.debug("->setParameters"); };
  try {
    chrome.vpnProvider.setParameters(nacl_.ipParams, log_cb);
  } catch (e) {
    // backward compatibility for <= Chrome M50
    console.debug("Enabling M50 compatibility");
    delete nacl_.ipParams.reconnect;
    chrome.vpnProvider.setParameters(nacl_.ipParams, log_cb);
  }
}

function handleIpParameters(d) {
  nacl_.ipParams = {
    "address": d.ipv4_addr + "/32",
    "mtu": d.mtu.toString(),
    "exclusionList": [d.gateway_ips + "/32"],
    "inclusionList": ["0.0.0.0/0"],
    "dnsServers": d.dns,
    "reconnect": "true"
  };
  sendIpParameters();
}

function handleCertValidation(d) {
  chrome.platformKeys.verifyTLSServerCertificate({
    "serverCertificateChain": d.cert_chain,
    "hostname": d.hostname
  }, function(result) {
    var res = "reject";
    if (result.trusted) {
      res = "accept";
      console.debug("platformKeys: cert passed");
    } else {
      console.error("cert failed:");
      console.error(result.debug_errors);
    }
    postMessage({"cmd": "peer_cert", "result": res});
  });
}

function handleAuthForm(d) {
  var opts = {};

  for (var i = 0; i < d.opts.length; i++) {
    var opt = d.opts[i];
    if (opt.name === "username") {
      if (!nacl_.usernameSent) {
        opts.username = config_.username;
        nacl_.usernameSent = true;
      }
    }
    if (opt.name === "password") {
      if (!nacl_.passwordSent) {
        opts.password = config_.password;
        nacl_.passwordSent = true;
      }
    }
  }
  if (Object.keys(opts).length > 0) {
    postMessage({"cmd": "auth_form", "opts": opts, "result": "submit"});
  } else {
    console.error("don't know how to handle this auth form:");
    console.error(d);
    postMessage({"cmd": "auth_form", "result": "cancel"});
  }
}

function handleCrypto(d) {
  chrome.platformKeys.selectClientCertificates({
    interactive: false,
    request: {
      certificateTypes: [ "rsaSign" ],
      certificateAuthorities: []
    }
  }, function(certlist) {
    // TODO: pick the right cert here
    if (certlist.length === 0) {
      postMessage({"cmd": d.cmd, "success": false});
      return;
    }
    var cert = certlist[0].certificate;

    if (d.cmd === "crypto-getcert") {
      postMessage({"cmd": d.cmd, "data": cert});
      return;
    }

    var keyParams = {
      hash: {
        name: "none"
      },
      name: "RSASSA-PKCS1-v1_5"
    };
    chrome.platformKeys.getKeyPair(cert, keyParams,
        function(pubKey, privKey) {
      if (privKey === null) {
        console.error("no private key for " + d.hash);
        postMessage({"cmd": d.cmd, "success": false});
        return;
      }

      if (d.cmd === "crypto-getprivkey") {
        postMessage({
          "cmd": d.cmd,
          "success": true,
          "privkey_type": privKey.algorithm.name
        });
        return;
      }

      // else: d.cmd === "crypto-sign"

      var sc = chrome.platformKeys.subtleCrypto();
      var future = sc.sign(privKey.algorithm, privKey, new Uint8Array(d.data));
      future.then(function(result) {
        postMessage({"cmd": d.cmd, "data": result});
      }, function() {
        console.error("crypto-sign failed");
        postMessage({"cmd": d.cmd, /* "data" is null */});
      });
    });
  });
}

function handleMessage(m) {
  var d = m.data;
  if (d instanceof ArrayBuffer) {
    if (vpnOwned_ === true)
      chrome.vpnProvider.sendPacket(d);
  } else if (d instanceof Object) {
    var cmd = d.cmd;
    if (cmd === "status") {
      handleConnectDisconnect(d);
    } else if (cmd === "ip") {
      handleIpParameters(d);
    } else if (cmd === "peer_cert") {
      handleCertValidation(d);
    } else if (cmd === "auth_form") {
      handleAuthForm(d);
    } else if (cmd.startsWith("crypto-")) {
      handleCrypto(d);
    } else if (cmd === "abort") {
      advanceStateMachine("nacl_disconnected");
    } else {
      console.debug(d);
    }
  }
}

function getConnection(name, f) {
  chrome.storage.local.get("connection", function(val) {
    f(val.connection);
  });
}

function lookupConfig(id, callback) {
  getConnection(id, function(conn) {
    if (conn === undefined) {
      setConnectionState("failure");
      console.error("can't find VPN " + id);
      openSettings();
    } else {
      config_ = conn;
      callback();
    }
  });
}

function doConnect() {
  startNative();
  postMessage({"cmd": "connect", "url": config_.url});
}

function clearRetryTimer() {
  if (retry_timer_)
    clearTimeout(retry_timer_);
  retry_timer_ = undefined;
}

function badTransition(message) {
  console.error("bad state transition: state=" + state_,
                "platformMessage=" + message);
  setConnectionState("failure");
}

function advanceStateMachine(message) {
  console.debug("advanceStateMachine: message=" + message,
                "oldState=" + state_);

  if (state_ === "idle") {
    if (message === "connected") {
      vpnOwned_ = true;
      doConnect();
      state_ = "active";
    } else if (message === "disconnected") {
      // ignore
    } else {
      badTransition(message);
    }
    return;
  }

  // The system has forcibly disconnected us
  if (message === "disconnected") {
    // FIXME: do a clean nacl shutdown
    clearRetryTimer();
    vpnOwned_ = false;
    stopNative();
    state_ = "idle";
    return;
  }

  if (state_ === "active") {
    if (message === "linkChanged") {
      postMessage({"cmd": "reconnect"});
    } else if (message === "linkDown") {
      postMessage({"cmd": "pause"});
      state_ = "paused";
    } else if (message === "suspend") {
      stopNative();
      state_ = "suspended";
    } else if (message === "nacl_connected") {
      setConnectionState("connected");
    } else if (message === "nacl_disconnected") {
      setConnectionState("failure");
      vpnOwned_ = false;
      stopNative();
      state_ = "idle";
    } else {
      badTransition(message);
    }
  } else if (state_ === "suspended") {
    if (message === "resume") {
      state_ = "reconnecting";
      doConnect();
    } else if (message === "linkDown") {
      state_ = "waiting";
    } else if (message === "linkChanged") {
      // no change - keep waiting for resume
    } else {
      badTransition(message);
    }
  } else if (state_ === "reconnecting") {
    if (message === "nacl_connected") {
      state_ = "active";
    } else if (message === "linkDown") {
      clearRetryTimer();
      stopNative();
      state_ = "waiting";
    } else if (message === "suspend") {
      clearRetryTimer();
      stopNative();
      state_ = "suspended";
    } else if (message === "linkChanged") {
      clearRetryTimer();
      stopNative();
      retry_timer_ = setTimeout(function() {
        advanceStateMachine("retry");
      }, 500);
    } else if (message === "nacl_disconnected") {
      clearRetryTimer();
      stopNative();
      retry_timer_ = setTimeout(function() {
        advanceStateMachine("retry");
      }, 2000);
    } else if (message === "retry") {
      doConnect();
    } else {
      badTransition(message);
    }
  } else if (state_ === "waiting") {
    if (message === "linkUp") {
      state_ = "reconnecting";
      doConnect();
    } else if (message === "resume") {
      // no change - link is still down
    } else if (message === "linkDown") {
      // HACK: work around duplicate messages
    } else {
      badTransition(message);
    }
  } else if (state_ === "paused") {
    if (message === "linkUp") {
      postMessage({"cmd": "resume"});
      state_ = "active";
    } else if (message === "suspend") {
      state_ = "waiting";
      stopNative();
    } else {
      badTransition(message);
    }
  }
}

chrome.vpnProvider.onPlatformMessage.addListener(function(id, message, error) {
  console.debug("<-onPlatformMessage", "id=" + id, "message=" + message, "error=" + error);
  if (message === "connected") {
    lookupConfig(id, function() { advanceStateMachine("connected"); });
  } else {
    advanceStateMachine(message);
  }
});

function openSettings() {
  chrome.app.window.create('settings.html', {
    'outerBounds': {
      'width': 400,
      'height': 500
    }
  }, function(createdWindow) {
    createdWindow.contentWindow.reloadConfig = reloadConfig;
  });
}

chrome.vpnProvider.onUIEvent.addListener(openSettings);

chrome.vpnProvider.onPacketReceived.addListener(function(data) {
  postMessage(data);
});

function reloadConfig() {
  getConnection("Default", function(conn) {
    if (conn !== undefined) {
      chrome.vpnProvider.createConfig("Default", function() {
        if (chrome.runtime.lastError) {
          // ignore - this just means we're re-registering the same
          // VPN name
        }
      });
    }
  });
}

reloadConfig();

chrome.app.runtime.onLaunched.addListener(openSettings);

chrome.runtime.onInstalled.addListener(function() {
  // force the pexe to be compiled now, so the user doesn't have to wait
  // a long time for his first connection to start
  startNative();
  reloadConfig();
});
