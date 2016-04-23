
# Overview

This repository contains an *experimental* port of the
[OpenConnect VPN client](http://www.infradead.org/openconnect/) to Chrome OS.

The official copy of this repository is hosted at
<https://chromium.googlesource.com/apps/nacl-openconnect>.

All changes must go through the Gerrit code review server on
<https://chromium-review.googlesource.com>.  Please see the
[HACK.md](/HACK.md) document in this directory for details on submitting
patches.

# Building from source

This procedure has been tested on Ubuntu Trusty (14.04) running in a
[crouton](https://github.com/dnschneid/crouton) chroot.

nacl-openconnect is built using the
[Chrome Native Client SDK](https://developer.chrome.com/native-client/sdk/download)
and [webports](https://chromium.googlesource.com/webports/), so the first
step is to install the host dependencies listed on the home pages for those
projects (python, git, etc.).  Also, install the `openssl` command line
tool.  You do not need to manually install nacl\_sdk, webports, or
depot\_tools by hand.

Next, chdir into the `nacl-openconnect` source tree and type `make`.
This will download and compile several dependencies, and eventually
generate an `openconnect.crx` output file.

To modify the libopenconnect library and rebuild the app, use:
`make libopenconnect && make clean && make`

To rebuild the app after changing the vpn\_instance wrapper or the
JavaScript code, just use: `make`

If you are building under crouton on a Chromebook, it may be helpful
to leave all of your sources under the shared `~/Downloads` directory.

# Installation

To "sideload" an app or extension under Chrome OS, open up
`chrome://extensions` in the browser, then open the file manager with
Alt-Shift-M, then drag the .crx file onto the extensions page.  On the
initial attempt, Chrome will prompt for permission to install the app.
On subsequent attempts the installation will succeed "silently" without
opening any dialogs.

# Testing and debugging

This app has been tested using [ocserv](http://www.infradead.org/ocserv/)
configured for user/pass authentication.  It should also work with
standard Cisco ASA appliances.

You can view the debug output by opening `chrome://extensions` and
inspecting the background page (select the Console tab).
