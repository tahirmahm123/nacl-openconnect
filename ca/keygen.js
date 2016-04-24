"use strict";

// Generating a hardware-bound client certificate:
// 1) Enable key generation under chrome://settings/content on Chromebook
// 2) Run `nodejs keygen.js [<cert_name>]` on Linux PC
// 3) Point Chromebook to http://<pc_ip>:8097
// 4) Click submit button; browser will download user.crt
// 5) Navigate to chrome://settings/certificates
// 6) Click "Import and bind to device"
// 7) Double-click user.crt from Downloads

var http = require("http");
var qs = require("querystring");
var exec = require("child_process").exec;
var fs = require("fs");

var certtool = "./certtool-3.4";

var cn = "unknown";

if (process.argv.length == 3) {
  cn = process.argv[2];
}

console.log("issuing cert for: " + cn);

function signReq(resp, spkac) {
  fs.writeFile("newreq.spkac", "SPKAC=" + spkac, function(err) {
    if (err)
      return console.log(err);
    exec("openssl spkac -pubkey -in newreq.spkac -out newreq.pem",
        function(err, stdout, stderr) {
      if (err)
        return console.log(err);
      var info =
        "cn = " + cn + "\n" +
        "expiration_days = 365\n" +
        "encryption_key\n" +
        "signing_key\n";
      fs.writeFile("info.txt", info, function(err) {
        if (err)
          return console.log(err);
        exec(certtool + " --generate-certificate --template info.txt " +
            "--load-ca-certificate cacert.pem " +
            "--load-ca-privkey cakey.pem " +
            "--load-pubkey newreq.pem --outder --outfile newcert.pem",
            function(err, stdout, stderr) {
          if (err)
            return console.log(err);
          fs.readFile("newcert.pem", function(err, data) {
            if (err)
              return console.log(err);
            console.log("sending certificate");
            resp.writeHead(200, {
              'Content-Type': 'application/x-x509-user-cert',
              'Content-Length': data.length
            });
            resp.end(data);
            process.exit(0);
          });
        });
      });
    });
  });
}

http.createServer(function(req, resp) {
  if (req.url === "/") {
    resp.writeHead(200, {'Content-Type': 'text/html'});
    resp.write("<html><body><form method='post' action='/keygen'><keygen name=request>");
    resp.write("<input type=submit></form></body></html>\n");
    resp.end();
    return;
  } else if (req.url === "/keygen") {
    var body = "";

    req.on("data", function(data) {
      body += data;
    });
    req.on("end", function() {
      console.log("processing request...");
      signReq(resp, qs.parse(body).request);
    });
  }
}).listen(8097);
