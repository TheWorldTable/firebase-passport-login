var path = require('path');
var express = require('express');
var https = require('https');
var config = require('./config');
var router = require('../../server/router')(config);
var fs = require('fs');

var app = express();
var port = Number(process.env.PORT || 8008);
var options = {
  key: fs.readFileSync(path.resolve(__dirname, 'ssl/local.example.com.key')),
  cert: fs.readFileSync(path.resolve(__dirname, 'ssl/local.example.com.crt'))
};

app.use('/auth/', router);
https.createServer(options, app).listen(port);
console.log("Listening for OAuth requests on port " + port);
