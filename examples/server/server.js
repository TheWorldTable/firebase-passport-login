var path = require('path'),
  program = require('commander'),
  express = require('express'),
  https = require('https'),
  config = require('./config'),
  firebasePassportLogin = require('firebase-passport-login'),
  fs = require('fs'),
  app = express(),
  options = {
    key: fs.readFileSync(path.resolve(__dirname, 'ssl/local.example.com.key')),
    cert: fs.readFileSync(path.resolve(__dirname, 'ssl/local.example.com.crt')),
    /*
    ca: [
      fs.readFileSync(path.resolve(__dirname, 'ssl/ca1.crt')),
      fs.readFileSync(path.resolve(__dirname, 'ssl/ca2.crt')),
      fs.readFileSync(path.resolve(__dirname, 'ssl/ca3.crt'))
    ]
    */
  };

program
  .version('1.0.0')
  .option('-p, --port <n>', 'Port', parseInt)
  .option('--dev', 'Run in development mode')
  .parse(process.argv);

if (program.dev) {
  console.log("Running in development mode");
}

var port = Number(program.port || 443),
  router = firebasePassportLogin(config, {devMode: program.dev});
app.use('/auth/', router);
https.createServer(options, app).listen(port);
console.log("Listening for OAuth requests on port " + port);


