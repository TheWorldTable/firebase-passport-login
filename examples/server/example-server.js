#!/usr/bin/env node
/* jshint -W106 */

const path = require('path'),
    program = require('commander'),
    https = require('https'),
    http = require('http'),
    fs = require('fs'),
    options = {
      key: fs.readFileSync(path.resolve(__dirname, 'ssl/domain.key')),
      cert: fs.readFileSync(path.resolve(__dirname, 'ssl/domain.crt')),
      ca: [
        fs.readFileSync(path.resolve(__dirname, 'ssl/ca1.crt')),
        fs.readFileSync(path.resolve(__dirname, 'ssl/ca2.crt'))
      ]
    },
    CONFIG_DIR = process.env.TWT_CONFIG_DIR || path.join(process.env.HOME || '/root', 'twt-config'),
    admin = require('firebase-admin');

program
    .version('3.0.0')
    .option('-p, --port <n>', 'http/https port', '443')
    .option('-l, --level <s>', 'express & router logging level')
    .option('--module-dev', 'use local firebase-passport-login module')
    .option('--insecure', 'run insecure/http server')
    .option('--test', 'run as test')
    .option('-v, --verbose', 'verbose output mode')
    .option('-T, --trace', 'console trace output mode')
    .option('-P, --project <project>', 'oAuth project', 'default')
    .option('-c, --config-dir <path>', 'configuration directory')
    .option('-h, --auth-host <hostname>', 'alternate host name for auth server [e.g. auth2.example.com')
    .option('--log-path <path>', 'Logfile path')
    .parse(process.argv);

if (program.authHost) {
  process.env.TWT_AUTH_HOST = program.authHost;
}

const express = require('express'),
    v1shim = require('oauth-shim'),
    logger = require('express-bunyan-logger'),
    config = require('./config'),
    app = express(),
    verbose = program.verbose ? console.log.bind(console) : function () {};

/********************************************************************************************
*
*   Config files are json files that contain the firebase project id/name "name" property
*
*   {
*     "name": "production-project-id",
*     "credentials": "production-rw.json"
*   }
*
*   Service account credentials (json files form google) are in a credentials subfolder
*   named by the "credentials" property (or named with project name)
*
*********************************************************************************************/

/**
 * Get server-side initialization info & credentials for twt firebase project
 * @param project {String} project id, project alias or defaults to 'default'
 * @param user {String} twt userId or 'backend' or 'admin' or defaults to 'backend'
 * @param configDir {String} twt-config directory or default to home directory + 'twt-config'
 * @returns {{name: String, initOptions: Object, databaseURL: string}}
 */
function getFirebaseConfig (project, user, configDir) {

  if (!project) {
    project = process.env.TWT_PROJECT || 'default';
  }

  if (!configDir) {
    configDir = process.env.TWT_CONFIG_DIR || path.join(process.env.HOME || '/root', 'twt-config');
  }

  let twtProject = {
    name: project
  };

  let configPath = path.join(configDir, `${project}.json`);

  if (fs.existsSync(configPath)) {
    twtProject = require(configPath);
    if (twtProject.name !== project) {
      twtProject.alias = project;
    }
  } else {
    return null;
  }

  twtProject.databaseURL = `https://${twtProject.name}.firebaseio.com`;

  twtProject.credentialsPath = path.join(configDir, 'credentials', twtProject.credentials || twtProject.name + '.json');
  twtProject.serviceAccount = require(twtProject.credentialsPath);
  twtProject.initOptions = {
    credential: admin.credential.cert(twtProject.serviceAccount),
    databaseURL: twtProject.databaseURL
  };

  if (!user || user !== 'admin') {
    twtProject.uid = user || 'backend';
    twtProject.initOptions.databaseAuthVariableOverride = {uid: twtProject.uid};
    if (twtProject.uid === 'backend') {
      twtProject.initOptions.databaseAuthVariableOverride.isBackendProcess = true;
    }
  }

  return twtProject;
}

let firebases = {}; // map of app:, database:

function getFirebaseConnection (firebaseUrl) {
  const match = /https:\/\/([^.]+)\./.exec(firebaseUrl),
      projectId = match[1];

  if (firebases[projectId]) {
    if (program.verbose) {
      verbose(`Returning cached connection to ${projectId}`);
    }
    return firebases[projectId].connection;
  }

  verbose(`Creating new connection to ${projectId}`);

  const twtProject = getFirebaseConfig(projectId, null, program.configDir || null);
  twtProject.connection = {
    app: admin.initializeApp(twtProject.initOptions, `auth2-connection-${projectId}`),
  };
  twtProject.connection.database = twtProject.connection.app.database();
  twtProject.connection.auth = twtProject.connection.app.auth();
  firebases[projectId] = twtProject;
  return twtProject.connection;
}

let firebasePassportLoginPath;

if (program.moduleDev) {
  firebasePassportLoginPath = '../../firebase-passport-login';
} else {
  firebasePassportLoginPath = 'firebase-passport-login';
}

const firebasePassportLogin = require(firebasePassportLoginPath),
    level = program.level || 'info',
    port = Number(program.port || (program.insecure ? 80 : 443)),
    logPath = program.logPath || '/var/log',
    logFile = path.join(logPath, 'oauth-client.log');

if (program.test) {

  app.get('/ping/', function (req, res) {
    res.send('pong');
  });

  http.createServer(app).listen(port);

  console.log(`Test server listening for OAuth requests on port ${port}`);

} else {

  // config.firebaseConfig = getFirebaseConfig(program.project);
  // config.firebaseProject = config.firebaseConfig.name;

  config.connectCallback = getFirebaseConnection;

  console.log(`Auth Host: ${program.authHost}`);
  console.log(`Port: ${port}`);
  console.log(`Secure: ${program.insecure ? 'no' : 'yes'}`);
  console.log(`Logging: ${logFile}`);
  console.log(`Module: ${firebasePassportLoginPath}`);

  let router = firebasePassportLogin(config, {}),
      eLog = logger({
        name: 'OAuthClient',
        streams: [{
          type: 'rotating-file',
          level: level,
          path: logFile,
          period: '1d',
          count: 8
        }]
      });

  app.use(eLog);

  app.get('/ping/', function (req, res) {
    res.send('pong');
  });

  app.use('/auth/', router);

  // Initiate the shim with Client ID's and secret, e.g.
  v1shim.init([{
    // id : secret
    client_id: config.twitter.consumerKey,
    client_secret: config.twitter.consumerSecret,
    // Define the grant_url where to exchange Authorisation codes for tokens
    grant_url: 'https://api.twitter.com/oauth/access_token',
    // Restrict the callback URL to a delimited list of callback paths
    //domain: 'test.com, example.com/redirect'
  }]);

  app.all('/oauthproxy/', v1shim);

  if (program.insecure) {
    http.createServer(app).listen(port);
  } else {
    https.createServer(options, app).listen(port);
  }

}
