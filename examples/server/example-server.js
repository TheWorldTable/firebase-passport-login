#!/usr/bin/env node
/* jshint -W106 */

const path = require('path'),
    program = require('commander'),
    https = require('https'),
    http = require('http'),
    fs = require('fs'),
    options = {
      key: fs.readFileSync(path.resolve(__dirname, 'ssl/star.worldtable.co.key')),
      cert: fs.readFileSync(path.resolve(__dirname, 'ssl/star.worldtable.co.crt')),
      ca: [
        fs.readFileSync(path.resolve(__dirname, 'ssl/ca1.crt')),
        fs.readFileSync(path.resolve(__dirname, 'ssl/ca2.crt'))
      ]
    },
    CONFIG_DIR = process.env.TWT_CONFIG_DIR || path.join(process.env.HOME || '/root', 'twt-config'),
    admin = require('firebase-admin');

program.version('3.1.0')
    .option('-p, --port <n>', 'http/https port (env TWT_UATH_PORT)', process.env.TWT_AUTH_PORT || null)
    .option('-l, --level <s>', 'express & router logging level (env TWT_AUTH_LOG_LEVEL)', process.env.TWT_AUTH_LOG_LEVEL || 'info')
    .option('--module-dev', 'use local firebase-passport-login module (env TWT_AUTH_DEV_MODULE)')  // loads auth from ../../firebase-passport-login
    .option('--insecure', 'run insecure/http server (env TWT_AUTH_INSECURE)')
    .option('--test', 'run as test') // to test server connectivity
    .option('-v, --verbose', 'verbose output mode (env TWT_AUTH_VERBOSE)')
    .option('-c, --config-dir <path>', 'configuration directory (env TWT_CONFIG_DIR)', process.env.TWT_CONFIG_DIR || path.join(process.env.HOME || '/root', 'twt-config'))
    .option('-H, --auth-host <hostname>', 'alternate host name for auth server [e.g. auth2.worldtable.co] (env TWT_AUTH_HOST)')
    .option('--log-path <path>', 'Logfile path (env TWT_AUTH_LOG_PATH)', process.env.TWT_AUTH_LOG_PATH || '/tmp')
    .option('--test', 'run as test') // to test server connectivity, uri with path /ping should respond with 'pong'
    .parse(process.argv);

if (program.authHost) {
  process.env.TWT_AUTH_HOST = program.authHost;
}

if (process.env.TWT_AUTH_VERBOSE && process.env.TWT_AUTH_VERBOSE !== '0') {
  program.verbose = true;
}

if (process.env.TWT_AUTH_INSECURE && process.env.TWT_AUTH_INSECURE !== '0') {
  program.insecure = true;
}

if (process.env.TWT_AUTH_DEV_MODULE && process.env.TWT_AUTH_DEV_MODULE !== '0') {
  program.moduleDev = true;
}

const express = require('express'),
    v1shim = require('oauth-shim'),
    logger = require('express-bunyan-logger'),
    moment = require('moment'),
    config = require('./config'),
    app = express(),
    configDir = program.configDir,
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
 * @param {String} project project id, project alias or defaults to 'default'
 * @param {String} user twt userId or 'backend' or 'admin' or defaults to 'backend'
 * @param {String} [configPath] twt-config directory or default to home directory + 'twt-config'
 * @returns {{name: String, initOptions: Object, databaseURL: string}}
 */
function getFirebaseConfig (project, user, configPath) {
  if (!project) {
    project = process.env.TWT_PROJECT || 'default';
  }

  let twtProject = {
    name: project
  };

  let configFilePath = path.join(configPath, `${project}.json`);

  if (fs.existsSync(configFilePath)) {
    twtProject = require(configFilePath);
    if (twtProject.name !== project) {
      twtProject.alias = project;
    }
  } else {
    return null;
  }

  twtProject.databaseURL = `https://${twtProject.name}.firebaseio.com`;

  twtProject.credentialsPath = path.join(configPath, 'credentials', twtProject.credentials || twtProject.name + '.json');
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

  const twtProject = getFirebaseConfig(projectId, null, configDir);
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
    level = program.level,
    port = Number(program.port || (program.insecure ? 80 : 443)),
    logPath = program.logPath,
    logFile = path.join(logPath, 'oauth-client.log');

if (program.test) {

  app.get('/ping/', function (req, res) {
    res.send('pong');
  });

  http.createServer(app).listen(port);

  console.log(`Test server listening for OAuth requests on port ${port}`);

} else {

  config.connectCallback = getFirebaseConnection;

  if (program.verbose) {
    process.stderr.write(`Version: ${program._version}\n`);
    process.stderr.write(`Verbose: ${program.verbose ? 'yes' : 'no'}\n`);
    process.stderr.write(`Secure: ${program.insecure ? 'no' : 'yes'}\n`);
    process.stderr.write(`Port: ${port}\n`);
    process.stderr.write(`Auth Host: ${config.AUTH_HOST}\n`);
    process.stderr.write(`Logging: ${logFile}\n`);
    process.stderr.write(`Log Level: ${level}\n`);
    process.stderr.write(`FPL Module: ${firebasePassportLoginPath} (${program.moduleDev ? 'dev mode' : 'from node_modules'})\n`);
    process.stderr.write(`Config Dir: ${configDir}\n`);
  }

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
