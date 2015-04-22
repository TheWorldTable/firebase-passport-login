var http = require('http');
var express = require('express');
var passport = require('passport');
var FirebaseTokenGenerator = require('firebase-token-generator');
var Firebase = require('firebase');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var Promise = require('rsvp').Promise;
var _ = require('lodash');

function SetPromise(ref, value){
  return new Promise(function(resolve, reject){
    ref.set(value, function callback(error){
      if(error){
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

module.exports = function (config) {
  var serverConfig = config;

  var router = express.Router(["strict"]);
  router.use(cookieParser(serverConfig.COOKIE_SECRET));
  router.use(bodyParser.json());
  router.use(session({ secret: serverConfig.COOKIE_SECRET, resave: true, saveUninitialized: true }));
  router.use(passport.initialize());
  router.use(passport.session());


  var tokGen = new FirebaseTokenGenerator(serverConfig.FIREBASE_SECRET);

  router.get('/loading', function (req, res, next) {
    // This is just an empty page to display while we're waiting for firebase-passport-login.js
    // to redirect to an authentication provider.
    res.set({'Content-Type': 'text/html'});
    res.send("<html><body></body></html>");
  });

  serverConfig.SERVICES.forEach(function (service) {
    var serviceObject = require('./services/' + service).setup(passport, serverConfig[service]);

    router.get('/' + service, function (req, res, next) {
      res.cookie('passportAnonymous', req.query.oAuthTokenPath, {signed: true});
      passport.authenticate(service, serviceObject.options)(req, res, next);
    });

    router.get('/' + service + '/callback', function (req, res, next) {
      var ref = new Firebase(serverConfig.FIREBASE_URL);
      passport.authenticate(service, function (err, auth, info) {
        if (err) {
          console.log("Error during passport authentication:", err);
          //next(err);
          return;
        }
        if (!auth) {
          console.log("User was not authenticated");
          next("Not authenticated");
          return;
        }

        var user = auth.user,
          thirdPartyUserData = auth.thirdPartyUserData;

        ref.authWithCustomToken(serverConfig.FIREBASE_SECRET, function (err, data) {
          if (err) {
            console.log("Error during Firebase authentication:", err);
            next(err);
            return;
          }

          var tok = null;
          if (user) {
            tok = tokGen.createToken(user);
          }
          user.thirdPartyUserData = JSON.stringify(thirdPartyUserData);

          // remove any undefined values (since undefined is not a valid JSON value, and Firebase will complain)
          user.displayName = _.pick(user.displayName, _.identity);

          SetPromise(ref.child('oAuthUsers').child(tok.replace(/\./g, '')), user)
          .then(function () {
            return SetPromise(ref.child(req.signedCookies.passportAnonymous), tok);
          })
          .then(function () {
            //console.log("Successfully signed in user");
            //res.set({'Content-Type': 'text/html'});
            //res.send("<script>alert('success!'); window.close();</script>");
            //next();
          })
          .catch(function(err) {
            console.log("Failed to login user:", err);
            next("Failure: " + err);
          });
        });
      })(req, res, next);
    });
  });

  return router;
};