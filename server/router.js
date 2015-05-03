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
var path = require('path');

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

module.exports = function (config, options) {
  var serverConfig = config, opts = options || {};

  var router = express.Router(["strict"]);
  router.use(cookieParser(serverConfig.COOKIE_SECRET));
  router.use(bodyParser.json());
  router.use(session({ secret: serverConfig.COOKIE_SECRET, resave: true, saveUninitialized: true }));
  router.use(passport.initialize());
  router.use(passport.session());

  var tokGen = new FirebaseTokenGenerator(serverConfig.FIREBASE_SECRETS[serverConfig.FIREBASE_URL]);

  serverConfig.SERVICES.forEach(function (service) {
    var serviceObject = require('./services/' + service).setup(passport, serverConfig[service]);

    router.get('/' + service, function (req, res, next) {
      res.cookie('passportAnonymous', req.query.oAuthTokenPath, {signed: true});
      res.cookie('passportRedirect', req.query.redirect, {signed: true});
      if (opts.devMode && req.query.firebaseUrl) {
        res.cookie('passportFirebase', req.query.firebaseUrl, {signed: true});
      }
      //console.log('/' + service, {passportAnonymous:req.query.oAuthTokenPath});
      passport.authenticate(service, serviceObject.options)(req, res, next);
    });

    router.get('/' + service + '/callback', function (req, res, next) {
      //console.log('/' + service + '/callback');
      var firebaseUrl = (opts.devMode && req.signedCookies.passportFirebase)
          ? decodeURIComponent(req.signedCookies.passportFirebase)
          : serverConfig.FIREBASE_URL,
        firebaseSecret = serverConfig.FIREBASE_SECRETS[firebaseUrl];

      if (!firebaseSecret) {
        var err = new Error("Secret not configured for Firebase URL '" + firebaseUrl + "'");
        console.error(err);
        next(err);
        return;
      }
      ref = new Firebase(firebaseUrl);

      passport.authenticate(service, function (err, auth) {
        if (err) {
          console.error("Error during passport authentication:", err);
          next(err);
          return;
        }
        if (!auth) {
          console.log("User was not authenticated");
          // If they canceled giving the provider permission, we don't want to leave the window open.
          // Return JavaScript to close it, and in case that doesn't work, attempt to redirect to the original
          // page (for Facebook mobile).
          res.send('<html><body><p>Not authenticated</p><script>window.close();window.location.href=decodeURIComponent('
            + '"' + req.signedCookies.passportRedirect + '");</script></body></html>');
          return;
        }

        //console.log("User authenticated successfully");
        var user = auth.user,
          thirdPartyUserData = auth.thirdPartyUserData;

        ref.authWithCustomToken(firebaseSecret, function (err, data) {
          if (err) {
            console.error("Error during Firebase authentication:", err);
            next(err);
            return;
          }

          var tok = null;
          if (user) {
            // For performance, if not running in dev mode, we save a FirebaseTokenGenerator
            // for the only Firebase URL, as part of the module initialization (above).
            // Otherwise, we have to create a token generator for the Firebase URL that
            // was specified with this request.
            if (! opts.devMode) {
              tok = tokGen.createToken(user);
            } else {
              var devTokGen = new FirebaseTokenGenerator(firebaseSecret);
              tok = devTokGen.createToken(user);
            }
          }
          user.thirdPartyUserData = JSON.stringify(thirdPartyUserData);

          // remove any undefined values (since undefined is not a valid JSON value, and Firebase will complain)
          user.displayName = _.pick(user.displayName, _.identity);

          SetPromise(ref.child('oAuth/users').child(tok.replace(/\./g, '')), user)
          .then(function () {
            //console.log("Set oAuthUsers");
            return SetPromise(ref.child(req.signedCookies.passportAnonymous), tok);
          })
          .then(function () {
            //console.log("Set oAuthLogin token");
            //console.log("Successfully signed in user");
            // firebase-passport-login.js will attempt to close the window when its Firebase listener
            // gets the token, but since this doesn't seem to work in Facebook mobile, we redirect to the 
            // original page.
            res.redirect(decodeURIComponent(req.signedCookies.passportRedirect));
          })
          .catch(function(err) {
            console.error("Failed to login user:", err);
            next("Failure: " + err);
          });
        });
      })(req, res, next);
    });
  });

  return router;
};
