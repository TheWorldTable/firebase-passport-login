var http = require('http');
var express = require('express');
var passport = require('passport');
var TokenGenerator = require('firebase-token-generator');
var Firebase = require('firebase');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');

module.exports = function(config){
  var serverConfig = config;

  var router = express.Router(["strict"]);
      router.use(cookieParser(serverConfig.COOKIE_SECRET));
      router.use(bodyParser());
      router.use(session({ secret: serverConfig.COOKIE_SECRET }));
      router.use(passport.initialize());
      router.use(passport.session());

  var tokGen = new FirebaseTokenGenerator(serverConfig.FIREBASE_SECRET);
  serverConfig.SERVICES.forEach(function (service) {
      var serviceObject = require('./services/' + service).setup(passport, serverConfig[service]);

      router.get('/' + service, function(req, res, next){
          res.cookie('passportAnonymous', req.query.oAuthTokenPath, {signed: true});
          passport.authenticate(service, serviceObject.options)(req, res, next);
      });

      router.get('/'+service+'/callback', function (req, res, next) {
          var ref = new Firebase(serverConfig.FIREBASE_URL);
          passport.authenticate(service, function(err, user, info) {
              if (err){
                res.write("errored");
                return;
              }

              ref.auth(serverConfig.FIREBASE_SECRET, function (err, data) {
                  if (err){
                    res.write("errored");
                    return;
                  }
                  ref.child('users').child(user.uid).set({accessToken: user.accessToken, provider: service});
                  var tok = null;
                  if( user ) {
                      tok = tokGen.createToken(user);
                  }

                  ref.child(req.signedCookies.passportAnonymous).set(tok);
              });
          })(req, res, next);
      });
  });
  return router;
};
