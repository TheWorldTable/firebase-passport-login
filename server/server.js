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
                console.log("error during passport auth:", err);
                next(err);
                return;
              }
              if(!user){
                console.log("user not authed");
                next("not authed");
                return;
              }

              ref.auth(serverConfig.FIREBASE_SECRET, function (err, data) {
                  if (err){
                    console.log("error during firebase auth", err);
                    next(err);
                    return;
                  }

                  ref.child('users').child(user.uid).set({accessToken: user.accessToken, provider: service});
                  //see if user already has account
                  if(ref.child('users').child(user.uid).hasChild('accountId')){
                    var accountId = ref.child('users').child(user.uid).child('accountId').val();
                    var accountRef = ref.child('accounts').child(accountId);
                  } else {
                    //check if person has already logged in as a user that has an account
                    if(req.signedCookies.accountId){
                        var accountRef = ref.child('accounts').push({users: users});
                        ref.child('users').child(user.uid).child('accountId').set(accountRef.name());
                    } else {
                      //create account
                      users[user.id] = true;
                      var accountRef = ref.child('accounts').push({users: users});
                      ref.child('users').child(user.uid).child('accountId').set(accountRef.name());
                    }
                  }

                  //set cookie identifying the account for future account additions
                  res.cookie('accountId', accountRef.name(), {signed: true});
                  var tok = null;
                  if( user ) {
                      tok = tokGen.createToken(user);
                  }

                  ref.child(req.signedCookies.passportAnonymous).set(tok);
                  console.log("successfully signed in user");
                  next("success");
              });
          })(req, res, next);
      });
  });
  return router;
};
