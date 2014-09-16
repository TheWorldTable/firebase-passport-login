var http = require('http');
var express = require('express');
var passport = require('passport');
var TokenGenerator = require('firebase-token-generator');
var Firebase = require('firebase');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var Promise = require('es6-promise').Promise;

function OnceValuePromise(ref){
  var p = new Promise(function(resolve, reject){
    ref.once('value', function success(snapshot){
      var pp = snapshot.val();
      if(pp){
        resolve(snapshot);
      } else {
        reject("non existant value");
      }
    }, function failure(error){
        reject(error);
    });
  });
  return p;
}

function SetPromise(ref, value){
  var p = new Promise(function(resolve, reject){
    ref.set(value, function callback(error){
      if(error){
        reject(error);
        return;
      }
      resolve();
    });
  });
  return p;
}

function UpdatePromise(ref, value){
  var p = new Promise(function(resolve, reject){
    ref.update(value, function callback(error){
      if(error){
        reject(error);
        return;
      }
      resolve();
    });
  });
  return p;
}

function PushPromise(ref, value){
  var p = new Promise(function(resolve, reject){
    var newRef = ref.push(value, function callback(error){
      if(error){
        reject(error);
        return;
      }
      resolve(newRef);
    });
  });
  return p;
}

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

                  var userUpdate = null;
                  var accountRef = null;
                  if(req.signedCookies.accountId){
                    accountRef = req.signedCookies.accountId;
                  } else {
                    users = {};
                    users[user.uid] = true;
                    accountRef = ref.child('accounts').push({users: users}).name();
                  }

                  userUpdate = UpdatePromise(ref.child('users').child(user.uid),{accessToken: user.accessToken, provider: service, accountId: accountRef});

                  userUpdate
                  .catch(function(error){
                    next("failure: "+error);
                  })
                  .then(function(){
                      return SetPromise(ref.child('accounts').child(accountRef).child('users').child(user.uid),true);
                  })
                  .then(function(){
                      res.cookie('accountId', accountRef, {signed: true});
                      var tok = null;
                      if( user ) {
                          tok = tokGen.createToken(user);
                      }
                      return SetPromise(ref.child(req.signedCookies.passportAnonymous),tok);
                  })
                  .catch(function(error){
                    next("failure: "+error);
                  })
                  .then(function(){
                    console.log("successfully signed in user");
                    next("success");
                  });



              });
          })(req, res, next);
      });
  });
  return router;
};
