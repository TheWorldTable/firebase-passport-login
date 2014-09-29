var http = require('http');
var express = require('express');
var passport = require('passport');
var TokenGenerator = require('firebase-token-generator');
var Firebase = require('firebase');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var Promise = require('es6-promise').Promise;
var crypto = require('crypto');

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
          if(req.query.accountToken && req.query.accountId){
            res.cookie('accountToken', {token: req.query.accountToken, id: req.query.accountId}, {signed: true});
          }
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
                userUpdate = UpdatePromise(ref.child('users').child(user.uid),{accessToken: user.accessToken, provider: service})
                .then(function(){
                  return OnceValuePromise(ref.child('users').child(user.uid)).then(function(userSnapshot){
                    accountRef = userSnapshot.val().accountId;
                    if(!accountRef){
                      var users = {};
                      users[userSnapshot.name()] = true;
                      if(req.signedCookies.accountToken){
                        var accountInfo = req.signedCookies.accountToken;
                        if(!accountInfo.id){
                          throw "unable to login, invalid account token";
                        }
                        return OnceValuePromise(ref.child('accounts').child(accountInfo.id)).then(function(accountSnap){
                          if(!(accountSnap.accountToken && accountInfo.accountToken)){
                            throw "unable to login, account token mismatch";
                          }
                          if(accountSnap.accountToken != accountInfo.accountToken){
                            throw "unable to login, account token mismatch";
                          } else {
                            accountRef = accountInfo.id;
                            return UpdatePromise(userSnapshot.ref(), {accountId: accountRef});
                          }
                        });
                      } else {
                        //generate a token that users can use to identify that they have access to the account
                        var buf = crypto.randomBytes(256).toString('hex'); // can throw
                        accountRef = ref.child('accounts').push({users: users, accountToken: buf}).name();
                      }
                      return UpdatePromise(userSnapshot.ref(), {accountId: accountRef});
                    }
                    return Promise.resolve();
                  });
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
                    return SetPromise(ref.child('tokens').child(req.signedCookies.passportAnonymous),tok);
                })
                .then(function(){
                  console.log("successfully signed in user");
                  res.set({
                    'Content-Type': 'text/html',
                  });
                  res.send("<script>window.close();</script>");
                  next();
                })
                .catch(function(error){
                  console.log("failed to login user:"+ error);
                  next("failure: "+error);
                });
              });
          })(req, res, next);
      });
  });
  return router;
};
