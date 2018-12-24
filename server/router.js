const http = require('http'),
    express = require('express'),
    passport = require('passport'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    session = require('express-session'),
    _ = require('lodash'),
    path = require('path');

module.exports = function (config, options) {
  let serverConfig = config, opts = options || {};

  let router = express.Router(['strict']);
  router.use(cookieParser(serverConfig.COOKIE_SECRET));
  router.use(bodyParser.json());
  router.use(session({ secret: serverConfig.COOKIE_SECRET, resave: true, saveUninitialized: true }));
  router.use(passport.initialize());
  router.use(passport.session());

  let firebases = {}; // map of app:, database:
  //let tokGen = new FirebaseTokenGenerator(serverConfig.firebaseConfig);

  serverConfig.SERVICES.forEach(function (service) {
    let serviceObject = require('./services/' + service).setup(passport, serverConfig[service]);

    router.get('/' + service, function (req, res, next) {
      res.cookie('passportAnonymous', req.query.oAuthTokenPath, {signed: true});
      res.cookie('passportRedirect', req.query.redirect, {signed: true});
      res.cookie('passportFirebase', req.query.firebaseURL, {signed: true});
      //console.log('/' + service, {passportAnonymous:req.query.oAuthTokenPath});
      passport.authenticate(service, serviceObject.options)(req, res, next);
    });

    router.get('/' + service + '/callback', function (req, res, next) {
      console.log('/' + service + '/callback');

      let firebaseUrl = req.signedCookies.passportFirebase ||
              req.session.passportFirebase ||
              serverConfig.FIREBASE_URL,
          connection = firebaseUrl && config.connectCallback(firebaseUrl);

      if (!connection) {
        let err = new Error('Connection unavailable for Firebase URL "' + firebaseUrl + '"');
        console.error(err);
        next(err);
        return;
      }

      passport.authenticate(service, function (err, auth) {
        if (err) {
          console.error('Error during passport authentication:', err);
          next(err);
          return;
        }
        if (!auth) {
          //console.log('User was not authenticated');
          // If they canceled giving the provider permission, we don't want to leave the window open.
          // Return JavaScript to close it, and in case that doesn't work, attempt to redirect to the original
          // page (for Facebook mobile).
          res.send('<html><body><p>Not authenticated</p><script>window.close();window.location.href=decodeURIComponent('
            + '"' + req.signedCookies.passportRedirect + '");</script></body></html>');
          return;
        }
        if (!req.signedCookies.passportAnonymous) {
          let cookiesDisabledDetected = false;
          console.error('No `passportAnonymous` cookie found; can\'t return authentication token through Firebase.');
          if (!req.signedCookies.passportRedirect) {
            console.error('No `passportRedirect` cookie found; can\'t redirect to original page if window.close() fails.');
            cookiesDisabledDetected = true;
          }
          let script = 'window.close();', msg = 'Not authenticated.';
          if (cookiesDisabledDetected) {
            msg += ' Are cookies disabled?';
          } else {
            script += 'window.location.href=decodeURIComponent("' + req.signedCookies.passportRedirect + '");'
          }
          res.send('<html><body><p>' + msg + '</p><script>' + script + '</script></body></html>');
          return;
        }

        console.log('User authenticated successfully');
        let user = auth.user,
          thirdPartyUserData = auth.thirdPartyUserData;

        user.displayName = _.pick(user.displayName, _.identity);

        connection.auth.createCustomToken(user.uid, user).then(function (token) {
          user.thirdPartyUserData = JSON.stringify(thirdPartyUserData);
          let payload = {
                token: token,
                user: user
              };

          return connection.database.ref(req.signedCookies.passportAnonymous).set(JSON.stringify(payload)).then(function () {
            console.log('set oAuth/login payload');
            console.log('Successfully signed in user');
            // firebase-passport-login.js will attempt to close the window when its Firebase listener
            // gets the token, but since this doesn't seem to work in Facebook mobile, we redirect to the
            // original page.
            res.redirect(decodeURIComponent(req.signedCookies.passportRedirect));
          }).catch(function(err) {
            console.error('Failed to login user:', err);
            next('Failure: ' + err);
          });
        }).catch(function (err) {
          console.error('Error during Firebase authentication:', err);
          next(err);
        })

      })(req, res, next);
    });
  });

  return router;
};
