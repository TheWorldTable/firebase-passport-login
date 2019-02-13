// Copyright (c) 2013 Abraham Haskins, https://github.com/abeisgreat https://github.com/rigidflame/firebase-passport-login

(function () {
  var cookie;
  /**
   * Create client shim for passport firebase auth
   * @param {Object} options - configuration for firebase used to communicate with auth server,
   *   @param {firebase.database.Database} options.firebaseApp - initialized firebase app object (as returned by firebase.initializeApp(congig)
   *   @param {String} options.authURL - URL to auth server
   *   @param {String=} options.redirectURL - configuration data for firebase
   *   @param {String} options.tokenPath - firebase path to token
   *   @param {Boolean=true} options.removeTokensImmediately - delete tokes right after use
   *   @param {Function|Boolean=false} options.debug - turn on/off logging
   *   @param {Number=1024} options.authWindowWidth - width of popup window
   *   @param {Number=650} options.authWindowHeight - height of popup window
   * @param {Function} callback
   * @constructor
   */
  function FirebasePassportLogin (options, callback) {
    'use strict';

    /* globals firebase */
    const self = this;
    self._opts = Object.assign({
            removeTokensImmediately: false,  // Change to false to persist user data at /oAuth/users/$token
            authWindowWidth: 1024,
            authWindowHeight: 650,
            redirectURL: null,
            tokenPath: 'oAuth/login',
            debug: false
          }, options || {});

    self._firebaseApp = self._opts.firebaseApp;
    self._firebaseDB = self._firebaseApp.database();
    self._firebaseURL = self._opts.firebaseConfig.databaseURL;
    self._ref = self._firebaseDB.ref();
    self._oAuthServerWindow = {width: self._opts.authWindowWidth, height: self._opts.authWindowHeight};
    self._callback = callback;
    self._ready = true;
    self._redirectURL = self._opts.redirectURL;

    if (!self._opts.firebaseApp || !self._opts.authURL) {
      throw new Error('Required option(s) missing, one or more of authUrl, firebaseApp and/or firebaseConfig')
    }

    if (self._opts.debug) {
      var opts = Object.assign({}, self._opts, {
            firebaseApp: typeof self._opts.firebaseApp === 'object' ? '[object]' : self._opts.firebaseApp
          });
      _debug('FirebasePassportLogin Options:\n' + JSON.stringify(opts, 0, 2));
    }

    function _popupCenter (url, title, w, h) {
      // from http://stackoverflow.com/questions/4068373/center-a-popup-window-on-screen
      // Fixes dual-screen position                         Most browsers      Firefox
      let dualScreenLeft = window.screenLeft !== undefined ? window.screenLeft : screen.left;
      let dualScreenTop = window.screenTop !== undefined ? window.screenTop : screen.top;

      let width = window.innerWidth ? window.innerWidth : document.documentElement.clientWidth ? document.documentElement.clientWidth : screen.width;
      let height = window.innerHeight ? window.innerHeight : document.documentElement.clientHeight ? document.documentElement.clientHeight : screen.height;

      let left = ((width / 2) - (w / 2)) + dualScreenLeft;
      let top = ((height / 2) - (h / 2)) + dualScreenTop;
      let newWindow = window.open(url, title, 'scrollbars=yes, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);

      // Puts focus on the newWindow
      if (window.focus) {
        newWindow.focus();
      }

      return newWindow;
    }

    /**
     * Set up Firebase listener on the anonymous user. When the anonymous user has been
     * authenticated through Passport, invoke @link{ _handleOAuthLogin } with the auth token
     * obtained through Passport.
     * @private
     */
    function _initializeFirebaseOAuthUserListener (oAuthTokenPath) {
      let oAuthTokenRef = self._ref.child(oAuthTokenPath);

      cookie.set('passportAnonymous', self._anonymousUid, {secure: document.location.href.indexOf('https') === 0});
      _debug('listening for firebase auth token at ' + oAuthTokenRef.toString());
      oAuthTokenRef.on('value', function (snapshot) {
        let payloadJSON = snapshot.val(),
            payload;
        try {
          payload = JSON.parse(payloadJSON);
        } catch (err) {
          _debug('Error parsing payload: ' + (err.message || 'unknown'));
        }
        if (payload && payload.token) {
          _debug('Auth Token: ' + payload.token);
          _debug('Auth User: ' + JSON.stringify(payload.user, 0, 2));
          cookie.remove('passportAnonymous');
          oAuthTokenRef.off();
          oAuthTokenRef.remove();
          try {
            self._oAuthWindow.close();
          }
          catch (err) {
            console.error(err);
          }
          _getUserForTokenAndSaveSession(payload);
        }
      });


    }

    /**
     * Authenticate to Firebase with the custom token obtained through OAuth and store it as a
     * `passportSession` cookie. Then call the user-provided callback method with the user object.
     *
     * @param {Object} payload - firebase v3 SDK auth response
     *   @param {String} payload.token - Passport session token
     *   @param {Object} payload.user - User data
     * @private
     */
    function _getUserForTokenAndSaveSession (payload) {

      if (!payload || !payload.token) {
        return;
      }

      return self._firebaseApp.auth().signOut().then(function () {
        return self._firebaseApp.auth().signInWithCustomToken(payload.token);
      }).then(function () {
        let user = payload.user;
        if (!user) {
          return;
        }
        user[user.provider] = {cachedUserProfile: JSON.parse(user.thirdPartyUserData)};
        user.token = payload.token;
        user.thirdPartyUserData = undefined;
        if (self._opts.removeTokensImmediately) {
          cookie.set('passportSession', '');
        }
        else {
          cookie.set('passportSession', payload.token);
        }
        self._callback(null, user);
      }).catch(function (error) {
        if (error.code === 'EXPIRED_TOKEN') {
          cookie.set('passportSession', '');
        }
        self._callback(error);
      });

    }

    /**
     * Output debug info
     * @private
     * @param {...*} message
     */
    function _debug (message) {
      if (self._opts.debug) {
        if (typeof self._opts.debug === 'function') {
          self._opts.debug.apply(this, Array.from(arguments))
        } else if (window.console) {
          console.log.apply(console, Array.from(arguments));
        }
      }
    }

    /**
     * Firebase path to which the authenticated user data should be written. It includes the uid of the
     * anonymous user we use to listen for the authenticated user object.
     *
     * @param {String} anonymousUid - UID of anonymous Firebase session used to listen for the authenticated user
     * object obtained through Passport by the backend auth service
     * @returns {string} - A Firebase path (not a ref) that can be passed to the backend auth service to let it know
     * where to store the user data obtained through Passport.
     *
     * @private
     */
    function _firebaseOAuthUserPath (anonymousUid) {
      return self._opts.tokenPath + '/' + anonymousUid;
    }

    function _getAnonymousUid () {

      return self._firebaseApp.auth().signOut().then(function () {
          return self._firebaseApp.auth().signInAnonymously();
      }).then(function (authData) {
        let user = authData.user;
        if (user) {
          return user.uid;
        }
      }).catch(function (err) {
        throw new Error("Anonymous login failed. Make sure Anonymous login is enabled in your Firebase");
      });
    }

    /**
     * To re-establish an anonymous connection to the database prior to calling login,
     * use
     *
     *   document.getElementById('login-iframe').contentWindow.postMessage(JSON.stringify({redirect:<url>}), '*' );
     *
     * where 'login-iframe' is the id of the iframe containing the login popup window.
     *
     */
    function _messageHandler (event) {
      let action;

      _debug('Message: ' + JSON.stringify(event, 0, 2));

      try {
        action = JSON.parse(event.data);
      } catch (err) {
        // couldn't parse the event data -- must have been a message not intended for us
      }

      if (action && action.type === 'init') {
        if (action.redirect && self._redirectURL !== action.redirect) {
          self._redirectURL = action.redirect;
        }
      }

    }

    self.startAnonymousAuthConnection = function (forceAnonymousReauth) {
      if (!forceAnonymousReauth && self._anonymousUid) {
        return Promise.resolve(self._anonymousUid);
      }
      return _getAnonymousUid().then(function (uid) {
        self._anonymousUid = uid;
        return uid;
      }).catch(function (err) {
        console.error(err);
      });
    };

    /**
     * Initialize
     *
     * Initialization occurs automatically with the setTimeout() call below,
     * so it should be unnecessary for other modules to call this method directly.
     */
    function _init () {

      _debug(`client/firebase-passport-login.js:_init: ${window.document.location.href}`);

      cookie = cookie || defineCookie();

      // Set up the message listener so that the calling window can create the
      // anonymous Firebase connection whenever the login window is opened as a dialog,
      // without reloading the page. Instead of attempting to authenticate automatically
      // with the passportSession when the page is first loaded
      // (by calling _getUserForTokenAndSaveSession()),
      // we allow Firebase to authenticate with the custom token that it stored from the
      // last successful authentication.

      // We don't create an anonymous connection until the postMessage event
      // so that we don't change what may be a valid Firebase session token into
      // an anonymous session token.

      let curUser = self._firebaseApp.auth().currentUser;
      if (curUser) {
        _debug({curUser: curUser}, 'FirebasePassportLogin._init()');
        Promise.resolve(curUser && curUser.getIdToken()).then(function (token) {
          self._callback(null, {token: token, provider: curUser.providerData, uid: curUser.uid});
        });
      }
      _debug('passportSession = ' + cookie.get('passportSession'));
      window.addEventListener('message', _messageHandler);
      setTimeout(self.startAnonymousAuthConnection, 50);
    }

    /**
     * Log in to Firebase through the indicated authentication provider.
     *
     * First creates an anonymous authentication with Firebase, passing the anonymous auth
     * token on to the server along with a Firebase key to set with authenticated user data.
     * We then listen for the authenticated user data to be set, calling the user-provided
     * `callback` function when it is.
     *
     * Finally we open an authentication window to a URL served by the backend auth service.
     *
     * The authenticated user token is stored in a cookie (`passportCookie`) to enable
     * automatic authentication later.
     *
     * @param {String} provider - Provider to authenticate through ('facebook', 'reddit', etc.)
     */
    self.login = function (provider) {

      // Have to open the authentication window immediately in order to avoid popup blockers

      self._provider = provider;
      // to prevent popup blockers, we should already have an anonymous uid
      if (self._anonymousUid) {
        return self._login();
      } else {
        return _getAnonymousUid().then(self._login);
      }
    };

    self._login = function () {
      // set up a Firebase listener to get the user object set by the backend auth service
      let oAuthTokenPath = _firebaseOAuthUserPath(self._anonymousUid);
      _initializeFirebaseOAuthUserListener(oAuthTokenPath);

      // open the authentication window provided by the backend auth service
      let oAuthWindowURL = self._opts.authURL + self._provider
        + '?oAuthTokenPath=' + oAuthTokenPath
        + '&redirect=' + encodeURIComponent(self._redirectURL);
      if (self._firebaseURL) {
        oAuthWindowURL += '&firebaseURL=' + encodeURIComponent(self._firebaseURL);
      }
      self._oAuthWindow = _popupCenter(oAuthWindowURL, '_blank',
        self._oAuthServerWindow.width,
        self._oAuthServerWindow.height);
    };

    /**
     * Disconnect from Firebase and clear the passportSession cookie.
     */
    self.logout = function () {
      let token = cookie.get('passportSession');
      if (token) {
        if (self._opts.removeTokensImmediately) {
          self._ref.child('oAuthUsers').child(token.replace(/\./g, '')).remove();
        }
      }
      self._firebaseApp.auth().signOut().then(function (){
        cookie.set('passportSession', '');
        self._callback(null, null);
      });
    };

    function defineCookie () {
      let exports = {};
      // Copyright (c) 2015 Florian Hartmann, https://github.com/florian https://github.com/florian/cookie.js
      !function(a,b){var c=function(){return c.get.apply(c,arguments)},d=c.utils={isArray:Array.isArray||function(a){return"[object Array]"===Object.prototype.toString.call(a)},isPlainObject:function(a){return!!a&&"[object Object]"===Object.prototype.toString.call(a)},toArray:function(a){return Array.prototype.slice.call(a)},getKeys:Object.keys||function(a){var b=[],c="";for(c in a)a.hasOwnProperty(c)&&b.push(c);return b},encode:function(a){return String(a).replace(/[,;"\\=\s%]/g,function(a){return encodeURIComponent(a)})},decode:function(a){return decodeURIComponent(a)},retrieve:function(a,b){return null==a?b:a}};c.defaults={},c.expiresMultiplier=86400,c.set=function(c,e,f){if(d.isPlainObject(c))for(var g in c)c.hasOwnProperty(g)&&this.set(g,c[g],e);else{f=d.isPlainObject(f)?f:{expires:f};var h=f.expires!==b?f.expires:this.defaults.expires||"",i=typeof h;"string"===i&&""!==h?h=new Date(h):"number"===i&&(h=new Date(+new Date+1e3*this.expiresMultiplier*h)),""!==h&&"toGMTString"in h&&(h=";expires="+h.toGMTString());var j=f.path||this.defaults.path;j=j?";path="+j:"";var k=f.domain||this.defaults.domain;k=k?";domain="+k:"";var l=f.secure||this.defaults.secure?";secure":"";f.secure===!1&&(l=""),a.cookie=d.encode(c)+"="+d.encode(e)+h+j+k+l}return this},c.setDefault=function(a,e,f){if(d.isPlainObject(a)){for(var g in a)this.get(g)===b&&this.set(g,a[g],e);return c}if(this.get(a)===b)return this.set.apply(this,arguments)},c.remove=function(a){a=d.isArray(a)?a:d.toArray(arguments);for(var b=0,c=a.length;b<c;b++)this.set(a[b],"",-1);return this},c.removeSpecific=function(a,b){if(!b)return this.remove(a);a=d.isArray(a)?a:[a],b.expires=-1;for(var c=0,e=a.length;c<e;c++)this.set(a[c],"",b);return this},c.empty=function(){return this.remove(d.getKeys(this.all()))},c.get=function(a,b){var c=this.all();if(d.isArray(a)){for(var e={},f=0,g=a.length;f<g;f++){var h=a[f];e[h]=d.retrieve(c[h],b)}return e}return d.retrieve(c[a],b)},c.all=function(){if(""===a.cookie)return{};for(var b=a.cookie.split("; "),c={},e=0,f=b.length;e<f;e++){var g=b[e].split("="),h=d.decode(g.shift()),i=d.decode(g.join("="));c[h]=i}return c},c.enabled=function(){if(navigator.cookieEnabled)return!0;var a="_"===c.set("_","_").get("_");return c.remove("_"),a},"function"==typeof define&&define.amd?define(function(){return{cookie:c}}):"undefined"!=typeof exports?exports.cookie=c:window.cookie=c}("undefined"==typeof document?null:document);
      //
      return exports.cookie;
    }

    _init();

  }
  window.FirebasePassportLogin = FirebasePassportLogin;
}());