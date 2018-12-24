// Copyright (c) 2013 Abraham Haskins, https://github.com/abeisgreat https://github.com/rigidflame/firebase-passport-login

(function () {
  /**
   * Create client shim for passport firebase auth
   * @param ref {firebase.database.Database} firebase to login to
   * @param authConfig {Object} configuration for firebase used to communicate with auth server, either .firebaseApp or .firebaseConfig
   * @param callback
   * @constructor
   */
  function FirebasePassportLogin (authConfig, callback) {
    'use strict';

    /* globals Firebase */
    const self = this;
    self._authConfig = authConfig;
    self._firebaseApp = authConfig.firebaseApp || firebase.initializeApp(authConfig.firebaseConfig);
    self._firebaseDB = self._firebaseApp.database();
    self._firebaseURL = authConfig.firebaseConfig.databaseURL;
    self._ref = self._firebaseDB.ref();
    self._tokenPath = 'oAuth/login';
    self._oAuthServerURL = authConfig.authURL;
    self._oAuthServerWindow = {width:1024, height:650};
    self._callback = callback;
    self._ready = true;
    self._redirectURL = null;
    self._removeTokensImmediately = true;       // Change to false to persist user data at /oAuth/users/$token

    function _popupCenter (url, title, w, h) {
      // from http://stackoverflow.com/questions/4068373/center-a-popup-window-on-screen
      // Fixes dual-screen position                         Most browsers      Firefox
      let dualScreenLeft = window.screenLeft != undefined ? window.screenLeft : screen.left;
      let dualScreenTop = window.screenTop != undefined ? window.screenTop : screen.top;

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
      console.log('listening for firebase auth token at ' + oAuthTokenRef.toString());
      oAuthTokenRef.on('value', function (snapshot) {
        let payloadJSON = snapshot.val(),
            payload;
        try {
          payload = JSON.parse(payloadJSON);
        } catch (err) {
          console.log('Error parsing payload: ' + (err.message || 'unknown'));
        }
        if (payload && payload.token) {
          console.log('auth token snapshot: ' + payload.token);
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
     * @param token - Passport session token
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
        if (!user) return;
        user[user.provider] = {cachedUserProfile: JSON.parse(user.thirdPartyUserData)};
        user.token = payload.token;
        user.thirdPartyUserData = undefined;
        if (self._removeTokensImmediately) {
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

    function _log (message) {
      if (console.log) {
        console.log("FirebasePassportLogin: " + message);
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
      return self._tokenPath + '/' + anonymousUid;
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

      try {
        action = JSON.parse(event.data);
      } catch (err) {
        // couldn't parse the event data -- must have been a message not intended for us
        //console.log({err:err, 'event.data': event.data, status: 'Error handling event'}, '_messageHandler');
      }

      if (action && action.type === 'init') {

        //console.log({event: event}, 'Received FirebasePassportLogin initialization request from parent window');

        if (action.redirect) {
          self._redirectURL = action.redirect;
        }

        self.startAnonymousAuthConnection();
      }

    }

    self.startAnonymousAuthConnection = function () {
      return _getAnonymousUid()
        .then(function (uid) {
          self._anonymousUid = uid;
        })
        .catch(console.error);
    };

    /**
     * Initialize
     *
     * Initialization occurs automatically with the setTimeout() call below,
     * so it should be unnecessary for other modules to call this method directly.
     */
    function _init () {

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
        console.log({curUser: curUser}, 'FirebasePassportLogin._init()');
        self._callback(null, {token: curUser.getIdToken(), provider: curUser.providerData, uid: curUser.uid});
      }
      //alert('passportSession = ' + cookie.get('passportSession'));
      window.addEventListener('message', _messageHandler);
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

      Promise.resolve(self._anonymousUid).then(function (uid) {
        if (uid) {
          return uid;
        }
        // user isn't anonymously authed, do so now
        return _getAnonymousUid();
      }).then(function (uid) {
        // set up a Firebase listener to get the user object set by the backend auth service
        let oAuthTokenPath = _firebaseOAuthUserPath(uid);
        _initializeFirebaseOAuthUserListener(oAuthTokenPath);

        // open the authentication window provided by the backend auth service
        let oAuthWindowURL = self._oAuthServerURL + self._provider
          + '?oAuthTokenPath=' + oAuthTokenPath
          + '&redirect=' + encodeURIComponent(self._redirectURL);
        if (self._firebaseURL) {
          oAuthWindowURL += '&firebaseURL=' + encodeURIComponent(self._firebaseURL);
        }
        self._oAuthWindow = _popupCenter(oAuthWindowURL, '_blank',
          self._oAuthServerWindow.width,
          self._oAuthServerWindow.height);
      });
    };

    /**
     * Disconnect from Firebase and clear the passportSession cookie.
     */
    self.logout = function () {
      let token = cookie.get('passportSession');
      if (token) {
        self._ref.child('oAuthUsers').child(token.replace(/\./g, '')).remove();
      }
      self._firebaseApp.auth().signOut().then(function (){
        cookie.set('passportSession', '');
        self._callback(null, null);
      });
    };


    // Copyright (c) 2012 Florian H., https://github.com/js-coder https://github.com/js-coder/cookie.js
    !function(e,t){var n=function(){return n.get.apply(n,arguments)},r=n.utils={isArray:Array.isArray||function(e){return Object.prototype.toString.call(e)==="[object Array]"},isPlainObject:function(e){return!!e&&Object.prototype.toString.call(e)==="[object Object]"},toArray:function(e){return Array.prototype.slice.call(e)},getKeys:Object.keys||function(e){var t=[],n="";for(n in e)e.hasOwnProperty(n)&&t.push(n);return t},escape:function(e){return String(e).replace(/[,;"\\=\s%]/g,function(e){return encodeURIComponent(e)})},retrieve:function(e,t){return e==null?t:e}};n.defaults={},n.expiresMultiplier=86400,n.set=function(n,i,s){if(r.isPlainObject(n))for(var o in n)n.hasOwnProperty(o)&&this.set(o,n[o],i);else{s=r.isPlainObject(s)?s:{expires:s};var u=s.expires!==t?s.expires:this.defaults.expires||"",a=typeof u;a==="string"&&u!==""?u=new Date(u):a==="number"&&(u=new Date(+(new Date)+1e3*this.expiresMultiplier*u)),u!==""&&"toGMTString"in u&&(u=";expires="+u.toGMTString());var f=s.path||this.defaults.path;f=f?";path="+f:"";var l=s.domain||this.defaults.domain;l=l?";domain="+l:"";var c=s.secure||this.defaults.secure?";secure":"";e.cookie=r.escape(n)+"="+r.escape(i)+u+f+l+c}return this},n.remove=function(e){e=r.isArray(e)?e:r.toArray(arguments);for(var t=0,n=e.length;t<n;t++)this.set(e[t],"",-1);return this},n.empty=function(){return this.remove(r.getKeys(this.all()))},n.get=function(e,n){n=n||t;var i=this.all();if(r.isArray(e)){var s={};for(var o=0,u=e.length;o<u;o++){var a=e[o];s[a]=r.retrieve(i[a],n)}return s}return r.retrieve(i[e],n)},n.all=function(){if(e.cookie==="")return{};var t=e.cookie.split("; "),n={};for(var r=0,i=t.length;r<i;r++){var s=t[r].split("=");n[decodeURIComponent(s[0])]=decodeURIComponent(s[1])}return n},n.enabled=function(){if(navigator.cookieEnabled)return!0;var e=n.set("_","_").get("_")==="_";return n.remove("_"),e},typeof define=="function"&&define.amd?define(function(){return n}):typeof exports!="undefined"?exports.cookie=n:window.cookie=n}(document);
    //

    // Attempt to authenticate automatically with the passportSession cookie.
    // This must come AFTER the cookie code pasted just above.
    _init();

  }
  window.FirebasePassportLogin = FirebasePassportLogin;
}());