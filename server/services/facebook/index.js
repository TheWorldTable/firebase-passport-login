exports.setup = function(passport, config) {
  var FacebookStrategy = require('passport-facebook').Strategy;

  passport.use(new FacebookStrategy({
      clientID: config.FACEBOOK_APP_ID,
      clientSecret: config.FACEBOOK_APP_SECRET,
      callbackURL: config.FACEBOOK_CALLBACK_URL
    },
    function(accessToken, refreshToken, profile, done) {
      var user = {
        refreshToken: refreshToken || "",
        accessToken: accessToken,
        provider: profile.provider,
        id: profile.id,
        uid: profile.provider + ':' + profile.id,
        displayName: profile.name,
      };
      return done(0, {user: user, thirdPartyUserData: profile._json});
    }
  ));

  return {
    options: {
      scope: 'read_stream'
    }
  };
};
