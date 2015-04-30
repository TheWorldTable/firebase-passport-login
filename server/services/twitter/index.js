exports.setup = function(passport, config) {
  var TwitterStrategy = require('passport-twitter').Strategy;

  passport.use(new TwitterStrategy({
      consumerKey: config.CONSUMER_KEY,
      consumerSecret: config.CONSUMER_SECRET,
      callbackURL: config.CALLBACK_URL
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
    options: config.options || {}
  };
};
