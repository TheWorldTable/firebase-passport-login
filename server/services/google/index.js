exports.setup = function(passport, config) {
  var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

  passport.use(new GoogleStrategy(Object.assign({
      clientID: config.clientID,
      clientSecret: config.clientSecret,
      callbackURL: config.callbackURL
    }, config.options || {}),
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
