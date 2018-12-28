exports.setup = function (passport, config) {
    var LinkedInStrategy = require('passport-linkedin').Strategy;

    passport.use(new LinkedInStrategy(Object.assign({
        consumerKey: config.clientID,
        consumerSecret: config.clientSecret,
        callbackURL: config.callbackURL
      }, config.options || {}),
      function(accessToken, refreshToken, profile, done) {
            var user = {
                refreshToken: refreshToken || "",
                accessToken: accessToken,
                provider: profile.provider,
                id: profile.id,
                uid: profile.provider + ':' + profile.id,
                displayName: profile.name  
            };
            return done(0, {user: user, thirdPartyUserData: profile._json});
      }
    ));

    return {
        options: {
            "state": "_____"
        }
    };
}
