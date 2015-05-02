exports.setup = function (passport, config) {
    var LinkedInStrategy = require('passport-linkedin').Strategy;

    passport.use(new LinkedInStrategy({
        consumerKey: config.clientID,
        consumerSecret: config.clientSecret,
        callbackURL: config.callbackURL
      },
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
