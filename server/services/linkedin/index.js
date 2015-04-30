exports.setup = function (passport, config) {
    var LinkedInStrategy = require('passport-linkedin').Strategy;

    passport.use(new LinkedInStrategy({
        consumerKey: config.CLIENT_ID,
        consumerSecret: config.CLIENT_SECRET,
        callbackURL: config.CALLBACK_URL
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
