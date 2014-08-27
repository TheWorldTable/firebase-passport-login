exports.setup = function (passport, config) {
    var GitHubStrategy = require('passport-github').Strategy;

    passport.use(new GitHubStrategy({
        clientID: config.GITHUB_CLIENT_ID,
        clientSecret: config.GITHUB_CLIENT_SECRET,
        callbackURL: config.GITHUB_CALLBACK_URL,
        scope: config.GITHUB_SCOPE 
      },
      function(accessToken, refreshToken, profile, done) {
            var user = {
                refreshToken: refreshToken || "",
                accessToken: accessToken,
                provider: profile.provider,
                id: profile.id,
                uid: profile.provider + ':' + profile.id,
                displayName: profile.name,
                thirdPartyUserData: profile._json
            };
            return done(0, user);
      }
    ));

    return {
        options: {
            "state": "_____"
        }
    };
};
