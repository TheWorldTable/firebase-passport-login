exports.setup = function (passport, config) {
    var StackStrategy = require('passport-stack').Strategy;

    passport.use(new StackStrategy({
        clientID: config.STACK_CLIENT_ID,
        clientSecret: config.STACK_CLIENT_SECRET,
        callbackURL: config.STACK_CALLBACK_URL,
        scope: config.STACK_SCOPE,
        authorizationURL: config.authorizationURL,
        tokenURL: config.tokenURL,
        userProfileURL: config.userProfileURL
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
