exports.setup = function (passport, config) {
    var TrelloStrategy = require('passport-trello').Strategy;

    passport.use(new TrelloStrategy({
        consumerKey: config.TRELLO_CLIENT_ID,
        consumerSecret: config.TRELLO_CLIENT_SECRET,
        callbackURL: config.TRELLO_CALLBACK_URL
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
