exports.setup = function (passport, config) {
    var TrelloStrategy = require('passport-trello').Strategy;
    if(config.TRELLO_CLIENT_ID.length == 0){
      throw "No trello client ID";
    }
    if(config.TRELLO_CLIENT_SECRET.length == 0){
      throw "No trello client secret";
    }
    if(config.TRELLO_CALLBACK_URL.length == 0){
      throw "No trello callback URL";
    }
    console.log(config); 
    passport.use(new TrelloStrategy({
        consumerKey: config.TRELLO_CLIENT_ID,
        consumerSecret: config.TRELLO_CLIENT_SECRET,
        callbackURL: config.TRELLO_CALLBACK_URL,
        trelloParams: {
          scope: config.TRELLO_SCOPE
          expiration: "never"
        }
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
