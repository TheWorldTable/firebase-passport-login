exports.debugTokens = false;

exports.COOKIE_SECRET = "<Random Secret>";
exports.FIREBASE_URL = "https://<Your Firebase>.firebaseio.com";
exports.FIREBASE_SECRETS = {
  'https://the-world-table.firebaseio.com': '<firebase_secret>',
  'https://twt-dev-server-nh.firebaseio.com': '<firebase_secret>',
  'https://twt-dev-sever.firebaseio.com': '<firebase_secret>'
};

exports.SERVICES = ["reddit", "foursquare", "linkedin"];

exports.reddit = {
  clientID: "",
  clientSecret: "",
  callbackURL: "http://localhost:1337/auth/reddit/callback",
};

exports.foursquare = {
  clientID: "",
  clientSecret: "",
  callbackURL: "http://localhost:1337/auth/foursquare/callback"
};

exports.linkedin = {
  clientID: "",
  clientSecret: "",
  callbackURL: "http://localhost:1337/auth/linkedin/callback"
};

exports.facebook = {
  clientId: "",
  clientSecret: "",
  callbackURL: "https://localhost:8008/auth/facebook/callback",
  options: {
    scope: 'email,user_location',
    display: 'popup'
  }
};

exports.google = {
  clientID: "",
  clientSecret: "",
  callbackURL: "https://localhost:8008/auth/google/callback",
  options: {
    scope: ["email","https://www.googleapis.com/auth/plus.me","https://www.googleapis.com/auth/plus.profiles.read"]
  }
};

exports.twitter = {
  consumerKey: "",
  consumerSecret: "",
  callbackURL: "https://localhost:8008/auth/twitter/callback"
};
