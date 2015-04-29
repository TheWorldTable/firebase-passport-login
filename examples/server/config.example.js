exports.SERVICES = ["reddit", "foursquare", "linkedin"];
exports.FIREBASE_SECRET = "";
exports.FIREBASE_URL = "https://<Your Firebase>.firebaseio.com";
exports.COOKIE_SECRET = "<Random Secret>";

exports.reddit = {
  REDDIT_CLIENT_ID: "",
  REDDIT_CLIENT_SECRET: "",
  REDDIT_CALLBACK_URL: "http://localhost:1337/auth/reddit/callback",
};

exports.foursquare = {
  FOURSQUARE_CLIENT_ID: "",
  FOURSQUARE_CLIENT_SECRET: "",
  FOURSQUARE_CALLBACK_URL: "http://localhost:1337/auth/foursquare/callback"
};

exports.linkedin = {
  LINKEDIN_CLIENT_ID: "", // API Secret
  LINKEDIN_CLIENT_SECRET: "", // API Key
  LINKEDIN_CALLBACK_URL: "http://localhost:1337/auth/linkedin/callback"
};

exports.facebook = {
  FACEBOOK_APP_ID: "785612021499967",
  FACEBOOK_APP_SECRET: "7e98ddedba770dc9aad1f3178a6f8ac8",
  FACEBOOK_CALLBACK_URL: "https://localhost:8008/auth/facebook/callback",
  options: {
    scope: 'email,user_location',
    display: 'popup'
  }
};

