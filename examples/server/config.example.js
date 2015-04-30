exports.SERVICES = ["reddit", "foursquare", "linkedin"];
exports.FIREBASE_SECRET = "";
exports.FIREBASE_URL = "https://<Your Firebase>.firebaseio.com";
exports.COOKIE_SECRET = "<Random Secret>";

exports.reddit = {
  CLIENT_ID: "",
  CLIENT_SECRET: "",
  CALLBACK_URL: "http://localhost:1337/auth/reddit/callback",
};

exports.foursquare = {
  CLIENT_ID: "",
  CLIENT_SECRET: "",
  CALLBACK_URL: "http://localhost:1337/auth/foursquare/callback"
};

exports.linkedin = {
  CLIENT_ID: "", // API Secret
  CLIENT_SECRET: "", // API Key
  CALLBACK_URL: "http://localhost:1337/auth/linkedin/callback"
};

exports.facebook = {
  APP_ID: "",
  APP_SECRET: "",
  CALLBACK_URL: "https://localhost:8008/auth/facebook/callback",
  options: {
    scope: 'email,user_location',
    display: 'popup'
  }
};

exports.google = {
  CLIENT_ID: "",
  CLIENT_SECRET: "",
  CALLBACK_URL: "https://localhost:8008/auth/google/callback",
  options: {
    scope: ["email","https://www.googleapis.com/auth/plus.me","https://www.googleapis.com/auth/plus.profiles.read"]
  }
};
