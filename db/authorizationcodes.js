var codes = {};


exports.find = function(key, done) {
  var code = codes[key];
  return done(null, code);
};

exports.findByClientIdAndRedirect = function(clientId, redirect_uri, done) {
  for(let code in codes) {
    if(codes[code].clientId === clientId && codes[code].redirectURI === redirect_uri) {
      return done(null, code);
    }
  }
  return done(null, null);
};

exports.save = function(code, clientId, redirectURI, userId, done) {
  codes[code] = { clientId: clientId, redirectURI: redirectURI, userId: userId };
  return done(null);
};

exports.delete = function(code, done) {
  delete codes[code]
  return done(null);
};
