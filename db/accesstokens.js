var tokens = {};


exports.find = function(key, done) {
  var token = tokens[key];
  return done(null, token);
};

exports.findByClientId = function(clientId, done) {
  for(let token in tokens) {
    if(tokens[token].clientId === clientId) {
      return done(null, token);
    }
  }
  return done(null, null);
};

exports.save = function(token, clientId, userId, expiresAt, done) {
  tokens[token] = { userId: userId, clientId: clientId, expiresAt : expiresAt};
  return done(null);
};
