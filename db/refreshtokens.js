var rtokens = {};


exports.find = function(key, done) {
  var token = rtokens[key];
  return done(null, token);
};

exports.findByClientId = function(clientId, done) {
  for(let token in rtokens) {
    if(rtokens[token].clientId === clientId) {
      return done(null, token);
    }
  }
  return done(null, null);
};

exports.save = function(token, clientId, userId, expiresAt, done) {
  rtokens[token] = { userId: userId, clientId: clientId , expiresAt : expiresAt};
  return done(null);
};
